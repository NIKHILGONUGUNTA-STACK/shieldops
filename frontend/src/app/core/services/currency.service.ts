import { Injectable } from '@angular/core';

/**
 * Metadata and calculation details for a financial currency presentation.
 */
export interface FinancialPresentationResult {
  readonly originalAmount: number | null;
  readonly originalCurrency: string;
  readonly originalFormatted: string;
  readonly inrEquivalentAmount: number | null;
  readonly inrFormatted: string | null;
  readonly exchangeRate: number | null;
  readonly rateLabel: string | null;
  readonly isDemonstrationRate: boolean;
  readonly disclaimer: string;
  readonly isConversionSupported: boolean;
}

/**
 * Centralized Financial Presentation and Formatting Service.
 *
 * Implements Indian Rupee (INR, ₹) as the preferred financial presentation
 * currency throughout ShieldOps while strictly preserving original ledger
 * currencies and amounts without implicit backend conversions.
 *
 * Uses Indian numbering system grouping ('en-IN', e.g. ₹10,40,234.16) and
 * explicit fixed demonstration reference exchange rates:
 * - USD -> INR: 84.00
 * - GBP -> INR: 108.50
 */
@Injectable({
  providedIn: 'root'
})
export class CurrencyService {
  /**
   * Fixed demonstration reference rates (demonstration only, not live market rates).
   */
  public static readonly DEMONSTRATION_RATES: Readonly<Record<string, number>> = Object.freeze({
    USD: 84.00,
    GBP: 108.50,
    INR: 1.00
  });

  /**
   * Universal explicit disclaimer for demonstration reference equivalents.
   */
  public static readonly DEMONSTRATION_DISCLAIMER =
    'Demonstration reference equivalent. Not an actual ledger balance or executed conversion.';

  private readonly inrFormatter: Intl.NumberFormat;
  private readonly usdFormatter: Intl.NumberFormat;
  private readonly gbpFormatter: Intl.NumberFormat;

  constructor() {
    this.inrFormatter = new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });

    this.usdFormatter = new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });

    this.gbpFormatter = new Intl.NumberFormat('en-GB', {
      style: 'currency',
      currency: 'GBP',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });
  }

  /**
   * Checks whether a currency has a configured demonstration reference rate.
   */
  public isSupported(currency: string | null | undefined): boolean {
    if (!currency) return false;
    const upper = currency.toUpperCase().trim();
    return Object.prototype.hasOwnProperty.call(CurrencyService.DEMONSTRATION_RATES, upper);
  }

  /**
   * Retrieves the fixed demonstration rate for a given source currency.
   */
  public getDemonstrationRate(currency: string | null | undefined): number | null {
    if (!currency) return null;
    const upper = currency.toUpperCase().trim();
    return CurrencyService.DEMONSTRATION_RATES[upper] ?? null;
  }

  /**
   * Returns the explicit human-readable rate label.
   */
  public getRateLabel(currency: string | null | undefined): string | null {
    if (!currency) return null;
    const upper = currency.toUpperCase().trim();
    const rate = this.getDemonstrationRate(upper);
    if (rate === null) return null;
    if (upper === 'INR') return '1 INR = ₹1.00 (Native Currency)';
    return `1 ${upper} = ₹${rate.toFixed(2)} (Demonstration Rate)`;
  }

  /**
   * Formats an amount directly into Indian numbering system INR (₹10,40,234.16).
   */
  public formatInr(amount: number | null | undefined): string {
    if (amount === null || amount === undefined || isNaN(amount)) {
      return '—';
    }
    // Handle floating-point negative zero
    const normalized = Object.is(amount, -0) ? 0 : amount;
    return this.inrFormatter.format(normalized);
  }

  /**
   * Formats an amount in its authoritative native currency.
   * Never mutates input.
   */
  public formatNative(amount: number | null | undefined, currency: string | null | undefined): string {
    if (amount === null || amount === undefined || isNaN(amount)) {
      return '—';
    }
    const curr = (currency || 'USD').toUpperCase().trim();
    const normalized = Object.is(amount, -0) ? 0 : amount;

    switch (curr) {
      case 'USD':
        return this.usdFormatter.format(normalized);
      case 'GBP':
        return this.gbpFormatter.format(normalized);
      case 'INR':
        return this.inrFormatter.format(normalized);
      default:
        try {
          return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: curr,
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
          }).format(normalized);
        } catch {
          return `${curr} ${normalized.toFixed(2)}`;
        }
    }
  }

  /**
   * Calculates the exact reference INR equivalent using fixed demonstration rates.
   * Returns null if amount is null/undefined or currency has no demonstration rate.
   */
  public calculateInrEquivalent(amount: number | null | undefined, fromCurrency: string | null | undefined): number | null {
    if (amount === null || amount === undefined || isNaN(amount)) {
      return null;
    }
    const rate = this.getDemonstrationRate(fromCurrency);
    if (rate === null) {
      return null;
    }
    // High-precision rounding to 2 decimal places
    const product = amount * rate;
    return Math.round((product + Number.EPSILON) * 100) / 100;
  }

  /**
   * Formats the reference INR equivalent as a string (₹10,40,234.16).
   * Returns null if currency is unsupported or amount is invalid.
   */
  public formatInrEquivalent(amount: number | null | undefined, fromCurrency: string | null | undefined): string | null {
    const equiv = this.calculateInrEquivalent(amount, fromCurrency);
    if (equiv === null) return null;
    return this.formatInr(equiv);
  }

  /**
   * Compiles complete dual-presentation metadata for a financial value.
   * Guarantees immutability and zero payload mutation.
   */
  public getPresentation(amount: number | null | undefined, currency: string | null | undefined): FinancialPresentationResult {
    const origCurrency = (currency || 'USD').toUpperCase().trim();
    const originalFormatted = this.formatNative(amount, origCurrency);
    const rate = this.getDemonstrationRate(origCurrency);
    const rateLabel = this.getRateLabel(origCurrency);
    const inrEquivalentAmount = this.calculateInrEquivalent(amount, origCurrency);
    const inrFormatted = inrEquivalentAmount !== null ? this.formatInr(inrEquivalentAmount) : null;
    const isConversionSupported = rate !== null;

    return Object.freeze({
      originalAmount: amount !== undefined && !isNaN(Number(amount)) ? amount : null,
      originalCurrency: origCurrency,
      originalFormatted,
      inrEquivalentAmount,
      inrFormatted,
      exchangeRate: rate,
      rateLabel,
      isDemonstrationRate: origCurrency !== 'INR' && rate !== null,
      disclaimer: CurrencyService.DEMONSTRATION_DISCLAIMER,
      isConversionSupported
    });
  }
}
