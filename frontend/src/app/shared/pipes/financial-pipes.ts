import { Pipe, PipeTransform, inject } from '@angular/core';
import { CurrencyService } from '../../core/services/currency.service';

/**
 * Pipe to format an amount in its authoritative native currency.
 * Usage: {{ amount | formatCurrency:currency }}
 * Example: {{ 12383.74 | formatCurrency:'USD' }} -> "$12,383.74"
 */
@Pipe({
  name: 'formatCurrency',
  standalone: true
})
export class CurrencyFormatPipe implements PipeTransform {
  private readonly currencyService = inject(CurrencyService);

  transform(amount: number | null | undefined, currency: string | null | undefined): string {
    return this.currencyService.formatNative(amount, currency);
  }
}

/**
 * Pipe to calculate and format the reference INR equivalent using Indian grouping ('en-IN').
 * Usage: {{ amount | inrEquivalent:currency }}
 * Example: {{ 12383.74 | inrEquivalent:'USD' }} -> "₹10,40,234.16"
 */
@Pipe({
  name: 'inrEquivalent',
  standalone: true
})
export class InrEquivalentPipe implements PipeTransform {
  private readonly currencyService = inject(CurrencyService);

  transform(amount: number | null | undefined, currency: string | null | undefined): string {
    return this.currencyService.formatInrEquivalent(amount, currency) ?? '—';
  }
}
