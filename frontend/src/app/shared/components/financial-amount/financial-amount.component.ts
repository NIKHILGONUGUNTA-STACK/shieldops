import { Component, Input, OnChanges, SimpleChanges, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CurrencyService, FinancialPresentationResult } from '../../../core/services/currency.service';

/**
 * Reusable Financial Amount Component.
 *
 * Implements Indian Rupee (INR, ₹) preferred presentation with dual-currency
 * transparency, Indian numbering system ('en-IN', e.g. ₹10,40,234.16), and
 * explicit demonstration reference rate badges and tooltips.
 */
@Component({
  selector: 'app-financial-amount',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span class="financial-amount-container" [class.size-sm]="size === 'sm'" [class.size-lg]="size === 'lg'">
      <!-- Native authoritative amount -->
      <span class="native-amount mono font-semibold">
        {{ presentation.originalFormatted }}
        <span class="currency-tag">{{ presentation.originalCurrency }}</span>
      </span>

      <!-- Reference INR Equivalent Badge (for USD / GBP) -->
      <span
        *ngIf="showReference && presentation.isDemonstrationRate && presentation.inrFormatted"
        class="inr-ref-pill"
        [title]="tooltipText"
      >
        <span class="approx-symbol">≈</span>
        <span class="inr-val mono">{{ presentation.inrFormatted }}</span>
        <span class="ref-badge" [attr.aria-label]="tooltipText">REF</span>
      </span>

      <!-- Unsupported Currency Indicator -->
      <span
        *ngIf="showReference && !presentation.isConversionSupported && presentation.originalCurrency !== 'INR'"
        class="inr-unsupported-pill"
        title="No demonstration reference conversion rate configured for this currency."
      >
        <span class="unsupported-tag">No FX Ref</span>
      </span>
    </span>
  `,
  styles: [`
    .financial-amount-container {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

    .native-amount {
      color: var(--text-primary, #ffffff);
      font-size: 13px;
    }

    .currency-tag {
      font-size: 11px;
      color: var(--text-muted, #8b949e);
      margin-left: 2px;
      font-weight: 500;
    }

    .inr-ref-pill {
      display: inline-flex;
      align-items: center;
      gap: 3px;
      padding: 1px 6px;
      background: rgba(74, 108, 255, 0.12);
      border: 1px solid rgba(74, 108, 255, 0.35);
      border-radius: 4px;
      font-size: 11px;
      color: #9db2ff;
      cursor: help;
      transition: all 0.15s ease-in-out;
    }

    .inr-ref-pill:hover {
      background: rgba(74, 108, 255, 0.22);
      border-color: rgba(74, 108, 255, 0.6);
      color: #ffffff;
    }

    .approx-symbol {
      opacity: 0.7;
      font-size: 10px;
    }

    .inr-val {
      font-weight: 600;
      color: #c9d7ff;
    }

    .ref-badge {
      font-size: 8px;
      font-weight: 700;
      background: #4A6CFF;
      color: #ffffff;
      padding: 0 3px;
      border-radius: 2px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .inr-unsupported-pill {
      display: inline-flex;
      align-items: center;
      padding: 1px 5px;
      background: rgba(140, 149, 159, 0.12);
      border: 1px dashed rgba(140, 149, 159, 0.3);
      border-radius: 3px;
      font-size: 10px;
      color: var(--text-muted, #8b949e);
    }

    /* Size variants */
    .size-sm .native-amount {
      font-size: 12px;
    }
    .size-sm .inr-ref-pill {
      font-size: 10px;
      padding: 0 4px;
    }

    .size-lg .native-amount {
      font-size: 18px;
      font-weight: 700;
    }
    .size-lg .inr-ref-pill {
      font-size: 13px;
      padding: 2px 8px;
    }
    .size-lg .currency-tag {
      font-size: 13px;
    }
  `]
})
export class FinancialAmountComponent implements OnChanges {
  private readonly currencyService = inject(CurrencyService);

  @Input() amount: number | null | undefined = null;
  @Input() currency: string = 'USD';
  @Input() showReference: boolean = true;
  @Input() size: 'sm' | 'md' | 'lg' = 'md';

  presentation: FinancialPresentationResult = this.currencyService.getPresentation(null, 'USD');

  get tooltipText(): string {
    const rateText = this.presentation.rateLabel ? `${this.presentation.rateLabel}. ` : '';
    return `${rateText}${this.presentation.disclaimer}`;
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['amount'] || changes['currency']) {
      this.updatePresentation();
    }
  }

  private updatePresentation(): void {
    this.presentation = this.currencyService.getPresentation(this.amount, this.currency);
  }
}
