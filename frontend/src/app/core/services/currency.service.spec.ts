import { TestBed } from '@angular/core/testing';
import { CurrencyService } from './currency.service';

describe('CurrencyService', () => {
  let service: CurrencyService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [CurrencyService]
    });
    service = TestBed.inject(CurrencyService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('Indian Numbering System and INR Formatting (en-IN)', () => {
    it('should format numbers with standard Indian digit grouping (₹10,40,234.16)', () => {
      const formatted = service.formatInr(1040234.16);
      expect(formatted).toBe('₹10,40,234.16');
    });

    it('should format smaller and larger amounts with correct Indian grouping', () => {
      expect(service.formatInr(2100.00)).toBe('₹2,100.00');
      expect(service.formatInr(575077.13)).toBe('₹5,75,077.13');
      expect(service.formatInr(10000000.00)).toBe('₹1,00,00,000.00'); // 1 Crore
    });

    it('should format zero correctly', () => {
      expect(service.formatInr(0)).toBe('₹0.00');
      expect(service.formatInr(-0)).toBe('₹0.00');
    });

    it('should format negative amounts correctly with minus sign', () => {
      const formatted = service.formatInr(-4200.50);
      expect(formatted).toBe('-₹4,200.50');
    });

    it('should safely handle null, undefined, and NaN without throwing', () => {
      expect(service.formatInr(null)).toBe('—');
      expect(service.formatInr(undefined)).toBe('—');
      expect(service.formatInr(NaN)).toBe('—');
    });
  });

  describe('USD and GBP Native Currency Formatting', () => {
    it('should format USD amounts correctly ($12,383.74)', () => {
      const formatted = service.formatNative(12383.74, 'USD');
      expect(formatted).toBe('$12,383.74');
    });

    it('should format GBP amounts correctly (£5,300.25)', () => {
      const formatted = service.formatNative(5300.25, 'GBP');
      expect(formatted).toBe('£5,300.25');
    });

    it('should format native INR amounts correctly (₹10,40,234.16)', () => {
      const formatted = service.formatNative(1040234.16, 'INR');
      expect(formatted).toBe('₹10,40,234.16');
    });

    it('should safely format negative USD and GBP amounts', () => {
      expect(service.formatNative(-25.00, 'USD')).toBe('-$25.00');
      expect(service.formatNative(-100.00, 'GBP')).toBe('-£100.00');
    });

    it('should handle fallback or unsupported currencies gracefully', () => {
      const eurFormatted = service.formatNative(500.00, 'EUR');
      expect(eurFormatted).toContain('500.00');
    });

    it('should return dash for null and undefined native amounts', () => {
      expect(service.formatNative(null, 'USD')).toBe('—');
      expect(service.formatNative(undefined, 'GBP')).toBe('—');
    });
  });

  describe('Demonstration Reference Exchange Rates & Calculations', () => {
    it('should maintain fixed demonstration reference rates (84.00 for USD, 108.50 for GBP)', () => {
      expect(service.getDemonstrationRate('USD')).toBe(84.00);
      expect(service.getDemonstrationRate('GBP')).toBe(108.50);
      expect(service.getDemonstrationRate('INR')).toBe(1.00);
    });

    it('should convert USD to reference INR equivalent accurately', () => {
      // Alex Morgan source account balance: 12383.74 * 84.00 = 1040234.16
      const inrEquiv = service.calculateInrEquivalent(12383.74, 'USD');
      expect(inrEquiv).toBe(1040234.16);

      // Planned transfer: 25.00 * 84.00 = 2100.00
      expect(service.calculateInrEquivalent(25.00, 'USD')).toBe(2100.00);
    });

    it('should convert GBP to reference INR equivalent with correct 2-decimal rounding', () => {
      // Sam Taylor balance: 5300.25 * 108.50 = 575077.125 -> 575077.13
      const inrEquiv = service.calculateInrEquivalent(5300.25, 'GBP');
      expect(inrEquiv).toBe(575077.13);
    });

    it('should format reference INR equivalent strings properly', () => {
      expect(service.formatInrEquivalent(12383.74, 'USD')).toBe('₹10,40,234.16');
      expect(service.formatInrEquivalent(25.00, 'USD')).toBe('₹2,100.00');
      expect(service.formatInrEquivalent(5300.25, 'GBP')).toBe('₹5,75,077.13');
    });

    it('should return null for unsupported currencies (e.g. EUR, JPY)', () => {
      expect(service.getDemonstrationRate('EUR')).toBeNull();
      expect(service.getDemonstrationRate('JPY')).toBeNull();
      expect(service.calculateInrEquivalent(100.00, 'EUR')).toBeNull();
      expect(service.formatInrEquivalent(100.00, 'EUR')).toBeNull();
    });

    it('should handle zero and negative conversions safely', () => {
      expect(service.calculateInrEquivalent(0, 'USD')).toBe(0);
      expect(service.formatInrEquivalent(0, 'USD')).toBe('₹0.00');

      expect(service.calculateInrEquivalent(-50.00, 'USD')).toBe(-4200.00);
      expect(service.formatInrEquivalent(-50.00, 'USD')).toBe('-₹4,200.00');
    });

    it('should handle null, undefined, and non-numeric values safely in calculation', () => {
      expect(service.calculateInrEquivalent(null, 'USD')).toBeNull();
      expect(service.calculateInrEquivalent(undefined, 'USD')).toBeNull();
      expect(service.calculateInrEquivalent(NaN, 'USD')).toBeNull();
      expect(service.formatInrEquivalent(null, 'USD')).toBeNull();
    });
  });

  describe('Full Presentation Object & Immutability', () => {
    it('should produce immutable presentation result with explicit rate labels and disclaimer', () => {
      const result = service.getPresentation(12383.74, 'USD');

      expect(result.originalAmount).toBe(12383.74);
      expect(result.originalCurrency).toBe('USD');
      expect(result.originalFormatted).toBe('$12,383.74');
      expect(result.inrEquivalentAmount).toBe(1040234.16);
      expect(result.inrFormatted).toBe('₹10,40,234.16');
      expect(result.exchangeRate).toBe(84.00);
      expect(result.rateLabel).toBe('1 USD = ₹84.00 (Demonstration Rate)');
      expect(result.isDemonstrationRate).toBeTrue();
      expect(result.disclaimer).toBe(CurrencyService.DEMONSTRATION_DISCLAIMER);
      expect(result.isConversionSupported).toBeTrue();

      // Ensure object is frozen/immutable
      expect(Object.isFrozen(result)).toBeTrue();
    });

    it('should produce correct presentation for native INR without marking as demonstration rate', () => {
      const result = service.getPresentation(1040234.16, 'INR');

      expect(result.originalCurrency).toBe('INR');
      expect(result.originalFormatted).toBe('₹10,40,234.16');
      expect(result.inrFormatted).toBe('₹10,40,234.16');
      expect(result.isDemonstrationRate).toBeFalse();
      expect(result.isConversionSupported).toBeTrue();
    });

    it('should produce correct presentation for unsupported currency', () => {
      const result = service.getPresentation(250.00, 'EUR');

      expect(result.originalCurrency).toBe('EUR');
      expect(result.originalFormatted).toContain('250.00');
      expect(result.inrEquivalentAmount).toBeNull();
      expect(result.inrFormatted).toBeNull();
      expect(result.exchangeRate).toBeNull();
      expect(result.isConversionSupported).toBeFalse();
      expect(result.isDemonstrationRate).toBeFalse();
    });

    it('should produce safe presentation for null amount', () => {
      const result = service.getPresentation(null, 'USD');

      expect(result.originalAmount).toBeNull();
      expect(result.originalFormatted).toBe('—');
      expect(result.inrEquivalentAmount).toBeNull();
      expect(result.inrFormatted).toBeNull();
    });
  });
});
