import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FinancialAmountComponent } from './financial-amount.component';
import { CurrencyService } from '../../../core/services/currency.service';

describe('FinancialAmountComponent', () => {
  let component: FinancialAmountComponent;
  let fixture: ComponentFixture<FinancialAmountComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FinancialAmountComponent],
      providers: [CurrencyService]
    }).compileComponents();

    fixture = TestBed.createComponent(FinancialAmountComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display authoritative native USD amount and INR reference badge', () => {
    component.amount = 12383.74;
    component.currency = 'USD';
    component.ngOnChanges({
      amount: {
        currentValue: 12383.74,
        previousValue: null,
        firstChange: true,
        isFirstChange: () => true
      }
    });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.native-amount')?.textContent).toContain('$12,383.74');
    expect(compiled.querySelector('.currency-tag')?.textContent).toContain('USD');

    const inrPill = compiled.querySelector('.inr-ref-pill');
    expect(inrPill).toBeTruthy();
    expect(inrPill?.textContent).toContain('₹10,40,234.16');
    expect(inrPill?.getAttribute('title')).toContain('1 USD = ₹84.00 (Demonstration Rate)');
    expect(inrPill?.getAttribute('title')).toContain('Demonstration reference equivalent');
  });

  it('should display GBP amount with correct INR reference equivalent', () => {
    component.amount = 5300.25;
    component.currency = 'GBP';
    component.ngOnChanges({
      amount: {
        currentValue: 5300.25,
        previousValue: null,
        firstChange: true,
        isFirstChange: () => true
      }
    });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.native-amount')?.textContent).toContain('£5,300.25');
    const inrPill = compiled.querySelector('.inr-ref-pill');
    expect(inrPill?.textContent).toContain('₹5,75,077.13');
  });

  it('should not display reference badge for native INR', () => {
    component.amount = 1040234.16;
    component.currency = 'INR';
    component.ngOnChanges({
      amount: {
        currentValue: 1040234.16,
        previousValue: null,
        firstChange: true,
        isFirstChange: () => true
      }
    });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.native-amount')?.textContent).toContain('₹10,40,234.16');
    expect(compiled.querySelector('.inr-ref-pill')).toBeNull();
  });

  it('should display unsupported indicator for unknown currencies', () => {
    component.amount = 1500.00;
    component.currency = 'EUR';
    component.ngOnChanges({
      amount: {
        currentValue: 1500.00,
        previousValue: null,
        firstChange: true,
        isFirstChange: () => true
      }
    });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.inr-ref-pill')).toBeNull();
    expect(compiled.querySelector('.inr-unsupported-pill')).toBeTruthy();
  });

  it('should handle null amounts gracefully without crashing', () => {
    component.amount = null;
    component.currency = 'USD';
    component.ngOnChanges({
      amount: {
        currentValue: null,
        previousValue: 100,
        firstChange: false,
        isFirstChange: () => false
      }
    });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.native-amount')?.textContent).toContain('—');
    expect(compiled.querySelector('.inr-ref-pill')).toBeNull();
  });
});
