import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FinancialPortfolioComponent } from './financial-portfolio.component';
import { CurrencyService } from '../../core/services/currency.service';
import { provideRouter } from '@angular/router';

describe('FinancialPortfolioComponent', () => {
  let component: FinancialPortfolioComponent;
  let fixture: ComponentFixture<FinancialPortfolioComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FinancialPortfolioComponent],
      providers: [
        CurrencyService,
        provideRouter([])
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(FinancialPortfolioComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should render total portfolio assets in preferred INR format (en-IN)', () => {
    // Alex: 12383.74 * 84 = 1040234.16
    // Sam: 5300.25 * 108.50 = 575077.13
    // Total = 1615311.29 -> ₹16,15,311.29
    expect(component.totalInrEquivalentFormatted).toBe('₹16,15,311.29');

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('₹16,15,311.29');
    expect(compiled.textContent).toContain('Total Assets (INR Ref)');
  });

  it('should render customer accounts with native balances and INR equivalents', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    // Check Alex Morgan's account
    expect(compiled.textContent).toContain('ACCT-00010001');
    expect(compiled.textContent).toContain('Alex Morgan');
    expect(compiled.textContent).toContain('$12,383.74');
    expect(compiled.textContent).toContain('₹10,40,234.16');

    // Check Sam Taylor's account
    expect(compiled.textContent).toContain('ACCT-00020001');
    expect(compiled.textContent).toContain('Sam Taylor');
    expect(compiled.textContent).toContain('£5,300.25');
    expect(compiled.textContent).toContain('₹5,75,077.13');
  });

  it('should render transaction activity with native amount and INR equivalent', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    // Reconciling historical debit ($116.26 * 84 = ₹9,765.84)
    expect(compiled.textContent).toContain('TX-DEBIT-001');
    expect(compiled.textContent).toContain('$116.26');
    expect(compiled.textContent).toContain('₹9,765.84');

    // Planned transfer ($25.00 * 84 = ₹2,100.00)
    expect(compiled.textContent).toContain('TX-PLAN-001');
    expect(compiled.textContent).toContain('$25.00');
    expect(compiled.textContent).toContain('₹2,100.00');
  });

  it('should display explicit demonstration rate disclaimer banner', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Aegis FinTech Presentation Integrity & FX Transparency Invariants');
    expect(compiled.textContent).toContain('1 USD = ₹84.00');
    expect(compiled.textContent).toContain('1 GBP = ₹108.50');
    expect(compiled.textContent).toContain('do not represent actual ledger funds');
  });
});
