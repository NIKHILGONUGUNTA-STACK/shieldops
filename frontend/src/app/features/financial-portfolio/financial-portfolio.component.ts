import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { FinancialAmountComponent } from '../../shared/components/financial-amount/financial-amount.component';
import { CurrencyService } from '../../core/services/currency.service';

interface CustomerAccountSummary {
  accountId: string;
  accountNumber: string;
  customerName: string;
  customerId: string;
  currency: string;
  balance: number;
  status: 'ACTIVE' | 'FROZEN' | 'SUSPENDED';
  accountType: string;
}

interface FinancialTransactionRecord {
  transactionId: string;
  reference: string;
  type: string;
  sourceAccount: string;
  destinationAccount: string;
  amount: number;
  currency: string;
  status: 'COMPLETED' | 'PENDING' | 'REJECTED';
  timestamp: string;
  description: string;
}

@Component({
  selector: 'app-financial-portfolio',
  standalone: true,
  imports: [CommonModule, RouterLink, FinancialAmountComponent],
  template: `
    <div class="soc-page-container">
      <!-- Header -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb mono text-xs text-muted">FINTECH LEDGER / FINANCIAL PRESENTATION AUDIT</div>
          <h1 class="soc-title">Financial Portfolio & Presentation Explorer</h1>
          <p class="soc-subtitle">
            Authoritative multi-currency account inventory, transaction activity, and customer asset balances with
            INR (₹) preferred presentation and transparent demonstration reference conversion.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon inr-icon">₹</div>
            <div class="soc-stat-content">
              <span class="soc-stat-val mono">INR (₹)</span>
              <span class="soc-stat-sub">Preferred Presentation</span>
            </div>
          </div>
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val mono">{{ totalInrEquivalentFormatted }}</span>
              <span class="soc-stat-sub">Total Assets (INR Ref)</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Financial Presentation Transparency & Invariant Banner -->
      <div class="fx-disclaimer-banner">
        <div class="banner-header">
          <span class="banner-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4A6CFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
          </span>
          <strong>Aegis FinTech Presentation Integrity & FX Transparency Invariants</strong>
        </div>
        <p class="banner-text">
          Indian Rupee (INR, ₹) is the preferred presentation currency across ShieldOps. Under FinTech core banking safety
          invariants, native account currencies (USD, GBP) and balances remain immutable. All INR equivalents are computed
          at fixed demonstration rates (<strong>1 USD = ₹84.00</strong>, <strong>1 GBP = ₹108.50</strong>) using the Indian
          numbering system (<code>en-IN</code>). They are reference presentation equivalents and do not represent actual ledger
          funds or executed currency conversions.
        </p>
      </div>

      <!-- Section 1: Customer Account Inventory -->
      <div class="soc-card section-card">
        <div class="card-header-strip">
          <div class="card-title-group">
            <h2 class="section-title">Customer Account Inventory</h2>
            <span class="badge badge-info">{{ accounts.length }} Verified Accounts</span>
          </div>
          <span class="text-muted text-xs mono">Baseline Verification Status: CONFIRMED</span>
        </div>

        <div class="soc-table-container">
          <table class="soc-table" aria-label="Customer Accounts Inventory">
            <thead>
              <tr>
                <th>Account Reference</th>
                <th>Owner / Customer</th>
                <th>Type</th>
                <th>Status</th>
                <th>Native Balance & INR Reference Equivalent</th>
                <th>Fixed FX Rate</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let acct of accounts">
                <td>
                  <span class="mono font-semibold">{{ acct.accountNumber }}</span>
                  <div class="text-2xs text-muted mono">{{ acct.accountId }}</div>
                </td>
                <td>
                  <div class="font-semibold text-primary">{{ acct.customerName }}</div>
                  <div class="text-2xs text-muted mono">{{ acct.customerId }}</div>
                </td>
                <td>
                  <span class="chip chip-muted">{{ acct.accountType }}</span>
                </td>
                <td>
                  <span class="status-pill status-active">{{ acct.status }}</span>
                </td>
                <td>
                  <app-financial-amount
                    [amount]="acct.balance"
                    [currency]="acct.currency"
                    size="md"
                  ></app-financial-amount>
                </td>
                <td>
                  <span class="mono text-xs text-secondary">{{ getRateLabel(acct.currency) }}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Section 2: Recent Transaction Activity -->
      <div class="soc-card section-card">
        <div class="card-header-strip">
          <div class="card-title-group">
            <h2 class="section-title">Transaction Activity & Historical Debits</h2>
            <span class="badge badge-info">{{ transactions.length }} Audited Transactions</span>
          </div>
          <span class="text-muted text-xs mono">Ledger Invariant: Reconciled</span>
        </div>

        <div class="soc-table-container">
          <table class="soc-table" aria-label="Recent Financial Transactions">
            <thead>
              <tr>
                <th>Transaction Reference</th>
                <th>Timestamp</th>
                <th>Flow</th>
                <th>Status</th>
                <th>Amount & INR Equivalent</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let tx of transactions">
                <td>
                  <span class="mono font-semibold">{{ tx.reference }}</span>
                  <div class="text-2xs text-muted mono">{{ tx.transactionId }}</div>
                </td>
                <td class="mono text-xs text-muted">{{ tx.timestamp }}</td>
                <td>
                  <div class="flow-cell">
                    <span class="mono text-xs text-secondary">{{ tx.sourceAccount }}</span>
                    <span class="arrow-sep">→</span>
                    <span class="mono text-xs text-teal">{{ tx.destinationAccount }}</span>
                  </div>
                </td>
                <td>
                  <span
                    class="status-pill"
                    [ngClass]="tx.status === 'COMPLETED' ? 'status-active' : 'status-pending'"
                  >
                    {{ tx.status }}
                  </span>
                </td>
                <td>
                  <app-financial-amount
                    [amount]="tx.amount"
                    [currency]="tx.currency"
                    size="sm"
                  ></app-financial-amount>
                </td>
                <td class="text-xs text-secondary">{{ tx.description }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      padding: var(--space-6, 24px);
      max-width: 1400px;
      margin: 0 auto;
    }

    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 20px;
      flex-wrap: wrap;
      gap: 16px;
    }

    .breadcrumb {
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }

    .soc-title {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary, #ffffff);
      margin: 0 0 6px 0;
    }

    .soc-subtitle {
      font-size: 13px;
      color: var(--text-secondary, #8b949e);
      margin: 0;
      max-width: 820px;
      line-height: 1.5;
    }

    .header-stat-pills {
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .soc-stat-pill {
      display: flex;
      align-items: center;
      gap: 10px;
      background: var(--bg-card, #161b22);
      border: 1px solid var(--border-color, #30363d);
      border-radius: 8px;
      padding: 8px 14px;
    }

    .soc-stat-icon {
      width: 32px;
      height: 32px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      font-weight: 700;
    }

    .soc-stat-icon.inr-icon {
      background: rgba(255, 159, 28, 0.15);
      color: #ff9f1c;
      border: 1px solid rgba(255, 159, 28, 0.3);
    }

    .soc-stat-icon.teal {
      background: rgba(0, 209, 178, 0.15);
      color: #00d1b2;
      border: 1px solid rgba(0, 209, 178, 0.3);
    }

    .soc-stat-val {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary, #ffffff);
      display: block;
    }

    .soc-stat-sub {
      font-size: 11px;
      color: var(--text-muted, #8b949e);
    }

    /* Transparency banner */
    .fx-disclaimer-banner {
      background: rgba(74, 108, 255, 0.08);
      border: 1px solid rgba(74, 108, 255, 0.25);
      border-radius: 8px;
      padding: 14px 18px;
      margin-bottom: 24px;
    }

    .banner-header {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #9db2ff;
      font-size: 13px;
      margin-bottom: 6px;
    }

    .banner-text {
      font-size: 12px;
      color: var(--text-secondary, #8b949e);
      margin: 0;
      line-height: 1.5;
    }

    .banner-text strong {
      color: #c9d7ff;
    }

    .banner-text code {
      background: rgba(255, 255, 255, 0.06);
      padding: 1px 4px;
      border-radius: 3px;
      color: #00d1b2;
    }

    /* Section Cards */
    .section-card {
      background: var(--bg-card, #161b22);
      border: 1px solid var(--border-color, #30363d);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 24px;
    }

    .card-header-strip {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }

    .card-title-group {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .section-title {
      font-size: 16px;
      font-weight: 600;
      color: var(--text-primary, #ffffff);
      margin: 0;
    }

    .badge-info {
      background: rgba(74, 108, 255, 0.15);
      color: #9db2ff;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }

    /* Table styling */
    .soc-table-container {
      overflow-x: auto;
    }

    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    .soc-table th {
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-color, #30363d);
      color: var(--text-muted, #8b949e);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .soc-table td {
      padding: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      color: var(--text-primary, #ffffff);
      vertical-align: middle;
    }

    .soc-table tr:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    .status-pill {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      letter-spacing: 0.5px;
    }

    .status-active {
      background: rgba(0, 209, 178, 0.15);
      color: #00d1b2;
      border: 1px solid rgba(0, 209, 178, 0.3);
    }

    .status-pending {
      background: rgba(255, 159, 28, 0.15);
      color: #ff9f1c;
      border: 1px solid rgba(255, 159, 28, 0.3);
    }

    .chip-muted {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-secondary, #8b949e);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
    }

    .flow-cell {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .arrow-sep {
      color: var(--text-muted, #8b949e);
      font-size: 12px;
    }
  `]
})
export class FinancialPortfolioComponent {
  private readonly currencyService = inject(CurrencyService);

  // Authoritative FinTech customer accounts
  readonly accounts: CustomerAccountSummary[] = [
    {
      accountId: '20000000-0000-4000-8000-000000000001',
      accountNumber: 'ACCT-00010001',
      customerName: 'Alex Morgan',
      customerId: '10000000-0000-4000-8000-000000000001',
      currency: 'USD',
      balance: 12383.74,
      status: 'ACTIVE',
      accountType: 'PRIMARY_CHECKING'
    },
    {
      accountId: '20000000-0000-4000-8000-000000000002',
      accountNumber: 'ACCT-00020001',
      customerName: 'Sam Taylor',
      customerId: '10000000-0000-4000-8000-000000000002',
      currency: 'GBP',
      balance: 5300.25,
      status: 'ACTIVE',
      accountType: 'SAVINGS'
    }
  ];

  // Audited financial transactions
  readonly transactions: FinancialTransactionRecord[] = [
    {
      transactionId: '30000000-0000-4000-8000-000000000001',
      reference: 'TX-DEBIT-001',
      type: 'ACCOUNT_DEBIT',
      sourceAccount: 'ACCT-00010001',
      destinationAccount: 'CLEARING-EXT',
      amount: 116.26,
      currency: 'USD',
      status: 'COMPLETED',
      timestamp: '2026-10-15 14:22:00 UTC',
      description: 'Historical verified debit reconciling seed balance to $12,383.74'
    },
    {
      transactionId: '30000000-0000-4000-8000-000000000099',
      reference: 'TX-PLAN-001',
      type: 'CUSTOMER_TRANSFER',
      sourceAccount: 'ACCT-00010001',
      destinationAccount: 'ACCT-00020001',
      amount: 25.00,
      currency: 'USD',
      status: 'PENDING',
      timestamp: '2026-11-07 14:52:00 UTC',
      description: 'Planned SCEN-BENIGN-01 outbound clearing transfer'
    }
  ];

  get totalInrEquivalentFormatted(): string {
    let totalInr = 0;
    for (const acct of this.accounts) {
      const equiv = this.currencyService.calculateInrEquivalent(acct.balance, acct.currency);
      if (equiv !== null) totalInr += equiv;
    }
    return this.currencyService.formatInr(totalInr);
  }

  getRateLabel(currency: string): string {
    return this.currencyService.getRateLabel(currency) ?? 'Unsupported Rate';
  }
}
