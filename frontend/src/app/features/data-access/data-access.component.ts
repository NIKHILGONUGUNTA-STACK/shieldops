import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityEventResponse, ProblemDetail } from '../../core/models/security.models';

@Component({
  selector: 'app-data-access',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Data Access Monitoring</h1>
          <p class="soc-subtitle">
            Privacy-conscious telemetry capture, cryptographic payload hashing, and sensitive resource access tracking.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">🔒</div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">SHA-256</span>
              <span class="soc-stat-sub">Privacy Invariant</span>
            </div>
          </div>
          <button (click)="loadDataAccessEvents()" class="btn btn-secondary btn-sm" [disabled]="loading">
            {{ loading ? 'Refreshing...' : '↻ Refresh' }}
          </button>
        </div>
      </div>

      <!-- Privacy & Data Protection Architecture Banner -->
      <div class="privacy-banner">
        <div class="privacy-header">
          <span class="privacy-shield">🛡️</span>
          <strong>Aegis Privacy-Conscious Telemetry Invariants</strong>
        </div>
        <p class="privacy-desc">
          Aegis Gateway enforces zero-raw-PII storage. In accordance with banking security standards,
          Authorization headers are strictly redacted (<code>Bearer [REDACTED]</code>), request/response bodies are
          hashed via cryptographic SHA-256, and only structural resource IDs and customer subjects are retained in telemetry.
        </p>
      </div>

      <!-- Error State -->
      <div *ngIf="error" class="error-banner" role="alert">
        <span class="error-icon">⚠️</span>
        <div>
          <div class="error-title">{{ error.title }}</div>
          <div class="error-detail">{{ error.detail }}</div>
        </div>
        <button (click)="loadDataAccessEvents()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Auditing resource data access events...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && events.length === 0" class="empty-state">
        <div class="empty-icon">🛡️</div>
        <h3>No Data Access Events</h3>
        <p>No telemetry events currently match data access tracking criteria.</p>
      </div>

      <!-- Resource Access Table -->
      <div *ngIf="!loading && !error && events.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Sensitive Resource Access Telemetry">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Resource Type</th>
              <th>Resource ID</th>
              <th>Customer ID</th>
              <th>HTTP Method</th>
              <th>Request URI</th>
              <th>Source IP</th>
              <th>Correlation Trace</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let ev of events">
              <td class="mono text-muted text-nowrap">{{ ev.timestamp | date:'yyyy-MM-dd HH:mm:ss' }}</td>
              <td>
                <span class="resource-badge mono">{{ ev.resourceType || 'API_ENDPOINT' }}</span>
              </td>
              <td class="mono text-teal">{{ ev.resourceId || '—' }}</td>
              <td class="mono font-semibold">{{ ev.customerId || 'ANONYMOUS' }}</td>
              <td>
                <span class="mono">{{ ev.httpMethod }}</span>
              </td>
              <td class="mono uri-cell" [title]="ev.requestUri">{{ ev.requestUri }}</td>
              <td class="mono text-muted">{{ ev.sourceIp }}</td>
              <td>
                <a [routerLink]="['/events']" [queryParams]="{ correlationId: ev.correlationId }" class="correlation-link mono">
                  {{ ev.correlationId ? ev.correlationId.substring(0, 10) + '...' : '—' }}
                </a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      padding: var(--space-6);
      max-width: 1400px;
      margin: 0 auto;
    }
    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: var(--space-4);
      flex-wrap: wrap;
      gap: var(--space-4);
    }
    .soc-title {
      font-size: 20px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .soc-subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 2px;
    }
    .header-stat-pills {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .privacy-banner {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      margin-bottom: var(--space-4);
    }
    .privacy-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: 13px;
      color: var(--text-primary);
      margin-bottom: var(--space-2);
    }
    .privacy-shield {
      font-size: 16px;
    }
    .privacy-desc {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.6;
    }
    .privacy-desc code {
      background: var(--bg-input);
      padding: 1px 4px;
      border-radius: 2px;
      font-family: var(--font-mono);
      color: var(--accent-teal);
    }
    .resource-badge {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: var(--accent-teal-subtle);
      color: var(--accent-teal);
      border: 1px solid var(--accent-teal-border);
    }
    .uri-cell {
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .correlation-link {
      color: var(--accent-teal);
      text-decoration: none;
      font-size: 11px;
    }
    .correlation-link:hover {
      text-decoration: underline;
    }
    .error-banner {
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
      color: var(--sev-critical);
      padding: var(--space-3) var(--space-4);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      gap: var(--space-3);
      margin-bottom: var(--space-4);
    }
    .loading-state, .empty-state {
      text-align: center;
      padding: var(--space-8);
      color: var(--text-secondary);
    }
    .spinner {
      width: 28px;
      height: 28px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: var(--accent-teal);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto var(--space-3);
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  `]
})
export class DataAccessComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  events: SecurityEventResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  ngOnInit(): void {
    this.loadDataAccessEvents();
  }

  loadDataAccessEvents(): void {
    this.loading = true;
    this.error = null;

    // Load recent API events
    this.api.getEvents({ page: 0, size: 50 }).subscribe({
      next: (page) => {
        this.events = page.events || [];
        this.loading = false;
      },
      error: (err) => {
        this.error = err;
        this.events = [];
        this.loading = false;
      }
    });
  }
}
