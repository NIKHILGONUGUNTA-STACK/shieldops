import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityEventResponse, ProblemDetail, SecurityOverview } from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';

@Component({
  selector: 'app-attacks',
  standalone: true,
  imports: [CommonModule, RouterLink, SeverityBadgeComponent],
  template: `
    <div class="soc-page-container">
      <!-- Page Header with Wallarm-Inspired Stat Badges -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Attack Activity</h1>
          <p class="soc-subtitle">
            Live anomalous API activity, flagged intrusion attempts, and attacker telemetry.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon amber">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ overview?.totalAnomalies24h ?? events.length }}</span>
              <span class="soc-stat-sub">Anomalies (24h)</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon red">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ getUniqueIpsCount() }}</span>
              <span class="soc-stat-sub">Active Attacker IPs</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Action / Tab Bar -->
      <div class="attack-controls-bar">
        <div class="pill-group">
          <button (click)="filterMethod = 'ALL'" [class.active]="filterMethod === 'ALL'" class="pill-btn">All Methods</button>
          <button (click)="filterMethod = 'POST'" [class.active]="filterMethod === 'POST'" class="pill-btn">POST</button>
          <button (click)="filterMethod = 'GET'" [class.active]="filterMethod === 'GET'" class="pill-btn">GET</button>
          <button (click)="filterMethod = 'PUT'" [class.active]="filterMethod === 'PUT'" class="pill-btn">PUT</button>
          <button (click)="filterMethod = 'DELETE'" [class.active]="filterMethod === 'DELETE'" class="pill-btn">DELETE</button>
        </div>

        <button (click)="loadAttackActivity()" class="btn btn-secondary btn-sm" [disabled]="loading">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
          {{ loading ? 'Refreshing...' : 'Refresh' }}
        </button>
      </div>

      <!-- Error State -->
      <div *ngIf="error" class="error-banner" role="alert">
        <span class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </span>
        <div>
          <div class="error-title">{{ error.title }}</div>
          <div class="error-detail">{{ error.detail }}</div>
        </div>
        <button (click)="loadAttackActivity()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Streaming anomalous API activity...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && filteredEvents.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
        </div>
        <h3>No Attack Activity Detected</h3>
        <p>No anomalous security events match the current filter criteria.</p>
      </div>

      <!-- Attack Activity Table -->
      <div *ngIf="!loading && !error && filteredEvents.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Attack Activity Telemetry">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Method</th>
              <th>Request URI</th>
              <th>Status</th>
              <th>Source IP</th>
              <th>Customer ID</th>
              <th>Anomaly Flags</th>
              <th>Correlation ID</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let ev of filteredEvents">
              <td class="mono text-muted text-nowrap">{{ ev.timestamp | date:'yyyy-MM-dd HH:mm:ss' }}</td>
              <td>
                <span class="method-badge" [ngClass]="ev.httpMethod.toLowerCase()">{{ ev.httpMethod }}</span>
              </td>
              <td class="mono uri-cell" [title]="ev.requestUri">{{ ev.requestUri }}</td>
              <td>
                <span class="status-code-badge" [ngClass]="getStatusCodeClass(ev.statusCode)">{{ ev.statusCode }}</span>
              </td>
              <td class="mono text-teal">{{ ev.sourceIp }}</td>
              <td class="mono">{{ ev.customerId || '—' }}</td>
              <td>
                <span class="anomaly-pill" *ngIf="ev.anomalyFlags">{{ ev.anomalyFlags }}</span>
                <span *ngIf="!ev.anomalyFlags" class="text-muted">—</span>
              </td>
              <td>
                <a [routerLink]="['/events']" [queryParams]="{ correlationId: ev.correlationId }" class="correlation-link mono" title="Inspect full telemetry trace">
                  {{ ev.correlationId ? ev.correlationId.substring(0, 12) + '...' : '—' }}
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
      gap: var(--space-3);
    }
    .attack-controls-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: var(--space-4);
      flex-wrap: wrap;
      gap: var(--space-3);
    }
    .method-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-family: var(--font-mono);
    }
    .method-badge.post { background: rgba(249, 115, 22, 0.15); color: var(--accent-amber); }
    .method-badge.get { background: rgba(20, 184, 166, 0.15); color: var(--accent-teal); }
    .method-badge.put { background: rgba(56, 189, 248, 0.15); color: var(--sev-low); }
    .method-badge.delete { background: rgba(239, 68, 68, 0.15); color: var(--sev-critical); }
    .status-code-badge {
      font-size: 11px;
      font-family: var(--font-mono);
      font-weight: 700;
      padding: 1px 5px;
      border-radius: var(--radius-sm);
    }
    .status-code-badge.status-2xx { color: var(--status-resolved); }
    .status-code-badge.status-4xx { color: var(--accent-amber); background: rgba(249, 115, 22, 0.1); }
    .status-code-badge.status-5xx { color: var(--sev-critical); background: rgba(239, 68, 68, 0.1); }
    .uri-cell {
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .anomaly-pill {
      font-size: 10px;
      font-weight: 600;
      color: var(--sev-critical);
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      font-family: var(--font-mono);
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
export class AttacksComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  events: SecurityEventResponse[] = [];
  overview: SecurityOverview | null = null;
  loading = false;
  error: ProblemDetail | null = null;
  filterMethod: string = 'ALL';

  ngOnInit(): void {
    this.loadAttackActivity();
  }

  loadAttackActivity(): void {
    this.loading = true;
    this.error = null;

    this.api.getEvents({ anomalyFlags: 'true', page: 0, size: 50 }).subscribe({
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

    this.api.getOverview(24).subscribe({
      next: (ov) => this.overview = ov,
      error: () => {} // Non-critical overview failure
    });
  }

  get filteredEvents(): SecurityEventResponse[] {
    if (this.filterMethod === 'ALL') return this.events;
    return this.events.filter(e => e.httpMethod === this.filterMethod);
  }

  getUniqueIpsCount(): number {
    return new Set(this.events.map(e => e.sourceIp)).size;
  }

  getStatusCodeClass(code: number): string {
    if (code >= 500) return 'status-5xx';
    if (code >= 400) return 'status-4xx';
    return 'status-2xx';
  }
}
