import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityOverview, ProblemDetail } from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';
import { LoadingSpinnerComponent } from '../../shared/components/loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../../shared/components/empty-state/empty-state.component';

@Component({
  selector: 'app-overview',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    SeverityBadgeComponent,
    StatusBadgeComponent,
    LoadingSpinnerComponent,
    EmptyStateComponent
  ],
  template: `
    <div class="soc-page">
      <!-- Page Header & Global Controls -->
      <div class="soc-header">
        <div>
          <div class="breadcrumb">COMMAND & CONTROL / SITUATIONAL AWARENESS</div>
          <h1 class="page-title">Security Telemetry Overview</h1>
          <p class="page-subtitle">
            Aggregated threat intelligence, correlation triggers, and active intrusion queue from live PostgreSQL data.
          </p>
        </div>

        <div class="soc-controls">
          <label for="windowHoursSelect" class="window-label">TIME WINDOW:</label>
          <select
            id="windowHoursSelect"
            [value]="selectedWindow()"
            (change)="onWindowChange($event)"
            class="form-select window-select"
            [disabled]="loading()"
          >
            <option [value]="6">Last 6 Hours</option>
            <option [value]="12">Last 12 Hours</option>
            <option [value]="24">Last 24 Hours</option>
            <option [value]="48">Last 48 Hours</option>
            <option [value]="72">Last 72 Hours</option>
            <option [value]="168">Last 7 Days (168h)</option>
          </select>

          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <span>↻</span> Refresh
          </button>
        </div>
      </div>

      <!-- Loading State -->
      <app-loading-spinner *ngIf="loading()" message="Querying PostgreSQL SOC aggregation indexes..."></app-loading-spinner>

      <!-- Error State -->
      <div *ngIf="error()" class="error-panel soc-card">
        <div class="error-header">
          <span class="error-icon">⚠️</span>
          <span class="error-title">Failed to load Security Overview</span>
        </div>
        <p class="error-detail">{{ error()?.detail || 'An unexpected error occurred.' }}</p>
        <button (click)="refresh()" class="btn btn-secondary btn-sm mt-3">Retry Request</button>
      </div>

      <!-- Main Content Area when loaded -->
      <div *ngIf="!loading() && overview() as data" class="overview-grid">
        <!-- KPI Strip: Dense Metrics -->
        <div class="kpi-strip">
          <div class="kpi-card soc-card">
            <div class="kpi-label">EVALUATED API EVENTS</div>
            <div class="kpi-value mono">{{ data.totalEvents24h | number }}</div>
            <div class="kpi-subtext text-muted">Ingested & correlated in window</div>
          </div>

          <div class="kpi-card soc-card alert">
            <div class="kpi-label">ANOMALY EVENTS FLAGGED</div>
            <div class="kpi-value mono text-teal">{{ data.totalAnomalies24h | number }}</div>
            <div class="kpi-subtext text-muted">Exceeding deterministic threshold</div>
          </div>

          <div class="kpi-card soc-card" [class.critical]="data.activeIncidentsCount > 0">
            <div class="kpi-label">OPEN INCIDENTS QUEUE</div>
            <div class="kpi-value mono">{{ data.activeIncidentsCount | number }}</div>
            <div class="kpi-subtext text-muted">Requiring analyst investigation</div>
          </div>

          <div class="kpi-card soc-card">
            <div class="kpi-label">ANOMALY RATIO</div>
            <div class="kpi-value mono">
              {{ calculateAnomalyRatio(data) }}%
            </div>
            <div class="kpi-subtext text-muted">Telemetry anomaly density</div>
          </div>
        </div>

        <!-- Distributions Row -->
        <div class="distributions-row">
          <!-- Severity Breakdown -->
          <div class="soc-card distribution-card">
            <div class="soc-card-header">
              <span class="soc-card-title">Incidents by Severity</span>
              <span class="badge badge-info">{{ getObjectCount(data.incidentsBySeverity) }} SEVERITIES</span>
            </div>

            <div *ngIf="getObjectCount(data.incidentsBySeverity) === 0" class="empty-compact text-muted">
              No incidents registered in this time window.
            </div>

            <div class="severity-bars">
              <div *ngFor="let item of getSeverityEntries(data.incidentsBySeverity)" class="dist-row">
                <div class="dist-label-col">
                  <app-severity-badge [severity]="item.key"></app-severity-badge>
                </div>
                <div class="dist-bar-track">
                  <div
                    class="dist-bar-fill"
                    [ngClass]="'bar-' + item.key.toLowerCase()"
                    [style.width.%]="getBarPercentage(item.value, data.activeIncidentsCount)"
                  ></div>
                </div>
                <div class="dist-count mono">{{ item.value }}</div>
              </div>
            </div>
          </div>

          <!-- Threat Category Distribution -->
          <div class="soc-card distribution-card">
            <div class="soc-card-header">
              <span class="soc-card-title">Threat Categories</span>
              <span class="badge badge-info">{{ getObjectCount(data.incidentsByCategory) }} CATEGORIES</span>
            </div>

            <div *ngIf="getObjectCount(data.incidentsByCategory) === 0" class="empty-compact text-muted">
              No category telemetry recorded in this time window.
            </div>

            <div class="category-list">
              <div *ngFor="let item of getCategoryEntries(data.incidentsByCategory)" class="category-item">
                <span class="cat-name mono">{{ item.key }}</span>
                <span class="cat-badge badge badge-info">{{ item.value }} INCIDENTS</span>
              </div>
            </div>
          </div>

          <!-- Top Triggered Rules -->
          <div class="soc-card distribution-card">
            <div class="soc-card-header">
              <span class="soc-card-title">Top Correlation Rules</span>
              <span class="badge badge-info">{{ data.topRulesTriggered.length }} RULES</span>
            </div>

            <div *ngIf="data.topRulesTriggered.length === 0" class="empty-compact text-muted">
              Zero rule triggers in current time window.
            </div>

            <div class="rules-table-compact">
              <div *ngFor="let rule of data.topRulesTriggered" class="rule-row">
                <span class="rule-id mono text-teal">{{ rule.ruleId }}</span>
                <span class="rule-count mono">{{ rule.count }} triggers</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Incidents Table -->
        <div class="soc-card incidents-section">
          <div class="soc-card-header">
            <span class="soc-card-title">Recent Correlated Incidents</span>
            <a routerLink="/incidents" class="btn btn-secondary btn-sm">View Full Queue →</a>
          </div>

          <div *ngIf="data.recentIncidents.length === 0">
            <app-empty-state
              title="Zero Active Threats"
              message="No security incidents match the evaluated criteria in this time window."
            ></app-empty-state>
          </div>

          <div *ngIf="data.recentIncidents.length > 0" class="soc-table-container">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Rule Triggered</th>
                  <th>Category</th>
                  <th>Target Entity</th>
                  <th>Events</th>
                  <th>Last Detected</th>
                  <th>Summary</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let inc of data.recentIncidents">
                  <td><app-severity-badge [severity]="inc.severity"></app-severity-badge></td>
                  <td><app-status-badge [status]="inc.status"></app-status-badge></td>
                  <td class="mono text-teal">{{ inc.ruleId }}</td>
                  <td><span class="badge badge-info">{{ inc.threatCategory }}</span></td>
                  <td class="mono text-secondary">{{ inc.targetEntityValue }}</td>
                  <td class="mono">{{ inc.eventCount }}</td>
                  <td class="mono text-muted">{{ formatTime(inc.lastEventAt) }}</td>
                  <td class="incident-summary" [title]="inc.summary">{{ inc.summary }}</td>
                  <td>
                    <a [routerLink]="['/incidents', inc.id]" class="btn btn-secondary btn-sm">
                      Inspect
                    </a>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Hourly Trend Listing -->
        <div *ngIf="data.eventVolumeTrend.length > 0" class="soc-card trend-section">
          <div class="soc-card-header">
            <span class="soc-card-title">Hourly Telemetry Density</span>
            <span class="mono text-muted text-sm">{{ data.eventVolumeTrend.length }} Hourly Buckets</span>
          </div>
          <div class="trend-strip">
            <div *ngFor="let bucket of data.eventVolumeTrend" class="trend-col">
              <span class="trend-count mono">{{ bucket.eventCount }}</span>
              <div class="trend-bar" [style.height.px]="getTrendBarHeight(bucket.eventCount)"></div>
              <span class="trend-time mono">{{ formatBucketHour(bucket.bucketTime) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page {
      padding: var(--space-6);
      display: flex;
      flex-direction: column;
      gap: var(--space-5);
    }
    .soc-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: var(--space-4);
      flex-wrap: wrap;
    }
    .breadcrumb {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--accent-teal);
      margin-bottom: var(--space-1);
    }
    .page-title {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: var(--space-1);
    }
    .page-subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      max-width: 600px;
    }
    .soc-controls {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .window-label {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
    }
    .window-select {
      font-family: var(--font-mono);
      min-width: 150px;
    }
    .overview-grid {
      display: flex;
      flex-direction: column;
      gap: var(--space-5);
    }
    .kpi-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: var(--space-4);
    }
    .kpi-card {
      padding: var(--space-4);
      display: flex;
      flex-direction: column;
      gap: var(--space-1);
    }
    .kpi-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.06em;
      color: var(--text-muted);
    }
    .kpi-value {
      font-size: 26px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .kpi-card.critical .kpi-value {
      color: var(--sev-critical);
    }
    .kpi-subtext {
      font-size: 11px;
    }
    .distributions-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: var(--space-4);
    }
    .distribution-card {
      min-height: 200px;
    }
    .severity-bars, .category-list, .rules-table-compact {
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
      padding: var(--space-2) 0;
    }
    .dist-row {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .dist-label-col {
      width: 90px;
    }
    .dist-bar-track {
      flex: 1;
      height: 8px;
      background: var(--bg-surface);
      border-radius: 4px;
      overflow: hidden;
    }
    .dist-bar-fill {
      height: 100%;
      border-radius: 4px;
      min-width: 4px;
    }
    .bar-critical { background: var(--sev-critical); }
    .bar-high { background: var(--sev-high); }
    .bar-medium { background: var(--sev-medium); }
    .bar-low { background: var(--sev-low); }
    .bar-info { background: var(--sev-info); }
    .dist-count {
      width: 30px;
      text-align: right;
      font-size: 12px;
      font-weight: 600;
    }
    .category-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 8px;
      background: var(--bg-surface);
      border-radius: var(--radius-sm);
      font-size: 12px;
    }
    .rule-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 8px;
      background: var(--bg-surface);
      border-radius: var(--radius-sm);
      font-size: 12px;
    }
    .empty-compact {
      font-size: 12px;
      padding: var(--space-4) 0;
      text-align: center;
    }
    .incident-summary {
      max-width: 250px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
    }
    .trend-strip {
      display: flex;
      align-items: flex-end;
      gap: var(--space-2);
      overflow-x: auto;
      padding-top: var(--space-4);
      height: 120px;
    }
    .trend-col {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
      min-width: 36px;
      height: 100%;
      justify-content: flex-end;
    }
    .trend-count {
      font-size: 10px;
      color: var(--accent-teal);
    }
    .trend-bar {
      width: 14px;
      background: var(--accent-teal);
      border-radius: 2px 2px 0 0;
      min-height: 4px;
    }
    .trend-time {
      font-size: 10px;
      color: var(--text-muted);
    }
    .error-panel {
      border-color: var(--sev-critical-border);
      background: var(--sev-critical-bg);
      color: var(--sev-critical);
      padding: var(--space-4);
    }
    .error-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-weight: 700;
      font-size: 14px;
      margin-bottom: var(--space-2);
    }
    .error-detail {
      font-size: 13px;
      color: var(--text-primary);
    }
    .mt-3 {
      margin-top: var(--space-3);
    }
  `]
})
export class OverviewComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  readonly selectedWindow = signal<number>(24);
  readonly loading = signal<boolean>(true);
  readonly overview = signal<SecurityOverview | null>(null);
  readonly error = signal<ProblemDetail | null>(null);

  ngOnInit(): void {
    this.loadOverview();
  }

  loadOverview(): void {
    this.loading.set(true);
    this.error.set(null);

    this.api.getOverview(this.selectedWindow()).subscribe({
      next: (data) => {
        this.overview.set(data);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onWindowChange(event: Event): void {
    const select = event.target as HTMLSelectElement;
    const windowHours = parseInt(select.value, 10);
    if (!isNaN(windowHours)) {
      this.selectedWindow.set(windowHours);
      this.loadOverview();
    }
  }

  refresh(): void {
    this.loadOverview();
  }

  calculateAnomalyRatio(data: SecurityOverview): string {
    if (!data.totalEvents24h || data.totalEvents24h === 0) return '0.0';
    const ratio = (data.totalAnomalies24h / data.totalEvents24h) * 100;
    return ratio.toFixed(1);
  }

  getObjectCount(obj: Record<string, number> | null | undefined): number {
    return obj ? Object.keys(obj).length : 0;
  }

  getSeverityEntries(obj: Record<string, number> | null | undefined): { key: string; value: number }[] {
    if (!obj) return [];
    return Object.entries(obj).map(([key, value]) => ({ key, value }));
  }

  getCategoryEntries(obj: Record<string, number> | null | undefined): { key: string; value: number }[] {
    if (!obj) return [];
    return Object.entries(obj).map(([key, value]) => ({ key, value }));
  }

  getBarPercentage(count: number, total: number): number {
    if (!total || total === 0) return count > 0 ? 100 : 0;
    return Math.min(100, Math.round((count / total) * 100));
  }

  formatTime(isoString: string): string {
    if (!isoString) return '—';
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  }

  formatBucketHour(bucketTime: string): string {
    if (!bucketTime) return '';
    try {
      const date = new Date(bucketTime);
      return `${date.getHours().toString().padStart(2, '0')}:00`;
    } catch {
      return bucketTime;
    }
  }

  getTrendBarHeight(count: number): number {
    return Math.min(80, Math.max(4, count * 8));
  }
}
