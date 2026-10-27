import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  SecurityEventResponse,
  SecurityEventPageResponse,
  EventFilterParams,
  ProblemDetail
} from '../../core/models/security.models';
import { LoadingSpinnerComponent } from '../../shared/components/loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../../shared/components/empty-state/empty-state.component';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    FormsModule,
    LoadingSpinnerComponent,
    EmptyStateComponent
  ],
  template: `
    <div class="soc-page">
      <!-- Header -->
      <div class="soc-header">
        <div>
          <div class="breadcrumb">TELEMETRY & AUDIT / ACTIVITY ANALYSIS</div>
          <h1 class="page-title">API Security Event Explorer</h1>
          <p class="page-subtitle">
            Search, filter, and inspect ingested HTTP telemetry records drained from Redis streams into PostgreSQL.
          </p>
        </div>

        <div class="soc-controls">
          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <span>↻</span> Refresh Telemetry
          </button>
        </div>
      </div>

      <!-- Filter Controls Strip -->
      <div class="soc-card filter-card">
        <div class="filter-grid">
          <!-- Status Code Filter -->
          <div class="filter-group">
            <label for="statusSelect" class="filter-label">HTTP STATUS</label>
            <select
              id="statusSelect"
              [value]="selectedStatusCode()"
              (change)="onStatusCodeChange($event)"
              class="form-select"
            >
              <option value="">All Statuses</option>
              <option value="200">200 OK</option>
              <option value="201">201 Created</option>
              <option value="400">400 Bad Request</option>
              <option value="401">401 Unauthorized</option>
              <option value="403">403 Forbidden</option>
              <option value="404">404 Not Found</option>
              <option value="409">409 Conflict</option>
              <option value="429">429 Rate Limited</option>
              <option value="500">500 Server Error</option>
            </select>
          </div>

          <!-- Method Filter -->
          <div class="filter-group">
            <label for="methodSelect" class="filter-label">HTTP METHOD</label>
            <select
              id="methodSelect"
              [value]="selectedMethod()"
              (change)="onMethodChange($event)"
              class="form-select"
            >
              <option value="">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
            </select>
          </div>

          <!-- Source IP Filter -->
          <div class="filter-group">
            <label for="ipInput" class="filter-label">SOURCE IP</label>
            <input
              id="ipInput"
              type="text"
              [(ngModel)]="sourceIpInput"
              (keydown.enter)="applyTextFilters()"
              placeholder="e.g. 192.168.1.100"
              class="form-input"
            />
          </div>

          <!-- Customer UUID Filter -->
          <div class="filter-group">
            <label for="custInput" class="filter-label">CUSTOMER UUID</label>
            <input
              id="custInput"
              type="text"
              [(ngModel)]="customerIdInput"
              (keydown.enter)="applyTextFilters()"
              placeholder="Filter by UUID..."
              class="form-input"
            />
          </div>

          <!-- Anomaly Flags Filter -->
          <div class="filter-group">
            <label for="anomalySelect" class="filter-label">ANOMALY INDICATOR</label>
            <select
              id="anomalySelect"
              [value]="selectedAnomaly()"
              (change)="onAnomalyChange($event)"
              class="form-select"
            >
              <option value="">All Telemetry</option>
              <option value="BOLA_VIOLATION">BOLA Violation</option>
              <option value="AUTH_FAILURE">Auth Failure</option>
              <option value="DATA_EXCESS">Data Excess</option>
              <option value="RATE_BURST">Rate Burst</option>
              <option value="PROBE">Probe</option>
              <option value="INJECTION">Injection</option>
            </select>
          </div>

          <!-- Resource Type Filter -->
          <div class="filter-group">
            <label for="resourceSelect" class="filter-label">RESOURCE TYPE</label>
            <select
              id="resourceSelect"
              [value]="selectedResourceType()"
              (change)="onResourceTypeChange($event)"
              class="form-select"
            >
              <option value="">All Resources</option>
              <option value="CUSTOMER">Customer</option>
              <option value="ACCOUNT">Account</option>
              <option value="TRANSFER">Transfer</option>
              <option value="BENEFICIARY">Beneficiary</option>
            </select>
          </div>

          <!-- Filter Action Buttons -->
          <div class="filter-group filter-actions">
            <button (click)="applyTextFilters()" class="btn btn-primary btn-sm">
              Search
            </button>
            <button (click)="resetFilters()" class="btn btn-secondary btn-sm" [disabled]="!hasActiveFilters()">
              Reset
            </button>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      <app-loading-spinner *ngIf="loading()" message="Executing index-accelerated telemetry search..."></app-loading-spinner>

      <!-- Error State -->
      <div *ngIf="error()" class="error-panel soc-card">
        <div class="error-header">
          <span class="error-icon">⚠️</span>
          <span class="error-title">Event Search Failed</span>
        </div>
        <p class="error-detail">{{ error()?.detail || 'An error occurred during telemetry retrieval.' }}</p>
        <button (click)="refresh()" class="btn btn-secondary btn-sm mt-3">Retry Query</button>
      </div>

      <!-- Main Explorer Layout: Table + Side Detail Drawer -->
      <div *ngIf="!loading() && pageData() as data" class="explorer-layout">
        <!-- Event Table Card -->
        <div class="soc-card table-panel" [class.with-drawer]="selectedEvent()">
          <div class="table-meta-bar">
            <span class="queue-count mono">
              Showing {{ data.events.length }} of {{ data.totalElements }} events (Page {{ data.page + 1 }} of {{ data.totalPages || 1 }})
            </span>

            <div class="page-size-selector">
              <label for="eventPageSize" class="text-muted" style="font-size: 11px;">PAGE SIZE:</label>
              <select
                id="eventPageSize"
                [value]="selectedPageSize()"
                (change)="onPageSizeChange($event)"
                class="form-select form-select-sm mono"
              >
                <option [value]="10">10</option>
                <option [value]="20">20</option>
                <option [value]="50">50</option>
                <option [value]="100">100</option>
              </select>
            </div>
          </div>

          <!-- Empty State -->
          <app-empty-state
            *ngIf="data.events.length === 0"
            title="Zero Matching Events"
            message="No security events match the current filter parameters."
          ></app-empty-state>

          <!-- Table View -->
          <div *ngIf="data.events.length > 0" class="soc-table-container">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Method</th>
                  <th>Request Path</th>
                  <th>Status</th>
                  <th>Source IP</th>
                  <th>Duration</th>
                  <th>Anomaly Flag</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  *ngFor="let evt of data.events"
                  (click)="selectEvent(evt)"
                  [class.selected-row]="selectedEvent()?.id === evt.id"
                  class="clickable-row"
                >
                  <td class="mono text-muted text-xs">{{ formatDateTime(evt.timestamp) }}</td>
                  <td>
                    <span class="method-badge" [ngClass]="'method-' + evt.httpMethod.toLowerCase()">
                      {{ evt.httpMethod }}
                    </span>
                  </td>
                  <td class="mono text-teal text-xs path-cell" [title]="evt.requestUri">
                    {{ evt.requestUri }}
                  </td>
                  <td>
                    <span class="status-code-badge" [ngClass]="getStatusCodeClass(evt.statusCode)">
                      {{ evt.statusCode }}
                    </span>
                  </td>
                  <td class="mono text-secondary text-xs">{{ evt.sourceIp }}</td>
                  <td class="mono text-xs">{{ evt.durationMs }}ms</td>
                  <td>
                    <span *ngIf="evt.anomalyFlags" class="anomaly-chip mono">
                      {{ evt.anomalyFlags }}
                    </span>
                    <span *ngIf="!evt.anomalyFlags" class="text-muted text-xs">—</span>
                  </td>
                  <td>
                    <button (click)="selectEvent(evt); $event.stopPropagation()" class="btn btn-secondary btn-sm">
                      Inspect
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Pagination Bar -->
          <div *ngIf="data.totalPages > 1" class="pagination-bar">
            <button
              (click)="goToPage(data.page - 1)"
              [disabled]="data.first"
              class="btn btn-secondary btn-sm"
            >
              ← Previous
            </button>

            <span class="page-indicator mono">
              Page {{ data.page + 1 }} / {{ data.totalPages }}
            </span>

            <button
              (click)="goToPage(data.page + 1)"
              [disabled]="data.last"
              class="btn btn-secondary btn-sm"
            >
              Next →
            </button>
          </div>
        </div>

        <!-- Side Detail Drawer -->
        <div *ngIf="selectedEvent() as evt" class="soc-card detail-drawer">
          <div class="drawer-header">
            <span class="soc-card-title">Event Telemetry Inspector</span>
            <button (click)="closeDrawer()" class="drawer-close" title="Close inspector">✕</button>
          </div>

          <div class="drawer-body">
            <div class="drawer-section">
              <div class="drawer-item">
                <span class="drawer-label">EVENT ID:</span>
                <span class="mono text-xs text-muted">{{ evt.id }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">CORRELATION ID:</span>
                <span class="mono text-xs text-teal">{{ evt.correlationId }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">TIMESTAMP:</span>
                <span class="mono text-xs">{{ formatDateTime(evt.timestamp) }}</span>
              </div>
            </div>

            <div class="drawer-section">
              <div class="drawer-item">
                <span class="drawer-label">REQUEST URI:</span>
                <span class="mono text-xs text-teal font-bold">{{ evt.httpMethod }} {{ evt.requestUri }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">ROUTE PATTERN:</span>
                <span class="mono text-xs text-secondary">{{ evt.routePattern || '—' }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">RESPONSE STATUS:</span>
                <span class="status-code-badge" [ngClass]="getStatusCodeClass(evt.statusCode)">
                  {{ evt.statusCode }}
                </span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">LATENCY:</span>
                <span class="mono text-xs">{{ evt.durationMs }} milliseconds</span>
              </div>
            </div>

            <div class="drawer-section">
              <div class="drawer-item">
                <span class="drawer-label">SOURCE IP:</span>
                <span class="mono text-xs text-secondary">{{ evt.sourceIp }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">USER AGENT:</span>
                <span class="mono text-xs text-muted text-break">{{ evt.userAgent || '—' }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">CUSTOMER UUID:</span>
                <span class="mono text-xs text-secondary">{{ evt.customerId || 'Unauthenticated / Anonymous' }}</span>
              </div>
              <div class="drawer-item">
                <span class="drawer-label">JWT SUBJECT:</span>
                <span class="mono text-xs text-secondary">{{ evt.subject || '—' }}</span>
              </div>
            </div>

            <div class="drawer-section" *ngIf="evt.resourceType || evt.anomalyFlags || evt.errorCode">
              <div class="drawer-item" *ngIf="evt.resourceType">
                <span class="drawer-label">TARGET RESOURCE:</span>
                <span class="mono text-xs">{{ evt.resourceType }} (ID: {{ evt.resourceId || '—' }})</span>
              </div>
              <div class="drawer-item" *ngIf="evt.anomalyFlags">
                <span class="drawer-label">ANOMALY FLAG:</span>
                <span class="anomaly-chip mono">{{ evt.anomalyFlags }}</span>
              </div>
              <div class="drawer-item" *ngIf="evt.errorCode">
                <span class="drawer-label">ERROR CODE:</span>
                <span class="mono text-xs text-danger">{{ evt.errorCode }}</span>
              </div>
            </div>

            <!-- Quick Correlation Action -->
            <div class="drawer-actions">
              <button
                (click)="filterByCorrelationId(evt.correlationId)"
                class="btn btn-secondary btn-sm w-100"
              >
                Find Correlated Events (Same Flow)
              </button>
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
      max-width: 700px;
    }
    .soc-controls {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .filter-card {
      padding: var(--space-4);
    }
    .filter-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: var(--space-3);
      align-items: flex-end;
    }
    .filter-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .filter-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .filter-actions {
      flex-direction: row;
      gap: var(--space-2);
    }
    .explorer-layout {
      display: flex;
      gap: var(--space-4);
      align-items: flex-start;
    }
    .table-panel {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
      padding: var(--space-4);
      transition: all 0.2s ease-in-out;
    }
    .detail-drawer {
      width: 360px;
      min-width: 360px;
      padding: var(--space-4);
      background: var(--bg-card);
      border-left: 3px solid var(--accent-teal);
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
    }
    .drawer-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: var(--space-2);
      border-bottom: 1px solid var(--border-subtle);
    }
    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      cursor: pointer;
    }
    .drawer-body {
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
    }
    .drawer-section {
      display: flex;
      flex-direction: column;
      gap: var(--space-2);
      padding-bottom: var(--space-3);
      border-bottom: 1px solid var(--border-subtle);
    }
    .drawer-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .drawer-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
    }
    .text-break {
      word-break: break-all;
    }
    .drawer-actions {
      padding-top: var(--space-2);
    }
    .table-meta-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: var(--space-2);
      border-bottom: 1px solid var(--border-subtle);
    }
    .queue-count {
      font-size: 12px;
      color: var(--text-secondary);
    }
    .page-size-selector {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .form-select-sm {
      padding: 2px 6px;
      font-size: 11px;
    }
    .clickable-row {
      cursor: pointer;
    }
    .selected-row {
      background: var(--accent-teal-subtle) !important;
    }
    .path-cell {
      max-width: 260px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .method-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-family: var(--font-mono);
    }
    .method-get { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
    .method-post { background: rgba(16, 185, 129, 0.15); color: #10b981; }
    .method-put { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
    .method-delete { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .method-patch { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
    .status-code-badge {
      font-size: 11px;
      font-family: var(--font-mono);
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 2px;
    }
    .status-2xx { color: var(--status-resolved); background: var(--status-resolved-bg); }
    .status-4xx { color: var(--status-open); background: var(--status-open-bg); }
    .status-403 { color: var(--sev-high); background: var(--sev-high-bg); }
    .status-5xx { color: var(--sev-critical); background: var(--sev-critical-bg); }
    .anomaly-chip {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
      color: var(--sev-critical);
      font-weight: 700;
    }
    .pagination-bar {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: var(--space-4);
      padding-top: var(--space-3);
      border-top: 1px solid var(--border-subtle);
    }
    .page-indicator {
      font-size: 12px;
      color: var(--text-secondary);
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
    .w-100 { width: 100%; }
    .mt-3 { margin-top: var(--space-3); }
    .text-danger { color: var(--sev-critical); }
  `]
})
export class EventsComponent implements OnInit {
  private readonly api = inject(SecurityApiService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly loading = signal<boolean>(true);
  readonly error = signal<ProblemDetail | null>(null);
  readonly pageData = signal<SecurityEventPageResponse | null>(null);
  readonly selectedEvent = signal<SecurityEventResponse | null>(null);

  readonly currentPage = signal<number>(0);
  readonly selectedPageSize = signal<number>(20);
  readonly selectedStatusCode = signal<string>('');
  readonly selectedMethod = signal<string>('');
  readonly selectedAnomaly = signal<string>('');
  readonly selectedResourceType = signal<string>('');

  sourceIpInput = '';
  customerIdInput = '';
  correlationIdFilter = '';

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      if (params['page'] !== undefined) this.currentPage.set(parseInt(params['page'], 10) || 0);
      if (params['size'] !== undefined) this.selectedPageSize.set(parseInt(params['size'], 10) || 20);
      if (params['statusCode'] !== undefined) this.selectedStatusCode.set(params['statusCode']);
      if (params['httpMethod'] !== undefined) this.selectedMethod.set(params['httpMethod']);
      if (params['anomalyFlags'] !== undefined) this.selectedAnomaly.set(params['anomalyFlags']);
      if (params['resourceType'] !== undefined) this.selectedResourceType.set(params['resourceType']);
      if (params['sourceIp'] !== undefined) this.sourceIpInput = params['sourceIp'];
      if (params['customerId'] !== undefined) this.customerIdInput = params['customerId'];
      if (params['correlationId'] !== undefined) this.correlationIdFilter = params['correlationId'];

      this.loadEvents();
    });
  }

  loadEvents(): void {
    this.loading.set(true);
    this.error.set(null);

    const filterParams: EventFilterParams = {
      page: this.currentPage(),
      size: this.selectedPageSize()
    };

    if (this.selectedStatusCode()) {
      const code = parseInt(this.selectedStatusCode(), 10);
      if (!isNaN(code)) filterParams.statusCode = code;
    }
    if (this.selectedMethod()) filterParams.httpMethod = this.selectedMethod();
    if (this.selectedAnomaly()) filterParams.anomalyFlags = this.selectedAnomaly();
    if (this.selectedResourceType()) filterParams.resourceType = this.selectedResourceType();
    if (this.sourceIpInput.trim()) filterParams.sourceIp = this.sourceIpInput.trim();
    if (this.customerIdInput.trim()) filterParams.customerId = this.customerIdInput.trim();
    if (this.correlationIdFilter.trim()) filterParams.correlationId = this.correlationIdFilter.trim();

    this.api.getEvents(filterParams).subscribe({
      next: (res) => {
        this.pageData.set(res);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  updateUrlParams(): void {
    const queryParams: Record<string, string | number | null> = {
      page: this.currentPage() > 0 ? this.currentPage() : null,
      size: this.selectedPageSize() !== 20 ? this.selectedPageSize() : null,
      statusCode: this.selectedStatusCode() || null,
      httpMethod: this.selectedMethod() || null,
      anomalyFlags: this.selectedAnomaly() || null,
      resourceType: this.selectedResourceType() || null,
      sourceIp: this.sourceIpInput.trim() || null,
      customerId: this.customerIdInput.trim() || null,
      correlationId: this.correlationIdFilter.trim() || null
    };

    this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      queryParamsHandling: 'merge'
    });
  }

  applyTextFilters(): void {
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onStatusCodeChange(event: Event): void {
    this.selectedStatusCode.set((event.target as HTMLSelectElement).value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onMethodChange(event: Event): void {
    this.selectedMethod.set((event.target as HTMLSelectElement).value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onAnomalyChange(event: Event): void {
    this.selectedAnomaly.set((event.target as HTMLSelectElement).value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onResourceTypeChange(event: Event): void {
    this.selectedResourceType.set((event.target as HTMLSelectElement).value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onPageSizeChange(event: Event): void {
    const value = parseInt((event.target as HTMLSelectElement).value, 10);
    this.selectedPageSize.set(value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  goToPage(page: number): void {
    if (page >= 0) {
      this.currentPage.set(page);
      this.updateUrlParams();
    }
  }

  filterByCorrelationId(corrId: string): void {
    this.correlationIdFilter = corrId;
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  resetFilters(): void {
    this.selectedStatusCode.set('');
    this.selectedMethod.set('');
    this.selectedAnomaly.set('');
    this.selectedResourceType.set('');
    this.sourceIpInput = '';
    this.customerIdInput = '';
    this.correlationIdFilter = '';
    this.currentPage.set(0);
    this.selectedEvent.set(null);
    this.updateUrlParams();
  }

  hasActiveFilters(): boolean {
    return !!(
      this.selectedStatusCode() ||
      this.selectedMethod() ||
      this.selectedAnomaly() ||
      this.selectedResourceType() ||
      this.sourceIpInput.trim() ||
      this.customerIdInput.trim() ||
      this.correlationIdFilter.trim()
    );
  }

  selectEvent(evt: SecurityEventResponse): void {
    this.selectedEvent.set(evt);
  }

  closeDrawer(): void {
    this.selectedEvent.set(null);
  }

  refresh(): void {
    this.loadEvents();
  }

  getStatusCodeClass(code: number): string {
    if (code >= 200 && code < 300) return 'status-2xx';
    if (code === 403) return 'status-403';
    if (code >= 400 && code < 500) return 'status-4xx';
    if (code >= 500) return 'status-5xx';
    return '';
  }

  formatDateTime(isoString: string): string {
    if (!isoString) return '—';
    try {
      const date = new Date(isoString);
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  }
}
