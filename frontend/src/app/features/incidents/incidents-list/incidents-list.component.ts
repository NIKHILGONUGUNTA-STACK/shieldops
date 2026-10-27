import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, ActivatedRoute, RouterLink } from '@angular/router';
import { SecurityApiService } from '../../../core/services/security-api.service';
import {
  IncidentResponse,
  IncidentPageResponse,
  IncidentSeverity,
  IncidentStatus,
  IncidentFilterParams,
  ProblemDetail
} from '../../../core/models/security.models';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../../shared/components/status-badge/status-badge.component';
import { LoadingSpinnerComponent } from '../../../shared/components/loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../../../shared/components/empty-state/empty-state.component';

@Component({
  selector: 'app-incidents-list',
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
      <!-- Header -->
      <div class="soc-header">
        <div>
          <div class="breadcrumb">INCIDENT RESPONSE / ACTIVE TRIAGE</div>
          <h1 class="page-title">Correlated Incident Queue</h1>
          <p class="page-subtitle">
            Server-side correlated intrusion campaigns requiring analyst investigation, mitigation, and audit lifecycle management.
          </p>
        </div>

        <div class="soc-controls">
          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            Refresh Queue
          </button>
        </div>
      </div>

      <!-- Filter Controls Strip -->
      <div class="soc-card filter-card">
        <div class="filter-grid">
          <!-- Status Filter -->
          <div class="filter-group">
            <label for="statusFilter" class="filter-label">STATUS</label>
            <select
              id="statusFilter"
              [value]="selectedStatus()"
              (change)="onStatusChange($event)"
              class="form-select"
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          <!-- Severity Filter -->
          <div class="filter-group">
            <label for="severityFilter" class="filter-label">SEVERITY</label>
            <select
              id="severityFilter"
              [value]="selectedSeverity()"
              (change)="onSeverityChange($event)"
              class="form-select"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>

          <!-- Threat Category Filter -->
          <div class="filter-group">
            <label for="categoryFilter" class="filter-label">THREAT CATEGORY</label>
            <select
              id="categoryFilter"
              [value]="selectedCategory()"
              (change)="onCategoryChange($event)"
              class="form-select"
            >
              <option value="">All Categories</option>
              <option value="BOLA">BOLA (Broken Object Level Auth)</option>
              <option value="AUTH_ANOMALY">Authentication Anomaly</option>
              <option value="DATA_EXFILTRATION">Excessive Data Access</option>
              <option value="RATE_BURST">Request Rate Burst</option>
              <option value="RECON_PROBE">Reconnaissance Probe</option>
              <option value="INJECTION_ATTEMPT">Injection Indicator</option>
              <option value="COMPLEX_INTRUSION">Complex Intrusion</option>
              <option value="MULTI_VECTOR_CAMPAIGN">Multi-Vector Campaign</option>
            </select>
          </div>

          <!-- Sort Field -->
          <div class="filter-group">
            <label for="sortBySelect" class="filter-label">SORT BY</label>
            <select
              id="sortBySelect"
              [value]="selectedSortBy()"
              (change)="onSortByChange($event)"
              class="form-select"
            >
              <option value="lastEventAt">Last Event Detected</option>
              <option value="createdAt">First Created</option>
              <option value="severity">Severity</option>
              <option value="eventCount">Event Volume</option>
            </select>
          </div>

          <!-- Sort Direction -->
          <div class="filter-group">
            <label for="sortDirSelect" class="filter-label">DIRECTION</label>
            <select
              id="sortDirSelect"
              [value]="selectedSortDirection()"
              (change)="onSortDirectionChange($event)"
              class="form-select"
            >
              <option value="DESC">Descending (Newest / Highest)</option>
              <option value="ASC">Ascending (Oldest / Lowest)</option>
            </select>
          </div>

          <!-- Reset Button -->
          <div class="filter-group reset-group">
            <label class="filter-label">&nbsp;</label>
            <button (click)="resetFilters()" class="btn btn-secondary btn-sm" [disabled]="!hasActiveFilters()">
              Reset Filters
            </button>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      <app-loading-spinner *ngIf="loading()" message="Querying PostgreSQL incident repository..."></app-loading-spinner>

      <!-- Error State -->
      <div *ngIf="error()" class="error-panel soc-card">
        <div class="error-header">
          <span class="error-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF4D5A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </span>
          <span class="error-title">Failed to load Incident Queue</span>
        </div>
        <p class="error-detail">{{ error()?.detail || 'An unexpected error occurred while communicating with the server.' }}</p>
        <button (click)="refresh()" class="btn btn-secondary btn-sm mt-3">Retry Request</button>
      </div>

      <!-- Incidents Data Table -->
      <div *ngIf="!loading() && pageData() as data" class="soc-card queue-table-card">
        <div class="queue-meta-bar">
          <span class="queue-count mono">
            Showing {{ data.incidents.length }} of {{ data.totalElements }} incidents (Page {{ data.page + 1 }} of {{ data.totalPages || 1 }})
          </span>

          <div class="page-size-selector">
            <label for="pageSizeSelect" class="text-muted" style="font-size: 11px;">PAGE SIZE:</label>
            <select
              id="pageSizeSelect"
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
          *ngIf="data.incidents.length === 0"
          title="No Incidents Match Filters"
          message="No security incidents match the selected status, severity, or category filters."
        ></app-empty-state>

        <!-- Table View -->
        <div *ngIf="data.incidents.length > 0" class="soc-table-container">
          <table class="soc-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Status</th>
                <th>Rule ID</th>
                <th>Category</th>
                <th>Target Entity</th>
                <th>Events</th>
                <th>First Detected</th>
                <th>Last Active</th>
                <th>Summary</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let inc of data.incidents">
                <td><app-severity-badge [severity]="inc.severity"></app-severity-badge></td>
                <td><app-status-badge [status]="inc.status"></app-status-badge></td>
                <td class="mono text-teal">{{ inc.ruleId }}</td>
                <td><span class="badge badge-info">{{ inc.threatCategory }}</span></td>
                <td class="mono text-secondary" [title]="inc.targetEntityValue">
                  {{ truncate(inc.targetEntityValue, 24) }}
                </td>
                <td class="mono">{{ inc.eventCount }}</td>
                <td class="mono text-muted">{{ formatDateTime(inc.firstDetectedAt) }}</td>
                <td class="mono text-muted">{{ formatDateTime(inc.lastEventAt) }}</td>
                <td class="incident-summary" [title]="inc.summary">{{ inc.summary }}</td>
                <td>
                  <a [routerLink]="['/incidents', inc.id]" class="btn btn-primary btn-sm">
                    Investigate →
                  </a>
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
      background: var(--bg-card);
    }
    .filter-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
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
    .reset-group {
      justify-content: flex-end;
    }
    .queue-table-card {
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
      padding: var(--space-4);
    }
    .queue-meta-bar {
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
    .incident-summary {
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
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
    .mt-3 {
      margin-top: var(--space-3);
    }
  `]
})
export class IncidentsListComponent implements OnInit {
  private readonly api = inject(SecurityApiService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly loading = signal<boolean>(true);
  readonly error = signal<ProblemDetail | null>(null);
  readonly pageData = signal<IncidentPageResponse | null>(null);

  readonly currentPage = signal<number>(0);
  readonly selectedPageSize = signal<number>(20);
  readonly selectedStatus = signal<IncidentStatus | ''>('');
  readonly selectedSeverity = signal<IncidentSeverity | ''>('');
  readonly selectedCategory = signal<string>('');
  readonly selectedSortBy = signal<string>('lastEventAt');
  readonly selectedSortDirection = signal<'DESC' | 'ASC'>('DESC');

  ngOnInit(): void {
    // Sync filters from URL query parameters
    this.route.queryParams.subscribe(params => {
      if (params['page'] !== undefined) this.currentPage.set(parseInt(params['page'], 10) || 0);
      if (params['size'] !== undefined) this.selectedPageSize.set(parseInt(params['size'], 10) || 20);
      if (params['status'] !== undefined) this.selectedStatus.set(params['status'] as IncidentStatus);
      if (params['severity'] !== undefined) this.selectedSeverity.set(params['severity'] as IncidentSeverity);
      if (params['threatCategory'] !== undefined) this.selectedCategory.set(params['threatCategory']);
      if (params['sortBy'] !== undefined) this.selectedSortBy.set(params['sortBy']);
      if (params['sortDirection'] !== undefined) {
        this.selectedSortDirection.set(params['sortDirection'].toUpperCase() === 'ASC' ? 'ASC' : 'DESC');
      }

      this.loadIncidents();
    });
  }

  loadIncidents(): void {
    this.loading.set(true);
    this.error.set(null);

    const filterParams: IncidentFilterParams = {
      page: this.currentPage(),
      size: this.selectedPageSize(),
      sortBy: this.selectedSortBy(),
      sortDirection: this.selectedSortDirection().toLowerCase() as 'asc' | 'desc'
    };

    if (this.selectedStatus()) filterParams.status = this.selectedStatus() as IncidentStatus;
    if (this.selectedSeverity()) filterParams.severity = this.selectedSeverity() as IncidentSeverity;
    if (this.selectedCategory()) filterParams.threatCategory = this.selectedCategory();

    this.api.getIncidents(filterParams).subscribe({
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
      status: this.selectedStatus() || null,
      severity: this.selectedSeverity() || null,
      threatCategory: this.selectedCategory() || null,
      sortBy: this.selectedSortBy() !== 'lastEventAt' ? this.selectedSortBy() : null,
      sortDirection: this.selectedSortDirection() !== 'DESC' ? this.selectedSortDirection() : null
    };

    this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      queryParamsHandling: 'merge'
    });
  }

  onStatusChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value as IncidentStatus | '';
    this.selectedStatus.set(value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onSeverityChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value as IncidentSeverity | '';
    this.selectedSeverity.set(value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onCategoryChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    this.selectedCategory.set(value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onSortByChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    this.selectedSortBy.set(value);
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  onSortDirectionChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value as 'DESC' | 'ASC';
    this.selectedSortDirection.set(value);
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

  resetFilters(): void {
    this.selectedStatus.set('');
    this.selectedSeverity.set('');
    this.selectedCategory.set('');
    this.selectedSortBy.set('lastEventAt');
    this.selectedSortDirection.set('DESC');
    this.currentPage.set(0);
    this.updateUrlParams();
  }

  hasActiveFilters(): boolean {
    return !!(
      this.selectedStatus() ||
      this.selectedSeverity() ||
      this.selectedCategory() ||
      this.selectedSortBy() !== 'lastEventAt' ||
      this.selectedSortDirection() !== 'DESC'
    );
  }

  refresh(): void {
    this.loadIncidents();
  }

  formatDateTime(isoString: string): string {
    if (!isoString) return '—';
    try {
      const date = new Date(isoString);
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return isoString;
    }
  }

  truncate(str: string, len: number): string {
    if (!str) return '—';
    return str.length > len ? str.substring(0, len) + '…' : str;
  }
}
