import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { DiscoveredEndpointResponse, DiscoveredEndpointPageResponse, ProblemDetail } from '../../core/models/security.models';

@Component({
  selector: 'app-api-inventory',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Page Header -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb-tag">
            <span class="live-dot"></span>
            PASSIVE WIRE TELEMETRY DISCOVERY
          </div>
          <h1 class="soc-title">Observed API Inventory</h1>
          <p class="soc-subtitle">
            Catalog of active API endpoints automatically discovered by aggregating live traffic across the Aegis Gateway perimeter.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon cyan">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                <polyline points="2 17 12 22 22 17"></polyline>
                <polyline points="2 12 12 17 22 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ totalObservedEndpoints() }}</span>
              <span class="soc-stat-sub">Observed Endpoints</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon green">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ totalObservedRequests() | number }}</span>
              <span class="soc-stat-sub">Indexed Requests</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon purple">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                <line x1="6" y1="18" x2="6.01" y2="18"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ totalMonitoredServices() }}</span>
              <span class="soc-stat-sub">Backend Services</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Controls & Filter Toolbar -->
      <div class="inventory-controls-bar">
        <div class="search-input-wrapper">
          <svg class="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input
            type="text"
            [(ngModel)]="searchQuery"
            (ngModelChange)="onSearchChange()"
            placeholder="Search route template, method, or service..."
            class="soc-search-input"
          />
        </div>

        <div class="filter-controls">
          <div class="select-group">
            <label class="filter-label">Method:</label>
            <select [(ngModel)]="selectedMethod" (ngModelChange)="loadEndpoints(0)" class="soc-select">
              <option value="">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
            </select>
          </div>

          <div class="select-group">
            <label class="filter-label">Service:</label>
            <select [(ngModel)]="selectedService" (ngModelChange)="loadEndpoints(0)" class="soc-select">
              <option value="">All Services</option>
              <option value="customer-service">customer-service</option>
              <option value="account-service">account-service</option>
              <option value="transaction-service">transaction-service</option>
              <option value="security-gateway">security-gateway</option>
            </select>
          </div>

          <button (click)="loadEndpoints(currentPage())" class="btn btn-secondary btn-sm refresh-btn" [disabled]="loading()">
            <svg [class.spin]="loading()" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="23 4 23 10 17 10"></polyline>
              <polyline points="1 20 1 14 7 14"></polyline>
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Error State -->
      <div *ngIf="error()" class="error-banner">
        <div class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        </div>
        <div class="error-content">
          <div class="error-title">{{ error()?.title || 'Telemetry Discovery Unavailable' }}</div>
          <div class="error-detail">{{ error()?.detail || 'Unable to connect to the discovery endpoint. Verify that backend telemetry services are running.' }}</div>
        </div>
        <button (click)="loadEndpoints(currentPage())" class="btn btn-outline btn-sm">Retry</button>
      </div>

      <!-- Main Content Card & Table -->
      <div class="soc-card">
        <div class="table-container">
          <table class="soc-table">
            <thead>
              <tr>
                <th style="width: 80px;">Method</th>
                <th>Observed Route Template</th>
                <th style="width: 160px;">Service Boundary</th>
                <th style="width: 110px; text-align: right;">Requests</th>
                <th style="width: 180px;">Status Breakdown</th>
                <th style="width: 140px;">First Seen</th>
                <th style="width: 140px;">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              <!-- Loading Skeleton -->
              <ng-container *ngIf="loading()">
                <tr *ngFor="let s of [1,2,3,4,5]" class="skeleton-row">
                  <td><div class="skeleton-pill"></div></td>
                  <td><div class="skeleton-bar w-70"></div></td>
                  <td><div class="skeleton-bar w-50"></div></td>
                  <td><div class="skeleton-bar w-30 ml-auto"></div></td>
                  <td><div class="skeleton-bar w-60"></div></td>
                  <td><div class="skeleton-bar w-40"></div></td>
                  <td><div class="skeleton-bar w-40"></div></td>
                </tr>
              </ng-container>

              <!-- Real Discovered Rows -->
              <ng-container *ngIf="!loading() && endpoints().length > 0">
                <tr *ngFor="let ep of endpoints(); trackBy: trackByEndpointId" class="endpoint-row">
                  <td>
                    <span class="method-badge" [ngClass]="ep.httpMethod.toLowerCase()">
                      {{ ep.httpMethod }}
                    </span>
                  </td>
                  <td class="route-cell">
                    <span class="route-template mono">{{ ep.routeTemplate }}</span>
                  </td>
                  <td>
                    <span class="service-pill" [ngClass]="getServiceClass(ep.serviceName)">
                      {{ ep.serviceName }}
                    </span>
                  </td>
                  <td class="req-cell">
                    <span class="req-count mono">{{ ep.totalRequests | number }}</span>
                  </td>
                  <td>
                    <div class="status-summary">
                      <div class="status-bar-container">
                        <div class="status-seg seg-2xx" [style.width.%]="getStatusPercent(ep, '2xx')" title="2xx: {{ ep.statusDistribution['2xx'] || 0 }}"></div>
                        <div class="status-seg seg-3xx" [style.width.%]="getStatusPercent(ep, '3xx')" title="3xx: {{ ep.statusDistribution['3xx'] || 0 }}"></div>
                        <div class="status-seg seg-4xx" [style.width.%]="getStatusPercent(ep, '4xx')" title="4xx: {{ ep.statusDistribution['4xx'] || 0 }}"></div>
                        <div class="status-seg seg-5xx" [style.width.%]="getStatusPercent(ep, '5xx')" title="5xx: {{ ep.statusDistribution['5xx'] || 0 }}"></div>
                      </div>
                      <div class="status-chips">
                        <span *ngIf="ep.statusDistribution['2xx']" class="chip chip-2xx mono">{{ ep.statusDistribution['2xx'] }} 2xx</span>
                        <span *ngIf="ep.statusDistribution['4xx']" class="chip chip-4xx mono">{{ ep.statusDistribution['4xx'] }} 4xx</span>
                        <span *ngIf="ep.statusDistribution['5xx']" class="chip chip-5xx mono">{{ ep.statusDistribution['5xx'] }} 5xx</span>
                      </div>
                    </div>
                  </td>
                  <td class="time-cell mono">
                    {{ formatTimestamp(ep.firstObservedAt) }}
                  </td>
                  <td class="time-cell mono">
                    {{ formatTimestamp(ep.lastObservedAt) }}
                  </td>
                </tr>
              </ng-container>

              <!-- Empty State -->
              <tr *ngIf="!loading() && endpoints().length === 0 && !error()">
                <td colspan="7" class="empty-state-cell">
                  <div class="empty-state-wrapper">
                    <div class="empty-icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                        <polyline points="2 17 12 22 22 17"></polyline>
                        <polyline points="2 12 12 17 22 12"></polyline>
                      </svg>
                    </div>
                    <div class="empty-title">No API Endpoints Discovered Yet</div>
                    <p class="empty-desc">
                      Endpoints will automatically appear in this inventory as live HTTP requests pass through the Aegis Gateway.
                      No matching telemetry events were found for the current filter criteria.
                    </p>
                    <div class="empty-actions">
                      <a routerLink="/events" class="btn btn-secondary btn-sm">Inspect Telemetry Events →</a>
                    </div>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Footer -->
        <div *ngIf="totalElements() > 0" class="pagination-footer">
          <div class="pagination-info mono">
            Showing {{ pageStart() }}–{{ pageEnd() }} of {{ totalElements() }} endpoints
          </div>
          <div class="pagination-buttons">
            <button
              (click)="loadEndpoints(currentPage() - 1)"
              [disabled]="!hasPrevious() || loading()"
              class="btn btn-secondary btn-sm"
            >
              Previous
            </button>
            <span class="page-current mono">Page {{ currentPage() + 1 }} of {{ totalPages() || 1 }}</span>
            <button
              (click)="loadEndpoints(currentPage() + 1)"
              [disabled]="!hasNext() || loading()"
              class="btn btn-secondary btn-sm"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
      padding: var(--space-6);
    }

    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: var(--space-6);
      flex-wrap: wrap;
    }

    .breadcrumb-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 10px;
      font-weight: 400;
      letter-spacing: 0.08em;
      color: var(--accent-orange);
      font-family: var(--font-mono);
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .live-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-orange);
      box-shadow: 0 0 6px var(--accent-orange);
    }

    .soc-title {
      font-size: 20px;
      font-weight: 400;
      color: var(--text-primary);
      margin: 0 0 4px 0;
      letter-spacing: -0.01em;
    }

    .soc-subtitle {
      font-size: 13px;
      font-weight: 400;
      color: var(--text-secondary);
      margin: 0;
      max-width: 680px;
      line-height: 1.45;
    }

    /* Header Stat Pills */
    .header-stat-pills {
      display: flex;
      gap: var(--space-3);
      flex-wrap: wrap;
    }

    .soc-stat-pill {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      padding: 8px 14px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      min-width: 150px;
    }

    .soc-stat-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
    }

    .soc-stat-icon.cyan { color: #00D2FF; }
    .soc-stat-icon.green { color: #00E5A3; }
    .soc-stat-icon.purple { color: #9D7BFF; }

    .soc-stat-content {
      display: flex;
      flex-direction: column;
    }

    .soc-stat-val {
      font-size: 16px;
      font-weight: 400;
      font-family: var(--font-mono);
      color: var(--text-primary);
      line-height: 1.2;
    }

    .soc-stat-sub {
      font-size: 11px;
      font-weight: 400;
      color: var(--text-muted);
      letter-spacing: 0.02em;
    }

    /* Controls Bar */
    .inventory-controls-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-4);
      flex-wrap: wrap;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: var(--space-3) var(--space-4);
    }

    .search-input-wrapper {
      position: relative;
      flex: 1;
      min-width: 260px;
    }

    .search-icon {
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      pointer-events: none;
    }

    .soc-search-input {
      width: 100%;
      padding: 7px 12px 7px 32px;
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 400;
      font-family: var(--font-sans);
      outline: none;
      transition: border-color 0.15s ease;
    }

    .soc-search-input:focus {
      border-color: var(--accent-orange);
    }

    .filter-controls {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }

    .select-group {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .filter-label {
      font-size: 11px;
      font-weight: 400;
      color: var(--text-muted);
    }

    .soc-select {
      padding: 6px 10px;
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 400;
      font-family: var(--font-sans);
      outline: none;
    }

    .refresh-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .spin {
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      100% { transform: rotate(360deg); }
    }

    /* Error Banner */
    .error-banner {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      padding: 12px 16px;
      background: rgba(255, 68, 68, 0.08);
      border: 1px solid rgba(255, 68, 68, 0.3);
      border-radius: var(--radius-md);
      color: #FF5A5A;
    }

    .error-icon {
      flex-shrink: 0;
    }

    .error-content {
      flex: 1;
    }

    .error-title {
      font-size: 13px;
      font-weight: 400;
    }

    .error-detail {
      font-size: 11px;
      color: var(--text-secondary);
      margin-top: 2px;
    }

    /* Card & Table */
    .soc-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }

    .table-container {
      width: 100%;
      overflow-x: auto;
    }

    .soc-table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }

    .soc-table th {
      padding: 10px 14px;
      font-size: 11px;
      font-weight: 400;
      color: var(--text-muted);
      letter-spacing: 0.04em;
      text-transform: uppercase;
      background: var(--bg-surface-elevated);
      border-bottom: 1px solid var(--border-subtle);
    }

    .soc-table td {
      padding: 11px 14px;
      font-size: 12px;
      font-weight: 400;
      color: var(--text-primary);
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: middle;
    }

    .endpoint-row:hover {
      background: var(--bg-surface-elevated);
    }

    /* Method Badges */
    .method-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 3px 6px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 400;
      font-family: var(--font-mono);
      letter-spacing: 0.05em;
      min-width: 48px;
    }

    .method-badge.get { background: rgba(0, 180, 216, 0.12); color: #00B4D8; border: 1px solid rgba(0, 180, 216, 0.3); }
    .method-badge.post { background: rgba(0, 229, 163, 0.12); color: #00E5A3; border: 1px solid rgba(0, 229, 163, 0.3); }
    .method-badge.put { background: rgba(255, 170, 0, 0.12); color: #FFAA00; border: 1px solid rgba(255, 170, 0, 0.3); }
    .method-badge.delete { background: rgba(255, 77, 77, 0.12); color: #FF4D4D; border: 1px solid rgba(255, 77, 77, 0.3); }
    .method-badge.patch { background: rgba(157, 123, 255, 0.12); color: #9D7BFF; border: 1px solid rgba(157, 123, 255, 0.3); }

    .route-cell {
      word-break: break-all;
    }

    .route-template {
      color: var(--text-primary);
      font-size: 12px;
    }

    /* Service Pills */
    .service-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 400;
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      border: 1px solid var(--border-subtle);
    }

    .service-customer { color: #5BC0BE; border-color: rgba(91, 192, 190, 0.3); }
    .service-account { color: #6FFFE9; border-color: rgba(111, 255, 233, 0.3); }
    .service-transaction { color: #FFB703; border-color: rgba(255, 183, 3, 0.3); }
    .service-security { color: #FB8500; border-color: rgba(251, 133, 0, 0.3); }

    .req-cell {
      text-align: right;
    }

    .req-count {
      color: var(--text-primary);
      font-size: 12px;
    }

    /* Status Breakdown Bar */
    .status-summary {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .status-bar-container {
      display: flex;
      height: 6px;
      background: var(--bg-surface-elevated);
      border-radius: 3px;
      overflow: hidden;
      width: 100%;
    }

    .status-seg.seg-2xx { background: #00E5A3; }
    .status-seg.seg-3xx { background: #00B4D8; }
    .status-seg.seg-4xx { background: #FFAA00; }
    .status-seg.seg-5xx { background: #FF4D4D; }

    .status-chips {
      display: flex;
      gap: 4px;
      flex-wrap: wrap;
    }

    .chip {
      font-size: 10px;
      padding: 1px 4px;
      border-radius: 3px;
    }

    .chip-2xx { color: #00E5A3; background: rgba(0, 229, 163, 0.1); }
    .chip-4xx { color: #FFAA00; background: rgba(255, 170, 0, 0.1); }
    .chip-5xx { color: #FF4D4D; background: rgba(255, 77, 77, 0.1); }

    .time-cell {
      font-size: 11px;
      color: var(--text-secondary);
      white-space: nowrap;
    }

    /* Skeleton Loading */
    .skeleton-pill {
      width: 44px;
      height: 18px;
      background: var(--bg-surface-elevated);
      border-radius: 4px;
      animation: pulse 1.5s infinite;
    }

    .skeleton-bar {
      height: 14px;
      background: var(--bg-surface-elevated);
      border-radius: 4px;
      animation: pulse 1.5s infinite;
    }

    .w-70 { width: 70%; }
    .w-60 { width: 60%; }
    .w-50 { width: 50%; }
    .w-40 { width: 40%; }
    .w-30 { width: 30%; }
    .ml-auto { margin-left: auto; }

    @keyframes pulse {
      0%, 100% { opacity: 0.4; }
      50% { opacity: 0.8; }
    }

    /* Empty State */
    .empty-state-cell {
      padding: 48px 16px !important;
      text-align: center;
    }

    .empty-state-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: var(--space-3);
      max-width: 440px;
      margin: 0 auto;
    }

    .empty-icon {
      color: var(--text-muted);
    }

    .empty-title {
      font-size: 14px;
      font-weight: 400;
      color: var(--text-primary);
    }

    .empty-desc {
      font-size: 12px;
      color: var(--text-secondary);
      margin: 0;
      line-height: 1.5;
    }

    .empty-actions {
      margin-top: var(--space-2);
    }

    /* Pagination Footer */
    .pagination-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      background: var(--bg-surface-elevated);
      border-top: 1px solid var(--border-subtle);
    }

    .pagination-info {
      font-size: 11px;
      color: var(--text-muted);
    }

    .pagination-buttons {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }

    .page-current {
      font-size: 11px;
      color: var(--text-secondary);
    }

    .mono {
      font-family: var(--font-mono);
    }
  `]
})
export class ApiInventoryComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  // Reactive State
  readonly endpoints = signal<DiscoveredEndpointResponse[]>([]);
  readonly loading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  // Summary Metrics
  readonly totalObservedEndpoints = signal<number>(0);
  readonly totalObservedRequests = signal<number>(0);
  readonly totalMonitoredServices = signal<number>(0);

  // Pagination
  readonly currentPage = signal<number>(0);
  readonly pageSize = signal<number>(20);
  readonly totalElements = signal<number>(0);
  readonly totalPages = signal<number>(0);
  readonly hasNext = signal<boolean>(false);
  readonly hasPrevious = signal<boolean>(false);

  // Filters
  searchQuery = '';
  selectedMethod = '';
  selectedService = '';
  private searchDebounceTimer: any = null;

  ngOnInit(): void {
    this.loadEndpoints(0);
  }

  loadEndpoints(page: number): void {
    this.loading.set(true);
    this.error.set(null);

    this.securityApi.getDiscoveredEndpoints({
      page: Math.max(0, page),
      size: this.pageSize(),
      method: this.selectedMethod || undefined,
      service: this.selectedService || undefined,
      search: this.searchQuery?.trim() || undefined,
      sortBy: 'lastObserved',
      sortDirection: 'DESC'
    }).subscribe({
      next: (res: DiscoveredEndpointPageResponse) => {
        this.endpoints.set(res.content || []);
        this.currentPage.set(res.page);
        this.totalElements.set(res.totalElements);
        this.totalPages.set(res.totalPages);
        this.hasNext.set(res.hasNext);
        this.hasPrevious.set(res.hasPrevious);
        this.totalObservedEndpoints.set(res.totalObservedEndpoints);
        this.totalObservedRequests.set(res.totalObservedRequests);
        this.totalMonitoredServices.set(res.totalMonitoredServices);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onSearchChange(): void {
    if (this.searchDebounceTimer) {
      clearTimeout(this.searchDebounceTimer);
    }
    this.searchDebounceTimer = setTimeout(() => {
      this.loadEndpoints(0);
    }, 250);
  }

  getStatusPercent(ep: DiscoveredEndpointResponse, category: string): number {
    if (!ep.totalRequests || ep.totalRequests === 0) return 0;
    const count = ep.statusDistribution[category] || 0;
    return Math.round((count / ep.totalRequests) * 100);
  }

  getServiceClass(serviceName: string): string {
    if (!serviceName) return '';
    if (serviceName.includes('customer')) return 'service-customer';
    if (serviceName.includes('account')) return 'service-account';
    if (serviceName.includes('transaction')) return 'service-transaction';
    if (serviceName.includes('security')) return 'service-security';
    return '';
  }

  formatTimestamp(isoString: string): string {
    if (!isoString) return '—';
    try {
      const date = new Date(isoString);
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });
    } catch {
      return isoString;
    }
  }

  pageStart(): number {
    return this.currentPage() * this.pageSize() + 1;
  }

  pageEnd(): number {
    return Math.min((this.currentPage() + 1) * this.pageSize(), this.totalElements());
  }

  trackByEndpointId(_index: number, item: DiscoveredEndpointResponse): string {
    return item.id;
  }
}
