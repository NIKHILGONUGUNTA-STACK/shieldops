import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  DiscoveredEndpointResponse,
  DiscoveredEndpointPageResponse,
  EndpointIntelligenceResponse,
  EndpointObservationHistoryResponse,
  EndpointSecurityHistoryResponse,
  ProblemDetail
} from '../../core/models/security.models';

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
            placeholder="Search by path prefix, method, or service..."
            class="soc-search-input"
          />
          <button *ngIf="searchQuery" (click)="searchQuery = ''; onSearchChange()" class="clear-btn">✕</button>
        </div>

        <div class="filter-actions-group">
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

      <!-- Main Layout: Table + Intelligence Side Drawer -->
      <div class="inventory-layout">
        <!-- Table Panel -->
        <div class="soc-card table-panel" [class.with-drawer]="selectedEndpoint()">
          <div class="table-container">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width: 80px;">Method</th>
                  <th>Observed Route Template</th>
                  <th style="width: 150px;">Service Boundary</th>
                  <th style="width: 90px; text-align: right;">Requests</th>
                  <th style="width: 150px;">Status Breakdown</th>
                  <th style="width: 120px;">Last Seen</th>
                  <th style="width: 80px; text-align: right;">Action</th>
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
                    <td><div class="skeleton-bar w-30 ml-auto"></div></td>
                  </tr>
                </ng-container>

                <!-- Real Discovered Rows -->
                <ng-container *ngIf="!loading() && endpoints().length > 0">
                  <tr
                    *ngFor="let ep of endpoints(); trackBy: trackByEndpointId"
                    class="endpoint-row"
                    [class.active-row]="selectedEndpoint()?.id === ep.id"
                    (click)="openIntelligence(ep)"
                  >
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
                      {{ formatTimestamp(ep.lastObservedAt) }}
                    </td>
                    <td class="action-cell">
                      <button
                        (click)="$event.stopPropagation(); openIntelligence(ep)"
                        class="btn btn-secondary btn-xs action-btn"
                        title="Open Endpoint Intelligence"
                      >
                        Intel
                      </button>
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

        <!-- Endpoint Intelligence Drawer -->
        <div *ngIf="selectedEndpoint() as selectedEp" class="soc-card intelligence-drawer">
          <!-- Drawer Header -->
          <div class="drawer-header">
            <div>
              <div class="drawer-pretitle mono">
                ENDPOINT INTELLIGENCE DOSSIER
                <span class="safe-tag mono">NON-VULNERABILITY TELEMETRY</span>
              </div>
              <h2 class="drawer-title mono">
                <span class="method-badge-sm" [ngClass]="selectedEp.httpMethod.toLowerCase()">{{ selectedEp.httpMethod }}</span>
                {{ selectedEp.routeTemplate }}
              </h2>
            </div>
            <button (click)="closeDrawer()" class="drawer-close" title="Close Intelligence Drawer">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>

          <!-- Drawer Navigation Tabs -->
          <div class="drawer-tabs">
            <button
              (click)="activeDrawerTab.set('overview')"
              class="drawer-tab-btn"
              [class.active]="activeDrawerTab() === 'overview'"
            >
              Overview & Contract
            </button>
            <button
              (click)="activeDrawerTab.set('history')"
              class="drawer-tab-btn"
              [class.active]="activeDrawerTab() === 'history'"
            >
              Observation History
            </button>
            <button
              (click)="activeDrawerTab.set('security')"
              class="drawer-tab-btn"
              [class.active]="activeDrawerTab() === 'security'"
            >
              Security & Incidents
            </button>
          </div>

          <!-- Drawer Loading -->
          <div *ngIf="drawerLoading()" class="drawer-loading">
            <div class="spinner"></div>
            <p class="mono text-muted">Compiling endpoint wire intelligence and historical telemetry...</p>
          </div>

          <!-- Drawer Error -->
          <div *ngIf="drawerError() as dErr" class="error-banner">
            <div class="error-title">{{ dErr.title }}</div>
            <div class="error-detail">{{ dErr.detail }}</div>
          </div>

          <!-- Drawer Content -->
          <div *ngIf="!drawerLoading() && intelligence() as intel" class="drawer-body">
            
            <!-- TAB 1: OVERVIEW & CONTRACT -->
            <ng-container *ngIf="activeDrawerTab() === 'overview'">
              <!-- Invariant Alert Pill -->
              <div class="safety-card">
                <span class="safety-indicator mono">CONFIRMED VULNERABILITY: NO</span>
                <span class="safety-sub mono">Discrepancy scoring denotes contract deviation only</span>
              </div>

              <!-- Identity & Telemetry Summary -->
              <div class="drawer-section">
                <span class="section-heading">Identity & Telemetry Metrics</span>
                <div class="metrics-grid">
                  <div class="metric-box">
                    <span class="metric-label">SERVICE BOUNDARY</span>
                    <span class="metric-val mono">{{ intel.serviceBoundary }}</span>
                    <span class="inferred-tag mono">{{ intel.inferredService ? 'Inferred from Path' : 'Explicit Config' }}</span>
                  </div>
                  <div class="metric-box">
                    <span class="metric-label">TOTAL REQUESTS</span>
                    <span class="metric-val mono">{{ intel.totalRequests | number }}</span>
                    <span class="metric-sub mono">Window: {{ intel.telemetryWindowHours }}h</span>
                  </div>
                  <div class="metric-box">
                    <span class="metric-label">LATENCY (AVG / MAX)</span>
                    <span class="metric-val mono">
                      {{ intel.averageLatencyMs != null ? (intel.averageLatencyMs | number:'1.1-1') + ' ms' : '—' }}
                    </span>
                    <span class="metric-sub mono">
                      Min: {{ intel.minLatencyMs != null ? (intel.minLatencyMs | number:'1.0-0') + 'ms' : '—' }} · Max: {{ intel.maxLatencyMs != null ? (intel.maxLatencyMs | number:'1.0-0') + 'ms' : '—' }}
                    </span>
                  </div>
                  <div class="metric-box">
                    <span class="metric-label">TIMESTAMPS</span>
                    <span class="metric-val-sm mono">Last: {{ formatTimestamp(intel.lastObservedAt) }}</span>
                    <span class="metric-sub mono">First: {{ formatTimestamp(intel.firstObservedAt) }}</span>
                  </div>
                </div>
              </div>

              <!-- Distinct HTTP Status Codes -->
              <div class="drawer-section">
                <span class="section-heading">Observed Status Codes & Distribution</span>
                <div class="status-codes-row">
                  <span *ngFor="let sc of intel.distinctStatusCodes" class="status-code-pill mono" [ngClass]="getStatusCodeClass(sc)">
                    {{ sc }}
                  </span>
                </div>
                <div class="distribution-bars">
                  <div class="dist-row" *ngFor="let item of getStatusDistList(intel.statusDistribution)">
                    <span class="dist-cat mono">{{ item.category }}</span>
                    <div class="dist-track">
                      <div class="dist-fill" [ngClass]="'fill-' + item.category" [style.width.%]="item.percentage"></div>
                    </div>
                    <span class="dist-count mono">{{ item.count }} ({{ item.percentage }}%)</span>
                  </div>
                </div>
              </div>

              <!-- Associated Specification Contract -->
              <div class="drawer-section">
                <span class="section-heading">Declared OpenAPI Contract</span>
                <div *ngIf="intel.specification as spec; else noSpec" class="contract-box">
                  <div class="contract-prop">
                    <span class="c-label">SPECIFICATION:</span>
                    <span class="c-val">{{ spec.specificationName }} (v{{ spec.specificationVersion }})</span>
                    <span class="rev-badge mono">Rev {{ spec.specificationRevision }}</span>
                  </div>
                  <div class="contract-prop">
                    <span class="c-label">DECLARED ROUTE:</span>
                    <span class="c-val mono">{{ spec.declaredMethod }} {{ spec.declaredPath }}</span>
                  </div>
                  <div *ngIf="spec.declaredOperationId" class="contract-prop">
                    <span class="c-label">OPERATION ID:</span>
                    <span class="c-val mono">{{ spec.declaredOperationId }}</span>
                  </div>
                  <div *ngIf="spec.declaredSummary" class="contract-prop">
                    <span class="c-label">SUMMARY:</span>
                    <span class="c-val">{{ spec.declaredSummary }}</span>
                  </div>
                </div>
                <ng-template #noSpec>
                  <div class="no-contract-notice mono">
                    No declared OpenAPI specification matches this endpoint. Endpoint is currently classified as Observed Undocumented (Shadow API).
                  </div>
                </ng-template>
              </div>

              <!-- Reconciliation & Discrepancy Prioritization -->
              <div class="drawer-section">
                <span class="section-heading">Reconciliation & Prioritization</span>
                <div class="recon-status-row">
                  <div class="recon-cat-box">
                    <span class="recon-label">STATUS CATEGORY</span>
                    <span class="recon-badge mono" [ngClass]="getReconClass(intel.reconciliation?.status)">
                      {{ intel.reconciliation?.status || 'UNRECONCILED' }}
                    </span>
                  </div>
                  <div class="recon-cat-box">
                    <span class="recon-label">PRIORITY SCORE</span>
                    <span class="priority-score mono" [ngClass]="getPriorityClass(intel.discrepancyPrioritization?.priorityLevel)">
                      {{ intel.discrepancyPrioritization?.priorityScore ?? 0 }} / 100
                      <span class="priority-lvl">{{ intel.discrepancyPrioritization?.priorityLevel || 'NONE' }}</span>
                    </span>
                  </div>
                </div>

                <div *ngIf="intel.discrepancyPrioritization as prio" class="prio-detail-box">
                  <div class="prio-reason">
                    <span class="prio-reason-label">PRIMARY RATIONALE:</span>
                    <span class="prio-reason-text">{{ prio.primaryReason }}</span>
                  </div>

                  <div *ngIf="prio.contributingFactors.length > 0" class="factors-table-wrap">
                    <table class="factors-table">
                      <thead>
                        <tr>
                          <th>Contributing Factor</th>
                          <th style="width: 70px; text-align: right;">Impact</th>
                          <th>Explanation</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr *ngFor="let factor of prio.contributingFactors">
                          <td class="factor-name mono">{{ factor.factor }}</td>
                          <td class="factor-impact mono" [class.positive]="factor.scoreImpact > 0">
                            {{ factor.scoreImpact > 0 ? '+' : '' }}{{ factor.scoreImpact }}
                          </td>
                          <td class="factor-expl">{{ factor.explanation }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </ng-container>

            <!-- TAB 2: OBSERVATION HISTORY -->
            <ng-container *ngIf="activeDrawerTab() === 'history'">
              <!-- Window Filter Toolbar -->
              <div class="history-controls-row">
                <span class="history-title">Observation Time Window:</span>
                <div class="window-btn-group">
                  <button
                    (click)="changeHistoryWindow(24, 60)"
                    class="window-btn mono"
                    [class.active]="historyWindowHours() === 24"
                  >
                    24h (Hourly)
                  </button>
                  <button
                    (click)="changeHistoryWindow(168, 240)"
                    class="window-btn mono"
                    [class.active]="historyWindowHours() === 168"
                  >
                    7d (4-Hourly)
                  </button>
                  <button
                    (click)="changeHistoryWindow(720, 1440)"
                    class="window-btn mono"
                    [class.active]="historyWindowHours() === 720"
                  >
                    30d (Daily)
                  </button>
                </div>
              </div>

              <!-- Retention Notice -->
              <div class="retention-info-card mono">
                Continuous zero-filled aggregation grid · Data bounded by 720h perimeter retention limit
              </div>

              <!-- Observation History Buckets -->
              <div *ngIf="observationHistory() as obs" class="buckets-container">
                <div class="buckets-summary-bar">
                  <span class="mono text-muted">Total Requests in Window:</span>
                  <span class="mono text-accent">{{ obs.totalRequestsInWindow | number }}</span>
                  <span class="mono text-muted">Interval: {{ obs.bucketIntervalMinutes }}m</span>
                </div>

                <div *ngIf="obs.buckets.length === 0" class="empty-buckets mono">
                  No observation buckets recorded for this window.
                </div>

                <div class="buckets-table-wrap" *ngIf="obs.buckets.length > 0">
                  <table class="soc-table mini-table">
                    <thead>
                      <tr>
                        <th>Interval Start</th>
                        <th style="width: 80px; text-align: right;">Volume</th>
                        <th style="width: 140px;">Response Distribution</th>
                        <th style="width: 90px; text-align: right;">Avg Latency</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr *ngFor="let b of obs.buckets">
                        <td class="time-cell mono">{{ formatTimestamp(b.bucketTimestamp) }}</td>
                        <td class="req-cell mono">{{ b.requestCount | number }}</td>
                        <td>
                          <div class="mini-status-chips mono">
                            <span *ngIf="b.status2xx" class="chip chip-2xx">{{ b.status2xx }} 2xx</span>
                            <span *ngIf="b.status3xx" class="chip chip-3xx">{{ b.status3xx }} 3xx</span>
                            <span *ngIf="b.status4xx" class="chip chip-4xx">{{ b.status4xx }} 4xx</span>
                            <span *ngIf="b.status5xx" class="chip chip-5xx">{{ b.status5xx }} 5xx</span>
                            <span *ngIf="!b.requestCount" class="text-muted">—</span>
                          </div>
                        </td>
                        <td class="latency-cell mono" style="text-align: right;">
                          {{ b.avgLatencyMs != null ? (b.avgLatencyMs | number:'1.0-0') + ' ms' : '—' }}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </ng-container>

            <!-- TAB 3: SECURITY & INCIDENTS -->
            <ng-container *ngIf="activeDrawerTab() === 'security'">
              <div *ngIf="securityHistory() as sec" class="sec-history-container">
                <!-- Security Metric Counters -->
                <div class="sec-stat-cards">
                  <div class="sec-stat-card">
                    <span class="sec-stat-label">AUTH FAILURES (401/403)</span>
                    <span class="sec-stat-val mono" [class.alert]="sec.totalAuthFailures > 0">{{ sec.totalAuthFailures }}</span>
                  </div>
                  <div class="sec-stat-card">
                    <span class="sec-stat-label">ANOMALY EVENTS</span>
                    <span class="sec-stat-val mono" [class.alert]="sec.totalAnomalies > 0">{{ sec.totalAnomalies }}</span>
                  </div>
                  <div class="sec-stat-card">
                    <span class="sec-stat-label">BLOCKED REQUESTS</span>
                    <span class="sec-stat-val mono">{{ sec.totalBlocked }}</span>
                  </div>
                </div>

                <!-- Recent Security Telemetry Events -->
                <div class="drawer-section">
                  <span class="section-heading">Recent Security Events Log</span>
                  <div *ngIf="sec.recentSecurityEvents.length === 0" class="empty-notice mono">
                    No security events or authorization failures recorded for this endpoint.
                  </div>
                  <div *ngIf="sec.recentSecurityEvents.length > 0" class="sec-events-table-wrap">
                    <table class="soc-table mini-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Client IP</th>
                          <th style="width: 60px;">Status</th>
                          <th style="width: 80px;">Anomaly</th>
                          <th style="width: 70px;">Blocked</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr *ngFor="let ev of sec.recentSecurityEvents">
                          <td class="time-cell mono">{{ formatTimestamp(ev.timestamp) }}</td>
                          <td class="mono">{{ ev.clientIp }}</td>
                          <td class="mono" [ngClass]="getStatusCodeClass(ev.statusCode)">{{ ev.statusCode }}</td>
                          <td class="mono">{{ ev.anomalyScore | number:'1.2-2' }}</td>
                          <td class="mono">
                            <span class="bool-pill" [class.blocked]="ev.blocked">{{ ev.blocked ? 'YES' : 'NO' }}</span>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <!-- Linked Security Incidents -->
                <div class="drawer-section">
                  <span class="section-heading">Correlated Security Incidents</span>
                  <div *ngIf="sec.linkedIncidents.length === 0" class="empty-notice mono">
                    No active or historical security incidents linked to this route.
                  </div>
                  <div *ngIf="sec.linkedIncidents.length > 0" class="incidents-stack">
                    <div *ngFor="let inc of sec.linkedIncidents" class="inc-item">
                      <div class="inc-head">
                        <span class="inc-sev-badge mono" [ngClass]="inc.severity.toLowerCase()">{{ inc.severity }}</span>
                        <span class="inc-title">{{ inc.title }}</span>
                        <span class="inc-status mono">{{ inc.status }}</span>
                      </div>
                      <div class="inc-foot mono">
                        <span>IP: {{ inc.clientIp }}</span>
                        <span>{{ formatTimestamp(inc.timestamp) }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </ng-container>

            <!-- Quick Action Links -->
            <div class="drawer-actions">
              <a
                [routerLink]="['/events']"
                [queryParams]="{ search: intel.normalizedRoute }"
                class="btn btn-secondary btn-sm"
              >
                Inspect Telemetry Events →
              </a>
              <a
                [routerLink]="['/api-reconciliation']"
                [queryParams]="{ search: intel.normalizedRoute }"
                class="btn btn-secondary btn-sm"
              >
                View in Reconciliation →
              </a>
              <button (click)="closeDrawer()" class="btn btn-outline btn-sm">Close Drawer</button>
            </div>
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
    }

    .soc-subtitle {
      font-size: 12px;
      color: var(--text-secondary);
      margin: 0;
      max-width: 680px;
    }

    .header-stat-pills {
      display: flex;
      gap: var(--space-3);
      flex-wrap: wrap;
    }

    .soc-stat-pill {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 8px 14px;
    }

    .soc-stat-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: var(--radius-sm);
    }
    .soc-stat-icon.cyan { background: rgba(0, 210, 255, 0.12); color: #00D2FF; }
    .soc-stat-icon.green { background: rgba(0, 230, 153, 0.12); color: #00E699; }
    .soc-stat-icon.purple { background: rgba(167, 139, 250, 0.12); color: #A78BFA; }

    .soc-stat-content {
      display: flex;
      flex-direction: column;
    }

    .soc-stat-val {
      font-size: 16px;
      font-family: var(--font-mono);
      color: var(--text-primary);
      line-height: 1.2;
    }

    .soc-stat-sub {
      font-size: 10px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    /* Controls Bar */
    .inventory-controls-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-4);
      flex-wrap: wrap;
    }

    .search-input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
      flex: 1;
      max-width: 440px;
    }

    .search-icon {
      position: absolute;
      left: 10px;
      color: var(--text-muted);
      pointer-events: none;
    }

    .soc-search-input {
      width: 100%;
      height: 32px;
      padding: 0 28px 0 32px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 400;
      transition: border-color var(--transition-fast);
    }
    .soc-search-input:focus {
      outline: none;
      border-color: #00D2FF;
    }

    .clear-btn {
      position: absolute;
      right: 8px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 11px;
    }

    .filter-actions-group {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      flex-wrap: wrap;
    }

    .select-group {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .filter-label {
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 400;
    }

    .soc-select {
      height: 32px;
      padding: 0 8px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 11px;
      font-weight: 400;
      cursor: pointer;
    }
    .soc-select:focus {
      outline: none;
      border-color: #00D2FF;
    }

    .refresh-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      height: 32px;
    }
    .refresh-btn svg.spin {
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Layout: Table + Drawer */
    .inventory-layout {
      display: flex;
      gap: var(--space-4);
      align-items: flex-start;
      position: relative;
    }

    .table-panel {
      flex: 1;
      min-width: 0;
      transition: all 0.2s ease;
    }
    .table-panel.with-drawer {
      flex: 1 1 55%;
    }

    .soc-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }

    .table-container {
      overflow-x: auto;
    }

    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }

    .soc-table th {
      padding: 10px 14px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border-subtle);
      font-size: 10px;
      font-weight: 400;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      white-space: nowrap;
    }

    .soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      vertical-align: middle;
    }

    .endpoint-row {
      cursor: pointer;
      transition: background var(--transition-fast);
    }
    .endpoint-row:hover {
      background: rgba(255, 255, 255, 0.03);
    }
    .endpoint-row.active-row {
      background: rgba(0, 210, 255, 0.05);
      border-left: 2px solid #00D2FF;
    }

    .method-badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-size: 10px;
      font-family: var(--font-mono);
      font-weight: 400;
      letter-spacing: 0.03em;
    }
    .method-badge.get { background: rgba(0, 230, 153, 0.15); color: #00E699; }
    .method-badge.post { background: rgba(0, 210, 255, 0.15); color: #00D2FF; }
    .method-badge.put { background: rgba(255, 170, 0, 0.15); color: #FFAA00; }
    .method-badge.delete { background: rgba(255, 77, 77, 0.15); color: #FF4D4D; }
    .method-badge.patch { background: rgba(167, 139, 250, 0.15); color: #A78BFA; }

    .route-template {
      font-size: 12px;
      color: var(--text-primary);
      word-break: break-all;
    }

    .service-pill {
      display: inline-block;
      padding: 2px 7px;
      border-radius: 10px;
      font-size: 10px;
      font-family: var(--font-mono);
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
    }
    .service-customer { color: #00D2FF; border-color: rgba(0, 210, 255, 0.3); }
    .service-account { color: #00E699; border-color: rgba(0, 230, 153, 0.3); }
    .service-transaction { color: #FFAA00; border-color: rgba(255, 170, 0, 0.3); }
    .service-security { color: #FF4D4D; border-color: rgba(255, 77, 77, 0.3); }

    .req-cell {
      text-align: right;
    }
    .req-count {
      color: var(--text-primary);
      font-size: 12px;
    }

    .status-summary {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .status-bar-container {
      display: flex;
      height: 4px;
      border-radius: 2px;
      overflow: hidden;
      background: rgba(255, 255, 255, 0.05);
      width: 100%;
    }
    .status-seg.seg-2xx { background: #00E699; }
    .status-seg.seg-3xx { background: #00D2FF; }
    .status-seg.seg-4xx { background: #FFAA00; }
    .status-seg.seg-5xx { background: #FF4D4D; }

    .status-chips {
      display: flex;
      gap: 4px;
      flex-wrap: wrap;
    }
    .chip {
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 2px;
    }
    .chip-2xx { color: #00E699; background: rgba(0, 230, 153, 0.1); }
    .chip-3xx { color: #00D2FF; background: rgba(0, 210, 255, 0.1); }
    .chip-4xx { color: #FFAA00; background: rgba(255, 170, 0, 0.1); }
    .chip-5xx { color: #FF4D4D; background: rgba(255, 77, 77, 0.1); }

    .time-cell {
      font-size: 11px;
      color: var(--text-muted);
      white-space: nowrap;
    }

    .action-cell {
      text-align: right;
    }
    .action-btn {
      font-size: 10px;
      padding: 2px 8px;
    }

    /* Intelligence Side Drawer */
    .intelligence-drawer {
      width: 480px;
      min-width: 480px;
      display: flex;
      flex-direction: column;
      border: 1px solid var(--border-subtle);
    }

    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding: 16px;
      border-bottom: 1px solid var(--border-subtle);
    }

    .drawer-pretitle {
      font-size: 10px;
      letter-spacing: 0.08em;
      color: #00D2FF;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .safe-tag {
      font-size: 9px;
      padding: 1px 5px;
      background: rgba(0, 230, 153, 0.15);
      color: #00E699;
      border-radius: 2px;
    }

    .drawer-title {
      font-size: 13px;
      color: var(--text-primary);
      margin: 0;
      word-break: break-all;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .method-badge-sm {
      font-size: 9px;
      padding: 1px 5px;
      border-radius: 2px;
      font-family: var(--font-mono);
    }
    .method-badge-sm.get { background: rgba(0, 230, 153, 0.2); color: #00E699; }
    .method-badge-sm.post { background: rgba(0, 210, 255, 0.2); color: #00D2FF; }
    .method-badge-sm.put { background: rgba(255, 170, 0, 0.2); color: #FFAA00; }
    .method-badge-sm.delete { background: rgba(255, 77, 77, 0.2); color: #FF4D4D; }

    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 4px;
    }
    .drawer-close:hover { color: var(--text-primary); }

    .drawer-tabs {
      display: flex;
      border-bottom: 1px solid var(--border-subtle);
      background: rgba(255, 255, 255, 0.02);
    }

    .drawer-tab-btn {
      flex: 1;
      padding: 10px 8px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
      font-size: 11px;
      cursor: pointer;
      font-weight: 400;
      transition: all var(--transition-fast);
    }
    .drawer-tab-btn.active {
      color: #00D2FF;
      border-bottom-color: #00D2FF;
      background: rgba(0, 210, 255, 0.05);
    }

    .drawer-loading {
      padding: 32px 16px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
    }
    .spinner {
      width: 24px;
      height: 24px;
      border: 2px solid var(--border-subtle);
      border-top-color: #00D2FF;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    .drawer-body {
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      max-height: calc(100vh - 280px);
      overflow-y: auto;
    }

    .safety-card {
      background: rgba(0, 230, 153, 0.08);
      border: 1px solid rgba(0, 230, 153, 0.25);
      border-radius: var(--radius-sm);
      padding: 8px 12px;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .safety-indicator {
      font-size: 10px;
      color: #00E699;
      letter-spacing: 0.05em;
    }
    .safety-sub {
      font-size: 9px;
      color: var(--text-muted);
    }

    .drawer-section {
      display: flex;
      flex-direction: column;
      gap: 8px;
      border-top: 1px solid var(--border-subtle);
      padding-top: 10px;
    }
    .section-heading {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 400;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }
    .metric-box {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      display: flex;
      flex-direction: column;
    }
    .metric-label {
      font-size: 9px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 2px;
    }
    .metric-val {
      font-size: 13px;
      color: var(--text-primary);
    }
    .metric-val-sm {
      font-size: 10px;
      color: var(--text-secondary);
    }
    .metric-sub {
      font-size: 9px;
      color: var(--text-muted);
      margin-top: 2px;
    }
    .inferred-tag {
      font-size: 9px;
      color: #FFAA00;
    }

    .status-codes-row {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .status-code-pill {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 2px;
      background: rgba(255, 255, 255, 0.05);
    }
    .sc-2xx { color: #00E699; background: rgba(0, 230, 153, 0.12); }
    .sc-3xx { color: #00D2FF; background: rgba(0, 210, 255, 0.12); }
    .sc-4xx { color: #FFAA00; background: rgba(255, 170, 0, 0.12); }
    .sc-5xx { color: #FF4D4D; background: rgba(255, 77, 77, 0.12); }

    .distribution-bars {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-top: 4px;
    }
    .dist-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 10px;
    }
    .dist-cat { width: 30px; color: var(--text-muted); }
    .dist-track {
      flex: 1;
      height: 6px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 3px;
      overflow: hidden;
    }
    .dist-fill { height: 100%; border-radius: 3px; }
    .fill-2xx { background: #00E699; }
    .fill-3xx { background: #00D2FF; }
    .fill-4xx { background: #FFAA00; }
    .fill-5xx { background: #FF4D4D; }
    .dist-count { width: 70px; text-align: right; color: var(--text-secondary); font-size: 9px; }

    .contract-box {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11px;
    }
    .contract-prop {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .c-label { font-size: 9px; color: var(--text-muted); width: 100px; text-transform: uppercase; }
    .c-val { color: var(--text-primary); }
    .rev-badge {
      font-size: 9px;
      padding: 1px 5px;
      background: rgba(0, 210, 255, 0.15);
      color: #00D2FF;
      border-radius: 2px;
      margin-left: auto;
    }
    .no-contract-notice {
      font-size: 11px;
      color: #FFAA00;
      background: rgba(255, 170, 0, 0.08);
      border: 1px solid rgba(255, 170, 0, 0.2);
      padding: 8px 10px;
      border-radius: var(--radius-sm);
    }

    .recon-status-row {
      display: flex;
      gap: 8px;
    }
    .recon-cat-box {
      flex: 1;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .recon-label { font-size: 9px; color: var(--text-muted); }
    .recon-badge {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 2px;
      display: inline-block;
      width: fit-content;
    }
    .recon-matched { color: #00E699; background: rgba(0, 230, 153, 0.15); }
    .recon-undocumented { color: #FFAA00; background: rgba(255, 170, 0, 0.15); }
    .recon-mismatch { color: #FF4D4D; background: rgba(255, 77, 77, 0.15); }

    .priority-score {
      font-size: 13px;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .priority-lvl {
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 2px;
    }
    .prio-critical { color: #FF4D4D; }
    .prio-high { color: #FFAA00; }
    .prio-medium { color: #00D2FF; }
    .prio-low { color: #A78BFA; }

    .prio-detail-box {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      font-size: 11px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .prio-reason-label { font-size: 9px; color: var(--text-muted); display: block; }
    .prio-reason-text { color: var(--text-secondary); }

    .factors-table-wrap {
      overflow-x: auto;
      margin-top: 4px;
    }
    .factors-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 10px;
    }
    .factors-table th {
      text-align: left;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-subtle);
      padding: 4px 6px;
      font-weight: 400;
    }
    .factors-table td {
      padding: 4px 6px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: var(--text-secondary);
    }
    .factor-name { color: var(--text-primary); }
    .factor-impact { color: var(--text-muted); text-align: right; }
    .factor-impact.positive { color: #FFAA00; }

    /* Observation History Tab */
    .history-controls-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }
    .history-title { font-size: 11px; color: var(--text-secondary); }
    .window-btn-group { display: flex; gap: 4px; }
    .window-btn {
      font-size: 10px;
      padding: 3px 8px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-muted);
      cursor: pointer;
    }
    .window-btn.active {
      color: #00D2FF;
      border-color: #00D2FF;
      background: rgba(0, 210, 255, 0.1);
    }
    .retention-info-card {
      font-size: 9px;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      padding: 6px 8px;
      border-radius: var(--radius-sm);
    }
    .buckets-summary-bar {
      display: flex;
      gap: 8px;
      font-size: 10px;
      margin-bottom: 6px;
    }
    .text-accent { color: #00D2FF; }
    .mini-table th, .mini-table td { padding: 6px 8px; font-size: 10px; }
    .mini-status-chips { display: flex; gap: 4px; flex-wrap: wrap; }
    .empty-buckets { font-size: 11px; color: var(--text-muted); text-align: center; padding: 24px; }

    /* Security Tab */
    .sec-stat-cards {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
    }
    .sec-stat-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px;
      display: flex;
      flex-direction: column;
    }
    .sec-stat-label { font-size: 8px; color: var(--text-muted); }
    .sec-stat-val { font-size: 16px; color: var(--text-primary); }
    .sec-stat-val.alert { color: #FF4D4D; }

    .bool-pill {
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 2px;
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-muted);
    }
    .bool-pill.blocked {
      background: rgba(255, 77, 77, 0.15);
      color: #FF4D4D;
    }

    .inc-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: 11px;
    }
    .inc-head { display: flex; align-items: center; gap: 6px; }
    .inc-sev-badge {
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 2px;
    }
    .inc-sev-badge.critical { background: rgba(255, 77, 77, 0.2); color: #FF4D4D; }
    .inc-sev-badge.high { background: rgba(255, 170, 0, 0.2); color: #FFAA00; }
    .inc-sev-badge.medium { background: rgba(0, 210, 255, 0.2); color: #00D2FF; }
    .inc-title { color: var(--text-primary); flex: 1; }
    .inc-status { font-size: 9px; color: var(--text-muted); }
    .inc-foot { display: flex; justify-content: space-between; font-size: 9px; color: var(--text-muted); }
    .empty-notice { font-size: 11px; color: var(--text-muted); padding: 12px 0; }

    .drawer-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
      border-top: 1px solid var(--border-subtle);
      padding-top: 12px;
    }

    /* General Pagination */
    .pagination-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 16px;
      border-top: 1px solid var(--border-subtle);
      font-size: 12px;
    }
    .pagination-info { color: var(--text-muted); font-size: 11px; }
    .pagination-buttons { display: flex; align-items: center; gap: 8px; }
    .page-current { font-size: 11px; color: var(--text-secondary); }

    /* Skeleton Loading */
    .skeleton-bar {
      height: 12px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 2px;
      animation: pulse 1.5s ease-in-out infinite;
    }
    .skeleton-pill {
      width: 44px;
      height: 16px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 2px;
      animation: pulse 1.5s ease-in-out infinite;
    }
    .w-30 { width: 30%; }
    .w-40 { width: 40%; }
    .w-50 { width: 50%; }
    .w-60 { width: 60%; }
    .w-70 { width: 70%; }
    .ml-auto { margin-left: auto; }

    @keyframes pulse {
      0%, 100% { opacity: 0.4; }
      50% { opacity: 0.8; }
    }

    .error-banner {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      background: rgba(255, 77, 77, 0.08);
      border: 1px solid rgba(255, 77, 77, 0.3);
      border-radius: var(--radius-md);
      padding: 12px 16px;
    }
    .error-icon { color: #FF4D4D; }
    .error-title { font-size: 12px; color: #FF4D4D; margin-bottom: 2px; }
    .error-detail { font-size: 11px; color: var(--text-secondary); }

    .empty-state-cell {
      padding: 48px 16px !important;
      text-align: center;
    }
    .empty-state-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      max-width: 440px;
      margin: 0 auto;
    }
    .empty-icon { color: var(--text-muted); margin-bottom: 12px; }
    .empty-title { font-size: 14px; color: var(--text-primary); margin-bottom: 6px; }
    .empty-desc { font-size: 12px; color: var(--text-muted); margin: 0 0 16px 0; }
  `]
})
export class ApiInventoryComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  // Endpoint List State
  readonly endpoints = signal<DiscoveredEndpointResponse[]>([]);
  readonly loading = signal<boolean>(true);
  readonly error = signal<ProblemDetail | null>(null);

  // Metrics
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

  // Drawer & Intelligence State
  readonly selectedEndpoint = signal<DiscoveredEndpointResponse | null>(null);
  readonly activeDrawerTab = signal<'overview' | 'history' | 'security'>('overview');
  readonly drawerLoading = signal<boolean>(false);
  readonly drawerError = signal<ProblemDetail | null>(null);
  readonly intelligence = signal<EndpointIntelligenceResponse | null>(null);
  readonly observationHistory = signal<EndpointObservationHistoryResponse | null>(null);
  readonly securityHistory = signal<EndpointSecurityHistoryResponse | null>(null);

  // History Time Window
  readonly historyWindowHours = signal<number>(24);
  readonly historyBucketMinutes = signal<number>(60);

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

  openIntelligence(ep: DiscoveredEndpointResponse): void {
    this.selectedEndpoint.set(ep);
    this.drawerLoading.set(true);
    this.drawerError.set(null);

    // Load Intelligence
    this.securityApi.getEndpointIntelligence(ep.id, { windowHours: this.historyWindowHours() }).subscribe({
      next: (intel: EndpointIntelligenceResponse) => {
        this.intelligence.set(intel);
        this.drawerLoading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.drawerError.set(err);
        this.drawerLoading.set(false);
      }
    });

    // Also preload Observation History and Security History
    this.loadObservationHistory(ep.id);
    this.loadSecurityHistory(ep.id);
  }

  loadObservationHistory(epId: string): void {
    this.securityApi.getEndpointObservationHistory(epId, {
      windowHours: this.historyWindowHours(),
      bucketMinutes: this.historyBucketMinutes()
    }).subscribe({
      next: (history: EndpointObservationHistoryResponse) => {
        this.observationHistory.set(history);
      },
      error: () => {
        // Tolerant failure: Keep null
      }
    });
  }

  loadSecurityHistory(epId: string): void {
    this.securityApi.getEndpointSecurityHistory(epId, {
      windowHours: this.historyWindowHours()
    }).subscribe({
      next: (sec: EndpointSecurityHistoryResponse) => {
        this.securityHistory.set(sec);
      },
      error: () => {
        // Tolerant failure: Keep null
      }
    });
  }

  changeHistoryWindow(hours: number, bucketMins: number): void {
    this.historyWindowHours.set(hours);
    this.historyBucketMinutes.set(bucketMins);
    const ep = this.selectedEndpoint();
    if (ep) {
      this.loadObservationHistory(ep.id);
      this.loadSecurityHistory(ep.id);
    }
  }

  closeDrawer(): void {
    this.selectedEndpoint.set(null);
    this.intelligence.set(null);
    this.observationHistory.set(null);
    this.securityHistory.set(null);
    this.drawerError.set(null);
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

  getStatusDistList(dist: Record<string, number> | undefined): Array<{ category: string; count: number; percentage: number }> {
    if (!dist) return [];
    const total = Object.values(dist).reduce((acc, v) => acc + v, 0);
    const categories = ['2xx', '3xx', '4xx', '5xx'];
    return categories.map(cat => {
      const count = dist[cat] || 0;
      const percentage = total > 0 ? Math.round((count / total) * 100) : 0;
      return { category: cat, count, percentage };
    });
  }

  getStatusCodeClass(code: number): string {
    if (code >= 200 && code < 300) return 'sc-2xx';
    if (code >= 300 && code < 400) return 'sc-3xx';
    if (code >= 400 && code < 500) return 'sc-4xx';
    return 'sc-5xx';
  }

  getReconClass(status: string | undefined): string {
    if (!status) return '';
    if (status === 'MATCHED') return 'recon-matched';
    if (status.includes('UNDOCUMENTED')) return 'recon-undocumented';
    return 'recon-mismatch';
  }

  getPriorityClass(level: string | undefined): string {
    if (!level) return '';
    const l = level.toLowerCase();
    if (l === 'critical') return 'prio-critical';
    if (l === 'high') return 'prio-high';
    if (l === 'medium') return 'prio-medium';
    return 'prio-low';
  }

  getServiceClass(serviceName: string): string {
    if (!serviceName) return '';
    if (serviceName.includes('customer')) return 'service-customer';
    if (serviceName.includes('account')) return 'service-account';
    if (serviceName.includes('transaction')) return 'service-transaction';
    if (serviceName.includes('security')) return 'service-security';
    return '';
  }

  formatTimestamp(isoString: string | undefined): string {
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
