import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  ReconciliationCategory,
  ReconciliationItemResponse,
  ReconciliationSummaryResponse,
  ApiSpecificationResponse,
  ProblemDetail
} from '../../core/models/security.models';

@Component({
  selector: 'app-api-reconciliation',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb-tag">
            <span class="recon-dot"></span>
            RECONCILIATION & CONTRACT DRIFT
          </div>
          <h1 class="soc-title">Documented vs. Observed API Reconciliation</h1>
          <p class="soc-subtitle">
            Continuous alignment of declared OpenAPI specifications against live gateway wire telemetry to identify
            verified contract coverage, undocumented shadow operations, unexercised endpoints, and method drift.
          </p>
        </div>

        <!-- Retention Notice -->
        <div class="retention-pill mono">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
          Telemetry Window: {{ selectedWindowHours }}h (Max retention: 720h / 30d)
        </div>
      </div>

      <!-- KPI Summary Cards Strip -->
      <div class="summary-cards-grid">
        <div class="summary-card" (click)="setCategoryFilter('')" [class.active-card]="selectedCategory === ''">
          <div class="summary-label">Total Evaluated</div>
          <div class="summary-val mono">{{ summary()?.totalEvaluated || 0 }}</div>
          <div class="summary-sub">Operations in scope</div>
        </div>

        <div class="summary-card matched" (click)="setCategoryFilter('MATCHED')" [class.active-card]="selectedCategory === 'MATCHED'">
          <div class="summary-label">Matched Contracts</div>
          <div class="summary-val mono green-text">{{ summary()?.matchedCount || 0 }}</div>
          <div class="summary-sub">Declared & active on wire</div>
        </div>

        <div class="summary-card undocumented" (click)="setCategoryFilter('OBSERVED_UNDOCUMENTED')" [class.active-card]="selectedCategory === 'OBSERVED_UNDOCUMENTED'">
          <div class="summary-label">Observed Undocumented</div>
          <div class="summary-val mono orange-text">{{ summary()?.observedUndocumentedCount || 0 }}</div>
          <div class="summary-sub">Shadow / uncataloged traffic</div>
        </div>

        <div class="summary-card unobserved" (click)="setCategoryFilter('DOCUMENTED_UNOBSERVED')" [class.active-card]="selectedCategory === 'DOCUMENTED_UNOBSERVED'">
          <div class="summary-label">Documented Unobserved</div>
          <div class="summary-val mono purple-text">{{ summary()?.documentedUnobservedCount || 0 }}</div>
          <div class="summary-sub">Zero traffic in window</div>
        </div>

        <div class="summary-card mismatch" (click)="setCategoryFilter('METHOD_MISMATCH')" [class.active-card]="selectedCategory === 'METHOD_MISMATCH'">
          <div class="summary-label">Method Mismatch</div>
          <div class="summary-val mono red-text">{{ summary()?.methodMismatchCount || 0 }}</div>
          <div class="summary-sub">Undeclared HTTP verbs</div>
        </div>

        <div class="summary-card coverage">
          <div class="summary-label">Contract Coverage</div>
          <div class="summary-val mono cyan-text">{{ summary()?.coveragePercentage || 0 }}%</div>
          <div class="summary-sub">Declared traffic verified</div>
        </div>
      </div>

      <!-- Filter Controls Bar -->
      <div class="reconciliation-controls-bar">
        <div class="search-input-wrapper">
          <svg class="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input
            type="text"
            [(ngModel)]="searchQuery"
            (ngModelChange)="onSearchChange()"
            placeholder="Search route template, operation ID, or service..."
            class="soc-search-input"
          />
        </div>

        <div class="filter-controls">
          <!-- Window Selector -->
          <div class="select-group">
            <label class="filter-label">Window:</label>
            <select [(ngModel)]="selectedWindowHours" (ngModelChange)="loadReconciliation(0)" class="soc-select">
              <option [ngValue]="24">Last 24 Hours</option>
              <option [ngValue]="48">Last 48 Hours</option>
              <option [ngValue]="168">Last 7 Days</option>
              <option [ngValue]="720">Last 30 Days</option>
            </select>
          </div>

          <!-- Category Filter -->
          <div class="select-group">
            <label class="filter-label">Category:</label>
            <select [(ngModel)]="selectedCategory" (ngModelChange)="loadReconciliation(0)" class="soc-select">
              <option value="">All Categories</option>
              <option value="MATCHED">Matched</option>
              <option value="OBSERVED_UNDOCUMENTED">Observed Undocumented</option>
              <option value="DOCUMENTED_UNOBSERVED">Documented Unobserved</option>
              <option value="METHOD_MISMATCH">Method Mismatch</option>
              <option value="AMBIGUOUS">Ambiguous</option>
            </select>
          </div>

          <!-- Service Filter -->
          <div class="select-group">
            <label class="filter-label">Service:</label>
            <select [(ngModel)]="selectedService" (ngModelChange)="loadReconciliation(0)" class="soc-select">
              <option value="">All Services</option>
              <option value="customer-service">customer-service</option>
              <option value="account-service">account-service</option>
              <option value="transaction-service">transaction-service</option>
              <option value="security-gateway">security-gateway</option>
            </select>
          </div>

          <!-- Specification Filter -->
          <div class="select-group">
            <label class="filter-label">Specification:</label>
            <select [(ngModel)]="selectedSpecId" (ngModelChange)="loadReconciliation(0)" class="soc-select">
              <option value="">All Specifications</option>
              <option *ngFor="let s of specifications()" [value]="s.id">{{ s.name }} (v{{ s.version }})</option>
            </select>
          </div>

          <!-- Refresh -->
          <button (click)="loadReconciliation(currentPage())" class="btn btn-secondary btn-sm refresh-btn" [disabled]="loading()">
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
          <div class="error-title">{{ error()?.title || 'Reconciliation Service Unavailable' }}</div>
          <div class="error-detail">{{ error()?.detail || 'Unable to connect to the reconciliation engine. Verify that backend services are running.' }}</div>
        </div>
        <button (click)="loadReconciliation(currentPage())" class="btn btn-outline btn-sm">Retry</button>
      </div>

      <!-- Main Reconciliation Results Card -->
      <div class="soc-card">
        <div class="table-container">
          <table class="soc-table">
            <thead>
              <tr>
                <th style="width: 70px;">Method</th>
                <th>Canonical Route Template</th>
                <th style="width: 170px;">Reconciliation Finding</th>
                <th style="width: 150px;">Service Boundary</th>
                <th style="width: 180px;">Specification Scope</th>
                <th style="width: 130px; text-align: right;">Observed Traffic</th>
                <th>Reconciliation Explanation</th>
                <th style="width: 100px; text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              <!-- Skeleton Loading -->
              <ng-container *ngIf="loading()">
                <tr *ngFor="let s of [1,2,3,4,5]" class="skeleton-row">
                  <td><div class="skeleton-pill"></div></td>
                  <td><div class="skeleton-bar w-70"></div></td>
                  <td><div class="skeleton-bar w-50"></div></td>
                  <td><div class="skeleton-bar w-50"></div></td>
                  <td><div class="skeleton-bar w-60"></div></td>
                  <td><div class="skeleton-bar w-30 ml-auto"></div></td>
                  <td><div class="skeleton-bar w-70"></div></td>
                  <td><div class="skeleton-bar w-40 ml-auto"></div></td>
                </tr>
              </ng-container>

              <!-- Real Data Rows -->
              <ng-container *ngIf="!loading() && items().length > 0">
                <tr *ngFor="let item of items(); trackBy: trackByItemId" class="recon-row">
                  <td>
                    <span class="method-badge" [ngClass]="item.httpMethod.toLowerCase()">
                      {{ item.httpMethod }}
                    </span>
                  </td>

                  <td>
                    <div class="route-line">
                      <span class="route-template mono">{{ item.normalizedRoute }}</span>
                      <span *ngIf="item.operationId" class="op-id-tag mono" [title]="'OpenAPI operationId: ' + item.operationId">
                        {{ item.operationId }}
                      </span>
                    </div>
                  </td>

                  <td>
                    <span class="category-chip" [ngClass]="getCategoryClass(item.category)">
                      <span class="cat-dot"></span>
                      {{ formatCategory(item.category) }}
                    </span>
                  </td>

                  <td>
                    <span class="service-pill" [ngClass]="getServiceClass(item.serviceBoundary)">
                      {{ item.serviceBoundary }}
                    </span>
                  </td>

                  <td>
                    <div *ngIf="item.specificationName; else unspec">
                      <span class="spec-name-tag">{{ item.specificationName }}</span>
                      <span *ngIf="item.specificationVersion" class="spec-ver mono">v{{ item.specificationVersion }}</span>
                    </div>
                    <ng-template #unspec>
                      <span class="unspec-text mono">None (Undocumented)</span>
                    </ng-template>
                  </td>

                  <td class="req-cell">
                    <div *ngIf="item.totalRequests > 0; else noTraffic">
                      <span class="req-count mono">{{ item.totalRequests | number }} req</span>
                      <div class="status-chips mono">
                        <span *ngIf="item.statusDistribution['2xx']" class="chip chip-2xx">{{ item.statusDistribution['2xx'] }} 2xx</span>
                        <span *ngIf="item.statusDistribution['4xx']" class="chip chip-4xx">{{ item.statusDistribution['4xx'] }} 4xx</span>
                      </div>
                    </div>
                    <ng-template #noTraffic>
                      <span class="zero-traffic mono">0 requests</span>
                    </ng-template>
                  </td>

                  <td>
                    <div class="explanation-text">
                      {{ item.explanation }}
                    </div>
                  </td>

                  <td class="actions-cell">
                    <a
                      *ngIf="item.totalRequests > 0"
                      [routerLink]="['/events']"
                      [queryParams]="{ search: item.normalizedRoute }"
                      class="btn btn-secondary btn-xs action-btn"
                      title="Inspect wire telemetry events"
                    >
                      Events →
                    </a>
                    <a
                      *ngIf="item.specificationId"
                      [routerLink]="['/api-specs']"
                      class="btn btn-outline btn-xs action-btn"
                      title="Inspect specification contract"
                    >
                      Spec →
                    </a>
                  </td>
                </tr>
              </ng-container>

              <!-- Empty State -->
              <tr *ngIf="!loading() && items().length === 0 && !error()">
                <td colspan="8" class="empty-state-cell">
                  <div class="empty-state-wrapper">
                    <div class="empty-icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="18" cy="18" r="3"></circle>
                        <circle cx="6" cy="6" r="3"></circle>
                        <path d="M13 6h3a2 2 0 0 1 2 2v7"></path>
                        <path d="M11 18H8a2 2 0 0 1-2-2V9"></path>
                      </svg>
                    </div>
                    <div class="empty-title">No Reconciled Operations Match Filters</div>
                    <p class="empty-desc">
                      No operations were found matching the selected category, service, or search criteria.
                      Adjust your filter settings or widen the observation window.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Footer -->
        <div *ngIf="totalElements() > 0" class="pagination-footer">
          <div class="pagination-info mono">
            Showing {{ pageStart() }}–{{ pageEnd() }} of {{ totalElements() }} reconciled operations
          </div>
          <div class="pagination-buttons">
            <button
              (click)="loadReconciliation(currentPage() - 1)"
              [disabled]="!hasPrevious() || loading()"
              class="btn btn-secondary btn-sm"
            >
              Previous
            </button>
            <span class="page-current mono">Page {{ currentPage() + 1 }} of {{ totalPages() || 1 }}</span>
            <button
              (click)="loadReconciliation(currentPage() + 1)"
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
      gap: var(--space-5);
      padding: var(--space-6);
      max-width: 1400px;
      margin: 0 auto;
      font-weight: 400;
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
      letter-spacing: 0.08em;
      color: #00D2FF;
      font-family: var(--font-mono);
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .recon-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #00D2FF;
      box-shadow: 0 0 6px #00D2FF;
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
      max-width: 760px;
      line-height: 1.45;
    }

    .retention-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      font-size: 11px;
      color: var(--text-secondary);
    }

    /* Summary Cards Strip */
    .summary-cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: var(--space-3);
    }

    .summary-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 12px 16px;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .summary-card:hover {
      border-color: var(--border-default);
      background: var(--bg-surface-elevated);
    }

    .summary-card.active-card {
      border-color: #3b82f6;
      background: rgba(59, 130, 246, 0.05);
    }

    .summary-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .summary-val {
      font-size: 20px;
      color: var(--text-primary);
      line-height: 1.2;
    }

    .summary-sub {
      font-size: 11px;
      color: var(--text-secondary);
    }

    .green-text { color: #00E5A3; }
    .orange-text { color: #FF7A1A; }
    .purple-text { color: #9D7BFF; }
    .red-text { color: #FF4D5A; }
    .cyan-text { color: #00D2FF; }

    /* Controls Bar */
    .reconciliation-controls-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-4);
      flex-wrap: wrap;
    }

    .search-input-wrapper {
      position: relative;
      flex: 1;
      max-width: 380px;
    }

    .search-icon {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      pointer-events: none;
    }

    .soc-search-input {
      width: 100%;
      padding: 7px 12px 7px 34px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 13px;
      outline: none;
    }

    .soc-search-input:focus { border-color: #00D2FF; }

    .filter-controls {
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
    }

    .soc-select {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 12px;
      padding: 6px 10px;
      outline: none;
    }

    .refresh-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    /* Error Banner */
    .error-banner {
      display: flex;
      align-items: center;
      gap: var(--space-4);
      padding: 12px 16px;
      background: rgba(255, 77, 90, 0.08);
      border: 1px solid rgba(255, 77, 90, 0.3);
      border-radius: var(--radius-md);
      color: #FF4D5A;
    }
    .error-content { flex: 1; }
    .error-title { font-size: 13px; margin-bottom: 2px; }
    .error-detail { font-size: 12px; color: var(--text-secondary); }

    /* Results Table */
    .table-container { overflow-x: auto; }
    .soc-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .soc-table th {
      padding: 10px 14px;
      font-size: 11px;
      font-weight: 400;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
      white-space: nowrap;
    }
    .soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-primary);
      vertical-align: middle;
    }
    .soc-table tr:last-child td { border-bottom: none; }
    .recon-row:hover { background: rgba(255, 255, 255, 0.015); }

    .route-line {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      flex-wrap: wrap;
    }

    .route-template {
      font-size: 13px;
      color: var(--text-primary);
    }

    .op-id-tag {
      font-size: 10px;
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
    }

    /* Category Chips */
    .category-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      font-size: 10px;
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      white-space: nowrap;
    }

    .cat-dot {
      width: 5px;
      height: 5px;
      border-radius: 50%;
    }

    .cat-matched {
      background: rgba(0, 229, 163, 0.12);
      border: 1px solid rgba(0, 229, 163, 0.3);
      color: #00E5A3;
    }
    .cat-matched .cat-dot { background: #00E5A3; }

    .cat-undocumented {
      background: rgba(255, 122, 26, 0.12);
      border: 1px solid rgba(255, 122, 26, 0.3);
      color: #FF7A1A;
    }
    .cat-undocumented .cat-dot { background: #FF7A1A; }

    .cat-unobserved {
      background: rgba(157, 123, 255, 0.12);
      border: 1px solid rgba(157, 123, 255, 0.3);
      color: #9D7BFF;
    }
    .cat-unobserved .cat-dot { background: #9D7BFF; }

    .cat-mismatch {
      background: rgba(255, 77, 90, 0.12);
      border: 1px solid rgba(255, 77, 90, 0.3);
      color: #FF4D5A;
    }
    .cat-mismatch .cat-dot { background: #FF4D5A; }

    .cat-ambiguous {
      background: rgba(148, 163, 184, 0.12);
      border: 1px solid rgba(148, 163, 184, 0.3);
      color: #94A3B8;
    }
    .cat-ambiguous .cat-dot { background: #94A3B8; }

    .spec-name-tag {
      font-size: 12px;
      color: var(--text-primary);
    }

    .spec-ver {
      font-size: 10px;
      color: var(--text-muted);
      margin-left: 4px;
    }

    .unspec-text {
      font-size: 11px;
      color: var(--text-muted);
    }

    .req-cell {
      text-align: right;
      white-space: nowrap;
    }

    .req-count {
      display: block;
      font-size: 12px;
      color: var(--text-primary);
    }

    .zero-traffic {
      font-size: 11px;
      color: var(--text-muted);
    }

    .status-chips {
      display: flex;
      gap: 3px;
      justify-content: flex-end;
      margin-top: 2px;
    }

    .chip {
      font-size: 9px;
      padding: 0 4px;
      border-radius: var(--radius-sm);
    }

    .chip-2xx { background: rgba(0, 229, 163, 0.1); color: #00E5A3; }
    .chip-4xx { background: rgba(255, 77, 90, 0.1); color: #FF4D5A; }

    .explanation-text {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.4;
      max-width: 440px;
    }

    .actions-cell {
      text-align: right;
      white-space: nowrap;
    }

    .action-btn {
      margin-left: 4px;
      font-size: 11px;
      padding: 3px 7px;
      cursor: pointer;
    }

    /* Empty state */
    .empty-state-cell { padding: 48px 16px !important; text-align: center; }
    .empty-state-wrapper { display: flex; flex-direction: column; align-items: center; gap: var(--space-3); max-width: 480px; margin: 0 auto; }
    .empty-icon { color: var(--text-muted); }
    .empty-title { font-size: 15px; color: var(--text-primary); }
    .empty-desc { font-size: 13px; color: var(--text-secondary); margin: 0; line-height: 1.45; }

    /* Skeleton Loading */
    .skeleton-row td { padding: 14px; }
    .skeleton-pill, .skeleton-bar {
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      animation: pulse 1.5s infinite;
    }
    .skeleton-pill { height: 20px; width: 50px; }
    .skeleton-bar { height: 12px; }
    .w-30 { width: 30%; } .w-40 { width: 40%; } .w-50 { width: 50%; } .w-60 { width: 60%; } .w-70 { width: 70%; } .ml-auto { margin-left: auto; }
    @keyframes pulse { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.8; } }
    .spin { animation: spin-anim 1s linear infinite; }
    @keyframes spin-anim { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

    /* Pagination Footer */
    .pagination-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      background: var(--bg-surface-elevated);
      border-top: 1px solid var(--border-subtle);
      font-size: 12px;
    }
    .pagination-info { color: var(--text-secondary); }
    .pagination-buttons { display: flex; align-items: center; gap: var(--space-3); }
    .page-current { color: var(--text-muted); font-size: 12px; }
  `]
})
export class ApiReconciliationComponent implements OnInit {
  private readonly securityApiService = inject(SecurityApiService);

  readonly items = signal<ReconciliationItemResponse[]>([]);
  readonly summary = signal<ReconciliationSummaryResponse | null>(null);
  readonly specifications = signal<ApiSpecificationResponse[]>([]);

  readonly loading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  readonly currentPage = signal<number>(0);
  readonly pageSize = signal<number>(20);
  readonly totalPages = signal<number>(0);
  readonly totalElements = signal<number>(0);
  readonly hasNext = signal<boolean>(false);
  readonly hasPrevious = signal<boolean>(false);

  searchQuery = '';
  selectedWindowHours = 24;
  selectedCategory: string = '';
  selectedService: string = '';
  selectedSpecId: string = '';

  ngOnInit(): void {
    this.loadSpecificationsDropdown();
    this.loadReconciliation(0);
  }

  loadSpecificationsDropdown(): void {
    this.securityApiService.getSpecifications({ page: 0, size: 100 }).subscribe({
      next: (res) => this.specifications.set(res.content),
      error: () => {} // Non-blocking dropdown failure
    });
  }

  loadReconciliation(page: number): void {
    this.loading.set(true);
    this.error.set(null);

    this.securityApiService.getReconciliation({
      page,
      size: this.pageSize(),
      specId: this.selectedSpecId || undefined,
      service: this.selectedService || undefined,
      category: this.selectedCategory || undefined,
      windowHours: this.selectedWindowHours,
      search: this.searchQuery.trim() || undefined
    }).subscribe({
      next: (res) => {
        this.items.set(res.content);
        this.currentPage.set(res.page);
        this.totalPages.set(res.totalPages);
        this.totalElements.set(res.totalElements);
        this.hasNext.set(res.hasNext);
        this.hasPrevious.set(res.hasPrevious);
        this.summary.set(res.summary);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onSearchChange(): void {
    this.loadReconciliation(0);
  }

  setCategoryFilter(category: string): void {
    this.selectedCategory = category;
    this.loadReconciliation(0);
  }

  trackByItemId(_index: number, item: ReconciliationItemResponse): string {
    return item.id;
  }

  pageStart(): number {
    return this.currentPage() * this.pageSize() + 1;
  }

  pageEnd(): number {
    return Math.min((this.currentPage() + 1) * this.pageSize(), this.totalElements());
  }

  formatCategory(category: ReconciliationCategory): string {
    switch (category) {
      case 'MATCHED': return 'Matched';
      case 'OBSERVED_UNDOCUMENTED': return 'Undocumented';
      case 'DOCUMENTED_UNOBSERVED': return 'Unobserved';
      case 'METHOD_MISMATCH': return 'Method Mismatch';
      case 'AMBIGUOUS': return 'Ambiguous';
      default: return category;
    }
  }

  getCategoryClass(category: ReconciliationCategory): string {
    switch (category) {
      case 'MATCHED': return 'cat-matched';
      case 'OBSERVED_UNDOCUMENTED': return 'cat-undocumented';
      case 'DOCUMENTED_UNOBSERVED': return 'cat-unobserved';
      case 'METHOD_MISMATCH': return 'cat-mismatch';
      case 'AMBIGUOUS': return 'cat-ambiguous';
      default: return '';
    }
  }

  getServiceClass(serviceName: string): string {
    if (!serviceName) return 'service-default';
    const lower = serviceName.toLowerCase();
    if (lower.includes('customer')) return 'service-customer';
    if (lower.includes('account')) return 'service-account';
    if (lower.includes('transaction')) return 'service-transaction';
    return 'service-default';
  }
}
