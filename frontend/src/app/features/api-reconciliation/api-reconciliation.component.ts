import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  ReconciliationCategory,
  ReconciliationPriority,
  ReconciliationItemResponse,
  ReconciliationSummaryResponse,
  ReconciliationInvestigationResponse,
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
            RECONCILIATION & DISCREPANCY PRIORITIZATION
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

          <!-- Priority Filter -->
          <div class="select-group">
            <label class="filter-label">Priority:</label>
            <select [(ngModel)]="selectedPriority" (ngModelChange)="loadReconciliation(0)" class="soc-select">
              <option value="">All Priorities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
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

      <!-- Layout: Table + Side Investigation Drawer -->
      <div class="recon-layout">
        <div class="soc-card table-panel" [class.with-drawer]="selectedItem()">
          <div class="table-container">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width: 70px;">Method</th>
                  <th>Canonical Route Template</th>
                  <th style="width: 140px;">Priority</th>
                  <th style="width: 150px;">Finding</th>
                  <th style="width: 140px;">Service Boundary</th>
                  <th style="width: 160px;">Specification</th>
                  <th style="width: 120px; text-align: right;">Observed Traffic</th>
                  <th style="width: 110px; text-align: right;">Actions</th>
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
                    <td><div class="skeleton-bar w-50"></div></td>
                    <td><div class="skeleton-bar w-60"></div></td>
                    <td><div class="skeleton-bar w-30 ml-auto"></div></td>
                    <td><div class="skeleton-bar w-40 ml-auto"></div></td>
                  </tr>
                </ng-container>

                <!-- Real Data Rows -->
                <ng-container *ngIf="!loading() && items().length > 0">
                  <tr
                    *ngFor="let item of items(); trackBy: trackByItemId"
                    class="recon-row"
                    [class.selected-row]="selectedItem()?.id === item.id"
                  >
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
                      <div class="priority-cell">
                        <span class="priority-badge" [ngClass]="getPriorityClass(item.priority)">
                          <span class="prio-dot"></span>
                          {{ item.priority }}
                        </span>
                        <span class="score-tag mono">{{ item.priorityScore }}</span>
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
                          <span *ngIf="item.authFailureCount > 0" class="chip chip-auth" title="Authorization failures (401/403)">{{ item.authFailureCount }} auth fail</span>
                        </div>
                      </div>
                      <ng-template #noTraffic>
                        <span class="zero-traffic mono">0 requests</span>
                      </ng-template>
                    </td>

                    <td class="actions-cell">
                      <button
                        (click)="openInvestigation(item)"
                        class="btn btn-primary btn-xs action-btn"
                        title="Investigate discrepancy finding"
                      >
                        Investigate →
                      </button>
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
                        No operations were found matching the selected category, priority, service, or search criteria.
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

        <!-- Investigation Side Drawer -->
        <div *ngIf="selectedItem() as item" class="soc-card investigation-drawer">
          <div class="drawer-header">
            <div>
              <div class="drawer-pretitle mono">FORENSIC DISCREPANCY INVESTIGATION</div>
              <h2 class="drawer-title mono">{{ item.httpMethod }} {{ item.normalizedRoute }}</h2>
            </div>
            <button (click)="closeDrawer()" class="drawer-close" title="Close investigation drawer" aria-label="Close investigation">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>

          <!-- Drawer Loading -->
          <div *ngIf="investigationLoading()" class="drawer-loading">
            <div class="spinner"></div>
            <p class="mono text-muted">Aggregating telemetry evidence and scoring discrepancy factors...</p>
          </div>

          <!-- Drawer Error -->
          <div *ngIf="investigationError() as err" class="error-banner">
            <div class="error-title">{{ err.title }}</div>
            <div class="error-detail">{{ err.detail }}</div>
          </div>

          <!-- Drawer Content -->
          <div *ngIf="!investigationLoading() && investigation() as inv" class="drawer-body">
            <!-- Strict Safety Disclaimer -->
            <div class="safety-attestation-card">
              <div class="safety-badge-row">
                <span class="safety-pill non-vulnerable mono">CONFIRMED VULNERABILITY: NO (DISCREPANCY ONLY)</span>
                <span class="confidence-pill mono" [ngClass]="getConfidenceClass(inv.matchingConfidence)">
                  CONFIDENCE: {{ inv.matchingConfidence }}
                </span>
              </div>
              <p class="safety-note">
                A discrepancy represents an empirical divergence between wire telemetry and imported documentation.
                It does not constitute proof of active exploitability, data exposure, or missing authorization.
              </p>
            </div>

            <!-- Score Breakdown Section -->
            <div class="drawer-section">
              <div class="section-title-row">
                <span class="drawer-section-title">Deterministic Prioritization Breakdown</span>
                <span class="rule-ver-tag mono">Rule {{ inv.priorityRuleVersion }}</span>
              </div>
              <div class="score-summary-bar">
                <div class="score-big mono" [ngClass]="getPriorityClass(inv.priority)">
                  {{ inv.priorityScore }} <span class="score-max">/ 100</span>
                </div>
                <div class="score-info">
                  <div class="priority-label-big" [ngClass]="getPriorityClass(inv.priority)">
                    {{ inv.priority }} PRIORITY
                  </div>
                  <div class="score-sub">{{ inv.confidenceRationale }}</div>
                </div>
              </div>

              <!-- Contributing Factors List -->
              <div class="factors-list">
                <div *ngFor="let factor of inv.contributingFactors" class="factor-item">
                  <div class="factor-header">
                    <span class="factor-name">{{ factor.factorName }}</span>
                    <span class="factor-delta mono" [class.positive]="factor.scoreDelta > 0">
                      {{ factor.scoreDelta > 0 ? '+' : '' }}{{ factor.scoreDelta }} pts
                    </span>
                  </div>
                  <div class="factor-rationale">{{ factor.rationale }}</div>
                </div>
              </div>
            </div>

            <!-- Telemetry Evidence Section -->
            <div class="drawer-section">
              <div class="drawer-section-title">Observed Telemetry Evidence</div>
              <div class="evidence-grid">
                <div class="evidence-item">
                  <span class="evidence-label">REQUEST VOLUME</span>
                  <span class="evidence-val mono">{{ inv.telemetryEvidence.totalRequests | number }} requests</span>
                </div>
                <div class="evidence-item">
                  <span class="evidence-label">WINDOW DURATION</span>
                  <span class="evidence-val mono">{{ inv.windowHours }} hours</span>
                </div>
                <div class="evidence-item">
                  <span class="evidence-label">AUTH FAILURES (401/403)</span>
                  <span class="evidence-val mono" [class.text-danger]="inv.telemetryEvidence.authFailureCount > 0">
                    {{ inv.telemetryEvidence.authFailureCount }} events
                  </span>
                </div>
                <div class="evidence-item">
                  <span class="evidence-label">ANOMALY FLAGS</span>
                  <span class="evidence-val mono" [class.text-danger]="inv.telemetryEvidence.anomalyEventCount > 0">
                    {{ inv.telemetryEvidence.anomalyEventCount }} flagged
                  </span>
                </div>
              </div>

              <div class="evidence-item mt-2">
                <span class="evidence-label">DISTINCT HTTP STATUS CODES</span>
                <div class="status-tags-row mono">
                  <span *ngFor="let code of inv.telemetryEvidence.distinctStatusCodes" class="code-tag">
                    {{ code }}
                  </span>
                  <span *ngIf="inv.telemetryEvidence.distinctStatusCodes.length === 0" class="text-muted">
                    None observed
                  </span>
                </div>
              </div>
            </div>

            <!-- Specification Contract Scope Section -->
            <div class="drawer-section">
              <div class="drawer-section-title">OpenAPI Specification Scope</div>
              <div *ngIf="inv.specification as spec; else noSpec" class="spec-detail-box">
                <div class="spec-prop"><span class="prop-label">SPECIFICATION:</span> <span class="prop-val">{{ spec.name }} (v{{ spec.version }})</span></div>
                <div class="spec-prop"><span class="prop-label">OPENAPI VERSION:</span> <span class="prop-val mono">{{ spec.openapiVersion }} ({{ spec.format }})</span></div>
                <div class="spec-prop"><span class="prop-label">SOURCE FILE:</span> <span class="prop-val mono">{{ spec.sourceFilename }}</span></div>
                <div *ngIf="spec.operationId" class="spec-prop"><span class="prop-label">OPERATION ID:</span> <span class="prop-val mono">{{ spec.operationId }}</span></div>
                <div *ngIf="spec.summary" class="spec-prop"><span class="prop-label">SUMMARY:</span> <span class="prop-val">{{ spec.summary }}</span></div>
              </div>
              <ng-template #noSpec>
                <div class="empty-spec-box mono">
                  Route is absent from all imported OpenAPI specifications (uncataloged shadow endpoint).
                </div>
              </ng-template>
            </div>

            <!-- Linked Correlation Incidents Section -->
            <div class="drawer-section">
              <div class="drawer-section-title">Linked Correlation Incidents</div>
              <div *ngIf="inv.linkedIncidents.length > 0; else noIncidents" class="incidents-list">
                <div *ngFor="let inc of inv.linkedIncidents" class="incident-card-mini">
                  <div class="incident-top">
                    <span class="incident-badge" [ngClass]="inc.severity.toLowerCase()">{{ inc.severity }}</span>
                    <span class="incident-cat mono">{{ inc.ruleId }} · {{ inc.threatCategory }}</span>
                    <span class="incident-status mono">{{ inc.status }}</span>
                  </div>
                  <div class="incident-summary">{{ inc.summary }}</div>
                </div>
              </div>
              <ng-template #noIncidents>
                <div class="empty-spec-box mono">
                  No correlation incidents linked to this endpoint or service in the monitoring window.
                </div>
              </ng-template>
            </div>

            <!-- Explicit Limitations Section -->
            <div class="drawer-section">
              <div class="drawer-section-title">Empirical Limitations</div>
              <ul class="limitations-list">
                <li *ngFor="let lim of inv.explicitLimitations">{{ lim }}</li>
              </ul>
            </div>

            <!-- Recommended Next Steps Section -->
            <div class="drawer-section">
              <div class="drawer-section-title">Recommended Investigation Steps</div>
              <ol class="steps-list">
                <li *ngFor="let step of inv.recommendedSteps">{{ step }}</li>
              </ol>
            </div>

            <!-- Quick Action Links -->
            <div class="drawer-actions">
              <a
                *ngIf="inv.telemetryEvidence.totalRequests > 0"
                [routerLink]="['/events']"
                [queryParams]="{ search: inv.normalizedRoute }"
                class="btn btn-secondary btn-sm"
              >
                Inspect Wire Events →
              </a>
              <a
                *ngIf="inv.specification"
                [routerLink]="['/api-specs']"
                class="btn btn-outline btn-sm"
              >
                Inspect OpenAPI Spec →
              </a>
              <button (click)="closeDrawer()" class="btn btn-outline btn-sm">Close Inspector</button>
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
      font-size: 12px;
      color: var(--text-secondary);
      max-width: 800px;
      margin: 0;
      line-height: 1.5;
    }

    .retention-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      font-size: 11px;
      color: var(--text-secondary);
    }

    /* KPI Summary Cards */
    .summary-cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: var(--space-3);
    }

    .summary-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 14px 16px;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .summary-card:hover {
      border-color: var(--border-muted);
      transform: translateY(-1px);
    }

    .active-card {
      border-color: #00D2FF !important;
      background: rgba(0, 210, 255, 0.03);
    }

    .summary-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
    }

    .summary-val {
      font-size: 22px;
      color: var(--text-primary);
      line-height: 1.1;
      margin-bottom: 4px;
    }

    .summary-sub {
      font-size: 11px;
      color: var(--text-muted);
    }

    .green-text { color: #00E676; }
    .orange-text { color: #FF9100; }
    .purple-text { color: #B388FF; }
    .red-text { color: #FF4D5A; }
    .cyan-text { color: #00D2FF; }

    /* Controls Bar */
    .reconciliation-controls-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-4);
      flex-wrap: wrap;
      background: var(--bg-surface);
      padding: 12px 16px;
      border-radius: var(--radius-md);
      border: 1px solid var(--border-subtle);
    }

    .search-input-wrapper {
      position: relative;
      flex: 1;
      min-width: 240px;
      max-width: 360px;
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
      padding: 6px 10px 6px 32px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 12px;
      outline: none;
    }

    .soc-search-input:focus {
      border-color: #00D2FF;
    }

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

    /* Layout & Table */
    .recon-layout {
      display: flex;
      gap: var(--space-4);
      align-items: flex-start;
    }

    .table-panel {
      flex: 1;
      min-width: 0;
    }

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
    .selected-row { background: rgba(0, 210, 255, 0.04) !important; border-left: 2px solid #00D2FF; }

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

    /* Priority Badges */
    .priority-cell {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .priority-badge {
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

    .prio-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
    }

    .prio-critical {
      background: rgba(255, 77, 90, 0.15);
      border: 1px solid rgba(255, 77, 90, 0.4);
      color: #FF4D5A;
    }
    .prio-critical .prio-dot { background: #FF4D5A; box-shadow: 0 0 4px #FF4D5A; }

    .prio-high {
      background: rgba(255, 152, 0, 0.15);
      border: 1px solid rgba(255, 152, 0, 0.4);
      color: #FF9800;
    }
    .prio-high .prio-dot { background: #FF9800; }

    .prio-medium {
      background: rgba(255, 193, 7, 0.15);
      border: 1px solid rgba(255, 193, 7, 0.4);
      color: #FFC107;
    }
    .prio-medium .prio-dot { background: #FFC107; }

    .prio-low {
      background: rgba(148, 163, 184, 0.12);
      border: 1px solid rgba(148, 163, 184, 0.3);
      color: #94A3B8;
    }
    .prio-low .prio-dot { background: #94A3B8; }

    .score-tag {
      font-size: 10px;
      color: var(--text-muted);
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
      width: 6px;
      height: 6px;
      border-radius: 50%;
    }

    .cat-matched {
      background: rgba(0, 230, 118, 0.1);
      border: 1px solid rgba(0, 230, 118, 0.3);
      color: #00E676;
    }
    .cat-matched .cat-dot { background: #00E676; }

    .cat-undocumented {
      background: rgba(255, 145, 0, 0.1);
      border: 1px solid rgba(255, 145, 0, 0.3);
      color: #FF9100;
    }
    .cat-undocumented .cat-dot { background: #FF9100; }

    .cat-unobserved {
      background: rgba(179, 136, 255, 0.1);
      border: 1px solid rgba(179, 136, 255, 0.3);
      color: #B388FF;
    }
    .cat-unobserved .cat-dot { background: #B388FF; }

    .cat-mismatch {
      background: rgba(255, 77, 90, 0.1);
      border: 1px solid rgba(255, 77, 90, 0.3);
      color: #FF4D5A;
    }
    .cat-mismatch .cat-dot { background: #FF4D5A; }

    .cat-ambiguous {
      background: rgba(255, 235, 59, 0.1);
      border: 1px solid rgba(255, 235, 59, 0.3);
      color: #FFEB3B;
    }
    .cat-ambiguous .cat-dot { background: #FFEB3B; }

    /* Method Badges */
    .method-badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-size: 10px;
      font-family: var(--font-mono);
      font-weight: 400;
      text-transform: uppercase;
      text-align: center;
    }
    .method-badge.get { background: rgba(0, 210, 255, 0.15); color: #00D2FF; }
    .method-badge.post { background: rgba(0, 230, 118, 0.15); color: #00E676; }
    .method-badge.put { background: rgba(255, 145, 0, 0.15); color: #FF9100; }
    .method-badge.delete { background: rgba(255, 77, 90, 0.15); color: #FF4D5A; }
    .method-badge.patch { background: rgba(179, 136, 255, 0.15); color: #B388FF; }

    /* Service Pills */
    .service-pill {
      display: inline-block;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-family: var(--font-mono);
    }
    .service-customer { background: rgba(56, 189, 248, 0.1); color: #38bdf8; }
    .service-account { background: rgba(167, 139, 250, 0.1); color: #a78bfa; }
    .service-transaction { background: rgba(251, 146, 60, 0.1); color: #fb923c; }
    .service-default { background: var(--bg-surface-elevated); color: var(--text-secondary); }

    .spec-name-tag { font-size: 12px; color: var(--text-primary); margin-right: 4px; }
    .spec-ver { font-size: 10px; color: var(--text-muted); }
    .unspec-text { font-size: 11px; color: var(--text-muted); }

    .req-cell { text-align: right; }
    .req-count { font-size: 12px; color: var(--text-primary); }
    .status-chips { display: flex; gap: 4px; justify-content: flex-end; margin-top: 2px; }
    .chip { font-size: 9px; padding: 1px 4px; border-radius: var(--radius-sm); }
    .chip-2xx { background: rgba(0, 230, 118, 0.1); color: #00E676; }
    .chip-4xx { background: rgba(255, 77, 90, 0.1); color: #FF4D5A; }
    .chip-auth { background: rgba(255, 145, 0, 0.15); color: #FF9100; }
    .zero-traffic { font-size: 11px; color: var(--text-muted); }

    .actions-cell { text-align: right; }
    .action-btn { margin-left: 4px; }

    /* Side Investigation Drawer */
    .investigation-drawer {
      width: 460px;
      min-width: 460px;
      display: flex;
      flex-direction: column;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      background: var(--bg-surface);
      max-height: calc(100vh - 180px);
      overflow-y: auto;
    }

    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding: 16px;
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
      position: sticky;
      top: 0;
      z-index: 2;
    }

    .drawer-pretitle {
      font-size: 10px;
      letter-spacing: 0.08em;
      color: #00D2FF;
      margin-bottom: 4px;
    }

    .drawer-title {
      font-size: 14px;
      color: var(--text-primary);
      margin: 0;
      word-break: break-all;
    }

    .drawer-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 4px;
    }

    .drawer-close:hover { color: var(--text-primary); }

    .drawer-loading {
      padding: 32px 16px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: var(--space-3);
    }

    .spinner {
      width: 24px;
      height: 24px;
      border: 2px solid var(--border-subtle);
      border-top-color: #00D2FF;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    .drawer-body {
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .safety-attestation-card {
      background: rgba(0, 210, 255, 0.03);
      border: 1px solid rgba(0, 210, 255, 0.2);
      border-radius: var(--radius-sm);
      padding: 12px;
    }

    .safety-badge-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .safety-pill {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: rgba(0, 230, 118, 0.12);
      border: 1px solid rgba(0, 230, 118, 0.3);
      color: #00E676;
    }

    .confidence-pill {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .conf-high { background: rgba(0, 230, 118, 0.1); color: #00E676; }
    .conf-med { background: rgba(255, 193, 7, 0.1); color: #FFC107; }
    .conf-low { background: rgba(255, 77, 90, 0.1); color: #FF4D5A; }

    .safety-note {
      font-size: 11px;
      color: var(--text-secondary);
      margin: 0;
      line-height: 1.4;
    }

    .drawer-section {
      display: flex;
      flex-direction: column;
      gap: 8px;
      border-top: 1px solid var(--border-subtle);
      padding-top: 12px;
    }

    .section-title-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .drawer-section-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }

    .rule-ver-tag {
      font-size: 10px;
      color: var(--text-muted);
    }

    .score-summary-bar {
      display: flex;
      align-items: center;
      gap: 16px;
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 12px;
    }

    .score-big {
      font-size: 28px;
      line-height: 1;
    }

    .score-max { font-size: 14px; color: var(--text-muted); }
    .priority-label-big { font-size: 12px; letter-spacing: 0.05em; margin-bottom: 2px; }
    .score-sub { font-size: 11px; color: var(--text-secondary); }

    .factors-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .factor-item {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
    }

    .factor-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2px;
    }

    .factor-name { font-size: 12px; color: var(--text-primary); }
    .factor-delta { font-size: 11px; color: var(--text-muted); }
    .factor-delta.positive { color: #FF9800; }
    .factor-rationale { font-size: 11px; color: var(--text-secondary); line-height: 1.3; }

    .evidence-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }

    .evidence-item {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .evidence-label { font-size: 9px; color: var(--text-muted); letter-spacing: 0.04em; }
    .evidence-val { font-size: 12px; color: var(--text-primary); }
    .text-danger { color: #FF4D5A; }

    .status-tags-row {
      display: flex;
      gap: 4px;
      flex-wrap: wrap;
      margin-top: 4px;
    }

    .code-tag {
      font-size: 10px;
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      color: var(--text-primary);
    }

    .spec-detail-box, .empty-spec-box {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 10px;
      font-size: 11px;
    }

    .empty-spec-box { color: var(--text-muted); font-size: 11px; }

    .spec-prop {
      display: flex;
      gap: 8px;
      margin-bottom: 4px;
    }

    .prop-label { font-size: 10px; color: var(--text-muted); width: 110px; flex-shrink: 0; }
    .prop-val { color: var(--text-primary); }

    .incidents-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .incident-card-mini {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
    }

    .incident-top {
      display: flex;
      gap: 6px;
      align-items: center;
      margin-bottom: 4px;
    }

    .incident-badge {
      font-size: 9px;
      padding: 1px 4px;
      border-radius: var(--radius-sm);
      text-transform: uppercase;
    }
    .incident-badge.critical { background: rgba(255, 77, 90, 0.2); color: #FF4D5A; }
    .incident-badge.high { background: rgba(255, 145, 0, 0.2); color: #FF9100; }
    .incident-badge.medium { background: rgba(255, 193, 7, 0.2); color: #FFC107; }

    .incident-cat { font-size: 10px; color: var(--text-secondary); }
    .incident-status { font-size: 9px; color: var(--text-muted); margin-left: auto; }
    .incident-summary { font-size: 11px; color: var(--text-primary); }

    .limitations-list, .steps-list {
      margin: 0;
      padding-left: 18px;
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.4;
    }

    .limitations-list li, .steps-list li { margin-bottom: 4px; }

    .drawer-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
      border-top: 1px solid var(--border-subtle);
      padding-top: 12px;
    }

    /* Skeleton Loading */
    .skeleton-row td { padding: 12px 14px; }
    .skeleton-bar, .skeleton-pill {
      height: 12px;
      background: linear-gradient(90deg, rgba(255,255,255,0.02) 25%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.02) 75%);
      background-size: 200% 100%;
      animation: shimmer 1.5s infinite;
      border-radius: var(--radius-sm);
    }
    .skeleton-pill { width: 45px; height: 18px; border-radius: var(--radius-sm); }
    .w-70 { width: 70%; }
    .w-60 { width: 60%; }
    .w-50 { width: 50%; }
    .w-40 { width: 40%; }
    .w-30 { width: 30%; }
    .ml-auto { margin-left: auto; }
    @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

    /* Empty State */
    .empty-state-cell { padding: 48px 16px; text-align: center; }
    .empty-state-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: var(--space-2);
      max-width: 420px;
      margin: 0 auto;
    }
    .empty-icon { color: var(--text-muted); opacity: 0.6; margin-bottom: 4px; }
    .empty-title { font-size: 14px; color: var(--text-primary); }
    .empty-desc { font-size: 12px; color: var(--text-secondary); line-height: 1.4; margin: 0; }

    /* Pagination */
    .pagination-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 16px;
      border-top: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
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

  readonly selectedItem = signal<ReconciliationItemResponse | null>(null);
  readonly investigation = signal<ReconciliationInvestigationResponse | null>(null);
  readonly investigationLoading = signal<boolean>(false);
  readonly investigationError = signal<ProblemDetail | null>(null);

  readonly currentPage = signal<number>(0);
  readonly pageSize = signal<number>(20);
  readonly totalPages = signal<number>(0);
  readonly totalElements = signal<number>(0);
  readonly hasNext = signal<boolean>(false);
  readonly hasPrevious = signal<boolean>(false);

  searchQuery = '';
  selectedWindowHours = 24;
  selectedCategory: string = '';
  selectedPriority: string = '';
  selectedService: string = '';
  selectedSpecId: string = '';

  ngOnInit(): void {
    this.loadSpecificationsDropdown();
    this.loadReconciliation(0);
  }

  loadSpecificationsDropdown(): void {
    this.securityApiService.getSpecifications({ page: 0, size: 100 }).subscribe({
      next: (res) => this.specifications.set(res.content),
      error: () => {}
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
      priority: this.selectedPriority || undefined,
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

  openInvestigation(item: ReconciliationItemResponse): void {
    this.selectedItem.set(item);
    this.investigation.set(null);
    this.investigationError.set(null);
    this.investigationLoading.set(true);

    this.securityApiService.getReconciliationInvestigation(item.id, {
      windowHours: this.selectedWindowHours,
      specId: this.selectedSpecId || undefined
    }).subscribe({
      next: (res) => {
        this.investigation.set(res);
        this.investigationLoading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.investigationError.set(err);
        this.investigationLoading.set(false);
      }
    });
  }

  closeDrawer(): void {
    this.selectedItem.set(null);
    this.investigation.set(null);
    this.investigationError.set(null);
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

  getPriorityClass(priority: ReconciliationPriority): string {
    switch (priority) {
      case 'CRITICAL': return 'prio-critical';
      case 'HIGH': return 'prio-high';
      case 'MEDIUM': return 'prio-medium';
      case 'LOW': return 'prio-low';
      default: return 'prio-low';
    }
  }

  getConfidenceClass(confidence: string): string {
    switch (confidence?.toUpperCase()) {
      case 'HIGH': return 'conf-high';
      case 'MEDIUM': return 'conf-med';
      case 'LOW': return 'conf-low';
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
