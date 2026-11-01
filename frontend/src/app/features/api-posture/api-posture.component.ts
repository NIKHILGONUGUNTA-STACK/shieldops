import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  EndpointPostureResponse,
  PostureSummaryResponse,
  PosturePageResponse,
  AssessmentDimensionType,
  DimensionStatus,
  OverallPosture,
  PostureEvidenceItem,
  DimensionAssessment,
  ProblemDetail
} from '../../core/models/security.models';

@Component({
  selector: 'app-api-posture',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb-tag">
            <span class="posture-dot"></span>
            SECURITY POSTURE & EVIDENCE COVERAGE
          </div>
          <h1 class="soc-title">API Security Posture Assessment</h1>
          <p class="soc-subtitle">
            Deterministic, multi-dimensional assessment of discovered API endpoints across Exposure, Authentication,
            Authorization, Data Sensitivity, Behavioral Telemetry, and Specification Coverage.
          </p>
        </div>

        <!-- Telemetry Window Notice -->
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
        <div class="summary-card" (click)="setPostureFilter('')" [class.active-card]="selectedPosture === ''">
          <div class="summary-label">Total Assessed</div>
          <div class="summary-val mono">{{ summary()?.totalAssessedEndpoints || 0 }}</div>
          <div class="summary-sub">Endpoints in observation scope</div>
        </div>

        <div class="summary-card adequate" (click)="setPostureFilter('ADEQUATE')" [class.active-card]="selectedPosture === 'ADEQUATE'">
          <div class="summary-label">Adequate Posture</div>
          <div class="summary-val mono green-text">{{ summary()?.adequateCount || 0 }}</div>
          <div class="summary-sub">All available evidence verified</div>
        </div>

        <div class="summary-card attention" (click)="setPostureFilter('ATTENTION_REQUIRED')" [class.active-card]="selectedPosture === 'ATTENTION_REQUIRED'">
          <div class="summary-label">Attention Required</div>
          <div class="summary-val mono orange-text">{{ summary()?.attentionRequiredCount || 0 }}</div>
          <div class="summary-sub">Discrepancies or anomalies detected</div>
        </div>

        <div class="summary-card unverified" (click)="setPostureFilter('INSUFFICIENT_EVIDENCE')" [class.active-card]="selectedPosture === 'INSUFFICIENT_EVIDENCE'">
          <div class="summary-label">Insufficient Evidence</div>
          <div class="summary-val mono slate-text">{{ summary()?.insufficientEvidenceCount || 0 }}</div>
          <div class="summary-sub">>= 3 unverified dimensions</div>
        </div>

        <div class="summary-card coverage">
          <div class="summary-label">Average Coverage</div>
          <div class="summary-val mono cyan-text">{{ summary()?.averageEvidenceCoveragePercentage || 0 }}%</div>
          <div class="summary-sub">Across 6 assessment dimensions</div>
        </div>
      </div>

      <!-- Filter Controls Strip -->
      <div class="soc-card filter-card">
        <div class="filter-row">
          <!-- Search Input -->
          <div class="filter-group flex-2">
            <label class="filter-label">Search Endpoints</label>
            <div class="search-input-wrap">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="search-icon">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
              <input
                type="text"
                [(ngModel)]="searchQuery"
                (ngModelChange)="onSearchChange()"
                placeholder="Filter by route template (e.g. /api/v1/customers)..."
                class="soc-input search-input"
              />
            </div>
          </div>

          <!-- Service Boundary Dropdown -->
          <div class="filter-group">
            <label class="filter-label">Service Boundary</label>
            <select [(ngModel)]="selectedService" (change)="onFilterChange()" class="soc-select">
              <option value="">All Services</option>
              <option value="customer-service">customer-service</option>
              <option value="account-service">account-service</option>
              <option value="transaction-service">transaction-service</option>
              <option value="gateway-service">gateway-service</option>
            </select>
          </div>

          <!-- Posture Category Dropdown -->
          <div class="filter-group">
            <label class="filter-label">Overall Posture</label>
            <select [(ngModel)]="selectedPosture" (change)="onFilterChange()" class="soc-select">
              <option value="">All Postures</option>
              <option value="ADEQUATE">Adequate</option>
              <option value="ATTENTION_REQUIRED">Attention Required</option>
              <option value="INSUFFICIENT_EVIDENCE">Insufficient Evidence</option>
            </select>
          </div>

          <!-- Observation Window Dropdown -->
          <div class="filter-group">
            <label class="filter-label">Observation Window</label>
            <select [(ngModel)]="selectedWindowHours" (change)="onFilterChange()" class="soc-select">
              <option [ngValue]="24">Last 24 Hours</option>
              <option [ngValue]="72">Last 3 Days (72h)</option>
              <option [ngValue]="168">Last 7 Days (168h)</option>
              <option [ngValue]="720">Last 30 Days (720h)</option>
            </select>
          </div>

          <!-- Refresh Action Button -->
          <div class="filter-action-group">
            <button (click)="loadPostureData(currentPage())" [disabled]="loading()" class="btn btn-secondary">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" [class.spin]="loading()">
                <polyline points="23 4 23 10 17 10"></polyline>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
              Refresh
            </button>
          </div>
        </div>
      </div>

      <!-- Main Layout: Grid vs Drawer -->
      <div class="soc-main-layout" [class.drawer-open]="selectedEndpoint() !== null">
        <!-- Posture Table -->
        <div class="soc-card table-card">
          <div class="table-wrap">
            <table class="soc-table">
              <thead>
                <tr>
                  <th style="width: 75px;">Method</th>
                  <th>Route & Service Boundary</th>
                  <th style="width: 140px;">Overall Posture</th>
                  <th style="width: 120px;">Coverage</th>
                  <th style="width: 220px;">Dimension Status</th>
                  <th style="width: 80px; text-align: center;">Findings</th>
                  <th style="width: 110px; text-align: right;">Observed</th>
                  <th style="width: 90px; text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody>
                <!-- Skeleton Loader -->
                <ng-container *ngIf="loading()">
                  <tr *ngFor="let s of [1,2,3,4,5]" class="skeleton-row">
                    <td><div class="skeleton-pill"></div></td>
                    <td><div class="skeleton-bar w-70"></div></td>
                    <td><div class="skeleton-bar w-50"></div></td>
                    <td><div class="skeleton-bar w-40"></div></td>
                    <td><div class="skeleton-bar w-60"></div></td>
                    <td><div class="skeleton-bar w-20 mx-auto"></div></td>
                    <td><div class="skeleton-bar w-40 ml-auto"></div></td>
                    <td><div class="skeleton-bar w-30 ml-auto"></div></td>
                  </tr>
                </ng-container>

                <!-- Data Rows -->
                <ng-container *ngIf="!loading() && items().length > 0">
                  <tr
                    *ngFor="let item of items(); trackBy: trackByEndpointId"
                    class="posture-row"
                    [class.selected-row]="selectedEndpoint()?.endpointId === item.endpointId"
                    (click)="inspectEndpoint(item)"
                  >
                    <td>
                      <span class="method-badge" [ngClass]="item.httpMethod.toLowerCase()">
                        {{ item.httpMethod }}
                      </span>
                    </td>

                    <td>
                      <div class="route-line">
                        <span class="route-template mono">{{ item.normalizedRoute }}</span>
                        <span class="service-tag mono">{{ item.serviceBoundary }}</span>
                      </div>
                    </td>

                    <td>
                      <span class="posture-chip" [ngClass]="getPostureClass(item.overallPosture)">
                        <span class="posture-dot"></span>
                        {{ formatPosture(item.overallPosture) }}
                      </span>
                    </td>

                    <td>
                      <div class="coverage-bar-cell">
                        <div class="coverage-track">
                          <div class="coverage-fill" [style.width.%]="item.evidenceCoveragePercentage"></div>
                        </div>
                        <span class="coverage-val mono">{{ item.evidenceCoveragePercentage | number:'1.0-0' }}%</span>
                      </div>
                    </td>

                    <td>
                      <div class="dimension-pills-row">
                        <span
                          *ngFor="let dimKey of dimensionKeys"
                          class="dim-mini-pill"
                          [ngClass]="getDimensionClass(item.dimensions[dimKey].status)"
                          [title]="getDimensionTooltip(dimKey, item.dimensions[dimKey])"
                        >
                          {{ getDimShortLabel(dimKey) }}
                        </span>
                      </div>
                    </td>

                    <td style="text-align: center;">
                      <span *ngIf="item.totalFindingsCount > 0" class="finding-badge mono">
                        {{ item.totalFindingsCount }}
                      </span>
                      <span *ngIf="item.totalFindingsCount === 0" class="clean-badge mono">
                        0
                      </span>
                    </td>

                    <td class="req-cell">
                      <span class="req-count mono">{{ item.totalRequests | number }} req</span>
                    </td>

                    <td style="text-align: right;">
                      <button
                        (click)="inspectEndpoint(item); $event.stopPropagation()"
                        class="btn-inspect mono"
                        title="Open detailed posture assessment dossier"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                </ng-container>

                <!-- Empty State -->
                <tr *ngIf="!loading() && items().length === 0">
                  <td colspan="8" class="empty-cell">
                    <div class="empty-state">
                      <div class="empty-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                      </div>
                      <div class="empty-title">No Endpoints Match Posture Filters</div>
                      <p class="empty-desc">
                        No endpoints match the current posture filter criteria or observation window.
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
              Showing {{ pageStart() }}–{{ pageEnd() }} of {{ totalElements() }} assessed endpoints
            </div>
            <div class="pagination-buttons">
              <button
                (click)="loadPostureData(currentPage() - 1)"
                [disabled]="!hasPrevious() || loading()"
                class="btn btn-secondary btn-sm"
              >
                Previous
              </button>
              <span class="page-current mono">Page {{ currentPage() + 1 }} of {{ totalPages() || 1 }}</span>
              <button
                (click)="loadPostureData(currentPage() + 1)"
                [disabled]="!hasNext() || loading()"
                class="btn btn-secondary btn-sm"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        <!-- Slide-out Posture Dossier Drawer -->
        <div *ngIf="selectedEndpoint() as ep" class="soc-card dossier-drawer">
          <div class="drawer-header">
            <div>
              <div class="drawer-pretitle mono">EVIDENCE-DRIVEN POSTURE ASSESSMENT</div>
              <h2 class="drawer-title mono">{{ ep.httpMethod }} {{ ep.normalizedRoute }}</h2>
              <div class="drawer-meta-row">
                <span class="service-tag mono">{{ ep.serviceBoundary }}</span>
                <span class="rule-ver-tag mono">Rules: {{ ep.assessmentRuleVersion }}</span>
              </div>
            </div>
            <button (click)="closeDrawer()" class="drawer-close" title="Close dossier" aria-label="Close dossier">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>

          <!-- Invariant Disclaimer Attestation -->
          <div class="safety-attestation-card">
            <div class="safety-badge-row">
              <span class="safety-pill green-pill mono">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                  <polyline points="9 12 11 14 15 10"></polyline>
                </svg>
                CONFIRMED VULNERABILITY: NO
              </span>
              <span class="safety-tag mono">ADVISORY ASSESSMENT ONLY</span>
            </div>
            <p class="safety-text">
              Assessment findings indicate unverified contracts, absent specifications, or elevated security telemetry
              signals. Aegis enforces strict non-speculation: missing evidence is marked UNKNOWN and never converted
              into speculative vulnerability conclusions.
            </p>
          </div>

          <!-- Drawer Body Content -->
          <div class="drawer-body">
            <!-- Overall Status Banner -->
            <div class="status-summary-box" [ngClass]="getPostureClass(ep.overallPosture)">
              <div class="status-box-header">
                <div class="status-box-title">
                  <span class="posture-dot"></span>
                  Overall Categorical Posture: {{ formatPosture(ep.overallPosture) }}
                </div>
                <div class="coverage-tag mono">
                  {{ ep.evidenceCoveragePercentage | number:'1.0-0' }}% Evidence Coverage
                </div>
              </div>
              <p class="status-box-explanation">{{ ep.overallExplanation }}</p>
            </div>

            <!-- Deep Links Row -->
            <div class="deep-links-bar">
              <a [routerLink]="['/events']" [queryParams]="{ route: ep.normalizedRoute }" class="deep-link-btn mono">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="8" y1="6" x2="21" y2="6"></line>
                  <line x1="8" y1="12" x2="21" y2="12"></line>
                  <line x1="8" y1="18" x2="21" y2="18"></line>
                </svg>
                View Telemetry
              </a>
              <a [routerLink]="['/api-inventory']" class="deep-link-btn mono">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                  <polyline points="2 17 12 22 22 17"></polyline>
                  <polyline points="2 12 12 17 22 12"></polyline>
                </svg>
                API Inventory
              </a>
              <a [routerLink]="['/api-reconciliation']" class="deep-link-btn mono">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="18" cy="18" r="3"></circle>
                  <circle cx="6" cy="6" r="3"></circle>
                  <path d="M13 6h3a2 2 0 0 1 2 2v7"></path>
                </svg>
                Reconciliation
              </a>
              <a [routerLink]="['/incidents']" class="deep-link-btn mono">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                </svg>
                Incidents
              </a>
            </div>

            <!-- 6 Dimensions Detailed Accordion/Cards -->
            <div class="dimension-sections-list">
              <div
                *ngFor="let dimKey of dimensionKeys"
                class="dimension-card"
                [class.has-finding]="ep.dimensions[dimKey].status === 'FINDING'"
                [class.is-unknown]="ep.dimensions[dimKey].status === 'UNKNOWN'"
              >
                <!-- Dimension Header -->
                <div class="dim-card-header">
                  <div class="dim-title-group">
                    <span class="dim-name mono">{{ getDimensionTitle(dimKey) }}</span>
                    <span class="dim-status-pill" [ngClass]="getDimensionClass(ep.dimensions[dimKey].status)">
                      {{ ep.dimensions[dimKey].status }}
                    </span>
                  </div>
                </div>

                <!-- Dimension Summary -->
                <p class="dim-summary-text">{{ ep.dimensions[dimKey].summary }}</p>

                <!-- Evidence Items -->
                <div *ngIf="ep.dimensions[dimKey].evidence.length" class="evidence-block">
                  <div class="dim-sub-heading mono">SUPPORTING EVIDENCE</div>
                  <div class="evidence-list">
                    <div *ngFor="let ev of ep.dimensions[dimKey].evidence" class="evidence-row">
                      <span class="source-tag mono" [ngClass]="getSourceClass(ev.sourceType)">
                        {{ ev.sourceType }}
                      </span>
                      <span class="evidence-desc">{{ ev.description }}</span>
                      <span *ngIf="ev.metricValue" class="metric-tag mono">{{ ev.metricValue }}</span>
                    </div>
                  </div>
                </div>

                <!-- Limitations / What Cannot Be Verified -->
                <div *ngIf="ep.dimensions[dimKey].limitations" class="limitations-block">
                  <div class="dim-sub-heading mono amber-text">OBSERVABILITY BOUNDARY & LIMITATIONS</div>
                  <p class="limitations-text">{{ ep.dimensions[dimKey].limitations }}</p>
                </div>

                <!-- Recommended Actions -->
                <div *ngIf="ep.dimensions[dimKey].recommendedActions.length" class="actions-block">
                  <div class="dim-sub-heading mono">RECOMMENDED INVESTIGATION ACTIONS</div>
                  <ul class="action-items-list">
                    <li *ngFor="let act of ep.dimensions[dimKey].recommendedActions">
                      {{ act }}
                    </li>
                  </ul>
                </div>
              </div>
            </div>

            <!-- Endpoint-Level Recommended Next Steps -->
            <div *ngIf="ep.recommendedSteps?.length" class="soc-card next-steps-card">
              <div class="next-steps-title mono">PRIORITIZED NEXT INVESTIGATION STEPS</div>
              <ol class="next-steps-list">
                <li *ngFor="let step of ep.recommendedSteps">{{ step }}</li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    /* SOC Typography: Strict Inter 400 across headers and body */
    .soc-page-container {
      padding: 24px;
      background-color: #0d1117;
      min-height: calc(100vh - 56px);
      color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
      font-weight: 400;
    }

    .mono {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    }

    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 20px;
      gap: 16px;
    }

    .breadcrumb-tag {
      font-size: 11px;
      font-weight: 400;
      color: #7d8590;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 4px;
    }

    .posture-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background-color: #238636;
      display: inline-block;
    }

    .soc-title {
      font-size: 20px;
      font-weight: 400;
      color: #f0f6fc;
      margin: 0 0 6px 0;
      letter-spacing: -0.01em;
    }

    .soc-subtitle {
      font-size: 13px;
      color: #8b949e;
      margin: 0;
      max-width: 820px;
      line-height: 1.45;
    }

    .retention-pill {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      color: #8b949e;
      display: flex;
      align-items: center;
      gap: 8px;
      white-space: nowrap;
    }

    /* KPI Cards */
    .summary-cards-grid {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 16px;
    }

    .summary-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 14px 16px;
      cursor: pointer;
      transition: border-color 0.15s ease, background 0.15s ease;
    }

    .summary-card:hover {
      border-color: #8b949e;
      background: #1c2128;
    }

    .summary-card.active-card {
      border-color: #58a6ff;
      background: rgba(56, 139, 253, 0.08);
    }

    .summary-label {
      font-size: 11px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
    }

    .summary-val {
      font-size: 24px;
      font-weight: 400;
      color: #f0f6fc;
      line-height: 1;
      margin-bottom: 6px;
    }

    .summary-sub {
      font-size: 11px;
      color: #7d8590;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .green-text { color: #3fb950; }
    .orange-text { color: #d29922; }
    .slate-text { color: #8b949e; }
    .cyan-text { color: #58a6ff; }
    .amber-text { color: #d29922; }

    /* Filters Strip */
    .filter-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 16px;
    }

    .filter-row {
      display: flex;
      align-items: flex-end;
      gap: 12px;
    }

    .filter-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
      flex: 1;
    }

    .flex-2 {
      flex: 2;
    }

    .filter-label {
      font-size: 11px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .search-input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }

    .search-icon {
      position: absolute;
      left: 10px;
      color: #7d8590;
      pointer-events: none;
    }

    .soc-input {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 6px 10px 6px 32px;
      font-size: 12px;
      color: #f0f6fc;
      width: 100%;
      height: 32px;
      box-sizing: border-box;
      outline: none;
    }

    .soc-input:focus {
      border-color: #58a6ff;
    }

    .soc-select {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 4px 8px;
      font-size: 12px;
      color: #f0f6fc;
      height: 32px;
      outline: none;
      width: 100%;
    }

    .soc-select:focus {
      border-color: #58a6ff;
    }

    .filter-action-group {
      display: flex;
      align-items: flex-end;
    }

    .btn {
      height: 32px;
      padding: 0 12px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 400;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      border: 1px solid #30363d;
      background: #21262d;
      color: #c9d1d9;
      transition: background 0.15s ease;
    }

    .btn:hover:not(:disabled) {
      background: #30363d;
      color: #f0f6fc;
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-sm {
      height: 28px;
      padding: 0 10px;
      font-size: 11px;
    }

    .spin {
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      100% { transform: rotate(360deg); }
    }

    /* Layout & Table */
    .soc-main-layout {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
      align-items: flex-start;
      transition: all 0.2s ease;
    }

    .soc-main-layout.drawer-open {
      grid-template-columns: 1fr 520px;
    }

    .table-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      overflow: hidden;
    }

    .table-wrap {
      overflow-x: auto;
    }

    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }

    .soc-table th {
      background: #161b22;
      color: #8b949e;
      padding: 10px 14px;
      font-weight: 400;
      border-bottom: 1px solid #30363d;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }

    .soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid #21262d;
      vertical-align: middle;
    }

    .posture-row {
      cursor: pointer;
      transition: background 0.12s ease;
    }

    .posture-row:hover {
      background: #1c2128;
    }

    .posture-row.selected-row {
      background: rgba(56, 139, 253, 0.09);
      border-left: 3px solid #58a6ff;
    }

    /* Badges & Chips */
    .method-badge {
      font-size: 11px;
      font-weight: 400;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
      display: inline-block;
      font-family: ui-monospace, monospace;
    }

    .method-badge.get { background: rgba(56, 139, 253, 0.15); color: #58a6ff; }
    .method-badge.post { background: rgba(63, 185, 80, 0.15); color: #3fb950; }
    .method-badge.put { background: rgba(210, 153, 34, 0.15); color: #d29922; }
    .method-badge.delete { background: rgba(248, 81, 73, 0.15); color: #f85149; }
    .method-badge.patch { background: rgba(163, 113, 247, 0.15); color: #bc8cff; }

    .route-line {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .route-template {
      color: #f0f6fc;
      font-size: 12px;
      word-break: break-all;
    }

    .service-tag {
      font-size: 11px;
      color: #7d8590;
    }

    .posture-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 400;
      white-space: nowrap;
    }

    .posture-chip.adequate {
      background: rgba(63, 185, 80, 0.12);
      color: #3fb950;
      border: 1px solid rgba(63, 185, 80, 0.3);
    }
    .posture-chip.adequate .posture-dot { background-color: #3fb950; }

    .posture-chip.attention {
      background: rgba(210, 153, 34, 0.12);
      color: #d29922;
      border: 1px solid rgba(210, 153, 34, 0.3);
    }
    .posture-chip.attention .posture-dot { background-color: #d29922; }

    .posture-chip.unverified {
      background: rgba(139, 148, 158, 0.12);
      color: #8b949e;
      border: 1px solid rgba(139, 148, 158, 0.3);
    }
    .posture-chip.unverified .posture-dot { background-color: #8b949e; }

    /* Coverage Progress Cell */
    .coverage-bar-cell {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .coverage-track {
      flex: 1;
      height: 6px;
      background: #21262d;
      border-radius: 3px;
      overflow: hidden;
    }

    .coverage-fill {
      height: 100%;
      background: #58a6ff;
      border-radius: 3px;
      transition: width 0.3s ease;
    }

    .coverage-val {
      font-size: 11px;
      color: #8b949e;
      width: 32px;
      text-align: right;
    }

    /* Dimension mini pills */
    .dimension-pills-row {
      display: flex;
      gap: 4px;
    }

    .dim-mini-pill {
      font-size: 10px;
      padding: 2px 5px;
      border-radius: 3px;
      font-family: ui-monospace, monospace;
      font-weight: 400;
    }

    .dim-verified {
      background: rgba(63, 185, 80, 0.15);
      color: #3fb950;
    }

    .dim-finding {
      background: rgba(210, 153, 34, 0.18);
      color: #d29922;
    }

    .dim-unknown {
      background: rgba(139, 148, 158, 0.12);
      color: #7d8590;
    }

    .finding-badge {
      background: rgba(210, 153, 34, 0.15);
      color: #d29922;
      border: 1px solid rgba(210, 153, 34, 0.3);
      padding: 2px 6px;
      border-radius: 10px;
      font-size: 11px;
    }

    .clean-badge {
      color: #7d8590;
      font-size: 11px;
    }

    .req-cell {
      text-align: right;
    }

    .req-count {
      color: #8b949e;
      font-size: 11px;
    }

    .btn-inspect {
      background: #21262d;
      border: 1px solid #30363d;
      border-radius: 4px;
      color: #c9d1d9;
      font-size: 11px;
      padding: 3px 8px;
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .btn-inspect:hover {
      background: #30363d;
      color: #f0f6fc;
      border-color: #58a6ff;
    }

    /* Pagination */
    .pagination-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      background: #161b22;
      border-top: 1px solid #30363d;
    }

    .pagination-info {
      font-size: 11px;
      color: #8b949e;
    }

    .pagination-buttons {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .page-current {
      font-size: 11px;
      color: #8b949e;
    }

    /* Slide-out Dossier Drawer */
    .dossier-drawer {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      overflow: hidden;
      max-height: calc(100vh - 120px);
      display: flex;
      flex-direction: column;
    }

    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding: 14px 16px;
      background: #161b22;
      border-bottom: 1px solid #30363d;
    }

    .drawer-pretitle {
      font-size: 10px;
      color: #7d8590;
      letter-spacing: 0.06em;
      margin-bottom: 4px;
    }

    .drawer-title {
      font-size: 14px;
      font-weight: 400;
      color: #f0f6fc;
      margin: 0 0 6px 0;
      word-break: break-all;
    }

    .drawer-meta-row {
      display: flex;
      gap: 8px;
    }

    .rule-ver-tag {
      font-size: 11px;
      color: #8b949e;
    }

    .drawer-close {
      background: transparent;
      border: none;
      color: #8b949e;
      cursor: pointer;
      padding: 4px;
      border-radius: 4px;
    }

    .drawer-close:hover {
      color: #f0f6fc;
      background: #21262d;
    }

    .safety-attestation-card {
      background: rgba(35, 134, 54, 0.08);
      border-bottom: 1px solid rgba(35, 134, 54, 0.2);
      padding: 10px 16px;
    }

    .safety-badge-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }

    .safety-pill {
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 4px;
      display: flex;
      align-items: center;
      gap: 4px;
    }

    .green-pill {
      background: rgba(63, 185, 80, 0.15);
      color: #3fb950;
    }

    .safety-tag {
      font-size: 10px;
      color: #7d8590;
    }

    .safety-text {
      font-size: 11px;
      color: #8b949e;
      margin: 0;
      line-height: 1.4;
    }

    .drawer-body {
      padding: 14px 16px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .status-summary-box {
      border-radius: 6px;
      padding: 12px 14px;
      border: 1px solid #30363d;
      background: #0d1117;
    }

    .status-summary-box.adequate {
      border-color: rgba(63, 185, 80, 0.3);
      background: rgba(63, 185, 80, 0.05);
    }

    .status-summary-box.attention {
      border-color: rgba(210, 153, 34, 0.3);
      background: rgba(210, 153, 34, 0.05);
    }

    .status-summary-box.unverified {
      border-color: rgba(139, 148, 158, 0.3);
      background: rgba(139, 148, 158, 0.05);
    }

    .status-box-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .status-box-title {
      font-size: 12px;
      color: #f0f6fc;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .coverage-tag {
      font-size: 11px;
      color: #58a6ff;
    }

    .status-box-explanation {
      font-size: 12px;
      color: #8b949e;
      margin: 0;
      line-height: 1.45;
    }

    /* Deep links bar */
    .deep-links-bar {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 6px;
    }

    .deep-link-btn {
      background: #21262d;
      border: 1px solid #30363d;
      border-radius: 4px;
      padding: 6px 8px;
      font-size: 11px;
      color: #c9d1d9;
      text-decoration: none;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      transition: background 0.15s ease;
      white-space: nowrap;
    }

    .deep-link-btn:hover {
      background: #30363d;
      color: #f0f6fc;
      border-color: #58a6ff;
    }

    /* Dimension Cards */
    .dimension-sections-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .dimension-card {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px 14px;
    }

    .dimension-card.has-finding {
      border-color: rgba(210, 153, 34, 0.4);
    }

    .dimension-card.is-unknown {
      opacity: 0.92;
    }

    .dim-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .dim-title-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .dim-name {
      font-size: 12px;
      color: #f0f6fc;
    }

    .dim-status-pill {
      font-size: 10px;
      padding: 1px 6px;
      border-radius: 10px;
      font-family: ui-monospace, monospace;
    }

    .dim-summary-text {
      font-size: 12px;
      color: #8b949e;
      margin: 0 0 8px 0;
      line-height: 1.4;
    }

    .dim-sub-heading {
      font-size: 10px;
      color: #7d8590;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }

    .evidence-block, .limitations-block, .actions-block {
      margin-top: 8px;
      padding-top: 8px;
      border-top: 1px solid #21262d;
    }

    .evidence-list {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .evidence-row {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      font-size: 11px;
      line-height: 1.4;
    }

    .source-tag {
      font-size: 10px;
      padding: 1px 5px;
      border-radius: 3px;
      white-space: nowrap;
    }

    .src-openapi { background: rgba(56, 139, 253, 0.15); color: #58a6ff; }
    .src-wire { background: rgba(63, 185, 80, 0.15); color: #3fb950; }
    .src-incident { background: rgba(248, 81, 73, 0.15); color: #f85149; }
    .src-gateway { background: rgba(163, 113, 247, 0.15); color: #bc8cff; }
    .src-recon { background: rgba(210, 153, 34, 0.15); color: #d29922; }

    .evidence-desc {
      color: #c9d1d9;
      flex: 1;
    }

    .metric-tag {
      font-size: 10px;
      color: #8b949e;
      background: #161b22;
      padding: 1px 4px;
      border-radius: 3px;
    }

    .limitations-text {
      font-size: 11px;
      color: #8b949e;
      margin: 0;
      line-height: 1.4;
    }

    .action-items-list {
      margin: 0;
      padding-left: 16px;
      font-size: 11px;
      color: #8b949e;
      line-height: 1.45;
    }

    .next-steps-card {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px 14px;
    }

    .next-steps-title {
      font-size: 11px;
      color: #58a6ff;
      margin-bottom: 6px;
    }

    .next-steps-list {
      margin: 0;
      padding-left: 18px;
      font-size: 11px;
      color: #c9d1d9;
      line-height: 1.5;
    }

    /* Skeleton rows */
    .skeleton-row td {
      padding: 12px 14px;
    }

    .skeleton-bar, .skeleton-pill {
      height: 14px;
      background: #21262d;
      border-radius: 4px;
      animation: pulse 1.5s infinite;
    }

    .skeleton-pill {
      width: 48px;
      height: 20px;
      border-radius: 4px;
    }

    .w-70 { width: 70%; }
    .w-60 { width: 60%; }
    .w-50 { width: 50%; }
    .w-40 { width: 40%; }
    .w-30 { width: 30%; }
    .w-20 { width: 20%; }
    .mx-auto { margin: 0 auto; }
    .ml-auto { margin-left: auto; }

    @keyframes pulse {
      0% { opacity: 0.6; }
      50% { opacity: 0.3; }
      100% { opacity: 0.6; }
    }

    /* Empty state */
    .empty-cell {
      text-align: center;
      padding: 48px 16px;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }

    .empty-icon {
      color: #7d8590;
      margin-bottom: 4px;
    }

    .empty-title {
      font-size: 14px;
      color: #f0f6fc;
    }

    .empty-desc {
      font-size: 12px;
      color: #8b949e;
      max-width: 400px;
      margin: 0;
    }
  `]
})
export class ApiPostureComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  readonly dimensionKeys: AssessmentDimensionType[] = [
    'EXPOSURE',
    'AUTHENTICATION',
    'AUTHORIZATION',
    'DATA_SENSITIVITY',
    'BEHAVIORAL',
    'SPECIFICATION'
  ];

  // State Signals
  readonly items = signal<EndpointPostureResponse[]>([]);
  readonly summary = signal<PostureSummaryResponse | null>(null);
  readonly selectedEndpoint = signal<EndpointPostureResponse | null>(null);
  readonly loading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  // Pagination Signals
  readonly currentPage = signal<number>(0);
  readonly pageSize = signal<number>(20);
  readonly totalElements = signal<number>(0);
  readonly totalPages = signal<number>(0);
  readonly hasNext = signal<boolean>(false);
  readonly hasPrevious = signal<boolean>(false);

  // Filter States
  searchQuery = '';
  selectedService = '';
  selectedPosture = '';
  selectedWindowHours = 24;

  readonly pageStart = computed(() => {
    if (this.totalElements() === 0) return 0;
    return this.currentPage() * this.pageSize() + 1;
  });

  readonly pageEnd = computed(() => {
    const end = (this.currentPage() + 1) * this.pageSize();
    return Math.min(end, this.totalElements());
  });

  ngOnInit(): void {
    this.loadPostureData(0);
  }

  loadPostureData(page = 0): void {
    this.loading.set(true);
    this.error.set(null);

    this.securityApi.getPosturePage({
      page,
      size: this.pageSize(),
      service: this.selectedService || undefined,
      posture: this.selectedPosture || undefined,
      search: this.searchQuery.trim() || undefined,
      windowHours: this.selectedWindowHours
    }).subscribe({
      next: (resp: PosturePageResponse) => {
        this.items.set(resp.content || []);
        this.currentPage.set(resp.page);
        this.totalElements.set(resp.totalElements);
        this.totalPages.set(resp.totalPages);
        this.hasNext.set(resp.hasNext);
        this.hasPrevious.set(resp.hasPrevious);
        this.summary.set(resp.summary);
        this.loading.set(false);

        // Keep selected endpoint updated if present
        const currentSelected = this.selectedEndpoint();
        if (currentSelected) {
          const fresh = resp.content.find(i => i.endpointId === currentSelected.endpointId);
          if (fresh) {
            this.selectedEndpoint.set(fresh);
          }
        }
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onFilterChange(): void {
    this.currentPage.set(0);
    this.loadPostureData(0);
  }

  onSearchChange(): void {
    this.currentPage.set(0);
    this.loadPostureData(0);
  }

  setPostureFilter(posture: string): void {
    this.selectedPosture = posture;
    this.onFilterChange();
  }

  inspectEndpoint(item: EndpointPostureResponse): void {
    this.selectedEndpoint.set(item);
  }

  closeDrawer(): void {
    this.selectedEndpoint.set(null);
  }

  trackByEndpointId(_index: number, item: EndpointPostureResponse): string {
    return item.endpointId;
  }

  getPostureClass(posture: OverallPosture): string {
    switch (posture) {
      case 'ADEQUATE': return 'adequate';
      case 'ATTENTION_REQUIRED': return 'attention';
      case 'INSUFFICIENT_EVIDENCE': return 'unverified';
      default: return 'unverified';
    }
  }

  formatPosture(posture: OverallPosture): string {
    switch (posture) {
      case 'ADEQUATE': return 'Adequate';
      case 'ATTENTION_REQUIRED': return 'Attention Required';
      case 'INSUFFICIENT_EVIDENCE': return 'Insufficient Evidence';
      default: return posture;
    }
  }

  getDimensionClass(status?: DimensionStatus): string {
    switch (status) {
      case 'VERIFIED': return 'dim-verified';
      case 'FINDING': return 'dim-finding';
      case 'UNKNOWN': return 'dim-unknown';
      default: return 'dim-unknown';
    }
  }

  getDimShortLabel(dimension: AssessmentDimensionType): string {
    switch (dimension) {
      case 'EXPOSURE': return 'EXP';
      case 'AUTHENTICATION': return 'AUTH';
      case 'AUTHORIZATION': return 'AUTHZ';
      case 'DATA_SENSITIVITY': return 'SENS';
      case 'BEHAVIORAL': return 'BEH';
      case 'SPECIFICATION': return 'SPEC';
      default: return '';
    }
  }

  getDimensionTitle(dimension: AssessmentDimensionType): string {
    switch (dimension) {
      case 'EXPOSURE': return 'API Exposure & Inventory';
      case 'AUTHENTICATION': return 'Authentication Posture';
      case 'AUTHORIZATION': return 'Authorization Posture';
      case 'DATA_SENSITIVITY': return 'Resource & Data Sensitivity';
      case 'BEHAVIORAL': return 'Traffic & Behavioral Telemetry';
      case 'SPECIFICATION': return 'API Specification & Drift';
      default: return '';
    }
  }

  getDimensionTooltip(dim: AssessmentDimensionType, assessment?: DimensionAssessment): string {
    if (!assessment) return `${dim}: UNKNOWN`;
    return `${this.getDimensionTitle(dim)}: [${assessment.status}] ${assessment.summary}`;
  }

  getSourceClass(sourceType: string): string {
    switch (sourceType) {
      case 'OPENAPI_SPEC': return 'src-openapi';
      case 'WIRE_TELEMETRY': return 'src-wire';
      case 'SECURITY_INCIDENT': return 'src-incident';
      case 'GATEWAY_CONFIG': return 'src-gateway';
      case 'RECONCILIATION_ENGINE': return 'src-recon';
      default: return 'src-gateway';
    }
  }
}

