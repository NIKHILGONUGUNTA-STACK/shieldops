import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  SensitiveDataInventorySummary,
  EndpointDataClassification,
  FieldClassification,
  DataSensitivityLevel,
  SensitiveDataFilterParams,
  ProblemDetail
} from '../../core/models/security.models';

@Component({
  selector: 'app-sensitive-data',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb-tag">
            <span class="live-dot"></span>
            DATA SENSITIVITY &amp; PRIVACY GOVERNANCE
          </div>
          <h1 class="soc-title">Sensitive Data Inventory</h1>
          <p class="soc-subtitle">
            Deterministic, explainable field-level classification, schema governance, access policy bindings, and data protection taxonomy across all FinTech services.
          </p>
        </div>

        <div class="header-actions">
          <div class="policy-badge mono">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            Policy: v1.0.0-deterministic
          </div>
          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="refresh-icon" [class.spin]="loading()">
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
            </svg>
            {{ loading() ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Privacy & Redaction Standard Banner -->
      <div class="privacy-banner">
        <div class="privacy-header">
          <span class="privacy-shield">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <polyline points="9 12 11 14 15 10"></polyline>
            </svg>
          </span>
          <strong>Deterministic FinTech Telemetry Redaction Standard</strong>
        </div>
        <p class="privacy-desc">
          Telemetry capture strictly prevents exfiltration of customer credentials or confidential financial ledger values.
          <code>RESTRICTED</code> fields (passwords, tokens, refresh secrets) are scrubbed to <code>[REDACTED_RESTRICTED]</code>.
          <code>CONFIDENTIAL</code> values (balances, emails, destination accounts) are structurally masked (e.g. <code>a***&#64;test.local</code>, <code>****0001</code>).
        </p>
      </div>

      <!-- Error State -->
      <div *ngIf="error()" class="error-banner" role="alert">
        <span class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </span>
        <div class="error-content">
          <div class="error-title">{{ error()?.title }}</div>
          <div class="error-detail">{{ error()?.detail }}</div>
        </div>
        <button (click)="refresh()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Top KPI Summary Cards -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Monitored Endpoints</div>
          <div class="kpi-val mono cyan">{{ summary()?.totalMonitoredEndpoints || 0 }}</div>
          <div class="kpi-sub">Gateway, FinTech &amp; SOC routes</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Discovered Fields</div>
          <div class="kpi-val mono">{{ summary()?.totalDiscoveredFields || 0 }}</div>
          <div class="kpi-sub">Request &amp; response payloads</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Classified Fields</div>
          <div class="kpi-val mono green">{{ summary()?.totalClassifiedFields || 0 }}</div>
          <div class="kpi-sub">Authoritative rule-mapped</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Unclassified Fields</div>
          <div class="kpi-val mono" [class.yellow]="(summary()?.totalUnclassifiedFields || 0) > 0">
            {{ summary()?.totalUnclassifiedFields || 0 }}
          </div>
          <div class="kpi-sub">Zero unclassified invariant</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Classification Coverage</div>
          <div class="kpi-val mono purple">{{ summary()?.overallCoveragePercentage || 0 }}%</div>
          <div class="kpi-sub">Deterministic field ratio</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Manual Review</div>
          <div class="kpi-val mono" [class.amber]="(summary()?.totalManualReviewRequired || 0) > 0">
            {{ summary()?.totalManualReviewRequired || 0 }}
          </div>
          <div class="kpi-sub">Flagged for human triage</div>
        </div>
      </div>

      <!-- Sensitivity Taxonomy Distribution Cards -->
      <div class="taxonomy-strip">
        <div class="tax-card restricted" (click)="setSensitivityFilter('RESTRICTED')" [class.active-card]="selectedSensitivity === 'RESTRICTED'">
          <div class="tax-header">
            <span class="tax-dot restricted"></span>
            <span class="tax-name">RESTRICTED</span>
          </div>
          <div class="tax-count mono">{{ summary()?.sensitivityBreakdown?.RESTRICTED || 0 }}</div>
          <div class="tax-desc">Authentication secrets, Bearer tokens, passwords, private keys</div>
        </div>

        <div class="tax-card confidential" (click)="setSensitivityFilter('CONFIDENTIAL')" [class.active-card]="selectedSensitivity === 'CONFIDENTIAL'">
          <div class="tax-header">
            <span class="tax-dot confidential"></span>
            <span class="tax-name">CONFIDENTIAL</span>
          </div>
          <div class="tax-count mono">{{ summary()?.sensitivityBreakdown?.CONFIDENTIAL || 0 }}</div>
          <div class="tax-desc">Customer profiles, emails, ledger balances, transactions, beneficiaries</div>
        </div>

        <div class="tax-card internal" (click)="setSensitivityFilter('INTERNAL')" [class.active-card]="selectedSensitivity === 'INTERNAL'">
          <div class="tax-header">
            <span class="tax-dot internal"></span>
            <span class="tax-name">INTERNAL</span>
          </div>
          <div class="tax-count mono">{{ summary()?.sensitivityBreakdown?.INTERNAL || 0 }}</div>
          <div class="tax-desc">Service health, correlation IDs, timestamps, internal metadata</div>
        </div>

        <div class="tax-card public" (click)="setSensitivityFilter('PUBLIC')" [class.active-card]="selectedSensitivity === 'PUBLIC'">
          <div class="tax-header">
            <span class="tax-dot public"></span>
            <span class="tax-name">PUBLIC</span>
          </div>
          <div class="tax-count mono">{{ summary()?.sensitivityBreakdown?.PUBLIC || 0 }}</div>
          <div class="tax-desc">Public OpenAPI discovery, realm endpoints, unauthenticated metadata</div>
        </div>
      </div>

      <!-- Service Coverage Breakdown Table -->
      <div class="soc-card service-breakdown-card">
        <div class="card-header">
          <h2 class="card-title">Service-Wise Data Classification Coverage</h2>
          <span class="card-sub">{{ summary()?.services?.length || 0 }} Monitored Service Boundaries</span>
        </div>
        <div class="service-table-wrapper">
          <table class="soc-table" aria-label="Service-wise classification coverage">
            <thead>
              <tr>
                <th>Service Boundary</th>
                <th>Endpoints</th>
                <th>Discovered Fields</th>
                <th>Classified</th>
                <th>Unclassified</th>
                <th>Coverage Ratio</th>
                <th>Sensitivity Breakdown</th>
                <th>Manual Review</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let svc of summary()?.services" (click)="setServiceFilter(svc.serviceBoundary)" class="clickable-row" [class.selected-row]="selectedService === svc.serviceBoundary">
                <td>
                  <span class="service-badge" [ngClass]="getServiceBadgeClass(svc.serviceBoundary)">
                    {{ svc.serviceBoundary }}
                  </span>
                </td>
                <td class="mono">{{ svc.totalEndpoints }}</td>
                <td class="mono">{{ svc.totalFields }}</td>
                <td class="mono green">{{ svc.classifiedFields }}</td>
                <td class="mono" [class.yellow]="svc.unclassifiedFields > 0">{{ svc.unclassifiedFields }}</td>
                <td>
                  <div class="coverage-bar-container">
                    <div class="coverage-bar-fill" [style.width.%]="svc.coveragePercentage"></div>
                    <span class="coverage-bar-label mono">{{ svc.coveragePercentage }}%</span>
                  </div>
                </td>
                <td>
                  <div class="mini-tax-chips">
                    <span class="chip chip-restricted" *ngIf="svc.sensitivityBreakdown.RESTRICTED > 0" title="Restricted fields">
                      R: {{ svc.sensitivityBreakdown.RESTRICTED }}
                    </span>
                    <span class="chip chip-confidential" *ngIf="svc.sensitivityBreakdown.CONFIDENTIAL > 0" title="Confidential fields">
                      C: {{ svc.sensitivityBreakdown.CONFIDENTIAL }}
                    </span>
                    <span class="chip chip-internal" *ngIf="svc.sensitivityBreakdown.INTERNAL > 0" title="Internal fields">
                      I: {{ svc.sensitivityBreakdown.INTERNAL }}
                    </span>
                    <span class="chip chip-public" *ngIf="svc.sensitivityBreakdown.PUBLIC > 0" title="Public fields">
                      P: {{ svc.sensitivityBreakdown.PUBLIC }}
                    </span>
                  </div>
                </td>
                <td>
                  <span class="review-tag" [class.has-review]="svc.manualReviewRequiredCount > 0">
                    {{ svc.manualReviewRequiredCount }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Controls & Filter Toolbar -->
      <div class="soc-card filter-card">
        <div class="filter-row">
          <!-- Search -->
          <div class="filter-group flex-2">
            <label class="filter-label">Search Endpoints &amp; Fields</label>
            <div class="search-input-wrap">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="search-icon">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
              <input
                type="text"
                [(ngModel)]="searchQuery"
                (ngModelChange)="onSearchChange()"
                placeholder="Search route template or field path (e.g. /customers, balance)..."
                class="soc-input search-input"
              />
              <button *ngIf="searchQuery" (click)="searchQuery = ''; onSearchChange()" class="clear-btn">✕</button>
            </div>
          </div>

          <!-- Service Filter -->
          <div class="filter-group">
            <label class="filter-label">Service Boundary</label>
            <select [(ngModel)]="selectedService" (ngModelChange)="loadInventory(0)" class="soc-select">
              <option value="">All Services</option>
              <option *ngFor="let svc of summary()?.services" [value]="svc.serviceBoundary">
                {{ svc.serviceBoundary }}
              </option>
            </select>
          </div>

          <!-- Sensitivity Filter -->
          <div class="filter-group">
            <label class="filter-label">Highest Sensitivity</label>
            <select [(ngModel)]="selectedSensitivity" (ngModelChange)="loadInventory(0)" class="soc-select">
              <option value="">All Levels</option>
              <option value="RESTRICTED">RESTRICTED</option>
              <option value="CONFIDENTIAL">CONFIDENTIAL</option>
              <option value="INTERNAL">INTERNAL</option>
              <option value="PUBLIC">PUBLIC</option>
            </select>
          </div>

          <!-- Manual Review Filter -->
          <div class="filter-group checkbox-group">
            <label class="checkbox-label">
              <input
                type="checkbox"
                [(ngModel)]="manualReviewOnly"
                (ngModelChange)="loadInventory(0)"
              />
              <span>Manual Review Only</span>
            </label>
          </div>

          <!-- Clear Filters Button -->
          <div class="filter-group reset-group" *ngIf="hasActiveFilters">
            <button (click)="resetFilters()" class="btn btn-secondary btn-xs reset-btn">Reset Filters</button>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading()" class="loading-state">
        <div class="spinner"></div>
        <span>Evaluating deterministic data classification policies...</span>
      </div>

      <!-- Endpoints Inventory Table -->
      <div *ngIf="!loading()" class="soc-card table-card">
        <div class="table-header-info">
          <div class="results-count">
            Showing <strong class="mono">{{ endpoints().length }}</strong> of <strong class="mono">{{ totalElements() }}</strong> endpoints
          </div>
          <div class="pagination-info" *ngIf="totalPages() > 1">
            Page {{ currentPage() + 1 }} of {{ totalPages() }}
          </div>
        </div>

        <div class="table-responsive">
          <table class="soc-table" aria-label="Sensitive Data Endpoints Inventory">
            <thead>
              <tr>
                <th>Method</th>
                <th>Route Template</th>
                <th>Service</th>
                <th>Highest Sensitivity</th>
                <th>Fields Count</th>
                <th>Classified</th>
                <th>Unclassified</th>
                <th>Manual Review</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <ng-container *ngFor="let ep of endpoints()">
                <tr class="endpoint-row" [class.expanded-row]="selectedEndpoint()?.endpointId === ep.endpointId" (click)="toggleEndpoint(ep)">
                  <td>
                    <span class="method-pill" [ngClass]="ep.httpMethod.toLowerCase()">
                      {{ ep.httpMethod }}
                    </span>
                  </td>
                  <td class="route-cell mono">
                    <span class="route-template">{{ ep.routeTemplate }}</span>
                  </td>
                  <td>
                    <span class="service-badge" [ngClass]="getServiceBadgeClass(ep.serviceBoundary)">
                      {{ ep.serviceBoundary }}
                    </span>
                  </td>
                  <td>
                    <span class="tax-badge" [ngClass]="ep.highestSensitivity.toLowerCase()">
                      {{ ep.highestSensitivity }}
                    </span>
                  </td>
                  <td class="mono">{{ ep.totalFields }}</td>
                  <td class="mono green">{{ ep.classifiedFieldsCount }}</td>
                  <td class="mono" [class.yellow]="ep.unclassifiedFieldsCount > 0">{{ ep.unclassifiedFieldsCount }}</td>
                  <td>
                    <span class="review-pill" *ngIf="ep.manualReviewRequiredCount > 0">
                      {{ ep.manualReviewRequiredCount }} review
                    </span>
                    <span class="ok-pill" *ngIf="ep.manualReviewRequiredCount === 0">
                      ✓ verified
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-secondary btn-xs inspect-btn" (click)="$event.stopPropagation(); toggleEndpoint(ep)">
                      {{ selectedEndpoint()?.endpointId === ep.endpointId ? 'Hide Dossier' : 'Inspect Dossier' }}
                    </button>
                  </td>
                </tr>

                <!-- Expanded Dossier Row -->
                <tr *ngIf="selectedEndpoint()?.endpointId === ep.endpointId" class="dossier-row">
                  <td colspan="9" class="dossier-cell">
                    <div class="dossier-container">
                      <div class="dossier-header">
                        <div class="dossier-title-group">
                          <span class="dossier-title">Field Classification Dossier</span>
                          <span class="mono dossier-sub">{{ ep.httpMethod }} {{ ep.routeTemplate }} ({{ ep.fields.length }} fields mapped)</span>
                        </div>
                        <div class="dossier-actions">
                          <span class="eval-time mono">Last Evaluated: {{ ep.lastEvaluatedAt }}</span>
                        </div>
                      </div>

                      <!-- Field Items Table -->
                      <div class="field-table-wrapper">
                        <table class="soc-subtable">
                          <thead>
                            <tr>
                              <th>Field Path</th>
                              <th>Sensitivity</th>
                              <th>Rationale</th>
                              <th>Approved Access Roles</th>
                              <th>Ownership Requirement</th>
                              <th>Schema Source</th>
                              <th>Confidence</th>
                              <th>Triage Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr *ngFor="let f of ep.fields" [class.restricted-row]="f.dataClassification === 'RESTRICTED'">
                              <td class="mono field-path-cell">
                                <code>{{ f.fieldPath }}</code>
                              </td>
                              <td>
                                <span class="tax-badge small" [ngClass]="f.dataClassification.toLowerCase()">
                                  {{ f.dataClassification }}
                                </span>
                              </td>
                              <td class="rationale-cell">{{ f.classificationRationale }}</td>
                              <td>
                                <div class="role-tags">
                                  <span class="role-tag" *ngFor="let r of f.approvedAccessRoles">{{ r }}</span>
                                </div>
                              </td>
                              <td class="mono ownership-cell">{{ f.resourceOwnershipRequirements }}</td>
                              <td class="mono source-cell">{{ f.schemaSource }}</td>
                              <td>
                                <span class="conf-badge" [ngClass]="f.confidence.toLowerCase()">
                                  {{ f.confidence }}
                                </span>
                              </td>
                              <td>
                                <span class="review-flag" *ngIf="f.manualReviewRequired">
                                  ⚠ Review Req
                                </span>
                                <span class="clean-flag" *ngIf="!f.manualReviewRequired">
                                  ✓ Clear
                                </span>
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </td>
                </tr>
              </ng-container>

              <!-- Empty Results -->
              <tr *ngIf="endpoints().length === 0">
                <td colspan="9" class="empty-state-cell">
                  <div class="empty-state">
                    <div class="empty-icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                        <circle cx="11" cy="11" r="8"></circle>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                      </svg>
                    </div>
                    <h3>No Endpoints Match Filter Criteria</h3>
                    <p>Adjust your search query or filter options above to inspect other API endpoints.</p>
                    <button (click)="resetFilters()" class="btn btn-secondary btn-sm">Reset All Filters</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Controls -->
        <div class="pagination-footer" *ngIf="totalPages() > 1">
          <button (click)="changePage(currentPage() - 1)" [disabled]="currentPage() === 0" class="btn btn-secondary btn-xs">
            Previous
          </button>
          <div class="page-numbers">
            <span class="page-num mono active">{{ currentPage() + 1 }}</span>
            <span class="mono">/ {{ totalPages() }}</span>
          </div>
          <button (click)="changePage(currentPage() + 1)" [disabled]="currentPage() >= totalPages() - 1" class="btn btn-secondary btn-xs">
            Next
          </button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      padding: 24px;
      max-width: 1440px;
      margin: 0 auto;
      color: #c9d1d9;
    }

    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 20px;
    }

    .breadcrumb-tag {
      font-size: 11px;
      font-family: ui-monospace, monospace;
      letter-spacing: 0.08em;
      color: #58a6ff;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .live-dot {
      width: 7px;
      height: 7px;
      background: #3fb950;
      border-radius: 50%;
      box-shadow: 0 0 8px rgba(63, 185, 80, 0.6);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.85); }
    }

    .soc-title {
      font-size: 24px;
      font-weight: 600;
      color: #f0f6fc;
      margin: 0 0 6px 0;
    }

    .soc-subtitle {
      font-size: 13px;
      color: #8b949e;
      margin: 0;
      max-width: 840px;
      line-height: 1.45;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .policy-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      background: #161b22;
      border: 1px solid #30363d;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 11px;
      color: #58a6ff;
    }

    .spin {
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      100% { transform: rotate(360deg); }
    }

    /* Privacy Banner */
    .privacy-banner {
      background: rgba(22, 27, 34, 0.85);
      border: 1px solid #30363d;
      border-left: 4px solid #58a6ff;
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 20px;
    }

    .privacy-header {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: #f0f6fc;
      margin-bottom: 4px;
    }

    .privacy-shield {
      color: #58a6ff;
      display: flex;
    }

    .privacy-desc {
      font-size: 12px;
      color: #8b949e;
      margin: 0;
      line-height: 1.5;
    }

    .privacy-desc code {
      background: #0d1117;
      padding: 2px 5px;
      border-radius: 4px;
      border: 1px solid #30363d;
      color: #f0883e;
      font-size: 11px;
    }

    /* Error Banner */
    .error-banner {
      display: flex;
      align-items: center;
      gap: 12px;
      background: rgba(248, 81, 73, 0.1);
      border: 1px solid #f85149;
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 20px;
      color: #f85149;
    }

    .error-content {
      flex: 1;
    }

    .error-title {
      font-weight: 600;
      font-size: 13px;
    }

    .error-detail {
      font-size: 12px;
      color: #c9d1d9;
    }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }

    .kpi-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px 14px;
    }

    .kpi-label {
      font-size: 11px;
      color: #8b949e;
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .kpi-val {
      font-size: 22px;
      font-weight: 600;
      color: #f0f6fc;
      margin-bottom: 2px;
    }

    .kpi-val.cyan { color: #58a6ff; }
    .kpi-val.green { color: #3fb950; }
    .kpi-val.purple { color: #bc8cff; }
    .kpi-val.yellow { color: #d29922; }
    .kpi-val.amber { color: #f0883e; }

    .kpi-sub {
      font-size: 11px;
      color: #8b949e;
    }

    /* Taxonomy Strip */
    .taxonomy-strip {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }

    .tax-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 14px;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .tax-card:hover {
      border-color: #58a6ff;
      background: #1c2128;
    }

    .tax-card.active-card {
      outline: 2px solid #58a6ff;
      background: #1c2128;
    }

    .tax-card.restricted { border-top: 3px solid #f85149; }
    .tax-card.confidential { border-top: 3px solid #d29922; }
    .tax-card.internal { border-top: 3px solid #58a6ff; }
    .tax-card.public { border-top: 3px solid #3fb950; }

    .tax-header {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 6px;
    }

    .tax-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .tax-dot.restricted { background: #f85149; }
    .tax-dot.confidential { background: #d29922; }
    .tax-dot.internal { background: #58a6ff; }
    .tax-dot.public { background: #3fb950; }

    .tax-name {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.05em;
      color: #f0f6fc;
    }

    .tax-count {
      font-size: 20px;
      font-weight: 600;
      color: #f0f6fc;
      margin-bottom: 4px;
    }

    .tax-desc {
      font-size: 11px;
      color: #8b949e;
      line-height: 1.4;
    }

    /* Cards */
    .soc-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      margin-bottom: 20px;
    }

    .card-header {
      padding: 14px 18px;
      border-bottom: 1px solid #30363d;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .card-title {
      font-size: 14px;
      font-weight: 600;
      color: #f0f6fc;
      margin: 0;
    }

    .card-sub {
      font-size: 11px;
      color: #8b949e;
    }

    /* Service Table */
    .service-breakdown-card {
      overflow: hidden;
    }

    .service-table-wrapper {
      overflow-x: auto;
    }

    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }

    .soc-table th {
      background: #0d1117;
      color: #8b949e;
      font-weight: 500;
      padding: 10px 14px;
      border-bottom: 1px solid #30363d;
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.05em;
    }

    .soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid #21262d;
      vertical-align: middle;
    }

    .clickable-row {
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .clickable-row:hover {
      background: #1f242c;
    }

    .selected-row {
      background: rgba(88, 166, 255, 0.1);
    }

    .service-badge {
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 4px;
      font-weight: 600;
      letter-spacing: 0.04em;
    }

    .service-badge.gateway { background: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.3); }
    .service-badge.customer { background: rgba(63, 185, 80, 0.15); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.3); }
    .service-badge.account { background: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3); }
    .service-badge.transaction { background: rgba(188, 140, 255, 0.15); color: #bc8cff; border: 1px solid rgba(188, 140, 255, 0.3); }
    .service-badge.security { background: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.3); }
    .service-badge.external { background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.3); }

    .coverage-bar-container {
      width: 140px;
      height: 18px;
      background: #0d1117;
      border-radius: 4px;
      border: 1px solid #30363d;
      position: relative;
      overflow: hidden;
      display: flex;
      align-items: center;
    }

    .coverage-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #1f6feb, #388bfd);
      border-radius: 3px 0 0 3px;
    }

    .coverage-bar-label {
      position: absolute;
      width: 100%;
      text-align: center;
      font-size: 10px;
      font-weight: 600;
      color: #f0f6fc;
      text-shadow: 0 0 3px rgba(0, 0, 0, 0.8);
    }

    .mini-tax-chips {
      display: flex;
      gap: 4px;
    }

    .chip {
      font-size: 10px;
      padding: 1px 5px;
      border-radius: 3px;
      font-family: ui-monospace, monospace;
    }

    .chip-restricted { background: rgba(248, 81, 73, 0.2); color: #f85149; }
    .chip-confidential { background: rgba(210, 153, 34, 0.2); color: #d29922; }
    .chip-internal { background: rgba(88, 166, 255, 0.2); color: #58a6ff; }
    .chip-public { background: rgba(63, 185, 80, 0.2); color: #3fb950; }

    .review-tag {
      font-size: 11px;
      color: #8b949e;
      font-family: ui-monospace, monospace;
    }

    .review-tag.has-review {
      color: #f0883e;
      font-weight: 600;
    }

    /* Filters */
    .filter-card {
      padding: 14px 18px;
    }

    .filter-row {
      display: flex;
      gap: 16px;
      align-items: flex-end;
      flex-wrap: wrap;
    }

    .filter-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .flex-2 { flex: 2; min-width: 260px; }

    .filter-label {
      font-size: 11px;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .search-input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }

    .search-icon {
      position: absolute;
      left: 10px;
      color: #8b949e;
    }

    .soc-input {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 6px 12px 6px 32px;
      color: #f0f6fc;
      font-size: 12px;
      width: 100%;
    }

    .soc-input:focus {
      outline: none;
      border-color: #58a6ff;
    }

    .clear-btn {
      position: absolute;
      right: 8px;
      background: none;
      border: none;
      color: #8b949e;
      cursor: pointer;
      font-size: 12px;
    }

    .soc-select {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 6px 10px;
      color: #f0f6fc;
      font-size: 12px;
      min-width: 140px;
    }

    .soc-select:focus {
      outline: none;
      border-color: #58a6ff;
    }

    .checkbox-group {
      justify-content: center;
      padding-bottom: 6px;
    }

    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: #c9d1d9;
      cursor: pointer;
    }

    .reset-group {
      justify-content: center;
      padding-bottom: 4px;
    }

    .reset-btn {
      color: #f85149;
    }

    /* Table Card */
    .table-header-info {
      padding: 12px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #30363d;
      font-size: 12px;
      color: #8b949e;
    }

    .results-count strong {
      color: #f0f6fc;
    }

    .endpoint-row {
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .endpoint-row:hover {
      background: #1c2128;
    }

    .expanded-row {
      background: rgba(88, 166, 255, 0.08);
      border-bottom-color: transparent;
    }

    .method-pill {
      font-size: 10px;
      font-family: ui-monospace, monospace;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
    }

    .method-pill.get { background: rgba(88, 166, 255, 0.2); color: #58a6ff; }
    .method-pill.post { background: rgba(63, 185, 80, 0.2); color: #3fb950; }
    .method-pill.put { background: rgba(210, 153, 34, 0.2); color: #d29922; }
    .method-pill.delete { background: rgba(248, 81, 73, 0.2); color: #f85149; }

    .route-cell {
      max-width: 380px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .route-template {
      color: #f0f6fc;
      font-size: 12px;
    }

    .tax-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      letter-spacing: 0.04em;
    }

    .tax-badge.small {
      font-size: 9px;
      padding: 2px 6px;
    }

    .tax-badge.restricted { background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.4); }
    .tax-badge.confidential { background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.4); }
    .tax-badge.internal { background: rgba(88, 166, 255, 0.2); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.4); }
    .tax-badge.public { background: rgba(63, 185, 80, 0.2); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); }

    .review-pill {
      background: rgba(240, 136, 62, 0.2);
      color: #f0883e;
      border: 1px solid rgba(240, 136, 62, 0.4);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 10px;
    }

    .ok-pill {
      color: #3fb950;
      font-size: 11px;
    }

    /* Dossier Expanded View */
    .dossier-row {
      background: #0d1117;
    }

    .dossier-cell {
      padding: 0 !important;
    }

    .dossier-container {
      padding: 16px 20px;
      border-top: 1px solid #30363d;
      border-bottom: 2px solid #58a6ff;
    }

    .dossier-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .dossier-title {
      font-size: 13px;
      font-weight: 600;
      color: #58a6ff;
      margin-right: 12px;
    }

    .dossier-sub {
      font-size: 11px;
      color: #8b949e;
    }

    .eval-time {
      font-size: 10px;
      color: #8b949e;
    }

    .field-table-wrapper {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      overflow-x: auto;
    }

    .soc-subtable {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
    }

    .soc-subtable th {
      background: #0d1117;
      color: #8b949e;
      padding: 8px 12px;
      font-weight: 500;
      border-bottom: 1px solid #30363d;
      text-transform: uppercase;
      font-size: 9px;
      letter-spacing: 0.05em;
    }

    .soc-subtable td {
      padding: 8px 12px;
      border-bottom: 1px solid #21262d;
      vertical-align: middle;
    }

    .field-path-cell code {
      color: #79c0ff;
      background: #0d1117;
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 11px;
    }

    .restricted-row {
      background: rgba(248, 81, 73, 0.04);
    }

    .rationale-cell {
      color: #c9d1d9;
      max-width: 280px;
      line-height: 1.4;
    }

    .role-tags {
      display: flex;
      gap: 4px;
      flex-wrap: wrap;
    }

    .role-tag {
      background: #21262d;
      border: 1px solid #30363d;
      color: #c9d1d9;
      font-size: 9px;
      padding: 1px 5px;
      border-radius: 3px;
      font-family: ui-monospace, monospace;
    }

    .ownership-cell {
      color: #d2a8ff;
      font-size: 10px;
    }

    .source-cell {
      color: #8b949e;
      font-size: 10px;
    }

    .conf-badge {
      font-size: 9px;
      font-weight: 600;
      padding: 2px 5px;
      border-radius: 3px;
    }

    .conf-badge.confirmed { background: rgba(63, 185, 80, 0.2); color: #3fb950; }
    .conf-badge.provisional { background: rgba(210, 153, 34, 0.2); color: #d29922; }
    .conf-badge.unknown { background: rgba(248, 81, 73, 0.2); color: #f85149; }

    .review-flag {
      color: #f0883e;
      font-size: 10px;
      font-weight: 600;
    }

    .clean-flag {
      color: #3fb950;
      font-size: 10px;
    }

    /* Pagination */
    .pagination-footer {
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: 12px;
      padding: 12px 18px;
      border-top: 1px solid #30363d;
    }

    .page-numbers {
      font-size: 11px;
      color: #8b949e;
    }

    .page-num.active {
      color: #58a6ff;
      font-weight: 600;
    }

    /* Common Buttons & Utilities */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid transparent;
    }

    .btn-secondary {
      background: #21262d;
      border-color: #30363d;
      color: #c9d1d9;
    }

    .btn-secondary:hover:not(:disabled) {
      background: #30363d;
      color: #f0f6fc;
      border-color: #8b949e;
    }

    .btn-secondary:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-sm { padding: 6px 12px; }
    .btn-xs { padding: 3px 8px; font-size: 11px; }

    .mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
    .green { color: #3fb950; }
    .yellow { color: #d29922; }

    .loading-state, .empty-state {
      padding: 48px 24px;
      text-align: center;
      color: #8b949e;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
    }

    .spinner {
      width: 28px;
      height: 28px;
      border: 3px solid #30363d;
      border-top-color: #58a6ff;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    .empty-icon {
      color: #8b949e;
      margin-bottom: 4px;
    }

    .empty-state h3 {
      font-size: 16px;
      color: #f0f6fc;
      margin: 0;
    }

    .empty-state p {
      font-size: 12px;
      max-width: 420px;
      margin: 0;
    }
  `]
})
export class SensitiveDataComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  readonly summary = signal<SensitiveDataInventorySummary | null>(null);
  readonly endpoints = signal<EndpointDataClassification[]>([]);
  readonly selectedEndpoint = signal<EndpointDataClassification | null>(null);
  readonly loading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  // Pagination & Filtering
  currentPage = signal<number>(0);
  pageSize = signal<number>(20);
  totalPages = signal<number>(0);
  totalElements = signal<number>(0);

  searchQuery = '';
  selectedService = '';
  selectedSensitivity = '';
  manualReviewOnly = false;

  get hasActiveFilters(): boolean {
    return !!(this.searchQuery || this.selectedService || this.selectedSensitivity || this.manualReviewOnly);
  }

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.loadSummary();
    this.loadInventory(0);
  }

  loadSummary(): void {
    this.securityApi.getSensitiveDataSummary(this.selectedService || undefined).subscribe({
      next: (sum) => this.summary.set(sum),
      error: (err) => {
        // Non-blocking for summary
        console.warn('Failed to load sensitive data summary', err);
      }
    });
  }

  loadInventory(page: number): void {
    this.loading.set(true);
    this.error.set(null);

    const filter: SensitiveDataFilterParams = {
      page,
      size: this.pageSize(),
      service: this.selectedService || undefined,
      sensitivity: this.selectedSensitivity || undefined,
      manualReviewRequired: this.manualReviewOnly ? true : undefined,
      search: this.searchQuery.trim() || undefined,
      sortBy: 'routeTemplate',
      sortDirection: 'ASC'
    };

    this.securityApi.getSensitiveDataInventory(filter).subscribe({
      next: (resp) => {
        this.endpoints.set(resp.endpoints);
        this.currentPage.set(resp.page);
        this.totalPages.set(resp.totalPages);
        this.totalElements.set(resp.totalElements);
        if (resp.summary) {
          this.summary.set(resp.summary);
        }
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onSearchChange(): void {
    this.loadInventory(0);
  }

  setSensitivityFilter(level: string): void {
    if (this.selectedSensitivity === level) {
      this.selectedSensitivity = '';
    } else {
      this.selectedSensitivity = level;
    }
    this.loadInventory(0);
  }

  setServiceFilter(service: string): void {
    if (this.selectedService === service) {
      this.selectedService = '';
    } else {
      this.selectedService = service;
    }
    this.loadInventory(0);
    this.loadSummary();
  }

  resetFilters(): void {
    this.searchQuery = '';
    this.selectedService = '';
    this.selectedSensitivity = '';
    this.manualReviewOnly = false;
    this.refresh();
  }

  toggleEndpoint(ep: EndpointDataClassification): void {
    if (this.selectedEndpoint()?.endpointId === ep.endpointId) {
      this.selectedEndpoint.set(null);
    } else {
      this.selectedEndpoint.set(ep);
    }
  }

  changePage(newPage: number): void {
    if (newPage >= 0 && newPage < this.totalPages()) {
      this.loadInventory(newPage);
    }
  }

  getServiceBadgeClass(service: string): string {
    const s = service.toLowerCase();
    if (s.includes('gateway')) return 'gateway';
    if (s.includes('customer')) return 'customer';
    if (s.includes('account')) return 'account';
    if (s.includes('transaction')) return 'transaction';
    if (s.includes('security') || s.includes('soc')) return 'security';
    return 'external';
  }
}

