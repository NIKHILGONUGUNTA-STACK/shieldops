import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  DataLeakageSummaryResponse,
  DataLeakageRuleInfoResponse,
  DataLeakageFilterParams,
  IncidentResponse,
  EvidenceResponse,
  ProblemDetail
} from '../../core/models/security.models';

@Component({
  selector: 'app-data-leakage',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb-tag">
            <span class="live-dot"></span>
            TELEMETRY-DRIVEN DATA LEAKAGE &amp; BOLA CORRELATION
          </div>
          <h1 class="soc-title">Data Leakage Detection &amp; BOLA Correlation</h1>
          <p class="soc-subtitle">
            Contextual, explainable correlation of caller identity, resource ownership, authorization decisions, sensitive field classifications, and multi-stage exfiltration sequences.
          </p>
        </div>

        <div class="header-actions">
          <div class="policy-badge mono">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Engine: Contextual-Correlation v2.0
          </div>
          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="refresh-icon" [class.spin]="loading()">
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
            </svg>
            {{ loading() ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Leakage Detection & Safety Architecture Banner -->
      <div class="privacy-banner">
        <div class="privacy-header">
          <span class="privacy-shield">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </span>
          <strong>Explainable Data Leakage &amp; BOLA Correlation Invariants</strong>
        </div>
        <p class="privacy-desc">
          A denied cross-owner attempt (HTTP 403) is recorded as security attempt evidence, but does not indicate successful exfiltration.
          Confirmed BOLA is established only when an unprivileged caller obtains successful access (HTTP 200) to another customer's confidential resource.
          Multi-stage exfiltration correlates sequential reconnaissance, authorization probing, and bulk data extraction across sliding windows without merging unrelated users sharing IP addresses.
        </p>
      </div>

      <!-- Error State -->
      <div *ngIf="error()" class="error-banner" role="alert">
        <span class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
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
          <div class="kpi-label">Total Leakage Incidents</div>
          <div class="kpi-val mono red">{{ summary()?.totalLeakageIncidents || 0 }}</div>
          <div class="kpi-sub">Correlated security incidents</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Confirmed BOLA Leaks</div>
          <div class="kpi-val mono" [class.red]="(summary()?.confirmedBolaLeaks || 0) > 0">
            {{ summary()?.confirmedBolaLeaks || 0 }}
          </div>
          <div class="kpi-sub">HTTP 200 on cross-owner data</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Denied BOLA Attempts</div>
          <div class="kpi-val mono orange">{{ summary()?.deniedBolaAttempts || 0 }}</div>
          <div class="kpi-sub">Blocked cross-customer probes</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Sensitive Data Exposures</div>
          <div class="kpi-val mono purple">{{ summary()?.sensitiveDataExposures || 0 }}</div>
          <div class="kpi-sub">Unapproved role or leak access</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Bulk Extractions</div>
          <div class="kpi-val mono cyan">{{ summary()?.bulkExtractionEvents || 0 }}</div>
          <div class="kpi-sub">&gt;= 3 resources or bulk volume</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label">Multi-Stage Campaigns</div>
          <div class="kpi-val mono" [class.red]="(summary()?.multiStageCampaigns || 0) > 0">
            {{ summary()?.multiStageCampaigns || 0 }}
          </div>
          <div class="kpi-sub">Recon &rarr; BOLA &rarr; Exfiltration</div>
        </div>
      </div>

      <!-- Category Distribution Strip (Clickable Filters) -->
      <div class="taxonomy-strip">
        <div class="tax-card bola-leak" (click)="setCategoryFilter('BOLA_CONFIRMED_LEAK')" [class.active-card]="selectedCategory === 'BOLA_CONFIRMED_LEAK'">
          <div class="tax-header">
            <span class="tax-dot bola-leak"></span>
            <span class="tax-name">CONFIRMED BOLA LEAK</span>
          </div>
          <div class="tax-count mono red">{{ summary()?.confirmedBolaLeaks || 0 }}</div>
          <div class="tax-desc">Active Broken Object Level Authorization: caller retrieved other customer records</div>
        </div>

        <div class="tax-card sensitive-exp" (click)="setCategoryFilter('SENSITIVE_DATA_EXPOSURE')" [class.active-card]="selectedCategory === 'SENSITIVE_DATA_EXPOSURE'">
          <div class="tax-header">
            <span class="tax-dot sensitive-exp"></span>
            <span class="tax-name">SENSITIVE EXPOSURE</span>
          </div>
          <div class="tax-count mono purple">{{ summary()?.sensitiveDataExposures || 0 }}</div>
          <div class="tax-desc">Unexpected confidential or restricted field exposure to unapproved roles</div>
        </div>

        <div class="tax-card bulk-extract" (click)="setCategoryFilter('EXCESSIVE_DATA_EXTRACTION')" [class.active-card]="selectedCategory === 'EXCESSIVE_DATA_EXTRACTION'">
          <div class="tax-header">
            <span class="tax-dot bulk-extract"></span>
            <span class="tax-name">BULK EXTRACTION</span>
          </div>
          <div class="tax-count mono cyan">{{ summary()?.bulkExtractionEvents || 0 }}</div>
          <div class="tax-desc">Iterative scraping across multiple customer/account records in sliding window</div>
        </div>

        <div class="tax-card exfil-camp" (click)="setCategoryFilter('DATA_EXFILTRATION_CAMPAIGN')" [class.active-card]="selectedCategory === 'DATA_EXFILTRATION_CAMPAIGN'">
          <div class="tax-header">
            <span class="tax-dot exfil-camp"></span>
            <span class="tax-name">MULTI-STAGE EXFILTRATION</span>
          </div>
          <div class="tax-count mono red">{{ summary()?.multiStageCampaigns || 0 }}</div>
          <div class="tax-desc">Correlated sequential attack: probing &rarr; BOLA attempts &rarr; data harvesting</div>
        </div>
      </div>

      <!-- Controls & Filter Toolbar -->
      <div class="soc-card filter-card">
        <div class="filter-row">
          <!-- Search -->
          <div class="filter-group flex-2">
            <label class="filter-label">Search Incidents</label>
            <div class="search-input-wrap">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="search-icon">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
              <input
                type="text"
                [(ngModel)]="searchQuery"
                (ngModelChange)="onSearchChange()"
                placeholder="Search entity value, rule ID, or findings..."
                class="soc-input search-input"
              />
              <button *ngIf="searchQuery" (click)="searchQuery = ''; onSearchChange()" class="clear-btn">✕</button>
            </div>
          </div>

          <!-- Category Filter -->
          <div class="filter-group">
            <label class="filter-label">Threat Category</label>
            <select [(ngModel)]="selectedCategory" (ngModelChange)="loadIncidents(0)" class="soc-select">
              <option value="">All Categories</option>
              <option value="BOLA_CONFIRMED_LEAK">Confirmed BOLA Leak</option>
              <option value="BOLA_ATTEMPT">Denied BOLA Attempt</option>
              <option value="BOLA_PROBE_CAMPAIGN">BOLA Probing Campaign</option>
              <option value="SENSITIVE_DATA_EXPOSURE">Sensitive Data Exposure</option>
              <option value="EXCESSIVE_DATA_EXTRACTION">Excessive Data Extraction</option>
              <option value="DATA_EXFILTRATION_CAMPAIGN">Data Exfiltration Campaign</option>
            </select>
          </div>

          <!-- Severity Filter -->
          <div class="filter-group">
            <label class="filter-label">Severity</label>
            <select [(ngModel)]="selectedSeverity" (ngModelChange)="loadIncidents(0)" class="soc-select">
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <!-- Status Filter -->
          <div class="filter-group">
            <label class="filter-label">Incident Status</label>
            <select [(ngModel)]="selectedStatus" (ngModelChange)="loadIncidents(0)" class="soc-select">
              <option value="">All Statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
            </select>
          </div>

          <!-- Reset Filter Button -->
          <div class="filter-group reset-group" *ngIf="hasActiveFilters">
            <button (click)="resetFilters()" class="btn btn-secondary btn-xs reset-btn">Reset Filters</button>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading()" class="loading-state">
        <div class="spinner"></div>
        <span>Correlating data leakage and BOLA telemetry...</span>
      </div>

      <!-- Incidents Table Card -->
      <div *ngIf="!loading()" class="soc-card table-card">
        <div class="table-header-info">
          <div class="results-count">
            Showing <strong class="mono">{{ incidents().length }}</strong> of <strong class="mono">{{ totalElements() }}</strong> data leakage incidents
          </div>
          <div class="pagination-info" *ngIf="totalPages() > 1">
            Page {{ currentPage() + 1 }} of {{ totalPages() }}
          </div>
        </div>

        <div class="table-responsive">
          <table class="soc-table" aria-label="Data Leakage Incidents Table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Threat Category</th>
                <th>Target Entity</th>
                <th>Rule ID</th>
                <th>Events</th>
                <th>Summary Findings</th>
                <th>Status</th>
                <th>Last Detected</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <ng-container *ngFor="let inc of incidents()">
                <tr class="incident-row" [class.expanded-row]="selectedIncident()?.id === inc.id" (click)="toggleIncident(inc)">
                  <td>
                    <span class="severity-pill" [ngClass]="inc.severity.toLowerCase()">
                      {{ inc.severity }}
                    </span>
                  </td>
                  <td>
                    <span class="category-badge" [ngClass]="getCategoryBadgeClass(inc.threatCategory)">
                      {{ inc.threatCategory }}
                    </span>
                  </td>
                  <td class="entity-cell mono">
                    <span class="entity-type">{{ inc.targetEntityType }}:</span>
                    <span class="entity-val">{{ inc.targetEntityValue }}</span>
                  </td>
                  <td class="mono rule-id-cell">{{ inc.ruleId }}</td>
                  <td class="mono events-count">{{ inc.eventCount }}</td>
                  <td class="summary-cell">{{ inc.summary }}</td>
                  <td>
                    <span class="status-pill" [ngClass]="inc.status.toLowerCase()">
                      {{ inc.status }}
                    </span>
                  </td>
                  <td class="mono time-cell">{{ inc.lastEventAt }}</td>
                  <td>
                    <button class="btn btn-secondary btn-xs inspect-btn" (click)="$event.stopPropagation(); toggleIncident(inc)">
                      {{ selectedIncident()?.id === inc.id ? 'Close Evidence' : 'Inspect Evidence' }}
                    </button>
                  </td>
                </tr>

                <!-- Expanded Forensic Evidence Drawer -->
                <tr *ngIf="selectedIncident()?.id === inc.id" class="evidence-row">
                  <td colspan="9" class="evidence-cell">
                    <div class="evidence-container">
                      <div class="evidence-header">
                        <div class="evidence-title-group">
                          <span class="evidence-title">Forensic Evidence Chain &amp; Correlation Timeline</span>
                          <span class="mono evidence-sub">Fingerprint: {{ inc.incidentFingerprint }}</span>
                        </div>
                        <div class="evidence-meta mono">
                          Confidence: High | Rule Version: {{ inc.ruleVersion }}
                        </div>
                      </div>

                      <!-- Evidence Items List -->
                      <div class="evidence-items-list" *ngIf="evidenceLoading()">
                        <div class="mini-spinner"></div>
                        <span>Retrieving telemetry evidence records...</span>
                      </div>

                      <div class="evidence-items-list" *ngIf="!evidenceLoading() && currentEvidence().length > 0">
                        <div class="evidence-card" *ngFor="let ev of currentEvidence()">
                          <div class="ev-card-header">
                            <span class="ev-rule mono">{{ ev.ruleId }} (v{{ ev.ruleVersion }})</span>
                            <span class="ev-severity" [ngClass]="ev.severity.toLowerCase()">{{ ev.severity }}</span>
                            <span class="ev-conf mono">Confidence: {{ (ev.confidenceScore * 100).toFixed(0) }}%</span>
                            <span class="ev-resources mono">Distinct Resources: {{ ev.distinctResourcesCount }}</span>
                            <span class="ev-time mono">{{ ev.evaluatedAt }}</span>
                          </div>
                          <div class="ev-condition">
                            <strong>Trigger Condition:</strong> {{ ev.triggerCondition }}
                          </div>
                          <div class="ev-details mono">
                            {{ ev.mitreTechnique ? 'MITRE: ' + ev.mitreTechnique + ' | ' : '' }}Contributing Events: {{ (ev.contributingEventIds && ev.contributingEventIds.length) || 0 }} event(s)
                          </div>
                        </div>
                      </div>

                      <div *ngIf="!evidenceLoading() && currentEvidence().length === 0" class="no-evidence">
                        No distinct evidence records found for this incident.
                      </div>
                    </div>
                  </td>
                </tr>
              </ng-container>

              <!-- Empty State -->
              <tr *ngIf="incidents().length === 0">
                <td colspan="9" class="empty-state-cell">
                  <div class="empty-state">
                    <div class="empty-icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                      </svg>
                    </div>
                    <h3>No Data Leakage Incidents Detected</h3>
                    <p>Zero unauthorized access or data exfiltration events match your filter criteria.</p>
                    <button (click)="resetFilters()" class="btn btn-secondary btn-sm">Reset All Filters</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Footer -->
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

      <!-- Detection Rules Reference Strip -->
      <div class="soc-card rules-card">
        <div class="card-header">
          <h2 class="card-title">Active Data Leakage Detection Models</h2>
          <span class="card-sub">{{ rules().length }} Deterministic Rules Registered</span>
        </div>
        <div class="rules-grid">
          <div class="rule-box" *ngFor="let r of rules()">
            <div class="rule-header">
              <span class="rule-id mono">{{ r.ruleId }}</span>
              <span class="rule-sev" [ngClass]="r.defaultSeverity.toLowerCase()">{{ r.defaultSeverity }}</span>
            </div>
            <div class="rule-name">{{ r.name }}</div>
            <div class="rule-desc">{{ r.description }}</div>
            <div class="rule-expl mono"><strong>Trigger:</strong> {{ r.triggerConditionExplanation }}</div>
          </div>
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
      background: #f85149;
      border-radius: 50%;
      box-shadow: 0 0 8px rgba(248, 81, 73, 0.6);
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
      max-width: 860px;
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
      color: #f85149;
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
      border-left: 4px solid #f85149;
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
      color: #f85149;
      display: flex;
    }

    .privacy-desc {
      font-size: 12px;
      color: #8b949e;
      margin: 0;
      line-height: 1.5;
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

    .kpi-val.red { color: #f85149; }
    .kpi-val.orange { color: #d29922; }
    .kpi-val.purple { color: #bc8cff; }
    .kpi-val.cyan { color: #58a6ff; }

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

    .tax-card.bola-leak { border-top: 3px solid #f85149; }
    .tax-card.sensitive-exp { border-top: 3px solid #bc8cff; }
    .tax-card.bulk-extract { border-top: 3px solid #58a6ff; }
    .tax-card.exfil-camp { border-top: 3px solid #f85149; }

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

    .tax-dot.bola-leak { background: #f85149; }
    .tax-dot.sensitive-exp { background: #bc8cff; }
    .tax-dot.bulk-extract { background: #58a6ff; }
    .tax-dot.exfil-camp { background: #f85149; }

    .tax-name {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.05em;
      color: #f0f6fc;
    }

    .tax-count {
      font-size: 20px;
      font-weight: 600;
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
      min-width: 150px;
    }

    .soc-select:focus {
      outline: none;
      border-color: #58a6ff;
    }

    .reset-group {
      justify-content: center;
      padding-bottom: 4px;
    }

    .reset-btn {
      color: #f85149;
    }

    /* Table */
    .table-header-info {
      padding: 12px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #30363d;
      font-size: 12px;
      color: #8b949e;
    }

    .table-responsive {
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

    .incident-row {
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .incident-row:hover {
      background: #1c2128;
    }

    .expanded-row {
      background: rgba(248, 81, 73, 0.06);
      border-bottom-color: transparent;
    }

    .severity-pill {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
    }

    .severity-pill.critical { background: rgba(248, 81, 73, 0.25); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.5); }
    .severity-pill.high { background: rgba(210, 153, 34, 0.25); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.5); }
    .severity-pill.medium { background: rgba(88, 166, 255, 0.25); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.5); }
    .severity-pill.low { background: rgba(139, 148, 158, 0.25); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.5); }

    .category-badge {
      font-size: 10px;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: 4px;
    }

    .category-badge.bola-leak { background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.4); }
    .category-badge.sensitive-exp { background: rgba(188, 140, 255, 0.2); color: #bc8cff; border: 1px solid rgba(188, 140, 255, 0.4); }
    .category-badge.bulk-extract { background: rgba(88, 166, 255, 0.2); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.4); }
    .category-badge.exfil-camp { background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.4); }
    .category-badge.default-cat { background: rgba(139, 148, 158, 0.2); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.4); }

    .entity-cell {
      max-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .entity-type { color: #8b949e; margin-right: 4px; font-size: 11px; }
    .entity-val { color: #f0f6fc; font-weight: 600; }

    .summary-cell {
      max-width: 320px;
      line-height: 1.4;
      color: #c9d1d9;
    }

    .status-pill {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, monospace;
    }

    .status-pill.open { background: rgba(248, 81, 73, 0.15); color: #f85149; }
    .status-pill.investigating { background: rgba(210, 153, 34, 0.15); color: #d29922; }
    .status-pill.contained { background: rgba(88, 166, 255, 0.15); color: #58a6ff; }
    .status-pill.resolved { background: rgba(63, 185, 80, 0.15); color: #3fb950; }

    .time-cell {
      font-size: 11px;
      color: #8b949e;
      white-space: nowrap;
    }

    /* Evidence Drawer */
    .evidence-row {
      background: #0d1117;
    }

    .evidence-cell {
      padding: 0 !important;
    }

    .evidence-container {
      padding: 16px 20px;
      border-top: 1px solid #30363d;
      border-bottom: 2px solid #f85149;
    }

    .evidence-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .evidence-title {
      font-size: 13px;
      font-weight: 600;
      color: #f85149;
      margin-right: 12px;
    }

    .evidence-sub {
      font-size: 11px;
      color: #8b949e;
    }

    .evidence-meta {
      font-size: 11px;
      color: #8b949e;
    }

    .evidence-items-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .evidence-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px 14px;
    }

    .ev-card-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 6px;
      font-size: 11px;
    }

    .ev-rule { color: #58a6ff; font-weight: 600; }
    .ev-severity { font-weight: 700; font-size: 10px; padding: 1px 5px; border-radius: 3px; }
    .ev-severity.critical { background: rgba(248, 81, 73, 0.2); color: #f85149; }
    .ev-severity.high { background: rgba(210, 153, 34, 0.2); color: #d29922; }
    .ev-conf { color: #3fb950; }
    .ev-resources { color: #bc8cff; }
    .ev-time { margin-left: auto; color: #8b949e; }

    .ev-condition {
      font-size: 12px;
      color: #f0f6fc;
      margin-bottom: 4px;
    }

    .ev-details {
      font-size: 11px;
      color: #8b949e;
    }

    .no-evidence {
      padding: 16px;
      text-align: center;
      color: #8b949e;
      font-size: 12px;
    }

    /* Rules Grid */
    .rules-card {
      padding-bottom: 8px;
    }

    .rules-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      padding: 16px;
    }

    .rule-box {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px;
    }

    .rule-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .rule-id {
      font-size: 11px;
      color: #58a6ff;
      font-weight: 600;
    }

    .rule-sev {
      font-size: 9px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 3px;
    }

    .rule-sev.critical { background: rgba(248, 81, 73, 0.2); color: #f85149; }
    .rule-sev.high { background: rgba(210, 153, 34, 0.2); color: #d29922; }

    .rule-name {
      font-size: 12px;
      font-weight: 600;
      color: #f0f6fc;
      margin-bottom: 4px;
    }

    .rule-desc {
      font-size: 11px;
      color: #8b949e;
      margin-bottom: 6px;
      line-height: 1.4;
    }

    .rule-expl {
      font-size: 10px;
      color: #d29922;
      background: rgba(210, 153, 34, 0.08);
      padding: 4px 6px;
      border-radius: 4px;
      border: 1px solid rgba(210, 153, 34, 0.2);
    }

    /* Common */
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
      border-top-color: #f85149;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    .mini-spinner {
      width: 16px;
      height: 16px;
      border: 2px solid #30363d;
      border-top-color: #f85149;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: inline-block;
      margin-right: 6px;
    }
  `]
})
export class DataLeakageComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  readonly summary = signal<DataLeakageSummaryResponse | null>(null);
  readonly incidents = signal<IncidentResponse[]>([]);
  readonly rules = signal<DataLeakageRuleInfoResponse[]>([]);
  readonly selectedIncident = signal<IncidentResponse | null>(null);
  readonly currentEvidence = signal<EvidenceResponse[]>([]);
  readonly loading = signal<boolean>(false);
  readonly evidenceLoading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  currentPage = signal<number>(0);
  pageSize = signal<number>(20);
  totalPages = signal<number>(0);
  totalElements = signal<number>(0);

  searchQuery = '';
  selectedCategory = '';
  selectedSeverity = '';
  selectedStatus = '';

  get hasActiveFilters(): boolean {
    return !!(this.searchQuery || this.selectedCategory || this.selectedSeverity || this.selectedStatus);
  }

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.loadSummary();
    this.loadIncidents(0);
    this.loadRules();
  }

  loadSummary(): void {
    this.securityApi.getDataLeakageSummary().subscribe({
      next: (sum) => this.summary.set(sum),
      error: (err) => console.warn('Failed to load leakage summary', err)
    });
  }

  loadIncidents(page: number): void {
    this.loading.set(true);
    this.error.set(null);

    const filter: DataLeakageFilterParams = {
      page,
      size: this.pageSize(),
      category: this.selectedCategory || undefined,
      severity: this.selectedSeverity || undefined,
      status: this.selectedStatus || undefined,
      search: this.searchQuery.trim() || undefined
    };

    this.securityApi.getDataLeakageIncidents(filter).subscribe({
      next: (resp) => {
        this.incidents.set(resp.content || resp.incidents || []);
        this.currentPage.set(resp.page);
        this.totalPages.set(resp.totalPages);
        this.totalElements.set(resp.totalElements);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  loadRules(): void {
    this.securityApi.getDataLeakageRules().subscribe({
      next: (rls) => this.rules.set(rls),
      error: (err) => console.warn('Failed to load leakage rules', err)
    });
  }

  onSearchChange(): void {
    this.loadIncidents(0);
  }

  setCategoryFilter(category: string): void {
    if (this.selectedCategory === category) {
      this.selectedCategory = '';
    } else {
      this.selectedCategory = category;
    }
    this.loadIncidents(0);
  }

  resetFilters(): void {
    this.searchQuery = '';
    this.selectedCategory = '';
    this.selectedSeverity = '';
    this.selectedStatus = '';
    this.refresh();
  }

  toggleIncident(inc: IncidentResponse): void {
    if (this.selectedIncident()?.id === inc.id) {
      this.selectedIncident.set(null);
      this.currentEvidence.set([]);
    } else {
      this.selectedIncident.set(inc);
      this.loadEvidence(inc.id);
    }
  }

  loadEvidence(incidentId: string): void {
    this.evidenceLoading.set(true);
    this.securityApi.getDataLeakageEvidence(incidentId).subscribe({
      next: (ev) => {
        this.currentEvidence.set(ev);
        this.evidenceLoading.set(false);
      },
      error: (err) => {
        console.warn('Failed to load evidence for incident ' + incidentId, err);
        this.evidenceLoading.set(false);
      }
    });
  }

  changePage(newPage: number): void {
    if (newPage >= 0 && newPage < this.totalPages()) {
      this.loadIncidents(newPage);
    }
  }

  getCategoryBadgeClass(category: string): string {
    const c = category.toUpperCase();
    if (c.includes('BOLA_CONFIRMED') || c.includes('CONFIRMED')) return 'bola-leak';
    if (c.includes('EXPOSURE') || c.includes('LEAK')) return 'sensitive-exp';
    if (c.includes('EXTRACTION') || c.includes('BULK')) return 'bulk-extract';
    if (c.includes('CAMPAIGN') || c.includes('EXFIL')) return 'exfil-camp';
    return 'default-cat';
  }
}
