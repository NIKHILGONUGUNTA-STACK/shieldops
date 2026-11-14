import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  CampaignResponse,
  CampaignTimelineEvent,
  CampaignRiskAssessment,
  CampaignEvidenceDetailsResponse,
  CampaignStatusHistory,
  CampaignStatus,
  ProblemDetail
} from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';

@Component({
  selector: 'app-campaigns',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, SeverityBadgeComponent, StatusBadgeComponent],
  template: `
    <div class="soc-page-container">
      <!-- Header -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Multi-Stage Exfiltration Campaigns</h1>
          <p class="soc-subtitle">
            Temporal kill-chain correlation detecting multi-stage reconnaissance, authorization probing, sensitive exposure, and cross-domain bulk extraction.
          </p>
        </div>

        <div class="header-stat-pills">
          <button (click)="loadCampaigns()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;">
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
            </svg>
            {{ loading ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-icon red">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <div class="kpi-content">
            <div class="kpi-val">{{ activeCampaignsCount }}</div>
            <div class="kpi-label">Active Campaigns</div>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-icon orange">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
          </div>
          <div class="kpi-content">
            <div class="kpi-val">{{ criticalRiskCount }}</div>
            <div class="kpi-label">Critical Risk (&ge;85.0)</div>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-icon blue">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          </div>
          <div class="kpi-content">
            <div class="kpi-val">{{ investigatingCount }}</div>
            <div class="kpi-label">Under Investigation</div>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-icon green">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          </div>
          <div class="kpi-content">
            <div class="kpi-val">{{ resolvedCount }}</div>
            <div class="kpi-label">Resolved / False Positives</div>
          </div>
        </div>
      </div>

      <!-- Engine Notice -->
      <div class="correlation-notice">
        <span class="notice-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </span>
        <div>
          <strong>Multi-Stage Exfiltration Engine:</strong> Continuously correlates independent API telemetry across a 900s sliding window. Requires &ge;2 distinct kill-chain stages to confirm attack progression; isolated anomalies are prevented from escalating into false attack campaigns.
        </div>
      </div>

      <!-- Filters & Toolbar -->
      <div class="filter-toolbar">
        <div class="filter-group">
          <label>Status:</label>
          <select [(ngModel)]="statusFilter" (change)="applyFilters()" class="filter-select">
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="ESCALATED">Escalated</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>

        <div class="filter-group">
          <label>Min Risk:</label>
          <select [(ngModel)]="minRiskFilter" (change)="applyFilters()" class="filter-select">
            <option [ngValue]="0">All Risks</option>
            <option [ngValue]="40">Medium (&ge; 40)</option>
            <option [ngValue]="65">High (&ge; 65)</option>
            <option [ngValue]="85">Critical (&ge; 85)</option>
          </select>
        </div>

        <div class="filter-group search-group">
          <input
            type="text"
            [(ngModel)]="searchQuery"
            (input)="applyFilters()"
            placeholder="Search by identity or tenant..."
            class="filter-input"
          />
        </div>
      </div>

      <!-- Error State -->
      <div *ngIf="error" class="error-banner" role="alert">
        <div>
          <div class="error-title">{{ error.title }}</div>
          <div class="error-detail">{{ error.detail }}</div>
        </div>
        <button (click)="loadCampaigns()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Evaluating correlated kill-chain campaigns...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && filteredCampaigns.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
        </div>
        <h3>No Attack Campaigns Match Filter</h3>
        <p>No active or historical multi-stage exfiltration campaigns match the selected criteria.</p>
      </div>

      <!-- Campaigns Table -->
      <div *ngIf="!loading && !error && filteredCampaigns.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Correlated Attack Campaigns">
          <thead>
            <tr>
              <th>Risk & Severity</th>
              <th>Campaign Name</th>
              <th>Kill-Chain Stages</th>
              <th>Correlation Identity</th>
              <th>Status</th>
              <th>Evidence</th>
              <th>Breadth</th>
              <th>Last Active</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let camp of filteredCampaigns" [class.selected-row]="selectedCampaign?.id === camp.id">
              <td>
                <div class="risk-badge-col">
                  <app-severity-badge [severity]="camp.severity"></app-severity-badge>
                  <div class="risk-score-pill" [ngClass]="getRiskScoreClass(camp.riskScore)">
                    {{ camp.riskScore.toFixed(1) }}
                  </div>
                </div>
              </td>
              <td class="campaign-title-cell">
                <div class="campaign-title" (click)="selectCampaign(camp)">
                  {{ camp.name }}
                </div>
                <div class="campaign-desc text-muted">{{ camp.description }}</div>
              </td>
              <td>
                <div class="stages-pills-row">
                  <span
                    *ngFor="let stage of camp.stagesObserved"
                    class="stage-chip"
                    [ngClass]="getStageChipClass(stage)"
                  >
                    {{ formatStage(stage) }}
                  </span>
                </div>
              </td>
              <td>
                <div class="mono text-teal">{{ camp.correlationIdentity }}</div>
                <div class="mono text-muted text-xs">Tenant: {{ camp.tenantId }}</div>
              </td>
              <td>
                <app-status-badge [status]="camp.status"></app-status-badge>
              </td>
              <td>
                <span class="completeness-badge" [ngClass]="camp.evidenceCompleteness.toLowerCase()">
                  {{ camp.evidenceCompleteness }}
                </span>
              </td>
              <td class="mono text-xs">
                <div>{{ camp.eventCount }} events</div>
                <div class="text-muted">{{ camp.distinctServices }} svcs / {{ camp.distinctResources }} res</div>
              </td>
              <td class="mono text-xs text-muted">
                {{ camp.lastObservedAt | date:'yyyy-MM-dd HH:mm:ss' }}
              </td>
              <td>
                <button (click)="selectCampaign(camp)" class="btn btn-secondary btn-sm investigate-btn">
                  Inspect &rarr;
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Campaign Detail Drawer / Modal -->
      <div *ngIf="selectedCampaign" class="detail-drawer-overlay" (click)="closeDetail()">
        <div class="detail-drawer" (click)="$event.stopPropagation()">
          <div class="drawer-header">
            <div>
              <div class="drawer-pretitle">CAMPAIGN DRILL-DOWN</div>
              <h2 class="drawer-title">{{ selectedCampaign.name }}</h2>
              <div class="drawer-subtitle mono text-muted">ID: {{ selectedCampaign.id }}</div>
            </div>
            <button class="btn btn-secondary btn-sm close-btn" (click)="closeDetail()">&times;</button>
          </div>

          <!-- Drawer Navigation Tabs -->
          <div class="drawer-tabs">
            <button class="drawer-tab" [class.active]="activeTab === 'TIMELINE'" (click)="activeTab = 'TIMELINE'">
              Attack Timeline ({{ timeline.length }})
            </button>
            <button class="drawer-tab" [class.active]="activeTab === 'RISK'" (click)="activeTab = 'RISK'">
              Risk Assessment
            </button>
            <button class="drawer-tab" [class.active]="activeTab === 'EVIDENCE'" (click)="activeTab = 'EVIDENCE'">
              Evidence Completeness
            </button>
            <button class="drawer-tab" [class.active]="activeTab === 'LIFECYCLE'" (click)="activeTab = 'LIFECYCLE'">
              Lifecycle & Transition
            </button>
          </div>

          <div class="drawer-body">
            <!-- TAB 1: Kill-Chain Timeline -->
            <div *ngIf="activeTab === 'TIMELINE'" class="tab-pane">
              <div *ngIf="timelineLoading" class="tab-loading">
                <div class="spinner"></div>
                <span>Loading attack timeline events...</span>
              </div>
              <div *ngIf="!timelineLoading && timeline.length === 0" class="tab-empty">
                No timeline events recorded for this campaign.
              </div>
              <div *ngIf="!timelineLoading && timeline.length > 0" class="timeline-container">
                <div *ngFor="let ev of timeline; let i = index" class="timeline-step">
                  <div class="step-marker" [ngClass]="getStageChipClass(ev.stage)">
                    {{ i + 1 }}
                  </div>
                  <div class="step-card">
                    <div class="step-header">
                      <span class="stage-chip" [ngClass]="getStageChipClass(ev.stage)">
                        {{ formatStage(ev.stage) }}
                      </span>
                      <span class="mono text-xs text-muted">{{ ev.eventTimestamp | date:'HH:mm:ss.SSS' }}</span>
                      <span class="risk-contrib">+{{ ev.riskContribution.toFixed(1) }} risk</span>
                    </div>
                    <div class="step-route mono">
                      <span class="method-tag">{{ ev.httpMethod }}</span>
                      <span class="route-text">{{ ev.route }}</span>
                      <span class="status-code" [class.status-err]="ev.statusCode >= 400" [class.status-ok]="ev.statusCode === 200">
                        {{ ev.statusCode }}
                      </span>
                    </div>
                    <div class="step-details text-secondary">{{ ev.details }}</div>
                  </div>
                </div>
              </div>
            </div>

            <!-- TAB 2: Risk Assessment -->
            <div *ngIf="activeTab === 'RISK'" class="tab-pane">
              <div *ngIf="riskLoading" class="tab-loading">
                <div class="spinner"></div>
                <span>Evaluating risk assessment...</span>
              </div>
              <div *ngIf="!riskLoading && riskAssessment" class="risk-pane">
                <div class="risk-overview-box">
                  <div class="risk-gauge-val" [ngClass]="getRiskScoreClass(riskAssessment.riskScore)">
                    {{ riskAssessment.riskScore.toFixed(1) }}
                  </div>
                  <div class="risk-gauge-meta">
                    <div class="risk-cat-label">{{ riskAssessment.riskCategory }} RISK</div>
                    <div class="text-secondary text-sm">Deterministic Bayesian kill-chain score</div>
                  </div>
                </div>

                <div class="section-title">Score Breakdown by Vector</div>
                <div class="breakdown-grid">
                  <div *ngFor="let item of getBreakdownEntries(riskAssessment.scoreBreakdown)" class="breakdown-card">
                    <span class="breakdown-key">{{ item.key }}</span>
                    <span class="breakdown-val mono font-semibold">+{{ item.value.toFixed(1) }}</span>
                  </div>
                </div>

                <div class="section-title" style="margin-top: 20px;">Key Risk Indicators</div>
                <ul class="kri-list">
                  <li *ngFor="let kri of riskAssessment.keyRiskIndicators" class="kri-item">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <span>{{ kri }}</span>
                  </li>
                </ul>
              </div>
            </div>

            <!-- TAB 3: Evidence Completeness -->
            <div *ngIf="activeTab === 'EVIDENCE'" class="tab-pane">
              <div *ngIf="evidenceLoading" class="tab-loading">
                <div class="spinner"></div>
                <span>Retrieving evidence details...</span>
              </div>
              <div *ngIf="!evidenceLoading && evidenceDetails" class="evidence-pane">
                <div class="evidence-status-box" [ngClass]="evidenceDetails.completeness.toLowerCase()">
                  <div>
                    <div class="evidence-status-title">Evidence Completeness: {{ evidenceDetails.completeness }}</div>
                    <div class="text-sm">
                      {{ evidenceDetails.incidentIds.length }} Correlated Incidents &bull; {{ evidenceDetails.evidenceUris.length }} Evidence Telemetry URIs
                    </div>
                  </div>
                </div>

                <div *ngIf="evidenceDetails.missingEvidenceReasons.length > 0" class="missing-reasons-box">
                  <div class="warning-title">Missing Evidence Warning</div>
                  <ul>
                    <li *ngFor="let reason of evidenceDetails.missingEvidenceReasons">{{ reason }}</li>
                  </ul>
                </div>

                <div class="section-title">Correlated Incident References</div>
                <div class="incident-pills-list">
                  <div *ngFor="let incId of evidenceDetails.incidentIds" class="incident-pill">
                    <a [routerLink]="['/incidents', incId]" class="mono text-teal">{{ incId }}</a>
                  </div>
                </div>

                <div class="section-title" style="margin-top: 20px;">Telemetry Evidence URIs</div>
                <div class="evidence-uris-list">
                  <div *ngFor="let uri of evidenceDetails.evidenceUris" class="mono text-xs uri-item">
                    {{ uri }}
                  </div>
                </div>
              </div>
            </div>

            <!-- TAB 4: Lifecycle & Transition -->
            <div *ngIf="activeTab === 'LIFECYCLE'" class="tab-pane">
              <div class="transition-form-box">
                <div class="section-title">Analyst Lifecycle Transition</div>
                <div class="transition-inputs">
                  <div class="input-col">
                    <label>Target Status:</label>
                    <select [(ngModel)]="newStatus" class="filter-select">
                      <option value="OPEN">OPEN</option>
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="ESCALATED">ESCALATED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                    </select>
                  </div>
                  <div class="input-col flex-1">
                    <label>Mandatory Audit Reason:</label>
                    <input
                      type="text"
                      [(ngModel)]="transitionReason"
                      placeholder="Specify rationale for state transition..."
                      class="filter-input"
                    />
                  </div>
                  <button
                    class="btn btn-primary btn-sm submit-trans-btn"
                    [disabled]="!transitionReason.trim() || transitionLoading"
                    (click)="submitTransition()"
                  >
                    {{ transitionLoading ? 'Applying...' : 'Apply Transition' }}
                  </button>
                </div>
                <div *ngIf="transitionError" class="text-xs text-red mt-2">{{ transitionError }}</div>
              </div>

              <div class="section-title" style="margin-top: 24px;">Status Transition Audit History</div>
              <div *ngIf="historyLoading" class="tab-loading">
                <div class="spinner"></div>
                <span>Loading lifecycle audit trail...</span>
              </div>
              <div *ngIf="!historyLoading && history.length === 0" class="tab-empty">
                No status transitions recorded yet.
              </div>
              <table *ngIf="!historyLoading && history.length > 0" class="soc-table history-table">
                <thead>
                  <tr>
                    <th>Transition</th>
                    <th>Changed By</th>
                    <th>Reason</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let h of history">
                    <td>
                      <span class="mono font-semibold">{{ h.fromStatus }} &rarr; {{ h.toStatus }}</span>
                    </td>
                    <td class="mono text-teal">{{ h.changedBy }}</td>
                    <td class="text-secondary">{{ h.transitionReason }}</td>
                    <td class="mono text-xs text-muted">{{ h.changedAt | date:'yyyy-MM-dd HH:mm:ss' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      padding: var(--space-6);
      max-width: 1400px;
      margin: 0 auto;
    }
    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: var(--space-4);
      flex-wrap: wrap;
      gap: var(--space-4);
    }
    .soc-title {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .soc-subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 3px;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: var(--space-4);
      margin-bottom: var(--space-4);
    }
    .kpi-card {
      background: var(--surface-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .kpi-icon {
      width: 40px;
      height: 40px;
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .kpi-icon.red { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .kpi-icon.orange { background: rgba(249, 115, 22, 0.15); color: #f97316; }
    .kpi-icon.blue { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
    .kpi-icon.green { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
    .kpi-val { font-size: 22px; font-weight: 700; color: var(--text-primary); font-family: var(--font-mono); }
    .kpi-label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }

    .correlation-notice {
      background: rgba(20, 184, 166, 0.08);
      border: 1px solid var(--accent-teal-border);
      color: var(--text-secondary);
      padding: var(--space-3) var(--space-4);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      gap: var(--space-3);
      font-size: 12px;
      line-height: 1.5;
      margin-bottom: var(--space-4);
    }
    .notice-icon { color: var(--accent-teal); flex-shrink: 0; }

    .filter-toolbar {
      background: var(--surface-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-3) var(--space-4);
      display: flex;
      align-items: center;
      gap: var(--space-4);
      margin-bottom: var(--space-4);
      flex-wrap: wrap;
    }
    .filter-group {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: 12px;
      color: var(--text-secondary);
    }
    .filter-select, .filter-input {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      color: var(--text-primary);
      border-radius: var(--radius-sm);
      padding: 4px 10px;
      font-size: 12px;
    }
    .search-group { flex: 1; min-width: 200px; }
    .search-group input { width: 100%; }

    .risk-badge-col {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .risk-score-pill {
      font-size: 11px;
      font-weight: 700;
      font-family: var(--font-mono);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .risk-score-pill.critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }
    .risk-score-pill.high { background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.4); }
    .risk-score-pill.medium { background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.4); }
    .risk-score-pill.low { background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.4); }

    .campaign-title-cell { max-width: 320px; }
    .campaign-title {
      font-weight: 600;
      color: var(--text-primary);
      cursor: pointer;
      font-size: 13px;
    }
    .campaign-title:hover { color: var(--accent-teal); }
    .campaign-desc { font-size: 11px; margin-top: 2px; }

    .stages-pills-row { display: flex; flex-wrap: wrap; gap: 4px; }
    .stage-chip {
      font-size: 9px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-family: var(--font-mono);
      text-transform: uppercase;
    }
    .stage-recon { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
    .stage-probe { background: rgba(234, 179, 8, 0.15); color: #eab308; }
    .stage-disco { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
    .stage-access { background: rgba(249, 115, 22, 0.15); color: #f97316; }
    .stage-bulk { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .stage-multi { background: rgba(168, 85, 247, 0.15); color: #a855f7; }

    .completeness-badge {
      font-size: 10px;
      font-weight: 700;
      font-family: var(--font-mono);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .completeness-badge.complete { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
    .completeness-badge.incomplete { background: rgba(234, 179, 8, 0.15); color: #eab308; }
    .completeness-badge.degraded { background: rgba(239, 68, 68, 0.15); color: #ef4444; }

    .selected-row { background: rgba(20, 184, 166, 0.05); }

    /* Drawer / Modal */
    .detail-drawer-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      z-index: 1000;
      display: flex;
      justify-content: flex-end;
    }
    .detail-drawer {
      width: 720px;
      max-width: 90vw;
      background: var(--surface-card);
      border-left: 1px solid var(--border-default);
      display: flex;
      flex-direction: column;
      height: 100%;
      box-shadow: -4px 0 20px rgba(0, 0, 0, 0.5);
    }
    .drawer-header {
      padding: var(--space-4) var(--space-6);
      border-bottom: 1px solid var(--border-default);
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    .drawer-pretitle { font-size: 10px; font-weight: 700; color: var(--accent-teal); letter-spacing: 0.5px; }
    .drawer-title { font-size: 18px; font-weight: 700; color: var(--text-primary); margin: 2px 0; }
    .close-btn { font-size: 20px; line-height: 1; padding: 2px 8px; }

    .drawer-tabs {
      display: flex;
      border-bottom: 1px solid var(--border-default);
      background: var(--surface-raised);
    }
    .drawer-tab {
      padding: 10px 18px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      cursor: pointer;
    }
    .drawer-tab:hover { color: var(--text-primary); }
    .drawer-tab.active {
      color: var(--accent-teal);
      border-bottom-color: var(--accent-teal);
      background: var(--surface-card);
    }
    .drawer-body {
      flex: 1;
      overflow-y: auto;
      padding: var(--space-6);
    }
    .section-title {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-secondary);
      margin-bottom: var(--space-3);
    }

    /* Timeline Tab */
    .timeline-container { position: relative; padding-left: 20px; }
    .timeline-container::before {
      content: '';
      position: absolute;
      left: 11px;
      top: 10px;
      bottom: 10px;
      width: 2px;
      background: var(--border-default);
    }
    .timeline-step { position: relative; margin-bottom: 16px; padding-left: 16px; }
    .step-marker {
      position: absolute;
      left: -19px;
      top: 6px;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 10px;
      font-weight: 700;
      font-family: var(--font-mono);
      border: 2px solid var(--surface-card);
    }
    .step-card {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: 10px 14px;
    }
    .step-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
    .risk-contrib { font-size: 11px; font-weight: 700; color: #ef4444; font-family: var(--font-mono); }
    .step-route { font-size: 12px; display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .method-tag { font-weight: 700; color: var(--accent-teal); }
    .status-code { font-weight: 700; padding: 1px 4px; border-radius: 2px; }
    .status-ok { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
    .status-err { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .step-details { font-size: 11px; }

    /* Risk Tab */
    .risk-overview-box {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      display: flex;
      align-items: center;
      gap: var(--space-4);
      margin-bottom: var(--space-4);
    }
    .risk-gauge-val {
      font-size: 36px;
      font-weight: 800;
      font-family: var(--font-mono);
      padding: 4px 14px;
      border-radius: var(--radius-md);
    }
    .risk-cat-label { font-size: 14px; font-weight: 700; color: var(--text-primary); }
    .breakdown-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 8px;
    }
    .breakdown-card {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-sm);
      padding: 8px 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
    }
    .breakdown-val { color: #f97316; }
    .kri-list { list-style: none; padding: 0; margin: 0; }
    .kri-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 0;
      font-size: 12px;
      color: var(--text-secondary);
      border-bottom: 1px solid var(--border-subtle);
    }
    .kri-item svg { color: #ef4444; flex-shrink: 0; }

    /* Evidence Tab */
    .evidence-status-box {
      border: 1px solid;
      border-radius: var(--radius-md);
      padding: var(--space-4);
      margin-bottom: var(--space-4);
    }
    .evidence-status-box.complete { background: rgba(34, 197, 94, 0.08); border-color: rgba(34, 197, 94, 0.3); color: #22c55e; }
    .evidence-status-box.incomplete { background: rgba(234, 179, 8, 0.08); border-color: rgba(234, 179, 8, 0.3); color: #eab308; }
    .evidence-status-box.degraded { background: rgba(239, 68, 68, 0.08); border-color: rgba(239, 68, 68, 0.3); color: #ef4444; }
    .evidence-status-title { font-weight: 700; font-size: 14px; margin-bottom: 4px; }
    .missing-reasons-box {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 10px 14px;
      border-radius: var(--radius-md);
      margin-bottom: var(--space-4);
      font-size: 12px;
      color: #ef4444;
    }
    .incident-pills-list { display: flex; flex-wrap: wrap; gap: 8px; }
    .incident-pill {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      font-size: 12px;
    }
    .evidence-uris-list { display: flex; flex-direction: column; gap: 4px; }
    .uri-item {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      padding: 6px 10px;
      border-radius: var(--radius-sm);
      word-break: break-all;
    }

    /* Lifecycle Tab */
    .transition-form-box {
      background: var(--surface-raised);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-4);
    }
    .transition-inputs { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; }
    .input-col { display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--text-secondary); }
    .input-col.flex-1 { flex: 1; min-width: 200px; }
    .submit-trans-btn { height: 28px; white-space: nowrap; }
    .history-table { margin-top: 10px; }

    .tab-loading, .tab-empty { text-align: center; padding: var(--space-8); color: var(--text-secondary); }
    .spinner {
      width: 24px;
      height: 24px;
      border: 2px solid rgba(255, 255, 255, 0.1);
      border-top-color: var(--accent-teal);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 8px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  `]
})
export class CampaignsComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  campaigns: CampaignResponse[] = [];
  filteredCampaigns: CampaignResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  // Filters
  statusFilter = 'ALL';
  minRiskFilter = 0;
  searchQuery = '';

  // Selection & Drill-Down
  selectedCampaign: CampaignResponse | null = null;
  activeTab: 'TIMELINE' | 'RISK' | 'EVIDENCE' | 'LIFECYCLE' = 'TIMELINE';

  // Detail Data
  timeline: CampaignTimelineEvent[] = [];
  timelineLoading = false;

  riskAssessment: CampaignRiskAssessment | null = null;
  riskLoading = false;

  evidenceDetails: CampaignEvidenceDetailsResponse | null = null;
  evidenceLoading = false;

  history: CampaignStatusHistory[] = [];
  historyLoading = false;

  // Transition form
  newStatus: CampaignStatus = 'INVESTIGATING';
  transitionReason = '';
  transitionLoading = false;
  transitionError: string | null = null;

  ngOnInit(): void {
    this.loadCampaigns();
  }

  get activeCampaignsCount(): number {
    return this.campaigns.filter(c => c.status === 'OPEN' || c.status === 'INVESTIGATING' || c.status === 'ESCALATED').length;
  }

  get criticalRiskCount(): number {
    return this.campaigns.filter(c => c.riskScore >= 85.0).length;
  }

  get investigatingCount(): number {
    return this.campaigns.filter(c => c.status === 'INVESTIGATING').length;
  }

  get resolvedCount(): number {
    return this.campaigns.filter(c => c.status === 'RESOLVED' || c.status === 'FALSE_POSITIVE').length;
  }

  loadCampaigns(): void {
    this.loading = true;
    this.error = null;

    this.api.getCampaigns({ page: 0, size: 50 }).subscribe({
      next: (page) => {
        this.campaigns = page.content || [];
        this.applyFilters();
        this.loading = false;
      },
      error: (err) => {
        this.error = err;
        this.campaigns = [];
        this.filteredCampaigns = [];
        this.loading = false;
      }
    });
  }

  applyFilters(): void {
    this.filteredCampaigns = this.campaigns.filter(c => {
      if (this.statusFilter !== 'ALL' && c.status !== this.statusFilter) return false;
      if (c.riskScore < this.minRiskFilter) return false;
      if (this.searchQuery.trim()) {
        const q = this.searchQuery.toLowerCase();
        const matchesIdent = c.correlationIdentity?.toLowerCase().includes(q);
        const matchesTenant = c.tenantId?.toLowerCase().includes(q);
        const matchesName = c.name?.toLowerCase().includes(q);
        if (!matchesIdent && !matchesTenant && !matchesName) return false;
      }
      return true;
    });
  }

  selectCampaign(camp: CampaignResponse): void {
    this.selectedCampaign = camp;
    this.newStatus = camp.status === 'OPEN' ? 'INVESTIGATING' : camp.status;
    this.transitionReason = '';
    this.transitionError = null;
    this.activeTab = 'TIMELINE';

    this.loadTimeline(camp.id);
    this.loadRisk(camp.id);
    this.loadEvidence(camp.id);
    this.loadHistory(camp.id);
  }

  closeDetail(): void {
    this.selectedCampaign = null;
  }

  loadTimeline(id: string): void {
    this.timelineLoading = true;
    this.api.getCampaignTimeline(id).subscribe({
      next: (events) => {
        this.timeline = events || [];
        this.timelineLoading = false;
      },
      error: () => {
        this.timeline = [];
        this.timelineLoading = false;
      }
    });
  }

  loadRisk(id: string): void {
    this.riskLoading = true;
    this.api.getCampaignRisk(id).subscribe({
      next: (res) => {
        this.riskAssessment = res;
        this.riskLoading = false;
      },
      error: () => {
        this.riskAssessment = null;
        this.riskLoading = false;
      }
    });
  }

  loadEvidence(id: string): void {
    this.evidenceLoading = true;
    this.api.getCampaignEvidence(id).subscribe({
      next: (res) => {
        this.evidenceDetails = res;
        this.evidenceLoading = false;
      },
      error: () => {
        this.evidenceDetails = null;
        this.evidenceLoading = false;
      }
    });
  }

  loadHistory(id: string): void {
    this.historyLoading = true;
    this.api.getCampaignHistory(id).subscribe({
      next: (items) => {
        this.history = items || [];
        this.historyLoading = false;
      },
      error: () => {
        this.history = [];
        this.historyLoading = false;
      }
    });
  }

  submitTransition(): void {
    if (!this.selectedCampaign || !this.transitionReason.trim()) return;

    this.transitionLoading = true;
    this.transitionError = null;

    this.api.updateCampaignStatus(this.selectedCampaign.id, {
      targetStatus: this.newStatus,
      transitionReason: this.transitionReason.trim()
    }).subscribe({
      next: (updated) => {
        this.selectedCampaign = updated;
        const idx = this.campaigns.findIndex(c => c.id === updated.id);
        if (idx !== -1) {
          this.campaigns[idx] = updated;
        }
        this.applyFilters();
        this.transitionReason = '';
        this.transitionLoading = false;
        this.loadHistory(updated.id);
      },
      error: (err) => {
        this.transitionError = err.detail || 'Status transition was rejected.';
        this.transitionLoading = false;
      }
    });
  }

  getRiskScoreClass(score: number): string {
    if (score >= 85) return 'critical';
    if (score >= 65) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  formatStage(stage: string): string {
    switch (stage) {
      case 'RECONNAISSANCE': return 'Recon';
      case 'AUTHORIZATION_PROBING': return 'Auth Probe';
      case 'RESOURCE_DISCOVERY': return 'Discovery';
      case 'SENSITIVE_DATA_ACCESS': return 'Sensitive';
      case 'BULK_EXTRACTION': return 'Bulk Exfil';
      case 'MULTI_DOMAIN_EXTRACTION': return 'Multi-Domain';
      default: return stage;
    }
  }

  getStageChipClass(stage: string): string {
    switch (stage) {
      case 'RECONNAISSANCE': return 'stage-recon';
      case 'AUTHORIZATION_PROBING': return 'stage-probe';
      case 'RESOURCE_DISCOVERY': return 'stage-disco';
      case 'SENSITIVE_DATA_ACCESS': return 'stage-access';
      case 'BULK_EXTRACTION': return 'stage-bulk';
      case 'MULTI_DOMAIN_EXTRACTION': return 'stage-multi';
      default: return '';
    }
  }

  getBreakdownEntries(breakdown: Record<string, number> | undefined): { key: string; value: number }[] {
    if (!breakdown) return [];
    return Object.entries(breakdown).map(([key, value]) => ({ key, value }));
  }
}
