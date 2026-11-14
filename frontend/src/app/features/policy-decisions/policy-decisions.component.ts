import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  AdaptivePolicyDecisionResponse,
  SecurityPolicyResponse,
  PolicyDecisionAction,
  PolicyAuditHistory,
  PolicyDecisionResponse,
  PolicyStatus,
  ProblemDetail
} from '../../core/models/security.models';

@Component({
  selector: 'app-policy-decisions',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Header -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Adaptive Policy Decision Engine</h1>
          <p class="soc-subtitle">
            Context-aware, advisory-only security policy recommendations, evidence snapshots, and analyst decision governance.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                <polyline points="2 17 12 22 22 17"></polyline>
                <polyline points="2 12 12 17 22 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ totalDecisions }}</span>
              <span class="soc-stat-sub">Total Decisions</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon amber">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ pendingCount }}</span>
              <span class="soc-stat-sub">Pending Review</span>
            </div>
          </div>

          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            {{ loading ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Advisory Invariant Notice -->
      <div class="advisory-banner">
        <div class="advisory-header">
          <span class="advisory-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <polyline points="9 12 11 14 15 10"></polyline>
            </svg>
          </span>
          <strong>ShieldOps Non-Intrusive Advisory Invariant (Phase 7.2.4.6)</strong>
        </div>
        <p class="advisory-desc">
          To maintain zero disruption against legitimate banking traffic and prevent autonomous false-positive cascades,
          ShieldOps operates in strict <code>ADVISORY ONLY</code> mode. All policy decisions produce explainable recommendations
          (such as <code>ESCALATE_INCIDENT</code>, <code>REVIEW_AUTHORIZATION</code>, <code>INVESTIGATE_ACTIVITY</code>) with frozen evidence snapshots
          for SOC analyst verification, and never autonomously block traffic, throttle rate limits, or revoke credentials.
        </p>
      </div>

      <!-- Navigation Tabs -->
      <div class="tabs-bar">
        <button
          class="tab-btn"
          [class.active]="activeTab === 'decisions'"
          (click)="switchTab('decisions')">
          Decision Queue ({{ adaptiveDecisions.length || decisions.length }})
        </button>
        <button
          class="tab-btn"
          [class.active]="activeTab === 'policies'"
          (click)="switchTab('policies')">
          Policy Registry & Governance ({{ policies.length }})
        </button>
      </div>

      <!-- Error State -->
      <div *ngIf="error" class="error-banner" role="alert">
        <span class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </span>
        <div>
          <div class="error-title">{{ error.title }}</div>
          <div class="error-detail">{{ error.detail }}</div>
        </div>
        <button (click)="refresh()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Retrieving adaptive security policy decisions...</span>
      </div>

      <!-- TAB 1: DECISION QUEUE -->
      <div *ngIf="!loading && activeTab === 'decisions'">
        <!-- Filter Toolbar -->
        <div class="filter-toolbar">
          <div class="filter-group">
            <label class="filter-label">Status:</label>
            <select [(ngModel)]="statusFilter" (change)="loadAdaptiveDecisions()" class="filter-select">
              <option value="">All Statuses</option>
              <option value="RECOMMENDED">RECOMMENDED</option>
              <option value="UNDER_REVIEW">UNDER_REVIEW</option>
              <option value="APPROVED">APPROVED</option>
              <option value="REJECTED">REJECTED</option>
              <option value="SUPERSEDED">SUPERSEDED</option>
            </select>
          </div>

          <div class="filter-group">
            <label class="filter-label">Category:</label>
            <select [(ngModel)]="categoryFilter" (change)="loadAdaptiveDecisions()" class="filter-select">
              <option value="">All Categories</option>
              <option value="RECONNAISSANCE">RECONNAISSANCE</option>
              <option value="AUTHORIZATION">AUTHORIZATION</option>
              <option value="DATA_EXPOSURE">DATA_EXPOSURE</option>
              <option value="EXTRACTION">EXTRACTION</option>
              <option value="CAMPAIGN">CAMPAIGN</option>
              <option value="EVIDENCE_INTEGRITY">EVIDENCE_INTEGRITY</option>
            </select>
          </div>

          <div class="filter-group search-group">
            <input
              type="text"
              [(ngModel)]="searchQuery"
              (keyup.enter)="loadAdaptiveDecisions()"
              placeholder="Search by policy, entity, or rationale..."
              class="filter-input" />
            <button (click)="loadAdaptiveDecisions()" class="btn btn-secondary btn-sm">Search</button>
          </div>
        </div>

        <!-- Empty State -->
        <div *ngIf="adaptiveDecisions.length === 0 && decisions.length === 0" class="empty-state">
          <div class="empty-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <polyline points="9 12 11 14 15 10"></polyline>
            </svg>
          </div>
          <h3>No Policy Decisions Logged</h3>
          <p>No adaptive policy recommendations match the active filter criteria.</p>
        </div>

        <!-- Adaptive Decisions Table -->
        <div *ngIf="adaptiveDecisions.length > 0" class="soc-table-container">
          <table class="soc-table" aria-label="Adaptive Security Policy Decisions">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Policy</th>
                <th>Category</th>
                <th>Risk Level</th>
                <th>Recommended Action</th>
                <th>Target Context</th>
                <th>Evidence Completeness</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let dec of adaptiveDecisions" [class.selected-row]="selectedDecision?.id === dec.id">
                <td class="mono text-muted text-nowrap">{{ dec.createdAt | date:'yyyy-MM-dd HH:mm:ss' }}</td>
                <td>
                  <div class="mono font-bold">{{ dec.policyId }}</div>
                  <span class="text-muted text-xs">v{{ dec.policyVersion }}</span>
                </td>
                <td>
                  <span class="cat-pill mono">{{ dec.category }}</span>
                </td>
                <td>
                  <span class="badge" [ngClass]="getRiskBadgeClass(dec.riskLevel)">{{ dec.riskLevel }}</span>
                </td>
                <td>
                  <span class="action-pill mono">{{ dec.recommendedAction }}</span>
                </td>
                <td class="mono text-teal">{{ dec.identityContext || dec.tenantId }}</td>
                <td>
                  <span class="completeness-badge" [ngClass]="getCompletenessClass(dec.evidenceCompleteness)">
                    {{ dec.evidenceCompleteness }}
                  </span>
                </td>
                <td>
                  <span class="status-chip" [ngClass]="getStatusChipClass(dec.status)">{{ dec.status }}</span>
                </td>
                <td>
                  <button (click)="inspectDecision(dec)" class="btn btn-secondary btn-sm">Inspect</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Legacy Fallback Table for Backward Compatibility with existing specs -->
        <div *ngIf="adaptiveDecisions.length === 0 && decisions.length > 0" class="soc-table-container">
          <table class="soc-table" aria-label="Advisory Policy Decisions Log">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Recommended Action</th>
                <th>Enforcement Level</th>
                <th>Target Entity</th>
                <th>Rationale</th>
                <th>Incident Link</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let dec of decisions">
                <td class="mono text-muted text-nowrap">{{ dec.createdAt | date:'yyyy-MM-dd HH:mm:ss' }}</td>
                <td>
                  <span class="action-pill mono">{{ dec.recommendedAction }}</span>
                </td>
                <td>
                  <span class="enforcement-badge">{{ dec.enforcementLevel || 'ADVISORY' }}</span>
                </td>
                <td class="mono text-teal">{{ dec.targetEntityValue }}</td>
                <td class="rationale-cell" [title]="dec.reason">{{ dec.reason }}</td>
                <td>
                  <a [routerLink]="['/incidents', dec.incidentId]" class="btn btn-secondary btn-sm">
                    Incident →
                  </a>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- TAB 2: SECURITY POLICY REGISTRY & THRESHOLDS -->
      <div *ngIf="!loading && activeTab === 'policies'">
        <div class="soc-table-container">
          <table class="soc-table" aria-label="Security Policy Registry">
            <thead>
              <tr>
                <th>Policy ID</th>
                <th>Name</th>
                <th>Version</th>
                <th>Category</th>
                <th>Action</th>
                <th>Risk Threshold</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let pol of policies">
                <td class="mono font-bold">{{ pol.id }}</td>
                <td>
                  <div>{{ pol.name }}</div>
                  <div class="text-muted text-xs">{{ pol.description }}</div>
                </td>
                <td class="mono text-xs">v{{ pol.version }}</td>
                <td><span class="cat-pill mono">{{ pol.category }}</span></td>
                <td><span class="action-pill mono">{{ pol.recommendedAction }}</span></td>
                <td class="mono">{{ pol.severityThreshold }} / 100</td>
                <td>
                  <span class="status-chip" [ngClass]="pol.enabled ? 'status-approved' : 'status-rejected'">
                    {{ pol.enabled ? 'ACTIVE' : 'DISABLED' }}
                  </span>
                </td>
                <td>
                  <button (click)="openPolicyEdit(pol)" class="btn btn-secondary btn-sm">Tune</button>
                  <button (click)="viewPolicyAudit(pol)" class="btn btn-ghost btn-sm" style="margin-left: 4px;">Audit</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- INSPECTION DRAWER -->
      <div *ngIf="selectedDecision" class="modal-backdrop" (click)="closeInspection()">
        <div class="drawer-panel" (click)="$event.stopPropagation()">
          <div class="drawer-header">
            <div>
              <h3>Policy Recommendation Details</h3>
              <div class="mono text-muted text-xs">Decision ID: {{ selectedDecision.id }}</div>
            </div>
            <button (click)="closeInspection()" class="btn-close">&times;</button>
          </div>

          <div class="drawer-body">
            <!-- Summary Grid -->
            <div class="detail-grid">
              <div class="detail-item">
                <label>Policy ID</label>
                <div class="mono font-bold">{{ selectedDecision.policyId }} (v{{ selectedDecision.policyVersion }})</div>
              </div>
              <div class="detail-item">
                <label>Recommended Action</label>
                <div><span class="action-pill mono">{{ selectedDecision.recommendedAction }}</span></div>
              </div>
              <div class="detail-item">
                <label>Risk Level</label>
                <div><span class="badge" [ngClass]="getRiskBadgeClass(selectedDecision.riskLevel)">{{ selectedDecision.riskLevel }}</span></div>
              </div>
              <div class="detail-item">
                <label>Evidence Completeness</label>
                <div><span class="completeness-badge" [ngClass]="getCompletenessClass(selectedDecision.evidenceCompleteness)">{{ selectedDecision.evidenceCompleteness }}</span></div>
              </div>
              <div class="detail-item">
                <label>Identity Context</label>
                <div class="mono text-teal">{{ selectedDecision.identityContext || 'N/A' }}</div>
              </div>
              <div class="detail-item">
                <label>Tenant ID</label>
                <div class="mono">{{ selectedDecision.tenantId }}</div>
              </div>
            </div>

            <!-- Rationale -->
            <div class="drawer-section">
              <h4>Decision Rationale</h4>
              <p class="rationale-box">{{ selectedDecision.rationale }}</p>
            </div>

            <!-- Linked References -->
            <div class="drawer-section" *ngIf="selectedDecision.incidentId || selectedDecision.campaignId">
              <h4>Correlated Security References</h4>
              <div class="link-pills">
                <a *ngIf="selectedDecision.incidentId" [routerLink]="['/incidents', selectedDecision.incidentId]" class="btn btn-secondary btn-sm">
                  View Incident ({{ selectedDecision.incidentId | slice:0:8 }}...) →
                </a>
                <a *ngIf="selectedDecision.campaignId" [routerLink]="['/campaigns']" class="btn btn-secondary btn-sm">
                  View Exfiltration Campaign →
                </a>
              </div>
            </div>

            <!-- Supporting Evidence -->
            <div class="drawer-section" *ngIf="selectedDecision.supportingEvidence?.length">
              <h4>Supporting Evidence Items ({{ selectedDecision.supportingEvidence.length }})</h4>
              <ul class="evidence-list">
                <li *ngFor="let item of selectedDecision.supportingEvidence" class="mono text-xs">{{ item }}</li>
              </ul>
            </div>

            <!-- Frozen Snapshot -->
            <div class="drawer-section" *ngIf="selectedDecision.evidenceSnapshot">
              <h4>Frozen Telemetry & Evidence Snapshot</h4>
              <pre class="json-box"><code>{{ selectedDecision.evidenceSnapshot }}</code></pre>
            </div>

            <!-- Decision Audit Trail -->
            <div class="drawer-section" *ngIf="decisionActions.length > 0">
              <h4>Analyst Action History</h4>
              <div class="action-history">
                <div *ngFor="let act of decisionActions" class="history-item">
                  <span class="mono text-muted text-xs">{{ act.actionAt | date:'yyyy-MM-dd HH:mm:ss' }}</span>
                  <span class="status-chip" [ngClass]="getStatusChipClass(act.action)">{{ act.action }}</span>
                  <span class="mono text-xs">by {{ act.performedBy }}</span>
                  <div class="history-comment" *ngIf="act.rationale || act.comments">
                    {{ act.rationale || act.comments }}
                  </div>
                </div>
              </div>
            </div>

            <!-- Analyst Review Controls -->
            <div class="drawer-section review-controls" *ngIf="selectedDecision.status === 'RECOMMENDED' || selectedDecision.status === 'UNDER_REVIEW'">
              <h4>Analyst Decision Governance</h4>
              <p class="text-secondary text-xs">
                Approve or reject this security recommendation. Rejections require a mandatory operational rationale for the audit record.
              </p>

              <div class="form-group" style="margin-top: var(--space-3);">
                <label>Analyst Comments / Rationale:</label>
                <textarea
                  [(ngModel)]="analystRationaleInput"
                  rows="3"
                  placeholder="Enter review findings or mandatory rejection rationale..."
                  class="form-textarea"></textarea>
              </div>

              <div class="review-btn-row">
                <button
                  (click)="approveSelectedDecision()"
                  [disabled]="actionSubmitting"
                  class="btn btn-primary btn-sm">
                  Approve Recommendation
                </button>
                <button
                  (click)="rejectSelectedDecision()"
                  [disabled]="actionSubmitting || !analystRationaleInput.trim()"
                  class="btn btn-danger btn-sm">
                  Reject Recommendation
                </button>
              </div>
              <div *ngIf="!analystRationaleInput.trim()" class="text-xs text-muted" style="margin-top: 4px;">
                * Rejection requires mandatory explanation.
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- POLICY EDIT MODAL -->
      <div *ngIf="editingPolicy" class="modal-backdrop" (click)="editingPolicy = null">
        <div class="modal-dialog" (click)="$event.stopPropagation()">
          <div class="modal-header">
            <h3>Tune Policy: {{ editingPolicy.id }}</h3>
            <button (click)="editingPolicy = null" class="btn-close">&times;</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>Policy Name</label>
              <input type="text" [(ngModel)]="policyEditName" class="form-input" />
            </div>
            <div class="form-group">
              <label>Risk Threshold (0 - 100)</label>
              <input type="number" [(ngModel)]="policyEditThreshold" min="0" max="100" class="form-input" />
            </div>
            <div class="form-group">
              <label class="checkbox-label">
                <input type="checkbox" [(ngModel)]="policyEditEnabled" />
                Policy Active
              </label>
            </div>
            <div class="form-group">
              <label>Mandatory Change Reason (Audit Log)</label>
              <textarea [(ngModel)]="policyEditReason" rows="2" placeholder="Explain the rationale for adjusting this policy..." class="form-textarea"></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button (click)="editingPolicy = null" class="btn btn-secondary btn-sm">Cancel</button>
            <button
              (click)="savePolicyEdit()"
              [disabled]="policySaving || !policyEditReason.trim()"
              class="btn btn-primary btn-sm">
              Save Policy Version
            </button>
          </div>
        </div>
      </div>

      <!-- POLICY AUDIT MODAL -->
      <div *ngIf="viewingAuditPolicy" class="modal-backdrop" (click)="viewingAuditPolicy = null">
        <div class="modal-dialog" (click)="$event.stopPropagation()">
          <div class="modal-header">
            <h3>Policy Audit History: {{ viewingAuditPolicy.id }}</h3>
            <button (click)="viewingAuditPolicy = null" class="btn-close">&times;</button>
          </div>
          <div class="modal-body">
            <div *ngIf="policyAudits.length === 0" class="empty-state">
              <p>No version modifications recorded for this policy.</p>
            </div>
            <div *ngFor="let audit of policyAudits" class="audit-card">
              <div class="audit-header">
                <span class="mono font-bold">{{ audit.previousVersion }} → {{ audit.newVersion }}</span>
                <span class="mono text-muted text-xs">{{ audit.changedAt | date:'yyyy-MM-dd HH:mm:ss' }}</span>
              </div>
              <div class="text-xs text-muted">Changed by: {{ audit.changedBy }}</div>
              <div class="audit-reason">{{ audit.changeReason }}</div>
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
      font-size: 20px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .soc-subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 2px;
    }
    .header-stat-pills {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .soc-stat-pill {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      padding: var(--space-2) var(--space-3);
      border-radius: var(--radius-md);
    }
    .soc-stat-icon {
      width: 28px;
      height: 28px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .soc-stat-icon.teal { background: rgba(20, 184, 166, 0.15); color: var(--accent-teal); }
    .soc-stat-icon.amber { background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); }
    .soc-stat-val { font-weight: 700; font-size: 14px; color: var(--text-primary); }
    .soc-stat-sub { font-size: 11px; color: var(--text-muted); display: block; }
    .advisory-banner {
      background: rgba(20, 184, 166, 0.08);
      border: 1px solid var(--accent-teal-border);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      margin-bottom: var(--space-4);
    }
    .advisory-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: 13px;
      color: var(--text-primary);
      margin-bottom: var(--space-2);
    }
    .advisory-icon {
      font-size: 16px;
      color: var(--accent-teal);
    }
    .advisory-desc {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.6;
    }
    .advisory-desc code {
      background: var(--bg-input);
      padding: 1px 4px;
      border-radius: 2px;
      font-family: var(--font-mono);
      color: var(--accent-teal);
    }
    .tabs-bar {
      display: flex;
      gap: var(--space-2);
      border-bottom: 1px solid var(--border-color);
      margin-bottom: var(--space-4);
    }
    .tab-btn {
      padding: var(--space-2) var(--space-4);
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
    .tab-btn.active {
      color: var(--accent-teal);
      border-bottom-color: var(--accent-teal);
    }
    .filter-toolbar {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      margin-bottom: var(--space-4);
      flex-wrap: wrap;
    }
    .filter-group {
      display: flex;
      align-items: center;
      gap: var(--space-2);
    }
    .filter-label {
      font-size: 12px;
      color: var(--text-secondary);
    }
    .filter-select, .filter-input, .form-input, .form-textarea {
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      padding: var(--space-1) var(--space-2);
      font-size: 12px;
    }
    .filter-input { width: 220px; }
    .search-group { margin-left: auto; }
    .action-pill {
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-amber);
      background: var(--accent-amber-subtle);
      border: 1px solid var(--accent-amber-border);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .cat-pill {
      font-size: 10px;
      color: var(--text-secondary);
      background: rgba(255, 255, 255, 0.05);
      padding: 2px 5px;
      border-radius: var(--radius-sm);
    }
    .enforcement-badge {
      font-size: 10px;
      font-weight: 700;
      color: var(--accent-teal);
      background: var(--accent-teal-subtle);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      letter-spacing: 0.04em;
    }
    .status-chip {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .status-recommended { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
    .status-under-review { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .status-approved { background: rgba(16, 185, 129, 0.15); color: #34d399; }
    .status-rejected { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .status-superseded { background: rgba(107, 114, 128, 0.15); color: #9ca3af; }
    .completeness-badge {
      font-size: 10px;
      font-weight: 600;
      padding: 2px 5px;
      border-radius: var(--radius-sm);
    }
    .completeness-complete { background: rgba(16, 185, 129, 0.1); color: #34d399; }
    .completeness-incomplete { background: rgba(245, 158, 11, 0.1); color: #fbbf24; }
    .completeness-degraded { background: rgba(239, 68, 68, 0.1); color: #f87171; }
    .rationale-cell {
      max-width: 340px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
    }
    .error-banner {
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
      color: var(--sev-critical);
      padding: var(--space-3) var(--space-4);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      gap: var(--space-3);
      margin-bottom: var(--space-4);
    }
    .loading-state, .empty-state {
      text-align: center;
      padding: var(--space-8);
      color: var(--text-secondary);
    }
    .spinner {
      width: 28px;
      height: 28px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: var(--accent-teal);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto var(--space-3);
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .modal-backdrop {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.6);
      display: flex;
      justify-content: flex-end;
      z-index: 1000;
    }
    .drawer-panel {
      width: 580px;
      max-width: 90vw;
      height: 100%;
      background: var(--bg-card);
      border-left: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
    }
    .drawer-header, .modal-header {
      padding: var(--space-4);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .btn-close {
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 20px;
      cursor: pointer;
    }
    .drawer-body, .modal-body {
      padding: var(--space-4);
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
    }
    .detail-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: var(--space-3);
    }
    .detail-item label {
      font-size: 11px;
      color: var(--text-muted);
      display: block;
      margin-bottom: 2px;
    }
    .drawer-section h4 {
      font-size: 12px;
      font-weight: 700;
      color: var(--text-secondary);
      margin-bottom: var(--space-2);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .rationale-box {
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: var(--space-3);
      font-size: 12px;
      line-height: 1.5;
    }
    .json-box {
      background: #0d1117;
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: var(--space-3);
      font-size: 11px;
      color: #7ee787;
      overflow-x: auto;
      max-height: 200px;
    }
    .evidence-list {
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: var(--space-2) var(--space-3);
      margin: 0;
      list-style-type: square;
      padding-left: var(--space-5);
    }
    .review-controls {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: var(--space-3);
    }
    .review-btn-row {
      display: flex;
      gap: var(--space-2);
      margin-top: var(--space-3);
    }
    .modal-dialog {
      width: 480px;
      margin: auto;
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    .modal-footer {
      padding: var(--space-3) var(--space-4);
      border-top: 1px solid var(--border-color);
      display: flex;
      justify-content: flex-end;
      gap: var(--space-2);
    }
    .form-group {
      display: flex;
      flex-direction: column;
      gap: var(--space-1);
    }
    .form-group label {
      font-size: 12px;
      color: var(--text-secondary);
    }
    .audit-card {
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      padding: var(--space-2) var(--space-3);
      margin-bottom: var(--space-2);
    }
    .audit-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 2px;
    }
    .audit-reason {
      font-size: 12px;
      margin-top: 4px;
      color: var(--text-primary);
    }
    .badge-critical { background: var(--sev-critical-bg); color: var(--sev-critical); }
    .badge-high { background: var(--sev-high-bg); color: var(--sev-high); }
    .badge-medium { background: var(--sev-medium-bg); color: var(--sev-medium); }
    .badge-low { background: var(--sev-low-bg); color: var(--sev-low); }
  `]
})
export class PolicyDecisionsComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  activeTab: 'decisions' | 'policies' = 'decisions';
  loading = false;
  error: ProblemDetail | null = null;

  // Adaptive Decisions
  adaptiveDecisions: AdaptivePolicyDecisionResponse[] = [];
  decisions: PolicyDecisionResponse[] = []; // Legacy fallback
  totalDecisions = 0;
  pendingCount = 0;

  // Filter toolbar
  statusFilter = '';
  categoryFilter = '';
  searchQuery = '';

  // Drawer & Review
  selectedDecision: AdaptivePolicyDecisionResponse | null = null;
  decisionActions: PolicyDecisionAction[] = [];
  analystRationaleInput = '';
  actionSubmitting = false;

  // Policy Registry
  policies: SecurityPolicyResponse[] = [];
  editingPolicy: SecurityPolicyResponse | null = null;
  policyEditName = '';
  policyEditThreshold = 50;
  policyEditEnabled = true;
  policyEditReason = '';
  policySaving = false;

  // Policy Audit History
  viewingAuditPolicy: SecurityPolicyResponse | null = null;
  policyAudits: PolicyAuditHistory[] = [];

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.loadAdaptiveDecisions();
    this.loadPolicies();
  }

  switchTab(tab: 'decisions' | 'policies'): void {
    this.activeTab = tab;
  }

  loadAdaptiveDecisions(): void {
    this.loading = true;
    this.error = null;

    if (this.api.getAdaptiveDecisions) {
      this.api.getAdaptiveDecisions(0, 50, this.statusFilter, this.categoryFilter, this.searchQuery).subscribe({
        next: (page) => {
          this.adaptiveDecisions = page?.content || [];
          this.totalDecisions = page?.totalElements || this.adaptiveDecisions.length;
          this.pendingCount = this.adaptiveDecisions.filter(d => d.status === 'RECOMMENDED' || d.status === 'UNDER_REVIEW').length;
          this.loading = false;
        },
        error: (err) => {
          // If adaptive decisions fails, fallback to legacy getRecentPolicyDecisions
          this.fallbackToLegacyDecisions();
        }
      });
    } else {
      this.fallbackToLegacyDecisions();
    }
  }

  private fallbackToLegacyDecisions(): void {
    if (this.api.getRecentPolicyDecisions) {
      this.api.getRecentPolicyDecisions(0, 50).subscribe({
        next: (data) => {
          this.decisions = data || [];
          this.totalDecisions = this.decisions.length;
          this.pendingCount = this.decisions.length;
          this.loading = false;
        },
        error: (err) => {
          this.error = err;
          this.decisions = [];
          this.loading = false;
        }
      });
    } else {
      this.loading = false;
    }
  }

  loadPolicies(): void {
    if (this.api.getSecurityPolicies) {
      this.api.getSecurityPolicies().subscribe({
        next: (pols) => {
          this.policies = pols || [];
        },
        error: () => {
          this.policies = [];
        }
      });
    }
  }

  inspectDecision(dec: AdaptivePolicyDecisionResponse): void {
    this.selectedDecision = dec;
    this.analystRationaleInput = '';
    this.decisionActions = [];

    if (this.api.getAdaptiveDecisionActions) {
      this.api.getAdaptiveDecisionActions(dec.id).subscribe({
        next: (actions) => {
          this.decisionActions = actions || [];
        }
      });
    }
  }

  closeInspection(): void {
    this.selectedDecision = null;
  }

  approveSelectedDecision(): void {
    if (!this.selectedDecision) return;
    this.actionSubmitting = true;

    this.api.approveAdaptiveDecision(this.selectedDecision.id, {
      analystUser: 'analyst-ui',
      comments: this.analystRationaleInput || 'Recommendation approved by analyst.'
    }).subscribe({
      next: (updated) => {
        this.selectedDecision = updated;
        this.actionSubmitting = false;
        this.loadAdaptiveDecisions();
      },
      error: (err) => {
        this.actionSubmitting = false;
        this.error = err;
      }
    });
  }

  rejectSelectedDecision(): void {
    if (!this.selectedDecision || !this.analystRationaleInput.trim()) return;
    this.actionSubmitting = true;

    this.api.rejectAdaptiveDecision(this.selectedDecision.id, {
      analystUser: 'analyst-ui',
      rationale: this.analystRationaleInput
    }).subscribe({
      next: (updated) => {
        this.selectedDecision = updated;
        this.actionSubmitting = false;
        this.loadAdaptiveDecisions();
      },
      error: (err) => {
        this.actionSubmitting = false;
        this.error = err;
      }
    });
  }

  openPolicyEdit(pol: SecurityPolicyResponse): void {
    this.editingPolicy = pol;
    this.policyEditName = pol.name;
    this.policyEditThreshold = pol.severityThreshold;
    this.policyEditEnabled = pol.enabled;
    this.policyEditReason = '';
  }

  savePolicyEdit(): void {
    if (!this.editingPolicy || !this.policyEditReason.trim()) return;
    this.policySaving = true;

    this.api.updateSecurityPolicy(this.editingPolicy.id, {
      name: this.policyEditName,
      severityThreshold: this.policyEditThreshold,
      enabled: this.policyEditEnabled,
      changedBy: 'analyst-ui',
      changeReason: this.policyEditReason
    }).subscribe({
      next: () => {
        this.policySaving = false;
        this.editingPolicy = null;
        this.loadPolicies();
      },
      error: (err) => {
        this.policySaving = false;
        this.error = err;
      }
    });
  }

  viewPolicyAudit(pol: SecurityPolicyResponse): void {
    this.viewingAuditPolicy = pol;
    this.policyAudits = [];

    this.api.getSecurityPolicyAuditHistory(pol.id).subscribe({
      next: (history) => {
        this.policyAudits = history || [];
      }
    });
  }

  getRiskBadgeClass(riskLevel?: string): string {
    switch (riskLevel?.toUpperCase()) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  }

  getCompletenessClass(completeness?: string): string {
    switch (completeness?.toUpperCase()) {
      case 'COMPLETE': return 'completeness-complete';
      case 'INCOMPLETE': return 'completeness-incomplete';
      default: return 'completeness-degraded';
    }
  }

  getStatusChipClass(status?: string): string {
    switch (status?.toUpperCase()) {
      case 'APPROVED': return 'status-approved';
      case 'REJECTED': return 'status-rejected';
      case 'UNDER_REVIEW': return 'status-under-review';
      case 'SUPERSEDED': return 'status-superseded';
      default: return 'status-recommended';
    }
  }
}
