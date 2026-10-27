import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../../core/services/security-api.service';
import { AuthService } from '../../../core/auth/auth.service';
import {
  IncidentResponse,
  EvidenceResponse,
  IncidentStatusHistoryResponse,
  PolicyDecisionResponse,
  IncidentStatus,
  ProblemDetail
} from '../../../core/models/security.models';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../../shared/components/status-badge/status-badge.component';
import { LoadingSpinnerComponent } from '../../../shared/components/loading-spinner/loading-spinner.component';

@Component({
  selector: 'app-incident-detail',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    FormsModule,
    SeverityBadgeComponent,
    StatusBadgeComponent,
    LoadingSpinnerComponent
  ],
  template: `
    <div class="soc-page">
      <!-- Top Navigation & Breadcrumb -->
      <div class="soc-header">
        <div>
          <div class="breadcrumb">
            <a routerLink="/incidents" class="back-link">INCIDENT QUEUE</a> / FORENSIC INVESTIGATION
          </div>
          <h1 class="page-title">
            Incident: <span class="mono text-teal">{{ incident()?.incidentFingerprint || incidentId() }}</span>
          </h1>
          <p class="page-subtitle">
            Forensic correlation trail, contributing evidence, advisory policy recommendations, and lifecycle audit history.
          </p>
        </div>

        <div class="soc-controls" *ngIf="incident() as inc">
          <button (click)="openStatusModal()" class="btn btn-primary">
            <span>⚡</span> Transition Status
          </button>
          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <span>↻</span> Refresh
          </button>
        </div>
      </div>

      <!-- Loading State -->
      <app-loading-spinner *ngIf="loading()" message="Loading incident investigation workspace..."></app-loading-spinner>

      <!-- Error State (e.g. 404 Not Found) -->
      <div *ngIf="error()" class="error-panel soc-card">
        <div class="error-header">
          <span class="error-icon">⚠️</span>
          <span class="error-title">{{ error()?.title || 'Incident Investigation Error' }}</span>
        </div>
        <p class="error-detail">{{ error()?.detail || 'Incident could not be found or access is unauthorized.' }}</p>
        <div class="mt-3">
          <a routerLink="/incidents" class="btn btn-secondary btn-sm">← Return to Incident Queue</a>
        </div>
      </div>

      <!-- Main Workspace -->
      <div *ngIf="!loading() && incident() as inc" class="investigation-grid">
        <!-- Identity & Summary Banner -->
        <div class="soc-card identity-card">
          <div class="identity-header">
            <div class="identity-tags">
              <app-severity-badge [severity]="inc.severity"></app-severity-badge>
              <app-status-badge [status]="inc.status"></app-status-badge>
              <span class="badge badge-info">{{ inc.threatCategory }}</span>
              <span class="mono text-muted text-sm">RULE: {{ inc.ruleId }} (v{{ inc.ruleVersion }})</span>
            </div>
            <div class="identity-meta text-muted text-sm mono">
              ID: {{ inc.id }}
            </div>
          </div>

          <div class="summary-box">
            <div class="summary-label">INCIDENT SUMMARY:</div>
            <div class="summary-text">{{ inc.summary }}</div>
          </div>

          <div class="identity-details-grid">
            <div class="meta-item">
              <span class="meta-label">TARGET ENTITY:</span>
              <span class="meta-val mono text-teal">{{ inc.targetEntityType }} : {{ inc.targetEntityValue }}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">CORRELATED EVENTS:</span>
              <span class="meta-val mono">{{ inc.eventCount | number }} requests</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">FIRST DETECTED:</span>
              <span class="meta-val mono text-muted">{{ formatDateTime(inc.firstDetectedAt) }}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">LAST ACTIVE:</span>
              <span class="meta-val mono text-muted">{{ formatDateTime(inc.lastEventAt) }}</span>
            </div>
          </div>
        </div>

        <!-- Two Column Forensics Layout -->
        <div class="forensics-split">
          <!-- Left Column: Evidence & Correlation -->
          <div class="forensics-col">
            <div class="soc-card section-card">
              <div class="soc-card-header">
                <span class="soc-card-title">Contributing Evidence & Rules ({{ evidence().length }})</span>
                <span class="badge badge-info">HEURISTIC EVALUATION</span>
              </div>

              <div *ngIf="evidence().length === 0" class="empty-compact text-muted">
                No granular evidence entries linked to this incident.
              </div>

              <div *ngFor="let ev of evidence()" class="evidence-block soc-card">
                <div class="ev-header">
                  <span class="mono text-teal font-bold">{{ ev.ruleId }} (v{{ ev.ruleVersion }})</span>
                  <div class="ev-badges">
                    <span class="confidence-chip mono" [title]="'Empirical Bayesian heuristic confidence score'">
                      CONFIDENCE: {{ (ev.confidenceScore * 100).toFixed(0) }}%
                    </span>
                    <app-severity-badge [severity]="ev.severity"></app-severity-badge>
                  </div>
                </div>

                <div class="ev-condition">
                  <span class="ev-label">TRIGGER CONDITION:</span>
                  <p class="ev-text">{{ ev.triggerCondition }}</p>
                </div>

                <div class="ev-meta-row text-sm">
                  <span class="text-muted">MITRE ATT&CK:</span>
                  <span class="mono text-teal">{{ ev.mitreTechnique || 'T1078 (Valid Accounts)' }}</span>
                  <span class="text-muted" style="margin-left: 12px;">DISTINCT TARGETS:</span>
                  <span class="mono">{{ ev.distinctResourcesCount }}</span>
                </div>

                <!-- Contributing Event IDs -->
                <div *ngIf="ev.contributingEventIds && ev.contributingEventIds.length > 0" class="contributing-events">
                  <span class="ev-label">CONTRIBUTING TELEMETRY IDS ({{ ev.contributingEventIds.length }}):</span>
                  <div class="event-id-chips">
                    <a
                      *ngFor="let evtId of ev.contributingEventIds"
                      [routerLink]="['/events']"
                      [queryParams]="{ correlationId: evtId }"
                      class="event-chip mono"
                      title="Inspect event in Event Explorer"
                    >
                      {{ truncate(evtId, 16) }} ↗
                    </a>
                  </div>
                </div>
              </div>
            </div>

            <!-- Advisory Policy Recommendations -->
            <div class="soc-card section-card mt-4">
              <div class="soc-card-header">
                <span class="soc-card-title">Advisory Response Policies ({{ policyDecisions().length }})</span>
                <span class="badge badge-info">NON-BLOCKING</span>
              </div>

              <div *ngIf="policyDecisions().length === 0" class="empty-compact text-muted">
                No active policy decisions generated for this incident.
              </div>

              <div *ngFor="let pol of policyDecisions()" class="policy-card soc-card">
                <div class="policy-header">
                  <span class="policy-action mono text-teal">RECOMMENDED: {{ pol.recommendedAction }}</span>
                  <span class="badge badge-info">LEVEL: {{ pol.enforcementLevel }}</span>
                </div>
                <p class="policy-reason text-sm">{{ pol.reason }}</p>
                <div class="policy-footer text-muted text-xs mono">
                  Evaluated at {{ formatDateTime(pol.createdAt) }} • Heuristic Confidence: {{ (pol.confidenceScore * 100).toFixed(0) }}%
                </div>
              </div>

              <div class="advisory-notice">
                <span class="notice-bullet">ℹ</span>
                <span>
                  <strong>Advisory Invariant:</strong> Aegis functions strictly in advisory alert mode.
                  Automatic blocking, IP blacklisting, or credential invalidation are intentionally bypassed to preserve customer availability.
                </span>
              </div>
            </div>
          </div>

          <!-- Right Column: Status Lifecycle Timeline -->
          <div class="forensics-col">
            <div class="soc-card section-card">
              <div class="soc-card-header">
                <span class="soc-card-title">Status Lifecycle Audit History</span>
                <span class="badge badge-info">{{ history().length }} TRANSITIONS</span>
              </div>

              <div *ngIf="history().length === 0" class="empty-compact text-muted">
                Incident remains in initial detection state. No analyst transitions recorded yet.
              </div>

              <div class="history-timeline">
                <div *ngFor="let item of history(); let last = last" class="timeline-entry">
                  <div class="timeline-marker"></div>
                  <div class="timeline-card soc-card">
                    <div class="timeline-header">
                      <div class="timeline-transition">
                        <app-status-badge [status]="item.previousStatus"></app-status-badge>
                        <span class="transition-arrow">→</span>
                        <app-status-badge [status]="item.newStatus"></app-status-badge>
                      </div>
                      <span class="timeline-time mono text-muted text-xs">
                        {{ formatDateTime(item.changedAt) }}
                      </span>
                    </div>

                    <div class="timeline-actor">
                      <span class="actor-label">ANALYST:</span>
                      <span class="mono text-teal">{{ item.changedBy }}</span>
                    </div>

                    <div class="timeline-reason">
                      <span class="reason-label">REASON:</span>
                      <p class="reason-text">{{ item.changeReason }}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Status Transition Modal Dialog -->
      <div *ngIf="showStatusModal()" class="modal-backdrop">
        <div class="modal-dialog soc-card">
          <div class="modal-header">
            <h3 class="modal-title">Transition Incident Status</h3>
            <button (click)="closeStatusModal()" class="modal-close" [disabled]="transitioning()">✕</button>
          </div>

          <div class="modal-body">
            <div class="current-state-strip">
              <span class="text-muted">Current Status:</span>
              <app-status-badge [status]="incident()?.status || 'OPEN'"></app-status-badge>
            </div>

            <!-- Terminal Reopening Warning -->
            <div *ngIf="isTerminalStatus() && !auth.isSecurityAdmin()" class="alert-box warning">
              <span>⚠️</span>
              <div>
                <strong>Restricted Action:</strong> Reopening a terminal incident (RESOLVED or FALSE_POSITIVE) requires
                <span class="mono">SECURITY_ADMIN</span> authorization.
              </div>
            </div>

            <div class="form-group mt-3">
              <label for="targetStatusSelect" class="form-label">TARGET STATUS:</label>
              <select
                id="targetStatusSelect"
                [(ngModel)]="selectedTargetStatus"
                class="form-select w-100"
                [disabled]="transitioning() || (isTerminalStatus() && !auth.isSecurityAdmin())"
              >
                <option value="">Select target status...</option>
                <option *ngFor="let opt of allowedTargetStatuses()" [value]="opt">
                  {{ opt }}
                </option>
              </select>
            </div>

            <div class="form-group mt-3">
              <label for="transitionReasonInput" class="form-label">
                ANALYST AUDIT REASON (Mandatory, 5–512 chars):
              </label>
              <textarea
                id="transitionReasonInput"
                [(ngModel)]="transitionReason"
                rows="4"
                class="form-input w-100"
                placeholder="Detail forensic findings, customer contact logs, or triage verification rationale..."
                [disabled]="transitioning() || (isTerminalStatus() && !auth.isSecurityAdmin())"
              ></textarea>
              <div class="char-counter text-xs" [class.text-danger]="transitionReason.length > 0 && transitionReason.length < 5">
                {{ transitionReason.length }} / 512 characters (minimum 5 required)
              </div>
            </div>

            <!-- Modal Error Display -->
            <div *ngIf="modalError()" class="alert-box error mt-3">
              <span>⚠️</span>
              <div>{{ modalError() }}</div>
            </div>
          </div>

          <div class="modal-footer">
            <button (click)="closeStatusModal()" class="btn btn-secondary" [disabled]="transitioning()">
              Cancel
            </button>
            <button
              (click)="submitStatusTransition()"
              class="btn btn-primary"
              [disabled]="!canSubmitTransition() || transitioning()"
            >
              <span *ngIf="transitioning()">Applying...</span>
              <span *ngIf="!transitioning()">Confirm Status Transition</span>
            </button>
          </div>
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
      color: var(--text-muted);
      margin-bottom: var(--space-1);
    }
    .back-link {
      color: var(--accent-teal);
      text-decoration: none;
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
    }
    .soc-controls {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .investigation-grid {
      display: flex;
      flex-direction: column;
      gap: var(--space-5);
    }
    .identity-card {
      background: var(--bg-card);
      padding: var(--space-5);
      border-left: 4px solid var(--accent-teal);
    }
    .identity-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: var(--space-4);
      flex-wrap: wrap;
      gap: var(--space-3);
    }
    .identity-tags {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      flex-wrap: wrap;
    }
    .summary-box {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: var(--space-3) var(--space-4);
      margin-bottom: var(--space-4);
    }
    .summary-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }
    .summary-text {
      font-size: 13px;
      color: var(--text-primary);
      line-height: 1.5;
    }
    .identity-details-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: var(--space-4);
      padding-top: var(--space-2);
    }
    .meta-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .meta-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .meta-val {
      font-size: 13px;
      font-weight: 500;
    }
    .forensics-split {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: var(--space-5);
    }
    @media (max-width: 1024px) {
      .forensics-split {
        grid-template-columns: 1fr;
      }
    }
    .forensics-col {
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
    }
    .section-card {
      padding: var(--space-4);
    }
    .evidence-block {
      background: var(--bg-surface);
      padding: var(--space-4);
      margin-bottom: var(--space-3);
      border-left: 3px solid var(--accent-teal);
    }
    .ev-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: var(--space-2);
      flex-wrap: wrap;
      gap: var(--space-2);
    }
    .ev-badges {
      display: flex;
      align-items: center;
      gap: var(--space-2);
    }
    .confidence-chip {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: rgba(20, 184, 166, 0.1);
      color: var(--accent-teal);
      border: 1px solid var(--accent-teal-border);
      font-weight: 700;
    }
    .ev-condition {
      margin-bottom: var(--space-2);
    }
    .ev-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
      display: block;
      margin-bottom: 2px;
    }
    .ev-text {
      font-size: 13px;
      color: var(--text-primary);
    }
    .contributing-events {
      margin-top: var(--space-3);
      padding-top: var(--space-2);
      border-top: 1px solid var(--border-subtle);
    }
    .event-id-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }
    .event-chip {
      font-size: 11px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      color: var(--text-secondary);
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      text-decoration: none;
      transition: all 0.15s ease-in-out;
    }
    .event-chip:hover {
      border-color: var(--accent-teal);
      color: var(--accent-teal);
    }
    .policy-card {
      background: var(--bg-surface);
      padding: var(--space-3) var(--space-4);
      margin-bottom: var(--space-3);
      border-left: 3px solid var(--accent-teal);
    }
    .policy-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: var(--space-1);
    }
    .advisory-notice {
      display: flex;
      align-items: flex-start;
      gap: var(--space-2);
      padding: var(--space-3);
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.25);
      border-radius: var(--radius-sm);
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: var(--space-3);
    }
    .notice-bullet {
      color: var(--status-investigating);
      font-weight: 700;
    }
    .history-timeline {
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
      padding: var(--space-2) 0;
      position: relative;
    }
    .timeline-entry {
      display: flex;
      gap: var(--space-3);
    }
    .timeline-card {
      flex: 1;
      background: var(--bg-surface);
      padding: var(--space-3);
    }
    .timeline-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: var(--space-2);
    }
    .timeline-transition {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .transition-arrow {
      color: var(--text-muted);
      font-weight: 700;
    }
    .timeline-actor {
      font-size: 12px;
      margin-bottom: 4px;
    }
    .actor-label, .reason-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
      margin-right: 6px;
    }
    .reason-text {
      font-size: 13px;
      color: var(--text-primary);
    }
    /* Modal Styles */
    .modal-backdrop {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(9, 13, 22, 0.85);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: var(--space-4);
    }
    .modal-dialog {
      width: 100%;
      max-width: 520px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      box-shadow: var(--shadow-lg);
      padding: var(--space-5);
    }
    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: var(--space-3);
      border-bottom: 1px solid var(--border-subtle);
    }
    .modal-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .modal-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 16px;
      cursor: pointer;
    }
    .modal-body {
      padding: var(--space-4) 0;
    }
    .current-state-strip {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: 13px;
      padding-bottom: var(--space-2);
      border-bottom: 1px solid var(--border-subtle);
    }
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .form-label {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
    }
    .w-100 {
      width: 100%;
    }
    .char-counter {
      color: var(--text-muted);
      text-align: right;
    }
    .text-danger {
      color: var(--sev-critical);
    }
    .alert-box {
      display: flex;
      align-items: flex-start;
      gap: var(--space-2);
      padding: var(--space-3);
      border-radius: var(--radius-sm);
      font-size: 12px;
    }
    .alert-box.warning {
      background: var(--status-open-bg);
      border: 1px solid rgba(245, 158, 11, 0.35);
      color: var(--status-open);
    }
    .alert-box.error {
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
      color: var(--sev-critical);
    }
    .modal-footer {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: var(--space-3);
      padding-top: var(--space-3);
      border-top: 1px solid var(--border-subtle);
    }
    .empty-compact {
      font-size: 12px;
      padding: var(--space-4) 0;
      text-align: center;
    }
    .mt-4 { margin-top: var(--space-4); }
  `]
})
export class IncidentDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly api = inject(SecurityApiService);
  readonly auth = inject(AuthService);

  readonly incidentId = signal<string>('');
  readonly loading = signal<boolean>(true);
  readonly error = signal<ProblemDetail | null>(null);

  readonly incident = signal<IncidentResponse | null>(null);
  readonly evidence = signal<EvidenceResponse[]>([]);
  readonly history = signal<IncidentStatusHistoryResponse[]>([]);
  readonly policyDecisions = signal<PolicyDecisionResponse[]>([]);

  // Modal State
  readonly showStatusModal = signal<boolean>(false);
  readonly transitioning = signal<boolean>(false);
  readonly modalError = signal<string | null>(null);

  selectedTargetStatus = '';
  transitionReason = '';

  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      const id = params.get('id');
      if (id) {
        this.incidentId.set(id);
        this.loadIncidentWorkspace();
      }
    });
  }

  loadIncidentWorkspace(): void {
    const id = this.incidentId();
    if (!id) return;

    this.loading.set(true);
    this.error.set(null);

    // Fetch primary incident record
    this.api.getIncidentById(id).subscribe({
      next: (inc) => {
        this.incident.set(inc);
        this.loading.set(false);
        // Parallel load forensic auxiliary data
        this.loadEvidence(id);
        this.loadHistory(id);
        this.loadPolicyDecisions(id);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  private loadEvidence(id: string): void {
    this.api.getIncidentEvidence(id).subscribe({
      next: (data) => this.evidence.set(data),
      error: (err) => console.warn('[Aegis SOC] Failed to load evidence:', err)
    });
  }

  private loadHistory(id: string): void {
    this.api.getIncidentHistory(id).subscribe({
      next: (data) => this.history.set(data),
      error: (err) => console.warn('[Aegis SOC] Failed to load status history:', err)
    });
  }

  private loadPolicyDecisions(id: string): void {
    this.api.getIncidentPolicyDecisions(id).subscribe({
      next: (data) => this.policyDecisions.set(data),
      error: (err) => console.warn('[Aegis SOC] Failed to load policy decisions:', err)
    });
  }

  refresh(): void {
    this.loadIncidentWorkspace();
  }

  // Allowed transitions matching backend state machine
  readonly allowedTargetStatuses = computed(() => {
    const current = this.incident()?.status;
    if (!current) return [];

    switch (current) {
      case 'OPEN':
        return ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
      case 'INVESTIGATING':
        return ['CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
      case 'CONTAINED':
        return ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
      case 'RESOLVED':
      case 'FALSE_POSITIVE':
        return ['INVESTIGATING']; // Reopening requires SECURITY_ADMIN
      default:
        return [];
    }
  });

  isTerminalStatus(): boolean {
    const s = this.incident()?.status;
    return s === 'RESOLVED' || s === 'FALSE_POSITIVE';
  }

  openStatusModal(): void {
    this.selectedTargetStatus = '';
    this.transitionReason = '';
    this.modalError.set(null);
    this.showStatusModal.set(true);
  }

  closeStatusModal(): void {
    if (!this.transitioning()) {
      this.showStatusModal.set(false);
    }
  }

  canSubmitTransition(): boolean {
    if (!this.selectedTargetStatus) return false;
    const len = this.transitionReason.trim().length;
    if (len < 5 || len > 512) return false;

    // Check terminal reopen privilege
    if (this.isTerminalStatus() && !this.auth.isSecurityAdmin()) {
      return false;
    }

    return true;
  }

  submitStatusTransition(): void {
    if (!this.canSubmitTransition()) return;

    this.transitioning.set(true);
    this.modalError.set(null);

    const id = this.incidentId();
    this.api.updateIncidentStatus(id, {
      targetStatus: this.selectedTargetStatus as IncidentStatus,
      reason: this.transitionReason.trim()
    }).subscribe({
      next: (updatedInc) => {
        this.incident.set(updatedInc);
        this.transitioning.set(false);
        this.showStatusModal.set(false);
        // Refresh audit history
        this.loadHistory(id);
      },
      error: (err: ProblemDetail) => {
        this.transitioning.set(false);
        if (err.status === 409) {
          this.modalError.set(`Conflict: ${err.detail || 'Invalid status transition for this incident state.'}`);
        } else if (err.status === 403) {
          this.modalError.set(`Forbidden: Reopening terminal incidents requires SECURITY_ADMIN role.`);
        } else {
          this.modalError.set(err.detail || 'Failed to update incident status.');
        }
      }
    });
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
