import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { EvidenceResponse, ProblemDetail } from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Component({
  selector: 'app-evidence',
  standalone: true,
  imports: [CommonModule, RouterLink, SeverityBadgeComponent],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Evidence Explorer</h1>
          <p class="soc-subtitle">
            Forensic detection evidence records, heuristic confidence evaluation, and contributing event attributions.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">🔬</div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ evidenceList.length }}</span>
              <span class="soc-stat-sub">Persisted Evidence Items</span>
            </div>
          </div>
          <button (click)="loadAllEvidence()" class="btn btn-secondary btn-sm" [disabled]="loading">
            {{ loading ? 'Refreshing...' : '↻ Refresh' }}
          </button>
        </div>
      </div>

      <!-- Heuristic Confidence Notice -->
      <div class="heuristic-notice">
        <span class="notice-icon">ℹ️</span>
        <div>
          <strong>Empirical Heuristic Metric:</strong> Confidence scores are derived from empirical Bayesian rule combination
          and sliding-window resource counts. They do not represent calibrated frequentist or statistical probabilities.
        </div>
      </div>

      <!-- Error State -->
      <div *ngIf="error" class="error-banner" role="alert">
        <span class="error-icon">⚠️</span>
        <div>
          <div class="error-title">{{ error.title }}</div>
          <div class="error-detail">{{ error.detail }}</div>
        </div>
        <button (click)="loadAllEvidence()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Aggregating forensic detection evidence...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && evidenceList.length === 0" class="empty-state">
        <div class="empty-icon">🛡️</div>
        <h3>No Evidence Records Found</h3>
        <p>No detection evidence has been persisted for current security incidents.</p>
      </div>

      <!-- Evidence Table -->
      <div *ngIf="!loading && !error && evidenceList.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Detection Evidence Records">
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Severity</th>
              <th>Heuristic Confidence</th>
              <th>Trigger Condition</th>
              <th>Resources</th>
              <th>Contributing Events</th>
              <th>Associated Incident</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let ev of evidenceList">
              <td>
                <span class="rule-id-pill mono">{{ ev.ruleId }}</span>
                <span class="rule-version text-muted mono">v{{ ev.ruleVersion }}</span>
              </td>
              <td>
                <app-severity-badge [severity]="ev.severity"></app-severity-badge>
              </td>
              <td>
                <div class="confidence-bar-wrap" [title]="'Empirical heuristic score: ' + (ev.confidenceScore * 100).toFixed(0) + '%'">
                  <div class="confidence-bar">
                    <div class="confidence-fill" [style.width.%]="ev.confidenceScore * 100"></div>
                  </div>
                  <span class="confidence-val mono">{{ (ev.confidenceScore * 100).toFixed(0) }}%</span>
                </div>
              </td>
              <td class="condition-cell" [title]="ev.triggerCondition">{{ ev.triggerCondition }}</td>
              <td class="mono font-semibold">{{ ev.distinctResourcesCount }}</td>
              <td>
                <div class="event-chips-list">
                  <a
                    *ngFor="let evtId of (ev.contributingEventIds || []).slice(0, 3)"
                    [routerLink]="['/events']"
                    [queryParams]="{ correlationId: evtId }"
                    class="event-chip mono"
                    [title]="'Inspect telemetry trace ' + evtId"
                  >
                    {{ evtId.substring(0, 8) }}...
                  </a>
                  <span *ngIf="(ev.contributingEventIds || []).length > 3" class="text-muted text-2xs">
                    +{{ ev.contributingEventIds.length - 3 }} more
                  </span>
                </div>
              </td>
              <td>
                <a [routerLink]="['/incidents', ev.incidentId]" class="btn btn-secondary btn-sm link-btn">
                  Incident →
                </a>
              </td>
            </tr>
          </tbody>
        </table>
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
    .heuristic-notice {
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
    .notice-icon {
      font-size: 16px;
      color: var(--accent-teal);
    }
    .rule-id-pill {
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-teal);
      background: var(--accent-teal-subtle);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .rule-version {
      font-size: 10px;
      margin-left: 4px;
    }
    .confidence-bar-wrap {
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 90px;
    }
    .confidence-bar {
      flex: 1;
      height: 6px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: var(--radius-full);
      overflow: hidden;
    }
    .confidence-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--accent-teal), var(--accent-amber));
      border-radius: var(--radius-full);
    }
    .confidence-val {
      font-size: 11px;
      color: var(--text-primary);
      width: 32px;
      text-align: right;
    }
    .condition-cell {
      max-width: 280px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
    }
    .event-chips-list {
      display: flex;
      align-items: center;
      gap: 4px;
      flex-wrap: wrap;
    }
    .event-chip {
      font-size: 10px;
      color: var(--accent-teal);
      background: rgba(20, 184, 166, 0.08);
      border: 1px solid var(--accent-teal-border);
      padding: 1px 5px;
      border-radius: var(--radius-sm);
      text-decoration: none;
    }
    .event-chip:hover {
      text-decoration: underline;
    }
    .link-btn {
      white-space: nowrap;
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
  `]
})
export class EvidenceComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  evidenceList: EvidenceResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  ngOnInit(): void {
    this.loadAllEvidence();
  }

  loadAllEvidence(): void {
    this.loading = true;
    this.error = null;

    this.api.getIncidents({ page: 0, size: 20 }).subscribe({
      next: (page) => {
        const incidents = page.incidents || [];
        if (incidents.length === 0) {
          this.evidenceList = [];
          this.loading = false;
          return;
        }

        // Fetch evidence across available incidents concurrently
        const evidenceCalls = incidents.map(inc =>
          this.api.getIncidentEvidence(inc.id).pipe(catchError(() => of([] as EvidenceResponse[])))
        );

        forkJoin(evidenceCalls).subscribe({
          next: (results) => {
            const flattened: EvidenceResponse[] = [];
            results.forEach(arr => flattened.push(...arr));
            this.evidenceList = flattened;
            this.loading = false;
          },
          error: (err) => {
            this.error = err;
            this.loading = false;
          }
        });
      },
      error: (err) => {
        this.error = err;
        this.loading = false;
      }
    });
  }
}
