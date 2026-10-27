import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { PolicyDecisionResponse, ProblemDetail } from '../../core/models/security.models';

@Component({
  selector: 'app-policy-decisions',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Advisory Policy Decisions</h1>
          <p class="soc-subtitle">
            Non-blocking security response recommendations and policy enforcement logs.
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
              <span class="soc-stat-val">{{ decisions.length }}</span>
              <span class="soc-stat-sub">Persisted Decisions</span>
            </div>
          </div>
          <button (click)="loadDecisions()" class="btn btn-secondary btn-sm" [disabled]="loading">
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
          <strong>Aegis Non-Intrusive Advisory Invariant</strong>
        </div>
        <p class="advisory-desc">
          To maintain zero false-positive service disruption against legitimate customer banking traffic,
          Aegis operates in strict <code>ADVISORY MODE</code>. All policy evaluations produce recommendations
          (such as <code>LOG_ALERT</code>) for analyst review and never execute autonomous traffic blocking,
          rate throttling, or session invalidation.
        </p>
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
        <button (click)="loadDecisions()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Retrieving advisory policy decision logs...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && decisions.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
        </div>
        <h3>No Policy Decisions Logged</h3>
        <p>No advisory policy evaluations have been triggered by recent security incidents.</p>
      </div>

      <!-- Decisions Table -->
      <div *ngIf="!loading && !error && decisions.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Advisory Policy Decisions Log">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Recommended Action</th>
              <th>Enforcement Level</th>
              <th>Target Entity</th>
              <th>Heuristic Confidence</th>
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
              <td>
                <div class="confidence-bar-wrap" [title]="'Empirical heuristic score: ' + (dec.confidenceScore * 100).toFixed(0) + '%'">
                  <div class="confidence-bar">
                    <div class="confidence-fill" [style.width.%]="dec.confidenceScore * 100"></div>
                  </div>
                  <span class="confidence-val mono">{{ (dec.confidenceScore * 100).toFixed(0) }}%</span>
                </div>
              </td>
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
    .action-pill {
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-amber);
      background: var(--accent-amber-subtle);
      border: 1px solid var(--accent-amber-border);
      padding: 2px 6px;
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
      background: var(--accent-teal);
      border-radius: var(--radius-full);
    }
    .confidence-val {
      font-size: 11px;
      color: var(--text-primary);
      width: 32px;
      text-align: right;
    }
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
  `]
})
export class PolicyDecisionsComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  decisions: PolicyDecisionResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  ngOnInit(): void {
    this.loadDecisions();
  }

  loadDecisions(): void {
    this.loading = true;
    this.error = null;

    this.api.getRecentPolicyDecisions(0, 50).subscribe({
      next: (data) => {
        this.decisions = data || [];
        this.loading = false;
      },
      error: (err) => {
        this.error = err;
        this.decisions = [];
        this.loading = false;
      }
    });
  }
}
