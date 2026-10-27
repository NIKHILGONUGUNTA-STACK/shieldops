import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { IncidentResponse, ProblemDetail } from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';

@Component({
  selector: 'app-campaigns',
  standalone: true,
  imports: [CommonModule, RouterLink, SeverityBadgeComponent, StatusBadgeComponent],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Attack Campaigns</h1>
          <p class="soc-subtitle">
            Correlated multi-vector attack campaigns, distributed attacker reconnaissance, and multi-resource escalations.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon red">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <circle cx="12" cy="12" r="6"></circle>
                <circle cx="12" cy="12" r="2"></circle>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ campaigns.length }}</span>
              <span class="soc-stat-sub">Active Campaigns</span>
            </div>
          </div>
          <button (click)="loadCampaigns()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            {{ loading ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Engine Correlation Notice -->
      <div class="correlation-notice">
        <span class="notice-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
          </svg>
        </span>
        <div>
          <strong>MultiVectorCampaignCorrelator:</strong> Cross-rule contextual correlation merges related events
          across disparate API endpoints into unified incident campaigns using Bayesian heuristic confidence combination.
        </div>
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
        <button (click)="loadCampaigns()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Evaluating correlated attack campaigns...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && campaigns.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
        </div>
        <h3>No Correlated Campaigns Detected</h3>
        <p>No multi-vector or multi-resource intrusion campaigns currently exceed the correlation threshold.</p>
      </div>

      <!-- Campaigns Table -->
      <div *ngIf="!loading && !error && campaigns.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Correlated Attack Campaigns">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Campaign / Title</th>
              <th>Category</th>
              <th>Status</th>
              <th>Target Entity</th>
              <th>Event Count</th>
              <th>First Detected</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let camp of campaigns">
              <td>
                <app-severity-badge [severity]="camp.severity"></app-severity-badge>
              </td>
              <td class="campaign-title-cell">
                <a [routerLink]="['/incidents', camp.id]" class="campaign-title-link">
                  {{ camp.summary }}
                </a>
                <div class="campaign-fp mono text-muted">{{ camp.incidentFingerprint }}</div>
              </td>
              <td>
                <span class="category-chip">{{ camp.threatCategory }}</span>
              </td>
              <td>
                <app-status-badge [status]="camp.status"></app-status-badge>
              </td>
              <td class="mono text-teal">{{ camp.targetEntityValue }}</td>
              <td class="mono font-semibold">{{ camp.eventCount }}</td>
              <td class="mono text-muted">{{ camp.firstDetectedAt | date:'yyyy-MM-dd HH:mm' }}</td>
              <td>
                <a [routerLink]="['/incidents', camp.id]" class="btn btn-secondary btn-sm investigate-btn">
                  Investigate →
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
    .notice-icon {
      font-size: 16px;
      color: var(--accent-teal);
    }
    .campaign-title-cell {
      max-width: 380px;
    }
    .campaign-title-link {
      color: var(--text-primary);
      text-decoration: none;
      font-weight: 600;
      font-size: 13px;
    }
    .campaign-title-link:hover {
      color: var(--accent-teal);
    }
    .campaign-fp {
      font-size: 10px;
      margin-top: 2px;
    }
    .category-chip {
      font-size: 10px;
      font-weight: 700;
      color: var(--accent-violet);
      background: var(--accent-violet-subtle);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      font-family: var(--font-mono);
    }
    .investigate-btn {
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
export class CampaignsComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  campaigns: IncidentResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  ngOnInit(): void {
    this.loadCampaigns();
  }

  loadCampaigns(): void {
    this.loading = true;
    this.error = null;

    // Retrieve incidents and filter for campaigns or multi-vector correlated threats
    this.api.getIncidents({ page: 0, size: 50 }).subscribe({
      next: (page) => {
        // Strictly filter for correlated multi-vector campaigns or complex multi-rule intrusions
        this.campaigns = (page.incidents || []).filter(inc =>
          inc.threatCategory === 'MULTI_VECTOR_CAMPAIGN' ||
          inc.threatCategory === 'COMPLEX_INTRUSION' ||
          inc.summary?.includes('Multi-Vector') ||
          inc.summary?.includes('Campaign')
        );
        this.loading = false;
      },
      error: (err) => {
        this.error = err;
        this.campaigns = [];
        this.loading = false;
      }
    });
  }
}
