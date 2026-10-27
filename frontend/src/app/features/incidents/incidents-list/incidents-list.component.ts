import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-incidents-list',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="soc-page">
      <div class="soc-header">
        <div>
          <div class="breadcrumb">INCIDENT RESPONSE / QUEUE</div>
          <h1 class="page-title">Active Incident Queue</h1>
          <p class="page-subtitle">
            Correlated intrusion campaigns requiring analyst triage, status progression, and remediation.
          </p>
        </div>
      </div>

      <!-- Construction Notice -->
      <div class="soc-card phase-notice">
        <div class="notice-icon">🚨</div>
        <div class="notice-content">
          <h3 class="notice-title">Incident Queue Backend APIs Ready (Phase 5.2)</h3>
          <p class="notice-text">
            Endpoints <span class="mono text-teal">GET /api/v1/security/incidents</span>,
            <span class="mono text-teal">PATCH /api/v1/security/incidents/&#123;id&#125;/status</span>, and
            <span class="mono text-teal">GET /api/v1/security/incidents/&#123;id&#125;/evidence</span> are active and verified.
            The paginated incident queue and batch triage view will be fully connected in Phase 5.4.
          </p>
          <div class="mt-3">
            <a routerLink="/overview" class="btn btn-secondary btn-sm">← Back to Overview</a>
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
    .breadcrumb {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--accent-teal);
      margin-bottom: var(--space-1);
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
    .phase-notice {
      display: flex;
      align-items: flex-start;
      gap: var(--space-4);
      padding: var(--space-6);
      border-left: 4px solid var(--sev-critical);
    }
    .notice-icon {
      font-size: 28px;
    }
    .notice-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: var(--space-1);
    }
    .notice-text {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .mt-3 {
      margin-top: var(--space-3);
    }
  `]
})
export class IncidentsListComponent {}
