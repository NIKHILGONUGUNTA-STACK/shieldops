import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';

@Component({
  selector: 'app-incident-detail',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="soc-page">
      <div class="soc-header">
        <div>
          <div class="breadcrumb">
            <a routerLink="/incidents" class="back-link">INCIDENTS</a> / INVESTIGATION
          </div>
          <h1 class="page-title">
            Incident Investigation: <span class="mono text-teal">{{ incidentId() }}</span>
          </h1>
          <p class="page-subtitle">
            Deep forensic timeline, contributing evidence, policy decisions, and status lifecycle history.
          </p>
        </div>

        <div>
          <a routerLink="/overview" class="btn btn-secondary btn-sm">← Back to Overview</a>
        </div>
      </div>

      <!-- Construction Notice -->
      <div class="soc-card phase-notice">
        <div class="notice-icon">🔬</div>
        <div class="notice-content">
          <h3 class="notice-title">Incident Detail Forensics (Phase 5.2 Endpoints Bound)</h3>
          <p class="notice-text">
            Incident ID <span class="mono text-teal">{{ incidentId() }}</span> route parameter successfully resolved.
            The complete multi-panel investigation layout (Evidence correlation, MITRE mapping, status transition modal, and audit timeline) will be fully wired in Phase 5.4.
          </p>
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
      color: var(--text-muted);
      margin-bottom: var(--space-1);
    }
    .back-link {
      color: var(--accent-teal);
      text-decoration: none;
    }
    .page-title {
      font-size: 20px;
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
      border-left: 4px solid var(--accent-teal);
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
  `]
})
export class IncidentDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  readonly incidentId = signal<string>('');

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id') || '';
    this.incidentId.set(id);
  }
}
