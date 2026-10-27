import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { IncidentResponse, ProblemDetail } from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';

@Component({
  selector: 'app-bola-detection',
  standalone: true,
  imports: [CommonModule, RouterLink, SeverityBadgeComponent, StatusBadgeComponent],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">BOLA Protection & Telemetry</h1>
          <p class="soc-subtitle">
            Dedicated Broken Object Level Authorization (OWASP API1:2023) sliding-window analysis and anti-affinity correlation.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <polyline points="9 12 11 14 15 10"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ incidents.length }}</span>
              <span class="soc-stat-sub">BOLA Incidents</span>
            </div>
          </div>
          <button (click)="loadBolaIncidents()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            {{ loading ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Architectural Mechanism Grid -->
      <div class="mechanisms-grid">
        <div class="mech-card">
          <div class="mech-header">
            <span class="mech-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
            </span>
            <h3>Redis Sliding Window</h3>
          </div>
          <p class="mech-desc">
            Tracks distinct resource IDs accessed per authenticated subject within a 300-second rolling TTL window.
            Threshold: 3 unauthorized attempts across ≥ 2 distinct resources triggers incident creation.
          </p>
          <div class="mech-badge mono">WINDOW: 300s | THRESHOLD: 3 ATTEMPTS / ≥ 2 RESOURCES</div>
        </div>

        <div class="mech-card">
          <div class="mech-header">
            <span class="mech-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="2" y1="12" x2="22" y2="12"></line>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
              </svg>
            </span>
            <h3>Anti-Affinity Cross-Tenant Defense</h3>
          </div>
          <p class="mech-desc">
            Mitigates false positives from shared NAT gateways or corporate proxies by combining subject IDs with
            cross-tenant verification rather than relying exclusively on source IP addresses.
          </p>
          <div class="mech-badge mono">DEFENSE: TENANT-SUBJECT BINDING</div>
        </div>

        <div class="mech-card">
          <div class="mech-header">
            <span class="mech-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="20" x2="18" y2="10"></line>
                <line x1="12" y1="20" x2="12" y2="4"></line>
                <line x1="6" y1="20" x2="6" y2="14"></line>
              </svg>
            </span>
            <h3>Dual-Group Stream Consumption</h3>
          </div>
          <p class="mech-desc">
            Telemetry is streamed via Redis consumer group <code>aegis-detectors</code> with verified pending-entry
            recovery to guarantee zero event loss across consumer reconnections.
          </p>
          <div class="mech-badge mono">GROUP: aegis-detectors</div>
        </div>
      </div>

      <!-- Authorization Outcome Interpretation Notice -->
      <div class="bola-interpretation-banner">
        <div class="interpretation-header">
          <span class="interpretation-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
              <polyline points="2 17 12 22 22 17"></polyline>
              <polyline points="2 12 12 17 22 12"></polyline>
            </svg>
          </span>
          <strong>Authorization Outcome & Breach Distinction</strong>
        </div>
        <p class="interpretation-desc">
          BOLA detector RULE-BOLA-01 evaluates authenticated callers receiving HTTP 403 Forbidden responses across multiple resources.
          The 403 Forbidden outcome confirms unauthorized requests were rejected at the service authorization layer.
          These findings represent attempted object-level enumeration; they do not indicate unauthorized data leakage or compromised customer data.
        </p>
      </div>

      <!-- Live BOLA Incidents Table -->
      <div class="incidents-section">
        <h2 class="section-heading">BOLA Detection Incidents Queue</h2>

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
          <button (click)="loadBolaIncidents()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
        </div>

        <div *ngIf="loading" class="loading-state">
          <div class="spinner"></div>
          <span>Retrieving BOLA security incidents...</span>
        </div>

        <div *ngIf="!loading && !error && incidents.length === 0" class="empty-state">
          <div class="empty-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <polyline points="9 12 11 14 15 10"></polyline>
            </svg>
          </div>
          <h3>Zero BOLA Incidents</h3>
          <p>No Broken Object Level Authorization violations detected in current operations.</p>
        </div>

        <div *ngIf="!loading && !error && incidents.length > 0" class="soc-table-container">
          <table class="soc-table" aria-label="BOLA Incidents Queue">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Target Resource</th>
                <th>Status</th>
                <th>Event Count</th>
                <th>First Detected</th>
                <th>Summary</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let inc of incidents">
                <td>
                  <app-severity-badge [severity]="inc.severity"></app-severity-badge>
                </td>
                <td class="mono text-teal">{{ inc.targetEntityValue }}</td>
                <td>
                  <app-status-badge [status]="inc.status"></app-status-badge>
                </td>
                <td class="mono font-semibold">{{ inc.eventCount }}</td>
                <td class="mono text-muted">{{ inc.firstDetectedAt | date:'yyyy-MM-dd HH:mm' }}</td>
                <td class="summary-cell" [title]="inc.summary">{{ inc.summary }}</td>
                <td>
                  <a [routerLink]="['/incidents', inc.id]" class="btn btn-secondary btn-sm">
                    Investigate →
                  </a>
                </td>
              </tr>
            </tbody>
          </table>
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
      margin-bottom: var(--space-6);
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
    .mechanisms-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: var(--space-4);
      margin-bottom: var(--space-6);
    }
    .mech-card {
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      padding: var(--space-4);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .mech-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      margin-bottom: var(--space-2);
    }
    .mech-header h3 {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .mech-icon {
      font-size: 18px;
    }
    .mech-desc {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
      margin-bottom: var(--space-3);
    }
    .mech-badge {
      font-size: 10px;
      color: var(--accent-teal);
      background: var(--accent-teal-subtle);
      border: 1px solid var(--accent-teal-border);
      padding: 3px 8px;
      border-radius: var(--radius-sm);
      display: inline-block;
      width: fit-content;
    }
    .bola-interpretation-banner {
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid var(--border-default);
      border-left: 3px solid var(--accent-teal);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      margin-bottom: var(--space-6);
    }
    .interpretation-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 6px;
    }
    .interpretation-icon {
      font-size: 16px;
    }
    .interpretation-desc {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
      margin: 0;
    }
    .section-heading {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: var(--space-3);
    }
    .summary-cell {
      max-width: 320px;
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
export class BolaDetectionComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  incidents: IncidentResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  ngOnInit(): void {
    this.loadBolaIncidents();
  }

  loadBolaIncidents(): void {
    this.loading = true;
    this.error = null;

    this.api.getIncidents({ threatCategory: 'BOLA', page: 0, size: 20 }).subscribe({
      next: (page) => {
        this.incidents = page.incidents || [];
        this.loading = false;
      },
      error: (err) => {
        this.error = err;
        this.incidents = [];
        this.loading = false;
      }
    });
  }
}
