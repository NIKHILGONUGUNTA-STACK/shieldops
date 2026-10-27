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
            <div class="soc-stat-icon teal">🛡️</div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ incidents.length }}</span>
              <span class="soc-stat-sub">BOLA Incidents</span>
            </div>
          </div>
          <button (click)="loadBolaIncidents()" class="btn btn-secondary btn-sm" [disabled]="loading">
            {{ loading ? 'Refreshing...' : '↻ Refresh' }}
          </button>
        </div>
      </div>

      <!-- Architectural Mechanism Grid -->
      <div class="mechanisms-grid">
        <div class="mech-card">
          <div class="mech-header">
            <span class="mech-icon">⏱️</span>
            <h3>Redis Sliding Window</h3>
          </div>
          <p class="mech-desc">
            Tracks distinct resource IDs accessed per authenticated subject within a 60-second rolling TTL window.
            Threshold: 3 unauthorized distinct resources triggers incident creation.
          </p>
          <div class="mech-badge mono">WINDOW: 60s | THRESHOLD: 3</div>
        </div>

        <div class="mech-card">
          <div class="mech-header">
            <span class="mech-icon">🌐</span>
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
            <span class="mech-icon">📊</span>
            <h3>Dual-Group Stream Consumption</h3>
          </div>
          <p class="mech-desc">
            Telemetry is streamed via Redis consumer group <code>aegis-detectors</code> with verified pending-entry
            recovery to guarantee zero event loss across consumer reconnections.
          </p>
          <div class="mech-badge mono">GROUP: aegis-detectors</div>
        </div>
      </div>

      <!-- Live BOLA Incidents Table -->
      <div class="incidents-section">
        <h2 class="section-heading">BOLA Detection Incidents Queue</h2>

        <div *ngIf="error" class="error-banner" role="alert">
          <span class="error-icon">⚠️</span>
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
          <div class="empty-icon">🛡️</div>
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
        this.loading = false;
      }
    });
  }
}
