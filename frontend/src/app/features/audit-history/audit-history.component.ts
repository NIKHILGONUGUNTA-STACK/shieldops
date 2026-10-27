import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { IncidentStatusHistoryResponse, ProblemDetail } from '../../core/models/security.models';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Component({
  selector: 'app-audit-history',
  standalone: true,
  imports: [CommonModule, RouterLink, StatusBadgeComponent],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Incident Audit History</h1>
          <p class="soc-subtitle">
            Immutable chronological audit log of analyst triage decisions, lifecycle status changes, and authenticated rationale.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ historyRecords.length }}</span>
              <span class="soc-stat-sub">Audit Events</span>
            </div>
          </div>
          <button (click)="loadAuditHistory()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            {{ loading ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Error State -->
      <div *ngIf="error" class="error-banner" role="alert">
        <span class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF4D5A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </span>
        <div>
          <div class="error-title">{{ error.title }}</div>
          <div class="error-detail">{{ error.detail }}</div>
        </div>
        <button (click)="loadAuditHistory()" class="btn btn-secondary btn-sm retry-btn">Retry</button>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="loading-state">
        <div class="spinner"></div>
        <span>Compiling incident audit timeline...</span>
      </div>

      <!-- Empty State -->
      <div *ngIf="!loading && !error && historyRecords.length === 0" class="empty-state">
        <div class="empty-icon">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#6E7280" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <h3>No Audit Records Found</h3>
        <p>No analyst status transitions have been logged for current incidents.</p>
      </div>

      <!-- Audit History Table -->
      <div *ngIf="!loading && !error && historyRecords.length > 0" class="soc-table-container">
        <table class="soc-table" aria-label="Incident Lifecycle Audit History">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Incident ID</th>
              <th>Transition</th>
              <th>Actor</th>
              <th>Analyst Rationale</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let h of historyRecords">
              <td class="mono text-muted text-nowrap">{{ h.changedAt | date:'yyyy-MM-dd HH:mm:ss' }}</td>
              <td>
                <span class="mono text-teal">{{ h.incidentId.substring(0, 10) }}...</span>
              </td>
              <td>
                <div class="transition-cell">
                  <app-status-badge [status]="h.previousStatus"></app-status-badge>
                  <span class="transition-arrow">→</span>
                  <app-status-badge [status]="h.newStatus"></app-status-badge>
                </div>
              </td>
              <td>
                <span class="actor-badge mono" [class.admin]="h.changedBy.includes('admin')">
                  {{ h.changedBy }}
                </span>
              </td>
              <td class="reason-cell" [title]="h.changeReason">{{ h.changeReason }}</td>
              <td>
                <a [routerLink]="['/incidents', h.incidentId]" class="btn btn-secondary btn-sm">
                  View Incident →
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
    .transition-cell {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .transition-arrow {
      color: var(--text-muted);
      font-size: 12px;
    }
    .actor-badge {
      font-size: 11px;
      color: var(--accent-teal);
      background: var(--accent-teal-subtle);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .actor-badge.admin {
      color: var(--sev-critical);
      background: var(--sev-critical-bg);
    }
    .reason-cell {
      max-width: 380px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
      color: var(--text-secondary);
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
export class AuditHistoryComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  historyRecords: IncidentStatusHistoryResponse[] = [];
  loading = false;
  error: ProblemDetail | null = null;

  ngOnInit(): void {
    this.loadAuditHistory();
  }

  loadAuditHistory(): void {
    this.loading = true;
    this.error = null;

    this.api.getIncidents({ page: 0, size: 25 }).subscribe({
      next: (page) => {
        const incidents = page.incidents || [];
        if (incidents.length === 0) {
          this.historyRecords = [];
          this.loading = false;
          return;
        }

        const historyCalls = incidents.map(inc =>
          this.api.getIncidentHistory(inc.id).pipe(catchError(() => of([] as IncidentStatusHistoryResponse[])))
        );

        forkJoin(historyCalls).subscribe({
          next: (results) => {
            const flattened: IncidentStatusHistoryResponse[] = [];
            results.forEach(arr => flattened.push(...arr));
            // Sort by changedAt descending
            flattened.sort((a, b) => new Date(b.changedAt).getTime() - new Date(a.changedAt).getTime());
            this.historyRecords = flattened;
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
        this.historyRecords = [];
        this.loading = false;
      }
    });
  }
}
