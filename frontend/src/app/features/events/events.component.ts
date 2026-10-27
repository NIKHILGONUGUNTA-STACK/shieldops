import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="soc-page">
      <div class="soc-header">
        <div>
          <div class="breadcrumb">TELEMETRY / FORENSICS</div>
          <h1 class="page-title">Security Event Explorer</h1>
          <p class="page-subtitle">
            Search, filter, and inspect ingested HTTP telemetry records across API Gateway access logs.
          </p>
        </div>
      </div>

      <!-- Filter Shell Placeholder -->
      <div class="soc-card filter-shell">
        <div class="filter-grid">
          <input type="text" placeholder="Filter by Source IP..." class="form-input" disabled />
          <input type="text" placeholder="Filter by Customer UUID..." class="form-input" disabled />
          <select class="form-select" disabled>
            <option>All HTTP Statuses</option>
          </select>
          <select class="form-select" disabled>
            <option>All HTTP Methods</option>
          </select>
          <button class="btn btn-primary" disabled>Apply Filters</button>
        </div>
      </div>

      <!-- Construction Notice -->
      <div class="soc-card phase-notice">
        <div class="notice-icon">🚧</div>
        <div class="notice-content">
          <h3 class="notice-title">Event Explorer Backend Contract Ready (Phase 5.2)</h3>
          <p class="notice-text">
            The backend API <span class="mono text-teal">GET /api/v1/security/events</span> is fully implemented, indexed, and verified in Phase 5.2.
            The rich interactive UI grid with server-side pagination, sorting, and drill-down inspector will be activated in Phase 5.4.
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
    .filter-shell {
      padding: var(--space-4);
    }
    .filter-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: var(--space-3);
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
export class EventsComponent {}
