import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, RouterLinkActive } from '@angular/router';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterLink, RouterLinkActive],
  template: `
    <aside class="soc-sidebar">
      <nav class="sidebar-nav">
        <div class="nav-section-title">COMMAND & CONTROL</div>
        <a routerLink="/overview" routerLinkActive="active" class="nav-item">
          <span class="nav-icon">📊</span>
          <span class="nav-label">Security Overview</span>
        </a>
        <a routerLink="/incidents" routerLinkActive="active" class="nav-item">
          <span class="nav-icon">🚨</span>
          <span class="nav-label">Incident Queue</span>
        </a>
        <a routerLink="/events" routerLinkActive="active" class="nav-item">
          <span class="nav-icon">🔍</span>
          <span class="nav-label">Event Explorer</span>
        </a>

        <div class="nav-section-title" style="margin-top: var(--space-6);">CORRELATION ENGINES</div>
        <div class="engine-badge-list">
          <div class="engine-item">
            <span class="engine-dot active"></span>
            <span class="mono">RULE-BOLA-01</span>
          </div>
          <div class="engine-item">
            <span class="engine-dot active"></span>
            <span class="mono">RULE-AUTH-01</span>
          </div>
          <div class="engine-item">
            <span class="engine-dot active"></span>
            <span class="mono">RULE-DATA-01</span>
          </div>
          <div class="engine-item">
            <span class="engine-dot active"></span>
            <span class="mono">RULE-RATE-01</span>
          </div>
          <div class="engine-item">
            <span class="engine-dot active"></span>
            <span class="mono">RULE-PROBE-01</span>
          </div>
          <div class="engine-item">
            <span class="engine-dot active"></span>
            <span class="mono">RULE-INJ-01</span>
          </div>
        </div>
      </nav>

      <div class="sidebar-footer">
        <div class="health-indicator">
          <span class="health-dot"></span>
          <span class="mono text-muted">STACK: POSTGRES-V3</span>
        </div>
      </div>
    </aside>
  `,
  styles: [`
    .soc-sidebar {
      width: 220px;
      min-width: 220px;
      background: var(--bg-sidebar);
      border-right: 1px solid var(--border-default);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: calc(100vh - 52px);
      padding: var(--space-4) var(--space-2);
    }
    .nav-section-title {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      padding: var(--space-1) var(--space-3);
      margin-bottom: var(--space-1);
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      padding: 9px 12px;
      border-radius: var(--radius-sm);
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: all 0.15s ease-in-out;
      margin-bottom: 2px;
    }
    .nav-item:hover {
      background: var(--bg-surface);
      color: var(--text-primary);
    }
    .nav-item.active {
      background: var(--accent-teal-subtle);
      color: var(--accent-teal);
      border-left: 3px solid var(--accent-teal);
      font-weight: 600;
    }
    .nav-icon {
      font-size: 15px;
    }
    .engine-badge-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding: 0 var(--space-3);
    }
    .engine-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--text-muted);
    }
    .engine-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--text-muted);
    }
    .engine-dot.active {
      background: var(--accent-teal);
    }
    .sidebar-footer {
      padding: var(--space-2) var(--space-3);
      border-top: 1px solid var(--border-subtle);
    }
    .health-indicator {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
    }
    .health-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--status-resolved);
    }
  `]
})
export class SidebarComponent {}
