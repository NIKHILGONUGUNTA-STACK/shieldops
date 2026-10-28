import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { NAV_SECTIONS, NavSection, NavItem } from '../../../core/navigation/nav-registry';
import { LayoutService } from '../../../core/services/layout.service';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterLink, RouterLinkActive],
  template: `
    <aside class="soc-sidebar" [class.collapsed]="layout.isSidebarCollapsed()">
      <!-- Top Brand Header with ShieldOps Transparent Logo matching Wallarm Top-Left Placement -->
      <div class="sidebar-header" *ngIf="!layout.isSidebarCollapsed()">
        <a routerLink="/overview" class="brand-link" title="ShieldOps Security Operations Center">
          <img src="assets/shieldops-logo.png" alt="ShieldOps" class="brand-logo-img" />
        </a>
      </div>

      <!-- Collapsed Brand Header -->
      <div class="sidebar-header collapsed-header" *ngIf="layout.isSidebarCollapsed()">
        <a routerLink="/overview" class="brand-link" title="ShieldOps">
          <img src="assets/shieldops-logo.png" alt="ShieldOps" class="brand-logo-collapsed" />
        </a>
      </div>

      <!-- Navigation Items Container -->
      <div class="sidebar-scrollable">
        <nav class="sidebar-nav" role="navigation" aria-label="SOC Navigation">
          <ng-container *ngFor="let section of sections">
            <div class="nav-section-title" *ngIf="!layout.isSidebarCollapsed()">
              {{ section.title }}
            </div>
            <div class="section-divider" *ngIf="layout.isSidebarCollapsed()"></div>

            <div class="nav-items-group">
              <a
                *ngFor="let item of section.items"
                [routerLink]="item.path"
                routerLinkActive="active"
                class="nav-item"
                [attr.title]="layout.isSidebarCollapsed() ? (item.label + (item.badge ? ' (' + item.badge + ')' : '')) : null"
                [attr.aria-label]="item.label"
                (click)="onItemClick()"
              >
                <!-- SVG Icon Based on Item ID -->
                <span class="nav-icon" [ngSwitch]="item.icon">
                  <!-- Dashboard / Grid -->
                  <svg *ngSwitchCase="'dashboard'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="7" height="7"></rect>
                    <rect x="14" y="3" width="7" height="7"></rect>
                    <rect x="14" y="14" width="7" height="7"></rect>
                    <rect x="3" y="14" width="7" height="7"></rect>
                  </svg>
                  <!-- Alert Triangle / Incidents -->
                  <svg *ngSwitchCase="'alert-triangle'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                  </svg>
                  <!-- Activity / Waveform -->
                  <svg *ngSwitchCase="'activity'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                  </svg>
                  <!-- Git Merge / Campaigns -->
                  <svg *ngSwitchCase="'git-merge'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="18" cy="18" r="3"></circle>
                    <circle cx="6" cy="6" r="3"></circle>
                    <path d="M6 21V9a9 9 0 0 0 9 9"></path>
                  </svg>
                  <!-- File Search / Evidence -->
                  <svg *ngSwitchCase="'file-search'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <circle cx="11.5" cy="14.5" r="2.5"></circle>
                    <path d="M13.3 16.3l2.2 2.2"></path>
                  </svg>
                  <!-- Layers / API Inventory -->
                  <svg *ngSwitchCase="'layers'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                    <polyline points="2 17 12 22 22 17"></polyline>
                    <polyline points="2 12 12 17 22 12"></polyline>
                  </svg>
                  <!-- List / Filter -->
                  <svg *ngSwitchCase="'list-filter'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="8" y1="6" x2="21" y2="6"></line>
                    <line x1="8" y1="12" x2="21" y2="12"></line>
                    <line x1="8" y1="18" x2="21" y2="18"></line>
                    <line x1="3" y1="6" x2="3.01" y2="6"></line>
                    <line x1="3" y1="12" x2="3.01" y2="12"></line>
                    <line x1="3" y1="18" x2="3.01" y2="18"></line>
                  </svg>
                  <!-- File Code / Specifications -->
                  <svg *ngSwitchCase="'file-code'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <polyline points="10 13 8 15 10 17"></polyline>
                    <polyline points="14 13 16 15 14 17"></polyline>
                  </svg>
                  <!-- Database / Data Access -->
                  <svg *ngSwitchCase="'database'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
                    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
                    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
                  </svg>
                  <!-- Sliders / Detection Rules -->
                  <svg *ngSwitchCase="'sliders'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="4" y1="21" x2="4" y2="14"></line>
                    <line x1="4" y1="10" x2="4" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="12"></line>
                    <line x1="12" y1="8" x2="12" y2="3"></line>
                    <line x1="20" y1="21" x2="20" y2="16"></line>
                    <line x1="20" y1="12" x2="20" y2="3"></line>
                    <line x1="1" y1="14" x2="7" y2="14"></line>
                    <line x1="9" y1="8" x2="15" y2="8"></line>
                    <line x1="17" y1="16" x2="23" y2="16"></line>
                  </svg>
                  <!-- Shield Lock / Automated Response -->
                  <svg *ngSwitchCase="'shield-lock'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <rect x="9" y="11" width="6" height="4" rx="1"></rect>
                  </svg>
                  <!-- Scale / Policy Decisions -->
                  <svg *ngSwitchCase="'scale'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 3v18"></path>
                    <path d="M6 7l6-4 6 4"></path>
                    <path d="M6 7L3 14h6L6 7z"></path>
                    <path d="M18 7l-3 7h6l-3-7z"></path>
                  </svg>
                  <!-- History / Clock -->
                  <svg *ngSwitchCase="'history'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                  </svg>
                  <!-- CPU / System Health -->
                  <svg *ngSwitchCase="'cpu'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="4" y="4" width="16" height="16" rx="2"></rect>
                    <rect x="9" y="9" width="6" height="6"></rect>
                    <line x1="9" y1="1" x2="9" y2="4"></line>
                    <line x1="15" y1="1" x2="15" y2="4"></line>
                    <line x1="9" y1="20" x2="9" y2="23"></line>
                    <line x1="15" y1="20" x2="15" y2="23"></line>
                    <line x1="20" y1="9" x2="23" y2="9"></line>
                    <line x1="20" y1="14" x2="23" y2="14"></line>
                    <line x1="1" y1="9" x2="4" y2="9"></line>
                    <line x1="1" y1="14" x2="4" y2="14"></line>
                  </svg>
                  <!-- Default Bullet -->
                  <span *ngSwitchDefault class="nav-dot"></span>
                </span>

                <!-- Label with Inter Regular Font -->
                <span class="nav-label" *ngIf="!layout.isSidebarCollapsed()">{{ item.label }}</span>

                <!-- Badge for Planned Capabilities -->
                <span class="badge-planned nav-badge" *ngIf="!layout.isSidebarCollapsed() && item.badge">
                  {{ item.badge }}
                </span>
              </a>
            </div>
          </ng-container>
        </nav>
      </div>

      <!-- Wallarm-Style Bottom Footer: Advisory Pill + Theme Switch Pill + Collapse Toggle -->
      <div class="sidebar-footer">
        <div class="footer-left" *ngIf="!layout.isSidebarCollapsed()">
          <div class="footer-info">
            <div class="advisory-pill">
              <span class="pulse-dot"></span>
              <span class="advisory-text">ADVISORY MODE</span>
            </div>
            <span class="stack-tag mono">SHIELDOPS v5.5</span>
          </div>

          <div class="theme-toggle-container">
            <div class="theme-switch-pill">
              <button type="button" class="theme-pill-btn" title="Light theme (Planned Phase 6)">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="5"></circle>
                  <line x1="12" y1="1" x2="12" y2="3"></line>
                  <line x1="12" y1="21" x2="12" y2="23"></line>
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                  <line x1="1" y1="12" x2="3" y2="12"></line>
                  <line x1="21" y1="12" x2="23" y2="12"></line>
                </svg>
                <span>Light</span>
              </button>
              <button type="button" class="theme-pill-btn active" title="Dark theme active">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
                <span>Dark</span>
              </button>
            </div>
          </div>
        </div>

        <button
          (click)="layout.toggleSidebar()"
          class="collapse-btn"
          [attr.title]="layout.isSidebarCollapsed() ? 'Expand Sidebar' : 'Collapse Sidebar'"
          [attr.aria-label]="layout.isSidebarCollapsed() ? 'Expand Sidebar' : 'Collapse Sidebar'"
        >
          <svg *ngIf="!layout.isSidebarCollapsed()" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="11 19 4 12 11 5"></polyline>
            <polyline points="18 19 11 12 18 5"></polyline>
          </svg>
          <svg *ngIf="layout.isSidebarCollapsed()" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="13 19 20 12 13 5"></polyline>
            <polyline points="6 19 13 12 6 5"></polyline>
          </svg>
        </button>
      </div>
    </aside>
  `,
  styles: [`
    .soc-sidebar {
      width: 240px;
      min-width: 240px;
      height: 100vh;
      background: var(--bg-sidebar); /* #0C0C10 */
      border-right: 1px solid var(--border-default); /* #262329 */
      display: flex;
      flex-direction: column;
      position: relative;
      user-select: none;
      z-index: 20;
      transition: width 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .soc-sidebar.collapsed {
      width: 64px;
      min-width: 64px;
    }

    /* Top Brand Header matching Wallarm */
    .sidebar-header {
      padding: 14px 18px 12px;
      display: flex;
      align-items: center;
      height: 52px;
      border-bottom: 1px solid var(--border-subtle);
      flex-shrink: 0;
    }

    .sidebar-header.collapsed-header {
      justify-content: center;
      padding: 12px 0;
    }

    .brand-link {
      display: flex;
      align-items: center;
      text-decoration: none;
    }

    .brand-logo-img {
      height: 28px;
      max-width: 175px;
      object-fit: contain;
      display: block;
    }

    .brand-logo-collapsed {
      width: 28px;
      height: 28px;
      object-fit: contain;
    }

    /* Scrollable Navigation */
    .sidebar-scrollable {
      flex: 1;
      overflow-y: auto;
      overflow-x: hidden;
      padding: 12px 8px;
    }

    .sidebar-scrollable::-webkit-scrollbar {
      width: 3px;
    }

    .sidebar-scrollable::-webkit-scrollbar-thumb {
      background: var(--border-subtle);
      border-radius: var(--radius-full);
    }

    .nav-section-title {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--text-muted); /* #88838D */
      padding: 12px 12px 4px;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }

    .section-divider {
      height: 1px;
      background: var(--border-subtle);
      margin: 8px 8px;
    }

    .nav-items-group {
      display: flex;
      flex-direction: column;
      gap: 2px;
      margin-bottom: 8px;
    }

    /* Inter Regular font for tabs in sidebar */
    .nav-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 7px 12px;
      border-radius: 6px;
      color: var(--text-secondary); /* #AAA6AD */
      text-decoration: none;
      font-family: var(--font-sans); /* Inter */
      font-size: 13px;
      font-weight: 400; /* Inter Regular! */
      line-height: 1.4;
      letter-spacing: -0.01em;
      transition: all 0.15s ease-in-out;
      border-left: 3px solid transparent;
      position: relative;
    }

    .soc-sidebar.collapsed .nav-item {
      justify-content: center;
      padding: 10px 0;
      border-left: none;
      border-radius: 6px;
    }

    .nav-item:hover {
      background: var(--bg-hover); /* #18181B */
      color: var(--text-primary); /* #F2F0F2 */
    }

    .nav-item:hover .nav-icon {
      color: var(--text-primary);
    }

    /* Active State matching Wallarm */
    .nav-item.active {
      background: var(--bg-nav-active); /* #222124 */
      color: #FFFFFF;
      font-weight: 400; /* Inter Regular */
      border-left-color: var(--accent-orange); /* #FF7A1A */
    }

    .soc-sidebar.collapsed .nav-item.active {
      background: var(--bg-nav-active);
      color: var(--accent-orange);
    }

    .nav-item.active .nav-icon {
      color: var(--accent-orange);
    }

    .nav-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      color: var(--text-muted);
      flex-shrink: 0;
      transition: color 0.15s ease-in-out;
    }

    .nav-label {
      flex: 1;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-family: var(--font-sans);
      font-weight: 400; /* Inter Regular */
    }

    .nav-badge {
      flex-shrink: 0;
      font-size: 9px;
      font-family: var(--font-mono);
      font-weight: 600;
    }

    /* Wallarm-Style Footer with Light/Dark Switch Pill */
    .sidebar-footer {
      padding: 12px 14px;
      border-top: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--bg-sidebar);
      flex-shrink: 0;
    }

    .soc-sidebar.collapsed .sidebar-footer {
      justify-content: center;
      padding: 10px 0;
    }

    .theme-toggle-container {
      display: flex;
      align-items: center;
    }

    .theme-switch-pill {
      display: inline-flex;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-full);
      padding: 2px;
      gap: 2px;
    }

    .theme-pill-btn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 11px;
      padding: 3px 8px;
      border-radius: var(--radius-full);
      cursor: pointer;
      font-family: var(--font-sans);
      font-weight: 500;
      transition: all 0.15s ease;
    }

    .theme-pill-btn.active {
      background: var(--bg-nav-active);
      color: var(--text-primary);
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
    }

    .footer-left {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .footer-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .advisory-pill {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 9px;
      font-weight: 600;
      color: var(--accent-orange);
      font-family: var(--font-mono);
    }

    .pulse-dot {
      width: 5px;
      height: 5px;
      border-radius: 50%;
      background: var(--accent-orange);
      box-shadow: 0 0 5px var(--accent-orange);
    }

    .stack-tag {
      font-size: 9px;
      color: var(--text-muted);
    }

    .collapse-btn {
      background: transparent;
      border: 1px solid var(--border-default);
      color: var(--text-secondary);
      width: 26px;
      height: 26px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
    }

    .collapse-btn:hover {
      background: var(--bg-hover);
      color: var(--text-primary);
      border-color: var(--border-focus);
    }
  `]
})
export class SidebarComponent {
  readonly layout = inject(LayoutService);
  readonly sections: NavSection[] = NAV_SECTIONS;

  onItemClick(): void {
    if (this.layout.isMobileOpen()) {
      this.layout.closeMobile();
    }
  }
}
