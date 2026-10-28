import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, Router } from '@angular/router';
import { AuthService } from '../../../core/auth/auth.service';
import { LayoutService } from '../../../core/services/layout.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <header class="soc-navbar" role="banner">
      <div class="nav-left">
        <!-- Mobile Drawer Toggle -->
        <button
          (click)="layout.toggleMobile()"
          class="mobile-toggle-btn"
          aria-label="Toggle Navigation Menu"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="3" y1="12" x2="21" y2="12"></line>
            <line x1="3" y1="6" x2="21" y2="6"></line>
            <line x1="3" y1="18" x2="21" y2="18"></line>
          </svg>
        </button>

        <!-- Brand Name & Mode Indicator for Responsive Screens and Contract Tests -->
        <div class="brand-context">
          <span class="brand-name">SHIELDOPS</span>
          <span class="env-pill">ACTIVE RECON</span>
        </div>
      </div>

      <!-- Center Global Search Input matching Wallarm Style -->
      <div class="nav-center">
        <div class="global-search-container">
          <svg class="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#88838D" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input
            type="text"
            class="global-search-input"
            placeholder="Search telemetry, incidents, events... ⌘K"
            (keydown.enter)="onSearch($event)"
            aria-label="Global Security Search"
          />
        </div>

        <div class="threat-status">
          <span class="pulse-dot"></span>
          <span class="threat-label">ENGINE: ADVISORY MODE</span>
        </div>
      </div>

      <!-- User Profile & Action Controls matching Wallarm Style -->
      <div class="nav-right">
        <ng-container *ngIf="auth.isAuthenticated(); else unauthTpl">
          <div class="user-profile-pill">
            <div class="user-avatar-circle" [class.admin]="auth.isSecurityAdmin()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
              </svg>
            </div>
            <div class="user-text-col">
              <span class="username">{{ auth.userProfile()?.username || (auth.isSecurityAdmin() ? 'security-admin' : 'security-analyst') }}</span>
              <span class="user-display-email">{{ auth.userProfile()?.email || (auth.isSecurityAdmin() ? 'admin@shieldops.local' : 'analyst@shieldops.local') }}</span>
            </div>
            <span class="user-role-badge" [class.admin]="auth.isSecurityAdmin()">
              {{ auth.isSecurityAdmin() ? 'SEC-ADMIN' : 'ANALYST' }}
            </span>
          </div>

          <!-- Settings Button -->
          <a routerLink="/settings" class="nav-icon-btn" title="Platform Settings">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
          </a>

          <!-- Logout Button -->
          <button (click)="logout()" class="nav-icon-btn logout-btn" title="End SOC Session">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
              <polyline points="16 17 21 12 16 7"></polyline>
              <line x1="21" y1="12" x2="9" y2="12"></line>
            </svg>
          </button>
        </ng-container>

        <ng-template #unauthTpl>
          <a routerLink="/login" class="btn btn-primary btn-sm">SOC Login</a>
        </ng-template>
      </div>
    </header>
  `,
  styles: [`
    .soc-navbar {
      height: 52px;
      min-height: 52px;
      background: transparent;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      gap: 16px;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .nav-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .mobile-toggle-btn {
      display: none;
      background: transparent;
      border: 1px solid var(--border-default);
      color: var(--text-secondary);
      border-radius: var(--radius-sm);
      padding: 4px;
      cursor: pointer;
    }

    @media (max-width: 900px) {
      .mobile-toggle-btn {
        display: flex;
      }
    }

    .brand-context {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .brand-name {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }

    .env-pill {
      font-size: 9px;
      padding: 2px 6px;
      border-radius: 4px;
      background: rgba(255, 122, 26, 0.1);
      color: var(--accent-orange);
      border: 1px solid rgba(255, 122, 26, 0.25);
      font-weight: 700;
      font-family: var(--font-mono);
      letter-spacing: 0.04em;
    }

    .nav-center {
      display: flex;
      align-items: center;
      gap: 16px;
      flex: 1;
      max-width: 540px;
    }

    .global-search-container {
      position: relative;
      width: 100%;
      max-width: 320px;
    }

    .search-icon {
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      pointer-events: none;
    }

    .global-search-input {
      width: 100%;
      background: var(--bg-input);
      border: 1px solid var(--border-input);
      color: var(--text-primary);
      border-radius: 6px;
      padding: 6px 12px 6px 30px;
      font-size: 12px;
      font-family: var(--font-sans);
      transition: all 0.15s ease-in-out;
    }

    .global-search-input:focus {
      outline: none;
      border-color: var(--border-focus);
      background: #0D0D10;
    }

    .threat-status {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 10px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      white-space: nowrap;
    }

    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-orange);
      box-shadow: 0 0 6px var(--accent-orange);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.35; }
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .user-profile-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: 6px;
      padding: 4px 10px;
    }

    .user-avatar-circle {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.06);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-secondary);
    }

    .user-avatar-circle.admin {
      background: rgba(255, 122, 26, 0.15);
      color: var(--accent-orange);
    }

    .user-text-col {
      display: flex;
      flex-direction: column;
      line-height: 1.15;
    }

    .username {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .user-display-email {
      font-size: 9px;
      color: var(--text-muted);
    }

    .user-role-badge {
      font-size: 9px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 3px;
      background: rgba(74, 108, 255, 0.15);
      color: #8CA3FF;
      font-family: var(--font-mono);
    }

    .user-role-badge.admin {
      background: rgba(255, 122, 26, 0.15);
      color: var(--accent-orange);
    }

    .nav-icon-btn {
      width: 30px;
      height: 30px;
      border-radius: 6px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.15s ease;
      text-decoration: none;
    }

    .nav-icon-btn:hover {
      background: var(--bg-hover);
      color: var(--text-primary);
      border-color: var(--border-focus);
    }

    @media (max-width: 800px) {
      .nav-center, .brand-context {
        display: none;
      }
    }
  `]
})
export class NavbarComponent {
  readonly auth = inject(AuthService);
  readonly layout = inject(LayoutService);
  private readonly router = inject(Router);

  logout(): void {
    this.auth.logout();
  }

  onSearch(event: any): void {
    const val = (event?.target?.value || '').trim();
    if (val) {
      this.router.navigate(['/events'], { queryParams: { correlationId: val } });
    }
  }
}
