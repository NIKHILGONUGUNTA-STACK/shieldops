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

        <a routerLink="/overview" class="brand-link" title="Aegis Security Operations Center">
          <span class="brand-shield">🛡️</span>
          <span class="brand-name">AEGIS <span class="brand-accent">SOC</span></span>
        </a>

        <span class="env-pill">ACTIVE RECON</span>
      </div>

      <!-- Wallarm-Inspired Center Global Search & Telemetry Controls -->
      <div class="nav-center">
        <div class="global-search-container">
          <svg class="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
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

      <!-- User Profile & Session Controls (Wallarm Style) -->
      <div class="nav-right">
        <ng-container *ngIf="auth.isAuthenticated(); else unauthTpl">
          <div class="user-profile-card">
            <div class="user-avatar" [class.admin]="auth.isSecurityAdmin()">
              {{ getInitials() }}
            </div>
            <div class="user-details">
              <span class="username">{{ auth.userProfile()?.username || (auth.isSecurityAdmin() ? 'security-admin' : 'security-analyst') }}</span>
              <span class="user-role-label">
                {{ auth.isSecurityAdmin() ? 'SECURITY ADMIN' : 'SECURITY ANALYST' }}
              </span>
            </div>
            <span class="user-role-badge" [class.admin]="auth.isSecurityAdmin()">
              {{ auth.isSecurityAdmin() ? 'SEC-ADMIN' : 'ANALYST' }}
            </span>
          </div>

          <button (click)="logout()" class="btn btn-secondary btn-sm logout-btn" title="End SOC Session">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
              <polyline points="16 17 21 12 16 7"></polyline>
              <line x1="21" y1="12" x2="9" y2="12"></line>
            </svg>
            <span class="logout-label">Logout</span>
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
      height: 56px;
      background: var(--bg-header);
      border-bottom: 1px solid var(--border-default);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 var(--space-4);
      z-index: 100;
      position: sticky;
      top: 0;
      gap: var(--space-4);
    }

    .nav-left {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      flex-shrink: 0;
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
        align-items: center;
        justify-content: center;
      }
    }

    .brand-link {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      text-decoration: none;
      color: var(--text-primary);
      font-weight: 700;
      font-size: 15px;
      letter-spacing: 0.05em;
    }

    .brand-shield {
      font-size: 18px;
    }

    .brand-accent {
      color: var(--accent-teal);
    }

    .env-pill {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: rgba(20, 184, 166, 0.1);
      color: var(--accent-teal);
      border: 1px solid var(--accent-teal-border);
      font-weight: 600;
      font-family: var(--font-mono);
      letter-spacing: 0.04em;
    }

    .nav-center {
      display: flex;
      align-items: center;
      gap: var(--space-4);
      flex: 1;
      max-width: 600px;
      justify-content: center;
    }

    .global-search-container {
      position: relative;
      width: 100%;
      max-width: 380px;
    }

    .search-icon {
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      pointer-events: none;
    }

    .global-search-input {
      width: 100%;
      background: var(--bg-input);
      border: 1px solid var(--border-default);
      color: var(--text-primary);
      border-radius: var(--radius-full);
      padding: 6px 12px 6px 30px;
      font-size: 12px;
      font-family: inherit;
      transition: all 0.15s ease-in-out;
    }

    .global-search-input:focus {
      outline: none;
      border-color: var(--accent-teal);
      box-shadow: 0 0 0 2px rgba(20, 184, 166, 0.15);
    }

    .threat-status {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--text-secondary);
      background: var(--bg-surface);
      padding: 4px 10px;
      border-radius: var(--radius-full);
      border: 1px solid var(--border-subtle);
      white-space: nowrap;
    }

    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--accent-teal);
      box-shadow: 0 0 8px var(--accent-teal);
      animation: pulse 2s infinite;
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      flex-shrink: 0;
    }

    .user-profile-card {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      padding: 4px 10px;
    }

    .user-avatar {
      width: 26px;
      height: 26px;
      border-radius: 50%;
      background: var(--accent-teal-subtle);
      color: var(--accent-teal);
      border: 1px solid var(--accent-teal-border);
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
    }

    .user-avatar.admin {
      background: var(--sev-critical-bg);
      color: var(--sev-critical);
      border-color: var(--sev-critical-border);
    }

    .user-details {
      display: flex;
      flex-direction: column;
      line-height: 1.2;
    }

    .username {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .user-role-label {
      font-size: 9px;
      color: var(--text-muted);
      letter-spacing: 0.04em;
    }

    .user-role-badge {
      font-size: 9px;
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      background: var(--accent-teal-subtle);
      color: var(--accent-teal);
      font-weight: 700;
      border: 1px solid var(--accent-teal-border);
    }

    .user-role-badge.admin {
      background: var(--sev-critical-bg);
      color: var(--sev-critical);
      border-color: var(--sev-critical-border);
    }

    .logout-btn {
      display: flex;
      align-items: center;
      gap: 4px;
    }

    @media (max-width: 768px) {
      .nav-center {
        display: none;
      }
      .user-details {
        display: none;
      }
      .logout-label {
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

  getInitials(): string {
    const username = this.auth.userProfile()?.username || (this.auth.isSecurityAdmin() ? 'Admin' : 'Analyst');
    return username.substring(0, 2).toUpperCase();
  }

  onSearch(event: any): void {
    const val = event.target.value?.trim();
    if (val) {
      this.router.navigate(['/events'], { queryParams: { correlationId: val } });
    }
  }
}
