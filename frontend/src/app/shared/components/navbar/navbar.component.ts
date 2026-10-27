import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../../core/auth/auth.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <header class="soc-navbar">
      <div class="nav-left">
        <a routerLink="/overview" class="brand-link">
          <span class="brand-shield">🛡️</span>
          <span class="brand-name">AEGIS <span class="brand-accent">SOC</span></span>
        </a>
        <span class="env-pill">ACTIVE RECON</span>
      </div>

      <div class="nav-center">
        <div class="threat-status">
          <span class="pulse-dot"></span>
          <span class="threat-label">ENGINE: ADVISORY MODE</span>
        </div>
      </div>

      <div class="nav-right">
        <ng-container *ngIf="auth.isAuthenticated(); else unauthTpl">
          <div class="user-chip">
            <span class="user-role-badge" [class.admin]="auth.isSecurityAdmin()">
              {{ auth.isSecurityAdmin() ? 'SEC-ADMIN' : 'ANALYST' }}
            </span>
            <span class="username mono">{{ auth.userProfile()?.username || 'analyst' }}</span>
          </div>
          <button (click)="logout()" class="btn btn-secondary btn-sm" title="End SOC Session">
            Logout
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
      background: var(--bg-header);
      border-bottom: 1px solid var(--border-default);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 var(--space-4);
      z-index: 100;
      position: sticky;
      top: 0;
    }
    .nav-left, .nav-center, .nav-right {
      display: flex;
      align-items: center;
      gap: var(--space-3);
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
    }
    .threat-status {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      font-family: var(--font-mono);
      color: var(--text-secondary);
      background: var(--bg-surface);
      padding: 3px 10px;
      border-radius: 9999px;
      border: 1px solid var(--border-subtle);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-teal);
      box-shadow: 0 0 8px var(--accent-teal);
    }
    .user-chip {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      background: var(--bg-surface);
      padding: 4px 8px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-default);
    }
    .user-role-badge {
      font-size: 10px;
      padding: 1px 5px;
      border-radius: 2px;
      background: var(--accent-teal-subtle);
      color: var(--accent-teal);
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .user-role-badge.admin {
      background: var(--sev-critical-bg);
      color: var(--sev-critical);
    }
    .username {
      font-size: 12px;
      color: var(--text-primary);
    }
  `]
})
export class NavbarComponent {
  readonly auth = inject(AuthService);

  logout(): void {
    this.auth.logout();
  }
}
