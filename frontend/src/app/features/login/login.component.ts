import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="login-wrapper">
      <div class="login-card soc-card">
        <div class="login-header">
          <div class="login-badge">AEGIS SECURITY SUITE</div>
          <h1 class="login-title">Security Operations Center</h1>
          <p class="login-subtitle">
            Authenticated telemetry and adaptive response console. Protected by Keycloak OIDC (PKCE S256).
          </p>
        </div>

        <div *ngIf="errorMessage" class="error-banner">
          {{ errorMessage }}
        </div>

        <div class="login-actions">
          <button (click)="onKeycloakLogin()" class="btn btn-primary login-btn">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -3px; margin-right: 6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Authenticate via Keycloak SSO
          </button>
        </div>

        <div class="dev-credentials-box">
          <div class="dev-title">AUTHORIZED LOCAL TEST ROLES</div>
          <div class="cred-row">
            <span class="role-tag">SECURITY_ANALYST</span>
            <span class="cred mono">analyst / Password123!</span>
          </div>
          <div class="cred-row">
            <span class="role-tag admin">SECURITY_ADMIN</span>
            <span class="cred mono">admin / Password123!</span>
          </div>
        </div>

        <div class="dev-bypass-actions">
          <span class="text-muted" style="font-size: 11px;">Local test simulation:</span>
          <button (click)="simulateAnalystLogin()" class="btn btn-secondary btn-sm">
            Simulate Analyst Session
          </button>
          <button (click)="simulateAdminLogin()" class="btn btn-secondary btn-sm">
            Simulate Admin Session
          </button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .login-wrapper {
      min-height: calc(100vh - 52px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: var(--space-6);
      background: radial-gradient(circle at 50% 30%, rgba(20, 184, 166, 0.05) 0%, rgba(9, 13, 22, 1) 70%);
    }
    .login-card {
      width: 100%;
      max-width: 440px;
      padding: var(--space-8);
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      box-shadow: var(--shadow-lg);
    }
    .login-header {
      margin-bottom: var(--space-6);
      text-align: center;
    }
    .login-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      color: var(--accent-teal);
      background: var(--accent-teal-subtle);
      padding: 3px 8px;
      border-radius: var(--radius-sm);
      margin-bottom: var(--space-3);
    }
    .login-title {
      font-size: 20px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: var(--space-2);
    }
    .login-subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .error-banner {
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
      color: var(--sev-critical);
      padding: var(--space-3);
      border-radius: var(--radius-sm);
      font-size: 12px;
      margin-bottom: var(--space-4);
      text-align: center;
    }
    .login-actions {
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
      margin-bottom: var(--space-6);
    }
    .login-btn {
      width: 100%;
      padding: 10px 16px;
      font-size: 14px;
    }
    .dev-credentials-box {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: var(--space-3);
      margin-bottom: var(--space-4);
    }
    .dev-title {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: var(--space-2);
    }
    .cred-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11px;
      padding: 3px 0;
    }
    .role-tag {
      font-size: 10px;
      font-weight: 600;
      color: var(--accent-teal);
    }
    .role-tag.admin {
      color: var(--sev-high);
    }
    .cred {
      color: var(--text-secondary);
    }
    .dev-bypass-actions {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: var(--space-2);
      flex-wrap: wrap;
      padding-top: var(--space-3);
      border-top: 1px solid var(--border-subtle);
    }
  `]
})
export class LoginComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  errorMessage: string | null = null;

  constructor() {
    const error = this.route.snapshot.queryParams['error'];
    if (error === 'insufficient_role') {
      this.errorMessage = 'Access denied: Your account lacks the required SECURITY_ANALYST role.';
    }
  }

  async onKeycloakLogin(): Promise<void> {
    const returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/overview';
    await this.auth.login(returnUrl);
  }

  simulateAnalystLogin(): void {
    this.auth.setMockAuthenticated({
      username: 'analyst',
      email: 'analyst@aegis.local',
      firstName: 'Security',
      lastName: 'Analyst',
      roles: ['SECURITY_ANALYST']
    });
    this.navigateAfterLogin();
  }

  simulateAdminLogin(): void {
    this.auth.setMockAuthenticated({
      username: 'admin',
      email: 'admin@aegis.local',
      firstName: 'Security',
      lastName: 'Admin',
      roles: ['SECURITY_ADMIN', 'SECURITY_ANALYST']
    });
    this.navigateAfterLogin();
  }

  private navigateAfterLogin(): void {
    const returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/overview';
    this.router.navigateByUrl(returnUrl);
  }
}
