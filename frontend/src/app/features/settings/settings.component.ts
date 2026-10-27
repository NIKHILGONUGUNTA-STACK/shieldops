import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../core/auth/auth.service';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Platform Settings & Runtime Configuration</h1>
          <p class="soc-subtitle">
            Authoritative platform settings, Keycloak OIDC/PKCE parameters, and immutable security invariants.
          </p>
        </div>
      </div>

      <div class="settings-grid">
        <!-- Security Invariant Card -->
        <div class="settings-card">
          <div class="card-header">
            <span class="header-icon">🛡️</span>
            <h3>Security Enforcement Invariant</h3>
          </div>
          <p class="card-desc">
            Aegis is strictly configured in non-blocking Advisory Mode. To protect legitimate banking microservices
            from automated availability hazards, this setting is non-toggleable at runtime.
          </p>

          <div class="settings-table">
            <div class="setting-row">
              <span class="setting-key">Operational Mode</span>
              <span class="setting-val mono text-teal font-bold">ADVISORY ONLY</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Automated Blocking</span>
              <span class="setting-val mono text-muted">DISABLED (BY DESIGN)</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Response Action</span>
              <span class="setting-val mono text-amber">LOG_ALERT</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Correlation Engine</span>
              <span class="setting-val mono text-teal">MultiVectorCampaignCorrelator</span>
            </div>
          </div>
        </div>

        <!-- Identity Provider & Keycloak Card -->
        <div class="settings-card">
          <div class="card-header">
            <span class="header-icon">🔑</span>
            <h3>Identity & Access Management</h3>
          </div>
          <p class="card-desc">
            Authentication is brokered by Keycloak 26 using Authorization Code Flow with PKCE (S256). Zero client secrets are exposed.
          </p>

          <div class="settings-table">
            <div class="setting-row">
              <span class="setting-key">Keycloak Realm</span>
              <span class="setting-val mono">{{ environment.keycloak.realm }}</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Public Client ID</span>
              <span class="setting-val mono text-teal">{{ environment.keycloak.clientId }}</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">PKCE Challenge Method</span>
              <span class="setting-val mono">S256 (SHA-256)</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Active User Session</span>
              <span class="setting-val mono">{{ auth.userProfile()?.username || (auth.isSecurityAdmin() ? 'security-admin' : 'security-analyst') }}</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Assigned Roles</span>
              <span class="setting-val mono text-teal">
                {{ auth.isSecurityAdmin() ? 'SECURITY_ADMIN, SECURITY_ANALYST' : 'SECURITY_ANALYST' }}
              </span>
            </div>
          </div>
        </div>

        <!-- Gateway Telemetry Card -->
        <div class="settings-card">
          <div class="card-header">
            <span class="header-icon">⚡</span>
            <h3>Gateway Telemetry & Privacy</h3>
          </div>
          <p class="card-desc">
            Gateway telemetry capture settings and privacy preservation configurations in Spring Cloud Gateway.
          </p>

          <div class="settings-table">
            <div class="setting-row">
              <span class="setting-key">API Base URL</span>
              <span class="setting-val mono text-teal">{{ environment.apiBaseUrl }}</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Redis Stream Key</span>
              <span class="setting-val mono">aegis:stream:api-events</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Telemetry Batch Size</span>
              <span class="setting-val mono">50 events</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Stream Drain Interval</span>
              <span class="setting-val mono">2000 ms</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Authorization Header Redaction</span>
              <span class="setting-val mono text-teal">Bearer [REDACTED]</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Payload Cryptographic Hash</span>
              <span class="setting-val mono">SHA-256</span>
            </div>
          </div>
        </div>

        <!-- Database & Persistence Card -->
        <div class="settings-card">
          <div class="card-header">
            <span class="header-icon">🐘</span>
            <h3>Data Persistence Tier</h3>
          </div>
          <p class="card-desc">
            PostgreSQL relational persistence and Flyway automated schema version management.
          </p>

          <div class="settings-table">
            <div class="setting-row">
              <span class="setting-key">Database Schema</span>
              <span class="setting-val mono text-teal">security_data</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Active Migration</span>
              <span class="setting-val mono text-teal">V3 (Sec Ops Indexes)</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Audit Immutability</span>
              <span class="setting-val mono">Append-Only History</span>
            </div>
          </div>
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
      margin-bottom: var(--space-6);
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
    .settings-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
      gap: var(--space-4);
    }
    .settings-card {
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      padding: var(--space-5);
    }
    .card-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      margin-bottom: var(--space-2);
    }
    .header-icon {
      font-size: 18px;
    }
    .card-header h3 {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .card-desc {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
      margin-bottom: var(--space-4);
    }
    .settings-table {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }
    .setting-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 12px;
    }
    .setting-row:last-child {
      border-bottom: none;
    }
    .setting-key {
      color: var(--text-secondary);
    }
    .setting-val {
      font-size: 12px;
      color: var(--text-primary);
    }
  `]
})
export class SettingsComponent {
  readonly auth = inject(AuthService);
  readonly environment = environment;
}
