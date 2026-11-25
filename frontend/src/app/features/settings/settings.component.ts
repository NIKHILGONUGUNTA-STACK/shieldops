import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../core/auth/auth.service';
import { TenantService } from '../../core/services/tenant.service';
import { WebhookService } from '../../core/services/webhook.service';
import { Tenant, TenantTier, TenantStatus, TenantUsageResponse, TenantCreateRequest } from '../../core/models/tenant.model';
import { WebhookSubscription, WebhookEventType, WebhookDispatchResult, WebhookSubscriptionCreateRequest } from '../../core/models/webhook.model';
import { environment } from '../../../environments/environment';

export type SettingsTab = 'invariants' | 'tenants' | 'webhooks';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Platform Administration & Settings</h1>
          <p class="soc-subtitle">
            Multi-tenant SaaS administration, outbound webhook alerting integrations, Keycloak OIDC/PKCE parameters, and immutable security invariants.
          </p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="settings-tabs-bar" role="tablist">
        <button
          type="button"
          role="tab"
          [attr.aria-selected]="activeTab === 'invariants'"
          class="settings-tab-btn"
          [class.active]="activeTab === 'invariants'"
          (click)="switchTab('invariants')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          Runtime Invariants
        </button>

        <button
          type="button"
          role="tab"
          [attr.aria-selected]="activeTab === 'tenants'"
          class="settings-tab-btn"
          [class.active]="activeTab === 'tenants'"
          (click)="switchTab('tenants')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          Tenant Administration
          <span class="tab-badge" *ngIf="tenants.length > 0">{{ tenants.length }}</span>
        </button>

        <button
          type="button"
          role="tab"
          [attr.aria-selected]="activeTab === 'webhooks'"
          class="settings-tab-btn"
          [class.active]="activeTab === 'webhooks'"
          (click)="switchTab('webhooks')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
          </svg>
          Webhook Integrations
          <span class="tab-badge" *ngIf="webhooks.length > 0">{{ webhooks.length }}</span>
        </button>
      </div>

      <!-- TAB 1: RUNTIME INVARIANTS -->
      <div *ngIf="activeTab === 'invariants'" class="settings-grid">
        <!-- Security Invariant Card -->
        <div class="settings-card">
          <div class="card-header">
            <span class="header-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF7A1A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </span>
            <h3>Security Enforcement Invariant</h3>
          </div>
          <p class="card-desc">
            ShieldOps is strictly configured in non-blocking Advisory Mode. To protect legitimate banking microservices
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
            <span class="header-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#7B61FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
            </span>
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
            <span class="header-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#C48A45" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
            </span>
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
            <span class="header-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4A6CFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
            </span>
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
              <span class="setting-val mono text-teal">V7 (SaaS Multitenancy & Webhooks)</span>
            </div>
            <div class="setting-row">
              <span class="setting-key">Audit Immutability</span>
              <span class="setting-val mono">Append-Only History</span>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 2: TENANT ADMINISTRATION -->
      <div *ngIf="activeTab === 'tenants'" class="tab-content-panel">
        <div class="panel-action-bar">
          <div class="panel-action-left">
            <span class="section-title">Registered SaaS Tenants</span>
            <span class="section-badge">{{ tenants.length }} Active</span>
          </div>
          <div class="panel-action-right">
            <button class="btn btn-secondary btn-sm" (click)="loadTenants()" [disabled]="loadingTenants">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" [class.spin]="loadingTenants">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
              </svg>
              Refresh
            </button>
            <button class="btn btn-primary btn-sm" (click)="openNewTenantModal()" *ngIf="auth.isSecurityAdmin()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Provision Tenant
            </button>
          </div>
        </div>

        <div *ngIf="tenantError" class="alert-banner alert-danger">
          {{ tenantError }}
        </div>

        <div *ngIf="loadingTenants" class="loading-state">
          <div class="spinner"></div>
          <span>Loading SaaS tenant registry...</span>
        </div>

        <div *ngIf="!loadingTenants && tenants.length === 0" class="empty-state">
          <h3>No SaaS Tenants Found</h3>
          <p>No tenants are currently configured in the platform registry.</p>
        </div>

        <div *ngIf="!loadingTenants && tenants.length > 0" class="soc-table-container">
          <table class="soc-table" aria-label="SaaS Tenant Directory">
            <thead>
              <tr>
                <th>Tenant ID</th>
                <th>Organization Name</th>
                <th>Service Tier</th>
                <th>Status</th>
                <th>Rate Limit (RPM)</th>
                <th>Retention (Days)</th>
                <th>Contact</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let t of tenants">
                <td class="mono text-teal font-semibold">{{ t.id }}</td>
                <td>{{ t.name }}</td>
                <td>
                  <span class="tier-badge" [ngClass]="t.tier ? t.tier.toLowerCase() : 'starter'">
                    {{ t.tier || 'STARTER' }}
                  </span>
                </td>
                <td>
                  <span class="status-pill" [ngClass]="t.status === 'ACTIVE' ? 'active' : 'suspended'">
                    {{ t.status }}
                  </span>
                </td>
                <td class="mono">{{ t.rateLimitRpm | number }} RPM</td>
                <td class="mono">{{ t.maxIncidentsRetentionDays }} days</td>
                <td class="text-secondary">{{ t.contactEmail || '—' }}</td>
                <td class="actions-cell">
                  <button class="btn btn-secondary btn-xs" (click)="inspectTenantUsage(t.id)" title="Inspect live RPM quota & telemetry">
                    Usage
                  </button>
                  <button
                    class="btn btn-secondary btn-xs"
                    *ngIf="auth.isSecurityAdmin()"
                    [class.btn-warning]="t.status === 'ACTIVE'"
                    [class.btn-success]="t.status !== 'ACTIVE'"
                    (click)="toggleTenantStatus(t)"
                    [title]="t.status === 'ACTIVE' ? 'Suspend Tenant' : 'Activate Tenant'">
                    {{ t.status === 'ACTIVE' ? 'Suspend' : 'Activate' }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- TAB 3: WEBHOOK INTEGRATIONS -->
      <div *ngIf="activeTab === 'webhooks'" class="tab-content-panel">
        <div class="panel-action-bar">
          <div class="panel-action-left">
            <span class="section-title">Outbound Alert Webhook Subscriptions</span>
            <span class="section-badge">{{ webhooks.length }} Configured</span>
          </div>
          <div class="panel-action-right">
            <button class="btn btn-secondary btn-sm" (click)="loadWebhooks()" [disabled]="loadingWebhooks">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" [class.spin]="loadingWebhooks">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
              </svg>
              Refresh
            </button>
            <button class="btn btn-primary btn-sm" (click)="openNewWebhookModal()" *ngIf="auth.isSecurityAdmin()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Add Webhook
            </button>
          </div>
        </div>

        <!-- Ping result notification -->
        <div *ngIf="testPingResult" class="ping-result-banner" [class.success]="testPingResult.success" [class.failure]="!testPingResult.success">
          <div class="ping-result-header">
            <strong>{{ testPingResult.success ? '✓ Ping Dispatch Successful' : '✗ Ping Dispatch Failed' }}</strong>
            <span class="mono">HTTP {{ testPingResult.statusCode }} ({{ testPingResult.latencyMs }}ms)</span>
          </div>
          <p class="ping-result-detail">{{ testPingResult.message }}</p>
          <button class="btn btn-secondary btn-xs close-ping" (click)="testPingResult = null">Dismiss</button>
        </div>

        <div *ngIf="webhookError" class="alert-banner alert-danger">
          {{ webhookError }}
        </div>

        <div *ngIf="loadingWebhooks" class="loading-state">
          <div class="spinner"></div>
          <span>Loading webhook subscriptions...</span>
        </div>

        <div *ngIf="!loadingWebhooks && webhooks.length === 0" class="empty-state">
          <h3>No Webhook Subscriptions Configured</h3>
          <p>Configure Slack, PagerDuty, or SIEM endpoints to receive real-time HMAC-signed security incident notifications.</p>
        </div>

        <div *ngIf="!loadingWebhooks && webhooks.length > 0" class="soc-table-container">
          <table class="soc-table" aria-label="Webhook Subscriptions Directory">
            <thead>
              <tr>
                <th>Name</th>
                <th>Target Endpoint URL</th>
                <th>Subscribed Events</th>
                <th>Status</th>
                <th>Deliveries</th>
                <th>Last Triggered</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let w of webhooks">
                <td class="font-semibold">{{ w.name }}</td>
                <td class="mono text-teal target-url-cell" [title]="w.targetUrl">{{ w.targetUrl }}</td>
                <td>
                  <div class="event-tags-container">
                    <span *ngFor="let ev of w.eventTypes" class="event-tag mono">{{ ev }}</span>
                  </div>
                </td>
                <td>
                  <span class="status-pill" [ngClass]="w.enabled ? 'active' : 'suspended'">
                    {{ w.enabled ? 'ENABLED' : 'DISABLED' }}
                  </span>
                </td>
                <td class="mono">
                  <span class="text-teal">{{ w.successCount }} ok</span> /
                  <span class="text-amber">{{ w.failureCount }} err</span>
                </td>
                <td class="mono text-secondary">
                  {{ w.lastTriggeredAt ? (w.lastTriggeredAt | date:'yyyy-MM-dd HH:mm') : 'Never' }}
                </td>
                <td class="actions-cell">
                  <button
                    class="btn btn-secondary btn-xs"
                    (click)="triggerWebhookTest(w.id)"
                    [disabled]="testingWebhookId === w.id"
                    title="Send signed HMAC test ping to destination">
                    {{ testingWebhookId === w.id ? 'Pinging...' : 'Send Test Ping' }}
                  </button>
                  <button
                    class="btn btn-secondary btn-xs btn-danger-action"
                    *ngIf="auth.isSecurityAdmin()"
                    (click)="deleteWebhook(w.id)"
                    title="Delete webhook subscription">
                    Delete
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- MODAL: TENANT USAGE INSPECTION -->
      <div *ngIf="selectedTenantUsage" class="modal-backdrop" (click)="closeUsageModal()">
        <div class="modal-dialog" (click)="$event.stopPropagation()">
          <div class="modal-header">
            <h3>Tenant Quota &amp; Telemetry: {{ selectedTenantUsage.tenantName }}</h3>
            <button class="modal-close-btn" (click)="closeUsageModal()">✕</button>
          </div>
          <div class="modal-body">
            <div class="usage-meter-container">
              <div class="usage-meter-label">
                <span>Current RPM Utilization</span>
                <span class="mono font-bold">{{ selectedTenantUsage.rateLimitUtilizationPercent | number:'1.1-1' }}%</span>
              </div>
              <div class="usage-progress-bar">
                <div
                  class="usage-progress-fill"
                  [style.width.%]="selectedTenantUsage.rateLimitUtilizationPercent > 100 ? 100 : selectedTenantUsage.rateLimitUtilizationPercent"
                  [class.high]="selectedTenantUsage.rateLimitUtilizationPercent >= 80"
                  [class.critical]="selectedTenantUsage.rateLimitUtilizationPercent >= 95">
                </div>
              </div>
            </div>

            <div class="settings-table">
              <div class="setting-row">
                <span class="setting-key">Tenant ID</span>
                <span class="setting-val mono text-teal">{{ selectedTenantUsage.tenantId }}</span>
              </div>
              <div class="setting-row">
                <span class="setting-key">Rate Limit Ceiling</span>
                <span class="setting-val mono">{{ selectedTenantUsage.rateLimitRpm | number }} RPM</span>
              </div>
              <div class="setting-row">
                <span class="setting-key">Current Window Requests</span>
                <span class="setting-val mono font-semibold">{{ selectedTenantUsage.currentWindowRequests | number }} req/min</span>
              </div>
              <div class="setting-row">
                <span class="setting-key">Total Recorded Events</span>
                <span class="setting-val mono">{{ selectedTenantUsage.totalRecordedEvents | number }}</span>
              </div>
              <div class="setting-row">
                <span class="setting-key">Active Security Incidents</span>
                <span class="setting-val mono text-amber font-semibold">{{ selectedTenantUsage.activeIncidentsCount }}</span>
              </div>
              <div class="setting-row">
                <span class="setting-key">Active Attack Campaigns</span>
                <span class="setting-val mono text-amber font-semibold">{{ selectedTenantUsage.activeCampaignsCount }}</span>
              </div>
              <div class="setting-row">
                <span class="setting-key">Evaluated At</span>
                <span class="setting-val mono text-secondary">{{ selectedTenantUsage.evaluatedAt | date:'yyyy-MM-dd HH:mm:ss' }}</span>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary btn-sm" (click)="closeUsageModal()">Close</button>
          </div>
        </div>
      </div>

      <!-- MODAL: PROVISION NEW TENANT -->
      <div *ngIf="showNewTenantModal" class="modal-backdrop" (click)="closeNewTenantModal()">
        <div class="modal-dialog" (click)="$event.stopPropagation()">
          <div class="modal-header">
            <h3>Provision New SaaS Tenant</h3>
            <button class="modal-close-btn" (click)="closeNewTenantModal()">✕</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label class="form-label" for="tenantIdInput">Tenant Identifier *</label>
              <input
                id="tenantIdInput"
                type="text"
                class="form-control mono"
                [(ngModel)]="newTenant.id"
                placeholder="e.g. tenant-wealth-apac"
                required />
              <span class="form-hint">Unique alphanumeric slug without spaces.</span>
            </div>

            <div class="form-group">
              <label class="form-label" for="tenantNameInput">Organization Name *</label>
              <input
                id="tenantNameInput"
                type="text"
                class="form-control"
                [(ngModel)]="newTenant.name"
                placeholder="e.g. APAC Wealth Management Ltd."
                required />
            </div>

            <div class="form-row">
              <div class="form-group col-half">
                <label class="form-label" for="tenantTierInput">Service Tier</label>
                <select id="tenantTierInput" class="form-control" [(ngModel)]="newTenant.tier">
                  <option value="STARTER">STARTER</option>
                  <option value="PROFESSIONAL">PROFESSIONAL</option>
                  <option value="ENTERPRISE">ENTERPRISE</option>
                </select>
              </div>

              <div class="form-group col-half">
                <label class="form-label" for="tenantRpmInput">Rate Limit (RPM)</label>
                <input
                  id="tenantRpmInput"
                  type="number"
                  class="form-control mono"
                  [(ngModel)]="newTenant.rateLimitRpm"
                  min="100"
                  step="500" />
              </div>
            </div>

            <div class="form-row">
              <div class="form-group col-half">
                <label class="form-label" for="tenantRetentionInput">Retention (Days)</label>
                <input
                  id="tenantRetentionInput"
                  type="number"
                  class="form-control mono"
                  [(ngModel)]="newTenant.maxIncidentsRetentionDays"
                  min="30"
                  max="730" />
              </div>

              <div class="form-group col-half">
                <label class="form-label" for="tenantEmailInput">Contact Email</label>
                <input
                  id="tenantEmailInput"
                  type="email"
                  class="form-control"
                  [(ngModel)]="newTenant.contactEmail"
                  placeholder="security@tenant.com" />
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary btn-sm" (click)="closeNewTenantModal()">Cancel</button>
            <button
              class="btn btn-primary btn-sm"
              [disabled]="!newTenant.id || !newTenant.name || creatingTenant"
              (click)="saveNewTenant()">
              {{ creatingTenant ? 'Provisioning...' : 'Provision Tenant' }}
            </button>
          </div>
        </div>
      </div>

      <!-- MODAL: ADD WEBHOOK SUBSCRIPTION -->
      <div *ngIf="showNewWebhookModal" class="modal-backdrop" (click)="closeNewWebhookModal()">
        <div class="modal-dialog" (click)="$event.stopPropagation()">
          <div class="modal-header">
            <h3>Add Outbound Alert Webhook</h3>
            <button class="modal-close-btn" (click)="closeNewWebhookModal()">✕</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label class="form-label" for="webhookNameInput">Integration Name *</label>
              <input
                id="webhookNameInput"
                type="text"
                class="form-control"
                [(ngModel)]="newWebhook.name"
                placeholder="e.g. SOC Primary Slack Alerts"
                required />
            </div>

            <div class="form-group">
              <label class="form-label" for="webhookUrlInput">Target Endpoint URL *</label>
              <input
                id="webhookUrlInput"
                type="url"
                class="form-control mono"
                [(ngModel)]="newWebhook.targetUrl"
                placeholder="https://hooks.slack.com/services/..."
                required />
              <span class="form-hint">Must begin with https:// or http://</span>
            </div>

            <div class="form-group">
              <label class="form-label" for="webhookSecretInput">HMAC-SHA256 Signing Secret</label>
              <input
                id="webhookSecretInput"
                type="password"
                class="form-control mono"
                [(ngModel)]="newWebhook.secretToken"
                placeholder="Optional shared secret (min 16 characters recommended)" />
              <span class="form-hint">Used to compute the X-Aegis-Signature header for receiver payload authentication.</span>
            </div>

            <div class="form-group">
              <label class="form-label">Subscribed Security Events *</label>
              <div class="checkbox-grid">
                <label *ngFor="let ev of availableEventTypes" class="checkbox-label">
                  <input
                    type="checkbox"
                    [checked]="isEventSelected(ev)"
                    (change)="toggleEventSelection(ev)" />
                  <span class="mono">{{ ev }}</span>
                </label>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary btn-sm" (click)="closeNewWebhookModal()">Cancel</button>
            <button
              class="btn btn-primary btn-sm"
              [disabled]="!newWebhook.name || !newWebhook.targetUrl || newWebhook.eventTypes.length === 0 || creatingWebhook"
              (click)="saveNewWebhook()">
              {{ creatingWebhook ? 'Saving...' : 'Create Subscription' }}
            </button>
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
      margin-bottom: var(--space-5);
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
      line-height: 1.5;
    }

    /* Tab Bar */
    .settings-tabs-bar {
      display: flex;
      gap: var(--space-2);
      border-bottom: 1px solid var(--border-default);
      margin-bottom: var(--space-6);
      padding-bottom: 2px;
    }
    .settings-tab-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
    }
    .settings-tab-btn:hover {
      color: var(--text-primary);
    }
    .settings-tab-btn.active {
      color: #58a6ff;
      border-bottom-color: #58a6ff;
      font-weight: 600;
    }
    .tab-badge {
      background: #21262d;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 2px 8px;
      font-size: 11px;
      color: #8b949e;
      font-weight: 600;
    }

    /* Invariants Grid */
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
      display: flex;
      align-items: center;
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

    /* Action Bar */
    .tab-content-panel {
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
    }
    .panel-action-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 16px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
    }
    .panel-action-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .section-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .section-badge {
      background: #1f2937;
      border: 1px solid #374151;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      color: #9ca3af;
    }
    .panel-action-right {
      display: flex;
      gap: 8px;
    }

    /* Badges */
    .tier-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      font-family: ui-monospace, monospace;
    }
    .tier-badge.starter { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
    .tier-badge.professional { background: #1f2937; color: #58a6ff; border: 1px solid #238636; }
    .tier-badge.enterprise { background: #2e1a47; color: #d2a8ff; border: 1px solid #8957e5; }

    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }
    .status-pill.active { background: rgba(46, 160, 67, 0.15); color: #3fb950; border: 1px solid #238636; }
    .status-pill.suspended { background: rgba(218, 54, 51, 0.15); color: #f85149; border: 1px solid #da3633; }

    .event-tags-container {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      max-width: 320px;
    }
    .event-tag {
      background: #161b22;
      border: 1px solid #30363d;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 10px;
      color: #79c0ff;
    }
    .target-url-cell {
      max-width: 240px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .actions-cell {
      display: flex;
      gap: 6px;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 6px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid transparent;
    }
    .btn-sm { padding: 6px 12px; font-size: 12px; }
    .btn-xs { padding: 4px 8px; font-size: 11px; }
    .btn-primary { background: #238636; color: #fff; border-color: #2ea043; }
    .btn-primary:hover:not(:disabled) { background: #2ea043; }
    .btn-secondary { background: #21262d; color: #c9d1d9; border-color: #30363d; }
    .btn-secondary:hover:not(:disabled) { background: #30363d; color: #fff; }
    .btn-warning { background: #b08800; color: #fff; border-color: #d29922; }
    .btn-warning:hover:not(:disabled) { background: #d29922; }
    .btn-success { background: #238636; color: #fff; border-color: #2ea043; }
    .btn-danger-action { color: #f85149; }
    .btn-danger-action:hover { background: #da3633; color: #fff; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }

    /* Ping Banner */
    .ping-result-banner {
      padding: 12px 16px;
      border-radius: 6px;
      position: relative;
    }
    .ping-result-banner.success {
      background: rgba(46, 160, 67, 0.12);
      border: 1px solid #238636;
      color: #3fb950;
    }
    .ping-result-banner.failure {
      background: rgba(218, 54, 51, 0.12);
      border: 1px solid #da3633;
      color: #f85149;
    }
    .ping-result-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 13px;
      margin-bottom: 4px;
    }
    .ping-result-detail {
      font-size: 12px;
      color: var(--text-secondary);
      margin: 0;
    }
    .close-ping {
      position: absolute;
      top: 10px;
      right: 12px;
    }

    /* Modal Styles */
    .modal-backdrop {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(2px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .modal-dialog {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      width: 100%;
      max-width: 540px;
      box-shadow: 0 16px 32px rgba(0, 0, 0, 0.5);
      overflow: hidden;
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      border-bottom: 1px solid #30363d;
    }
    .modal-header h3 {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-primary);
      margin: 0;
    }
    .modal-close-btn {
      background: transparent;
      border: none;
      color: #8b949e;
      font-size: 16px;
      cursor: pointer;
    }
    .modal-body {
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      padding: 12px 18px;
      border-top: 1px solid #30363d;
      background: #0d1117;
    }

    /* Forms */
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .form-row {
      display: flex;
      gap: 12px;
    }
    .col-half {
      flex: 1;
    }
    .form-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-secondary);
    }
    .form-control {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 8px 12px;
      color: #c9d1d9;
      font-size: 13px;
    }
    .form-control:focus {
      outline: none;
      border-color: #58a6ff;
    }
    .form-hint {
      font-size: 11px;
      color: #8b949e;
    }
    .checkbox-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-top: 4px;
    }
    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--text-primary);
      cursor: pointer;
    }

    /* Quota Meter */
    .usage-meter-container {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-bottom: 8px;
    }
    .usage-meter-label {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: var(--text-secondary);
    }
    .usage-progress-bar {
      height: 8px;
      background: #21262d;
      border-radius: 4px;
      overflow: hidden;
    }
    .usage-progress-fill {
      height: 100%;
      background: #238636;
      transition: width 0.3s ease;
    }
    .usage-progress-fill.high { background: #d29922; }
    .usage-progress-fill.critical { background: #da3633; }

    /* States */
    .loading-state, .empty-state {
      padding: 32px;
      text-align: center;
      color: var(--text-secondary);
    }
    .spin {
      animation: spin 1s linear infinite;
    }
    @keyframes spin { 100% { transform: rotate(360deg); } }
  `]
})
export class SettingsComponent implements OnInit {
  readonly auth = inject(AuthService);
  private readonly tenantService = inject(TenantService);
  private readonly webhookService = inject(WebhookService);
  readonly environment = environment;

  activeTab: SettingsTab = 'invariants';

  // Tenant state
  tenants: Tenant[] = [];
  loadingTenants = false;
  tenantError: string | null = null;
  selectedTenantUsage: TenantUsageResponse | null = null;
  showNewTenantModal = false;
  creatingTenant = false;

  newTenant: TenantCreateRequest = {
    id: '',
    name: '',
    tier: 'STARTER',
    rateLimitRpm: 1000,
    maxIncidentsRetentionDays: 90,
    contactEmail: ''
  };

  // Webhook state
  webhooks: WebhookSubscription[] = [];
  loadingWebhooks = false;
  webhookError: string | null = null;
  testingWebhookId: string | null = null;
  testPingResult: WebhookDispatchResult | null = null;
  showNewWebhookModal = false;
  creatingWebhook = false;

  availableEventTypes: WebhookEventType[] = [
    'INCIDENT_CREATED',
    'INCIDENT_STATUS_CHANGED',
    'INCIDENT_CRITICAL',
    'CAMPAIGN_ESCALATED',
    'POLICY_ADVISORY_TRIGGERED',
    'TEST_PING'
  ];

  newWebhook: WebhookSubscriptionCreateRequest = {
    name: '',
    targetUrl: '',
    secretToken: '',
    eventTypes: ['INCIDENT_CREATED', 'INCIDENT_CRITICAL', 'CAMPAIGN_ESCALATED']
  };

  ngOnInit(): void {
    // Optionally pre-load tenant and webhook counts for tab badges
    this.loadTenants();
    this.loadWebhooks();
  }

  switchTab(tab: SettingsTab): void {
    this.activeTab = tab;
    if (tab === 'tenants' && this.tenants.length === 0) {
      this.loadTenants();
    } else if (tab === 'webhooks' && this.webhooks.length === 0) {
      this.loadWebhooks();
    }
  }

  // --- Tenant Handlers ---
  loadTenants(): void {
    this.loadingTenants = true;
    this.tenantError = null;
    this.tenantService.getTenants({ page: 0, size: 50 }).subscribe({
      next: (page) => {
        this.tenants = page.content || [];
        this.loadingTenants = false;
      },
      error: (err) => {
        this.tenantError = 'Failed to load SaaS tenants: ' + (err?.message || 'Server error');
        this.loadingTenants = false;
      }
    });
  }

  openNewTenantModal(): void {
    this.newTenant = {
      id: '',
      name: '',
      tier: 'STARTER',
      rateLimitRpm: 1000,
      maxIncidentsRetentionDays: 90,
      contactEmail: ''
    };
    this.showNewTenantModal = true;
  }

  closeNewTenantModal(): void {
    this.showNewTenantModal = false;
    this.creatingTenant = false;
  }

  saveNewTenant(): void {
    if (!this.newTenant.id || !this.newTenant.name) return;
    this.creatingTenant = true;
    this.tenantService.createTenant(this.newTenant).subscribe({
      next: () => {
        this.creatingTenant = false;
        this.closeNewTenantModal();
        this.loadTenants();
      },
      error: (err) => {
        this.creatingTenant = false;
        this.tenantError = 'Failed to provision tenant: ' + (err?.error?.detail || err?.message || 'Validation error');
      }
    });
  }

  toggleTenantStatus(tenant: Tenant): void {
    const newStatus: TenantStatus = tenant.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';
    this.tenantService.updateStatus(tenant.id, {
      status: newStatus,
      reason: 'Administrator toggled status in Settings Console'
    }).subscribe({
      next: (updated) => {
        const index = this.tenants.findIndex(t => t.id === updated.id);
        if (index >= 0) {
          this.tenants[index] = updated;
        } else {
          this.loadTenants();
        }
      },
      error: (err) => {
        this.tenantError = 'Failed to update tenant status: ' + (err?.message || 'Server error');
      }
    });
  }

  inspectTenantUsage(tenantId: string): void {
    this.tenantService.getTenantUsage(tenantId).subscribe({
      next: (usage) => {
        this.selectedTenantUsage = usage;
      },
      error: (err) => {
        this.tenantError = 'Failed to retrieve usage metrics: ' + (err?.message || 'Server error');
      }
    });
  }

  closeUsageModal(): void {
    this.selectedTenantUsage = null;
  }

  // --- Webhook Handlers ---
  loadWebhooks(): void {
    this.loadingWebhooks = true;
    this.webhookError = null;
    this.webhookService.getSubscriptions().subscribe({
      next: (subs) => {
        this.webhooks = subs || [];
        this.loadingWebhooks = false;
      },
      error: (err) => {
        this.webhookError = 'Failed to load webhooks: ' + (err?.message || 'Server error');
        this.loadingWebhooks = false;
      }
    });
  }

  openNewWebhookModal(): void {
    this.newWebhook = {
      name: '',
      targetUrl: '',
      secretToken: '',
      eventTypes: ['INCIDENT_CREATED', 'INCIDENT_CRITICAL', 'CAMPAIGN_ESCALATED']
    };
    this.showNewWebhookModal = true;
  }

  closeNewWebhookModal(): void {
    this.showNewWebhookModal = false;
    this.creatingWebhook = false;
  }

  isEventSelected(eventType: WebhookEventType): boolean {
    return this.newWebhook.eventTypes.includes(eventType);
  }

  toggleEventSelection(eventType: WebhookEventType): void {
    const index = this.newWebhook.eventTypes.indexOf(eventType);
    if (index >= 0) {
      this.newWebhook.eventTypes.splice(index, 1);
    } else {
      this.newWebhook.eventTypes.push(eventType);
    }
  }

  saveNewWebhook(): void {
    if (!this.newWebhook.name || !this.newWebhook.targetUrl || this.newWebhook.eventTypes.length === 0) return;
    this.creatingWebhook = true;
    this.webhookService.createSubscription(this.newWebhook).subscribe({
      next: () => {
        this.creatingWebhook = false;
        this.closeNewWebhookModal();
        this.loadWebhooks();
      },
      error: (err) => {
        this.creatingWebhook = false;
        this.webhookError = 'Failed to create webhook: ' + (err?.error?.detail || err?.message || 'Validation error');
      }
    });
  }

  triggerWebhookTest(id: string): void {
    this.testingWebhookId = id;
    this.testPingResult = null;
    this.webhookService.triggerTest(id).subscribe({
      next: (result) => {
        this.testPingResult = result;
        this.testingWebhookId = null;
        this.loadWebhooks(); // Refresh delivery statistics
      },
      error: (err) => {
        this.testingWebhookId = null;
        this.testPingResult = {
          subscriptionId: id,
          targetUrl: 'Target',
          statusCode: err?.status || 500,
          success: false,
          message: err?.error?.detail || err?.message || 'Dispatch timeout or unreachable target',
          latencyMs: 0,
          timestamp: new Date().toISOString()
        };
      }
    });
  }

  deleteWebhook(id: string): void {
    if (!confirm('Are you sure you want to delete this webhook subscription?')) return;
    this.webhookService.deleteSubscription(id).subscribe({
      next: () => {
        this.loadWebhooks();
      },
      error: (err) => {
        this.webhookError = 'Failed to delete webhook: ' + (err?.message || 'Server error');
      }
    });
  }
}
