import { Component, OnInit, OnDestroy, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  NetworkIntelligenceResponse,
  IdentityIntelligenceResponse,
  TenantActivityResponse,
  InfrastructureObservabilityResponse,
  ObservedIpRecord,
  ObservedIdentityRecord,
  TenantActivityRecord,
  ProblemDetail
} from '../../core/models/security.models';
import { LoadingSpinnerComponent } from '../../shared/components/loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../../shared/components/empty-state/empty-state.component';

type ActiveTab = 'network' | 'identity' | 'tenant' | 'infrastructure';

@Component({
  selector: 'app-soc-operations',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
    LoadingSpinnerComponent,
    EmptyStateComponent
  ],
  template: `
    <div class="soc-page">
      <!-- Header -->
      <div class="soc-header">
        <div>
          <div class="breadcrumb">GOVERNANCE & OPERATIONS / SOC RUNTIME</div>
          <h1 class="page-title">Enterprise SOC Runtime Operations & Observability</h1>
          <p class="page-subtitle">
            Evidence-driven operational telemetry, observed network & identity intelligence, tenant partitioning, and deep infrastructure health.
          </p>
        </div>

        <div class="header-actions">
          <div class="auto-refresh-toggle">
            <label class="toggle-label mono">
              <input type="checkbox" [(ngModel)]="autoRefresh" (change)="toggleAutoRefresh()" />
              AUTO-POLL (15s)
            </label>
          </div>
          <button (click)="refreshCurrentTab()" class="btn btn-secondary btn-sm" [disabled]="loading()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            {{ loading() ? 'Refreshing...' : 'Refresh Telemetry' }}
          </button>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="tab-strip">
        <button
          class="tab-btn"
          [class.active]="activeTab() === 'network'"
          (click)="setTab('network')"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          Network Intelligence
        </button>
        <button
          class="tab-btn"
          [class.active]="activeTab() === 'identity'"
          (click)="setTab('identity')"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          Identity Intelligence
        </button>
        <button
          class="tab-btn"
          [class.active]="activeTab() === 'tenant'"
          (click)="setTab('tenant')"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          Tenant Telemetry
        </button>
        <button
          class="tab-btn"
          [class.active]="activeTab() === 'infrastructure'"
          (click)="setTab('infrastructure')"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>
          Infrastructure Observability
        </button>
      </div>

      <!-- Error State -->
      <div *ngIf="error()" class="error-panel soc-card">
        <div class="error-header">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF4D5A" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>SOC Telemetry Query Failed</span>
        </div>
        <p class="error-detail">{{ error()?.detail || 'Failed to retrieve operational metrics from backend.' }}</p>
        <button (click)="refreshCurrentTab()" class="btn btn-secondary btn-sm mt-3">Retry Request</button>
      </div>

      <!-- Loading State -->
      <app-loading-spinner *ngIf="loading()" message="Aggregating runtime SOC telemetry from PostgreSQL & gateway monitors..."></app-loading-spinner>

      <!-- ==================================================================== -->
      <!-- TAB 1: NETWORK INTELLIGENCE -->
      <!-- ==================================================================== -->
      <div *ngIf="!loading() && activeTab() === 'network'">
        <!-- Filter Controls -->
        <div class="soc-card filter-card">
          <div class="filter-row">
            <div class="filter-item">
              <label class="filter-label">LOOKBACK WINDOW</label>
              <select [(ngModel)]="windowHours" (change)="loadNetworkIntelligence()" class="form-select">
                <option [value]="1">Last 1 Hour</option>
                <option [value]="6">Last 6 Hours</option>
                <option [value]="24">Last 24 Hours</option>
                <option [value]="72">Last 3 Days</option>
                <option [value]="168">Last 7 Days</option>
              </select>
            </div>
            <div class="filter-item">
              <label class="filter-label">MAX IP RESULTS</label>
              <select [(ngModel)]="recordLimit" (change)="loadNetworkIntelligence()" class="form-select">
                <option [value]="10">Top 10</option>
                <option [value]="25">Top 25</option>
                <option [value]="50">Top 50</option>
                <option [value]="100">Top 100</option>
              </select>
            </div>
          </div>
        </div>

        <div *ngIf="networkData() as net" class="content-block">
          <!-- Summary Cards -->
          <div class="stats-grid">
            <div class="stat-card">
              <span class="stat-title">Observed IP Addresses</span>
              <span class="stat-val text-teal font-bold">{{ net.totalObservedIps }}</span>
              <span class="stat-sub">Across {{ net.windowHours }}h lookback window</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Total Ingested Requests</span>
              <span class="stat-val">{{ calculateTotalNetworkRequests(net) }}</span>
              <span class="stat-sub">Aggregated HTTP gateway flows</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Overall Error Ratio</span>
              <span class="stat-val" [class.text-danger]="calculateNetworkErrorRate(net) > 20">
                {{ calculateNetworkErrorRate(net) | number:'1.1-1' }}%
              </span>
              <span class="stat-sub">4xx client + 5xx server faults</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Reputation Categories</span>
              <div class="reputation-summary-pills">
                <span class="badge loopback">Loopback: {{ countReputation(net, 'LOCAL_LOOPBACK') }}</span>
                <span class="badge internal">Internal: {{ countReputation(net, 'INTERNAL_NETWORK') }}</span>
                <span class="badge external">External: {{ countReputation(net, 'OBSERVED_EXTERNAL') }}</span>
              </div>
            </div>
          </div>

          <!-- Network IPs Table -->
          <div class="soc-card table-panel mt-4">
            <div class="panel-header">
              <h2 class="panel-title">Observed IP Traffic & Local Attribution</h2>
              <span class="mono text-muted text-xs">Sorted by highest request volume</span>
            </div>

            <app-empty-state
              *ngIf="net.observedIps.length === 0"
              title="Zero IP Traffic Observed"
              message="No network requests match the selected lookback window."
            ></app-empty-state>

            <div *ngIf="net.observedIps.length > 0" class="soc-table-container">
              <table class="soc-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Reputation Status</th>
                    <th>Total Requests</th>
                    <th>2xx / 4xx / 5xx</th>
                    <th>Error Rate</th>
                    <th>Unique Endpoints</th>
                    <th>First / Last Observed</th>
                    <th>Investigation</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let ip of net.observedIps">
                    <td class="mono font-bold">{{ ip.ipAddress }}</td>
                    <td>
                      <span class="reputation-badge" [ngClass]="getReputationClass(ip.reputationStatus)">
                        {{ ip.reputationStatus }}
                      </span>
                    </td>
                    <td class="mono">{{ ip.totalRequests | number }}</td>
                    <td class="mono text-xs">
                      <span class="text-success">{{ ip.requests2xx }}</span> /
                      <span class="text-warning">{{ ip.requests4xx }}</span> /
                      <span class="text-danger">{{ ip.requests5xx }}</span>
                    </td>
                    <td>
                      <div class="error-bar-container">
                        <span class="mono text-xs" [class.text-danger]="ip.errorRate > 20">{{ ip.errorRate | number:'1.1-1' }}%</span>
                        <div class="error-bar">
                          <div class="error-fill" [style.width.%]="Math.min(ip.errorRate, 100)" [class.critical]="ip.errorRate > 20"></div>
                        </div>
                      </div>
                    </td>
                    <td class="mono text-xs">{{ ip.uniqueEndpointsCount }}</td>
                    <td class="mono text-xs text-muted">
                      <div>{{ formatDateTime(ip.lastSeen) }}</div>
                      <div class="text-micro">First: {{ formatDateTime(ip.firstSeen) }}</div>
                    </td>
                    <td>
                      <a [routerLink]="['/events']" [queryParams]="{ sourceIp: ip.ipAddress }" class="btn btn-secondary btn-sm">
                        Trace in Events
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- ==================================================================== -->
      <!-- TAB 2: IDENTITY INTELLIGENCE -->
      <!-- ==================================================================== -->
      <div *ngIf="!loading() && activeTab() === 'identity'">
        <div class="soc-card filter-card">
          <div class="filter-row">
            <div class="filter-item">
              <label class="filter-label">LOOKBACK WINDOW</label>
              <select [(ngModel)]="windowHours" (change)="loadIdentityIntelligence()" class="form-select">
                <option [value]="1">Last 1 Hour</option>
                <option [value]="6">Last 6 Hours</option>
                <option [value]="24">Last 24 Hours</option>
                <option [value]="72">Last 3 Days</option>
                <option [value]="168">Last 7 Days</option>
              </select>
            </div>
            <div class="filter-item">
              <label class="filter-label">MAX IDENTITY RESULTS</label>
              <select [(ngModel)]="recordLimit" (change)="loadIdentityIntelligence()" class="form-select">
                <option [value]="10">Top 10</option>
                <option [value]="25">Top 25</option>
                <option [value]="50">Top 50</option>
                <option [value]="100">Top 100</option>
              </select>
            </div>
          </div>
        </div>

        <div *ngIf="identityData() as idData" class="content-block">
          <!-- Summary Cards -->
          <div class="stats-grid">
            <div class="stat-card">
              <span class="stat-title">Observed Identities</span>
              <span class="stat-val text-teal font-bold">{{ idData.totalObservedIdentities }}</span>
              <span class="stat-sub">JWT subjects & customer associations</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">High Risk Identities</span>
              <span class="stat-val text-danger font-bold">{{ countRisk(idData, 'HIGH_RISK') }}</span>
              <span class="stat-sub">Anomalies or high failure ratios</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Elevated Risk</span>
              <span class="stat-val text-warning font-bold">{{ countRisk(idData, 'ELEVATED') }}</span>
              <span class="stat-sub">Elevated 4xx or multi-tenant activity</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Benign Baseline</span>
              <span class="stat-val text-success font-bold">{{ countRisk(idData, 'BENIGN') }}</span>
              <span class="stat-sub">Normal transactional behavior</span>
            </div>
          </div>

          <!-- Identity Table -->
          <div class="soc-card table-panel mt-4">
            <div class="panel-header">
              <h2 class="panel-title">Authenticated Identity Profiles & Risk Classification</h2>
              <span class="mono text-muted text-xs">Deterministic risk based on observed anomalies and failure rates</span>
            </div>

            <app-empty-state
              *ngIf="idData.observedIdentities.length === 0"
              title="Zero Identities Observed"
              message="No authenticated identities recorded in the selected lookback window."
            ></app-empty-state>

            <div *ngIf="idData.observedIdentities.length > 0" class="soc-table-container">
              <table class="soc-table">
                <thead>
                  <tr>
                    <th>JWT Subject / Principal</th>
                    <th>Customer Binding</th>
                    <th>Roles</th>
                    <th>Risk Category</th>
                    <th>Total Requests</th>
                    <th>2xx / 4xx / 5xx</th>
                    <th>Anomalous Events</th>
                    <th>IPs / Tenants</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let record of idData.observedIdentities">
                    <td class="mono font-bold text-xs" [title]="record.subject">{{ truncateText(record.subject, 28) }}</td>
                    <td class="mono text-xs">{{ record.customerId || '—' }}</td>
                    <td class="mono text-xs text-muted">{{ record.roles || '—' }}</td>
                    <td>
                      <span class="risk-badge" [ngClass]="getRiskClass(record.riskCategory)">
                        <span class="risk-pulse" *ngIf="record.riskCategory === 'HIGH_RISK'"></span>
                        {{ record.riskCategory }}
                      </span>
                    </td>
                    <td class="mono">{{ record.totalRequests | number }}</td>
                    <td class="mono text-xs">
                      <span class="text-success">{{ record.requests2xx }}</span> /
                      <span class="text-warning">{{ record.requests4xx }}</span> /
                      <span class="text-danger">{{ record.requests5xx }}</span>
                    </td>
                    <td>
                      <span class="mono text-xs" [class.text-danger]="record.anomalousEventsCount > 0">
                        {{ record.anomalousEventsCount }}
                      </span>
                    </td>
                    <td class="mono text-xs">{{ record.uniqueIpsCount }} IPs / {{ record.tenantCount }} tenants</td>
                    <td>
                      <a
                        [routerLink]="['/events']"
                        [queryParams]="record.customerId ? { customerId: record.customerId } : {}"
                        class="btn btn-secondary btn-sm"
                      >
                        Explore
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- ==================================================================== -->
      <!-- TAB 3: TENANT ACTIVITY -->
      <!-- ==================================================================== -->
      <div *ngIf="!loading() && activeTab() === 'tenant'">
        <div class="soc-card filter-card">
          <div class="filter-row">
            <div class="filter-item">
              <label class="filter-label">LOOKBACK WINDOW</label>
              <select [(ngModel)]="windowHours" (change)="loadTenantActivity()" class="form-select">
                <option [value]="1">Last 1 Hour</option>
                <option [value]="6">Last 6 Hours</option>
                <option [value]="24">Last 24 Hours</option>
                <option [value]="72">Last 3 Days</option>
                <option [value]="168">Last 7 Days</option>
              </select>
            </div>
            <div class="filter-item">
              <label class="filter-label">MAX TENANT RESULTS</label>
              <select [(ngModel)]="recordLimit" (change)="loadTenantActivity()" class="form-select">
                <option [value]="10">Top 10</option>
                <option [value]="25">Top 25</option>
                <option [value]="50">Top 50</option>
              </select>
            </div>
          </div>
        </div>

        <div *ngIf="tenantData() as tData" class="content-block">
          <!-- Summary Cards -->
          <div class="stats-grid">
            <div class="stat-card">
              <span class="stat-title">Observed Tenant Partitions</span>
              <span class="stat-val text-teal font-bold">{{ tData.totalObservedTenants }}</span>
              <span class="stat-sub">Distinct active tenant workspaces</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Total Partitioned Requests</span>
              <span class="stat-val">{{ calculateTotalTenantRequests(tData) }}</span>
              <span class="stat-sub">Across all attributed tenants</span>
            </div>
            <div class="stat-card">
              <span class="stat-title">Attributed Identities</span>
              <span class="stat-val text-success font-bold">{{ calculateTotalTenantIdentities(tData) }}</span>
              <span class="stat-sub">Unique callers across partitions</span>
            </div>
          </div>

          <!-- Tenant Table -->
          <div class="soc-card table-panel mt-4">
            <div class="panel-header">
              <h2 class="panel-title">Multi-Tenant Telemetry Partition Activity</h2>
              <span class="mono text-muted text-xs">Derived from Flyway V10 tenant_id schema attribution</span>
            </div>

            <app-empty-state
              *ngIf="tData.tenants.length === 0"
              title="Zero Tenant Telemetry Observed"
              message="No tenant-attributed events found in the selected lookback window."
            ></app-empty-state>

            <div *ngIf="tData.tenants.length > 0" class="soc-table-container">
              <table class="soc-table">
                <thead>
                  <tr>
                    <th>Tenant Partition ID</th>
                    <th>Total Requests</th>
                    <th>2xx / 4xx / 5xx</th>
                    <th>Error Rate</th>
                    <th>Active Identities</th>
                    <th>Source IPs</th>
                    <th>First / Last Active</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let tenant of tData.tenants">
                    <td class="mono font-bold text-teal">{{ tenant.tenantId }}</td>
                    <td class="mono">{{ tenant.totalRequests | number }}</td>
                    <td class="mono text-xs">
                      <span class="text-success">{{ tenant.requests2xx }}</span> /
                      <span class="text-warning">{{ tenant.requests4xx }}</span> /
                      <span class="text-danger">{{ tenant.requests5xx }}</span>
                    </td>
                    <td>
                      <div class="error-bar-container">
                        <span class="mono text-xs" [class.text-danger]="tenant.errorRate > 20">{{ tenant.errorRate | number:'1.1-1' }}%</span>
                        <div class="error-bar">
                          <div class="error-fill" [style.width.%]="Math.min(tenant.errorRate, 100)" [class.critical]="tenant.errorRate > 20"></div>
                        </div>
                      </div>
                    </td>
                    <td class="mono">{{ tenant.uniqueIdentitiesCount }}</td>
                    <td class="mono">{{ tenant.uniqueIpsCount }}</td>
                    <td class="mono text-xs text-muted">
                      <div>{{ formatDateTime(tenant.lastSeen) }}</div>
                      <div class="text-micro">First: {{ formatDateTime(tenant.firstSeen) }}</div>
                    </td>
                    <td>
                      <a [routerLink]="['/events']" [queryParams]="{ tenantId: tenant.tenantId }" class="btn btn-secondary btn-sm">
                        Filter Events
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- ==================================================================== -->
      <!-- TAB 4: INFRASTRUCTURE OBSERVABILITY -->
      <!-- ==================================================================== -->
      <div *ngIf="!loading() && activeTab() === 'infrastructure'">
        <div *ngIf="infraData() as infra" class="content-block">
          <!-- Gateway Status Banner -->
          <div class="soc-card status-banner" [class.degraded]="infra.gatewayStatus !== 'HEALTHY'">
            <div class="banner-status-group">
              <span class="status-indicator-dot" [class.healthy]="infra.gatewayStatus === 'HEALTHY'"></span>
              <div>
                <h3 class="banner-title">API Gateway Tier: {{ infra.gatewayStatus }}</h3>
                <span class="mono text-muted text-xs">
                  Uptime: {{ formatUptime(infra.uptimeSeconds) }} · Host Time: {{ formatDateTime(infra.timestamp) }}
                </span>
              </div>
            </div>
            <span class="freshness-badge mono" [ngClass]="getFreshnessClass(infra.telemetryPipeline.freshnessSeconds)">
              Pipeline Freshness: {{ infra.telemetryPipeline.freshnessSeconds }}s latency
            </span>
          </div>

          <!-- Observability Grid -->
          <div class="infra-grid mt-4">
            <!-- 1. JVM Runtime -->
            <div class="soc-card infra-card">
              <div class="infra-card-header">
                <span class="infra-icon jvm">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>
                </span>
                <div>
                  <h4 class="infra-name">JVM Runtime & Memory</h4>
                  <span class="mono text-muted text-xs">HotSpot Virtual Machine</span>
                </div>
              </div>

              <div class="infra-body">
                <div class="metric-row">
                  <span class="metric-label">Heap Memory Used</span>
                  <span class="mono font-bold">
                    {{ formatBytes(infra.jvm.heapUsedBytes) }} / {{ formatBytes(infra.jvm.heapMaxBytes) }}
                  </span>
                </div>
                <div class="progress-bar-wrap">
                  <div class="progress-bar-fill" [style.width.%]="calculateHeapPercentage(infra.jvm)"></div>
                </div>
                <div class="metric-sub mono text-muted">
                  Utilization: {{ calculateHeapPercentage(infra.jvm) | number:'1.1-1' }}% · Free: {{ formatBytes(infra.jvm.heapFreeBytes) }}
                </div>

                <div class="metric-divider"></div>

                <div class="metric-row">
                  <span class="metric-label">Thread Pools</span>
                  <span class="mono font-bold">{{ infra.jvm.activeThreads }} Active</span>
                </div>
                <div class="thread-stats mono text-xs text-muted">
                  <span>Peak: {{ infra.jvm.peakThreads }}</span> ·
                  <span>Daemon: {{ infra.jvm.daemonThreads }}</span>
                </div>

                <div class="metric-divider"></div>

                <div class="metric-row">
                  <span class="metric-label">Process CPU Load</span>
                  <span class="mono font-bold">
                    {{ (infra.jvm.processCpuLoad >= 0 ? (infra.jvm.processCpuLoad * 100 | number:'1.1-1') + '%' : 'N/A') }}
                  </span>
                </div>
              </div>
            </div>

            <!-- 2. PostgreSQL HikariCP Connection Pool -->
            <div class="soc-card infra-card">
              <div class="infra-card-header">
                <span class="infra-icon db">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                </span>
                <div>
                  <h4 class="infra-name">PostgreSQL 17 Connection Pool</h4>
                  <span class="mono text-muted text-xs">HikariCP Datasource</span>
                </div>
              </div>

              <div class="infra-body">
                <div class="metric-row">
                  <span class="metric-label">Connection Status</span>
                  <span class="reputation-badge loopback font-bold">{{ infra.database.status }}</span>
                </div>

                <div class="metric-row mt-3">
                  <span class="metric-label">Active Connections</span>
                  <span class="mono font-bold text-teal">{{ infra.database.activeConnections }} / {{ infra.database.maxConnections }}</span>
                </div>
                <div class="progress-bar-wrap">
                  <div
                    class="progress-bar-fill db-fill"
                    [style.width.%]="(infra.database.activeConnections / (infra.database.maxConnections || 1)) * 100"
                  ></div>
                </div>

                <div class="metric-divider"></div>

                <div class="metric-row">
                  <span class="metric-label">Idle Connections</span>
                  <span class="mono">{{ infra.database.idleConnections }}</span>
                </div>
                <div class="metric-row mt-2">
                  <span class="metric-label">Total Allocated Connections</span>
                  <span class="mono">{{ infra.database.totalConnections }}</span>
                </div>
              </div>
            </div>

            <!-- 3. Redis Streams Telemetry Queue -->
            <div class="soc-card infra-card">
              <div class="infra-card-header">
                <span class="infra-icon redis">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                </span>
                <div>
                  <h4 class="infra-name">Redis Streams Broker</h4>
                  <span class="mono text-muted text-xs">Decoupled Telemetry Ingestion</span>
                </div>
              </div>

              <div class="infra-body">
                <div class="metric-row">
                  <span class="metric-label">Redis Status</span>
                  <span class="reputation-badge loopback font-bold">{{ infra.redis.status }}</span>
                </div>

                <div class="metric-divider"></div>

                <div class="metric-row">
                  <span class="metric-label">Stream Key</span>
                  <span class="mono text-xs text-teal">{{ infra.redis.streamKey }}</span>
                </div>

                <div class="metric-row mt-2">
                  <span class="metric-label">Queue Length (Backlog)</span>
                  <span class="mono font-bold" [class.text-danger]="(infra.redis.streamLength || 0) > 1000">
                    {{ infra.redis.streamLength !== null ? (infra.redis.streamLength | number) : 'N/A' }} msgs
                  </span>
                </div>

                <div class="metric-row mt-2">
                  <span class="metric-label">Ping Response</span>
                  <span class="mono text-xs text-success">{{ infra.redis.pingResponse || 'N/A' }}</span>
                </div>
              </div>
            </div>

            <!-- 4. Telemetry Pipeline Throughput & Freshness -->
            <div class="soc-card infra-card">
              <div class="infra-card-header">
                <span class="infra-icon pipeline">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                </span>
                <div>
                  <h4 class="infra-name">Telemetry Pipeline Ingestion</h4>
                  <span class="mono text-muted text-xs">Drain Worker & Posture Engine</span>
                </div>
              </div>

              <div class="infra-body">
                <div class="metric-row">
                  <span class="metric-label">Total Persisted Events</span>
                  <span class="mono font-bold text-teal">{{ infra.telemetryPipeline.totalEventsPersisted | number }}</span>
                </div>

                <div class="metric-row mt-2">
                  <span class="metric-label">Rate (Last 1 Hour)</span>
                  <span class="mono font-bold">{{ infra.telemetryPipeline.eventsLastHour | number }} events/hr</span>
                </div>

                <div class="metric-divider"></div>

                <div class="metric-row">
                  <span class="metric-label">Data Freshness</span>
                  <span class="mono font-bold" [ngClass]="getFreshnessTextClass(infra.telemetryPipeline.freshnessSeconds)">
                    {{ infra.telemetryPipeline.freshnessSeconds }}s
                  </span>
                </div>

                <div class="metric-row mt-2">
                  <span class="metric-label">Latest Ingested Event</span>
                  <span class="mono text-xs text-muted">
                    {{ formatDateTime(infra.telemetryPipeline.latestEventTimestamp || '') }}
                  </span>
                </div>

                <div class="metric-row mt-2">
                  <span class="metric-label">Ingestion Failures</span>
                  <span class="mono text-xs" [class.text-danger]="infra.telemetryPipeline.failureCount > 0">
                    {{ infra.telemetryPipeline.failureCount }}
                  </span>
                </div>
              </div>
            </div>
          </div>
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
    .soc-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: var(--space-4);
      flex-wrap: wrap;
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
      max-width: 750px;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: var(--space-4);
    }
    .auto-refresh-toggle {
      font-size: 11px;
      color: var(--text-secondary);
    }
    .toggle-label {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      cursor: pointer;
    }
    .tab-strip {
      display: flex;
      gap: var(--space-2);
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: var(--space-2);
      overflow-x: auto;
    }
    .tab-btn {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      padding: var(--space-2) var(--space-4);
      background: transparent;
      border: 1px solid transparent;
      border-radius: var(--radius-sm);
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .tab-btn:hover {
      color: var(--text-primary);
      background: var(--bg-hover);
    }
    .tab-btn.active {
      color: var(--accent-teal);
      background: rgba(255, 122, 26, 0.1);
      border-color: rgba(255, 122, 26, 0.3);
    }
    .filter-card {
      padding: var(--space-3) var(--space-4);
    }
    .filter-row {
      display: flex;
      gap: var(--space-4);
      flex-wrap: wrap;
    }
    .filter-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      min-width: 160px;
    }
    .filter-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .content-block {
      display: flex;
      flex-direction: column;
      gap: var(--space-4);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: var(--space-4);
    }
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border-card);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .stat-title {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
    }
    .stat-val {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      font-family: var(--font-mono);
    }
    .stat-sub {
      font-size: 11px;
      color: var(--text-muted);
    }
    .reputation-summary-pills {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-top: 4px;
    }
    .badge {
      font-size: 10px;
      font-family: var(--font-mono);
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 2px;
      display: inline-block;
    }
    .badge.loopback { background: rgba(74, 108, 255, 0.15); color: #4A6CFF; }
    .badge.internal { background: rgba(196, 138, 69, 0.15); color: #C48A45; }
    .badge.external { background: rgba(255, 77, 90, 0.15); color: #FF4D5A; }

    .reputation-badge {
      font-size: 10px;
      font-family: var(--font-mono);
      font-weight: 700;
      padding: 2px 6px;
      border-radius: var(--radius-sm);
    }
    .reputation-badge.loopback { background: rgba(74, 108, 255, 0.15); color: #4A6CFF; border: 1px solid rgba(74, 108, 255, 0.3); }
    .reputation-badge.internal { background: rgba(196, 138, 69, 0.15); color: #C48A45; border: 1px solid rgba(196, 138, 69, 0.3); }
    .reputation-badge.external { background: rgba(255, 77, 90, 0.15); color: #FF4D5A; border: 1px solid rgba(255, 77, 90, 0.3); }

    .risk-badge {
      font-size: 10px;
      font-family: var(--font-mono);
      font-weight: 700;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }
    .risk-badge.critical { background: rgba(255, 77, 90, 0.15); color: #FF4D5A; border: 1px solid rgba(255, 77, 90, 0.3); }
    .risk-badge.elevated { background: rgba(196, 138, 69, 0.15); color: #C48A45; border: 1px solid rgba(196, 138, 69, 0.3); }
    .risk-badge.benign { background: rgba(46, 204, 113, 0.15); color: #2ECC71; border: 1px solid rgba(46, 204, 113, 0.3); }
    .risk-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #FF4D5A;
      animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
      0% { opacity: 0.4; }
      50% { opacity: 1; }
      100% { opacity: 0.4; }
    }

    .error-bar-container {
      display: flex;
      align-items: center;
      gap: var(--space-2);
    }
    .error-bar {
      flex: 1;
      height: 6px;
      background: var(--border-subtle);
      border-radius: 3px;
      overflow: hidden;
      max-width: 60px;
    }
    .error-fill {
      height: 100%;
      background: var(--accent-amber);
    }
    .error-fill.critical {
      background: var(--sev-critical);
    }

    .status-banner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: var(--space-4);
      background: rgba(46, 204, 113, 0.05);
      border-color: rgba(46, 204, 113, 0.3);
      flex-wrap: wrap;
      gap: var(--space-3);
    }
    .status-banner.degraded {
      background: rgba(255, 77, 90, 0.05);
      border-color: rgba(255, 77, 90, 0.3);
    }
    .banner-status-group {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .status-indicator-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: #FF4D5A;
    }
    .status-indicator-dot.healthy {
      background: #2ECC71;
      box-shadow: 0 0 10px rgba(46, 204, 113, 0.5);
    }
    .banner-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0;
    }
    .freshness-badge {
      font-size: 11px;
      font-weight: 700;
      padding: 4px 8px;
      border-radius: var(--radius-sm);
    }
    .freshness-badge.fresh { background: rgba(46, 204, 113, 0.15); color: #2ECC71; border: 1px solid rgba(46, 204, 113, 0.3); }
    .freshness-badge.warm { background: rgba(196, 138, 69, 0.15); color: #C48A45; border: 1px solid rgba(196, 138, 69, 0.3); }
    .freshness-badge.stale { background: rgba(255, 77, 90, 0.15); color: #FF4D5A; border: 1px solid rgba(255, 77, 90, 0.3); }

    .infra-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: var(--space-4);
    }
    .infra-card {
      padding: var(--space-4);
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
    }
    .infra-card-header {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      padding-bottom: var(--space-3);
      border-bottom: 1px solid var(--border-subtle);
    }
    .infra-icon {
      width: 36px;
      height: 36px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .infra-icon.jvm { background: rgba(255, 122, 26, 0.15); color: #FF7A1A; }
    .infra-icon.db { background: rgba(74, 108, 255, 0.15); color: #4A6CFF; }
    .infra-icon.redis { background: rgba(196, 138, 69, 0.15); color: #C48A45; }
    .infra-icon.pipeline { background: rgba(46, 204, 113, 0.15); color: #2ECC71; }
    .infra-name {
      font-size: 14px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0;
    }
    .infra-body {
      display: flex;
      flex-direction: column;
      gap: var(--space-2);
    }
    .metric-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
    }
    .metric-label {
      color: var(--text-secondary);
    }
    .metric-divider {
      height: 1px;
      background: var(--border-subtle);
      margin: var(--space-1) 0;
    }
    .progress-bar-wrap {
      height: 6px;
      background: var(--border-subtle);
      border-radius: 3px;
      overflow: hidden;
      margin: 4px 0;
    }
    .progress-bar-fill {
      height: 100%;
      background: var(--accent-teal);
    }
    .progress-bar-fill.db-fill {
      background: #4A6CFF;
    }
    .text-micro {
      font-size: 9px;
      color: var(--text-muted);
    }
    .text-success { color: #2ECC71; }
    .text-warning { color: #C48A45; }
    .text-danger { color: #FF4D5A; }
    .text-teal { color: var(--accent-teal); }
    .font-bold { font-weight: 700; }
    .mt-2 { margin-top: var(--space-2); }
    .mt-3 { margin-top: var(--space-3); }
    .mt-4 { margin-top: var(--space-4); }

    .error-panel {
      border-color: var(--sev-critical-border);
      background: var(--sev-critical-bg);
      color: var(--sev-critical);
      padding: var(--space-4);
    }
    .error-header {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-weight: 700;
      font-size: 14px;
      margin-bottom: var(--space-2);
    }
    .error-detail {
      font-size: 13px;
      color: var(--text-primary);
    }
  `]
})
export class SocOperationsComponent implements OnInit, OnDestroy {
  private readonly api = inject(SecurityApiService);

  readonly Math = Math;

  readonly activeTab = signal<ActiveTab>('network');
  readonly loading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  readonly networkData = signal<NetworkIntelligenceResponse | null>(null);
  readonly identityData = signal<IdentityIntelligenceResponse | null>(null);
  readonly tenantData = signal<TenantActivityResponse | null>(null);
  readonly infraData = signal<InfrastructureObservabilityResponse | null>(null);

  windowHours = 24;
  recordLimit = 25;
  autoRefresh = false;
  private refreshTimer: any = null;

  ngOnInit(): void {
    this.refreshCurrentTab();
  }

  ngOnDestroy(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }
  }

  setTab(tab: ActiveTab): void {
    this.activeTab.set(tab);
    this.refreshCurrentTab();
  }

  toggleAutoRefresh(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.autoRefresh) {
      this.refreshTimer = setInterval(() => {
        this.refreshCurrentTab(true);
      }, 15000);
    }
  }

  refreshCurrentTab(silent = false): void {
    if (!silent) this.loading.set(true);
    this.error.set(null);

    switch (this.activeTab()) {
      case 'network':
        this.loadNetworkIntelligence();
        break;
      case 'identity':
        this.loadIdentityIntelligence();
        break;
      case 'tenant':
        this.loadTenantActivity();
        break;
      case 'infrastructure':
        this.loadInfrastructureObservability();
        break;
    }
  }

  loadNetworkIntelligence(): void {
    this.api.getNetworkIntelligence(this.windowHours, this.recordLimit).subscribe({
      next: (res) => {
        this.networkData.set(res);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  loadIdentityIntelligence(): void {
    this.api.getIdentityIntelligence(this.windowHours, this.recordLimit).subscribe({
      next: (res) => {
        this.identityData.set(res);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  loadTenantActivity(): void {
    this.api.getTenantActivity(this.windowHours, this.recordLimit).subscribe({
      next: (res) => {
        this.tenantData.set(res);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  loadInfrastructureObservability(): void {
    this.api.getInfrastructureObservability().subscribe({
      next: (res) => {
        this.infraData.set(res);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  // Helpers
  calculateTotalNetworkRequests(net: NetworkIntelligenceResponse): number {
    return net.observedIps.reduce((acc, curr) => acc + curr.totalRequests, 0);
  }

  calculateNetworkErrorRate(net: NetworkIntelligenceResponse): number {
    const total = this.calculateTotalNetworkRequests(net);
    if (total === 0) return 0;
    const errors = net.observedIps.reduce((acc, curr) => acc + curr.requests4xx + curr.requests5xx, 0);
    return (errors / total) * 100;
  }

  countReputation(net: NetworkIntelligenceResponse, status: string): number {
    return net.observedIps.filter(ip => ip.reputationStatus === status).length;
  }

  countRisk(idData: IdentityIntelligenceResponse, category: string): number {
    return idData.observedIdentities.filter(id => id.riskCategory === category).length;
  }

  calculateTotalTenantRequests(tData: TenantActivityResponse): number {
    return tData.tenants.reduce((acc, curr) => acc + curr.totalRequests, 0);
  }

  calculateTotalTenantIdentities(tData: TenantActivityResponse): number {
    return tData.tenants.reduce((acc, curr) => acc + curr.uniqueIdentitiesCount, 0);
  }

  getReputationClass(status: string): string {
    switch (status) {
      case 'LOCAL_LOOPBACK': return 'loopback';
      case 'INTERNAL_NETWORK': return 'internal';
      default: return 'external';
    }
  }

  getRiskClass(cat: string): string {
    switch (cat) {
      case 'HIGH_RISK': return 'critical';
      case 'ELEVATED': return 'elevated';
      default: return 'benign';
    }
  }

  getFreshnessClass(sec: number): string {
    if (sec <= 15) return 'fresh';
    if (sec <= 60) return 'warm';
    return 'stale';
  }

  getFreshnessTextClass(sec: number): string {
    if (sec <= 15) return 'text-success';
    if (sec <= 60) return 'text-warning';
    return 'text-danger';
  }

  calculateHeapPercentage(jvm: any): number {
    if (!jvm || !jvm.heapMaxBytes) return 0;
    return (jvm.heapUsedBytes / jvm.heapMaxBytes) * 100;
  }

  formatBytes(bytes: number): string {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  formatUptime(sec: number): string {
    if (!sec) return '0s';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  formatDateTime(isoString: string): string {
    if (!isoString) return '—';
    try {
      const date = new Date(isoString);
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  }

  truncateText(str: string, maxLen: number): string {
    if (!str) return '—';
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '...';
  }
}
