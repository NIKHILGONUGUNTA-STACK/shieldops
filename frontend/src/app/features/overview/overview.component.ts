import { Component, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityOverview, ProblemDetail, IncidentSummary } from '../../core/models/security.models';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../shared/components/status-badge/status-badge.component';
import { LoadingSpinnerComponent } from '../../shared/components/loading-spinner/loading-spinner.component';
import { EmptyStateComponent } from '../../shared/components/empty-state/empty-state.component';

@Component({
  selector: 'app-overview',
  standalone: true,
  imports: [
    CommonModule,
    RouterLink,
    SeverityBadgeComponent,
    StatusBadgeComponent,
    LoadingSpinnerComponent,
    EmptyStateComponent
  ],
  template: `
    <div class="soc-page">
      <!-- Top Title, Window Selector & Dual Stat Rings matching Wallarm Structure -->
      <div class="page-top-bar">
        <div class="title-with-controls">
          <div class="breadcrumb-tag">
            <span class="live-dot"></span>
            SHIELDOPS SOC / SITUATIONAL AWARENESS
          </div>
          <h1 class="main-title">API Abuse Prevention & Telemetry</h1>

          <!-- Time Window Selector & Refresh Controls -->
          <div class="window-controls-bar">
            <label for="windowHoursSelect" class="window-label">TIME WINDOW:</label>
            <select
              id="windowHoursSelect"
              [value]="selectedWindow()"
              (change)="onWindowChange($event)"
              class="form-select window-select"
              [disabled]="loading()"
            >
              <option [value]="6">Last 6 Hours</option>
              <option [value]="12">Last 12 Hours</option>
              <option [value]="24">Last 24 Hours</option>
              <option [value]="48">Last 48 Hours</option>
              <option [value]="72">Last 72 Hours</option>
              <option [value]="168">Last 7 Days (168h)</option>
            </select>

            <button (click)="refresh()" class="btn btn-secondary btn-sm refresh-btn" [disabled]="loading()">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" [class.spin]="loading()">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
              </svg>
              Refresh
            </button>
          </div>
        </div>

        <!-- Right Side Dual Stat Rings (Populated from Real Backend Overview) -->
        <div class="top-stat-rings" *ngIf="overview() as data">
          <div class="stat-ring-card">
            <div class="ring-icon-wrap red-ring">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF4D5A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            </div>
            <div class="ring-text">
              <div class="ring-val font-semibold">{{ data.activeIncidentsCount }} Open Incidents</div>
              <div class="ring-sub text-muted">for active {{ selectedWindow() }}h window</div>
            </div>
          </div>

          <div class="stat-ring-card">
            <div class="ring-icon-wrap amber-ring">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF7A1A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
              </svg>
            </div>
            <div class="ring-text">
              <div class="ring-val font-semibold">{{ data.totalEvents24h | number }} Evaluated Events</div>
              <div class="ring-sub text-muted">{{ calculateAnomalyRatio(data) }}% anomaly density</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      <app-loading-spinner *ngIf="loading()" message="Aggregating live PostgreSQL SOC telemetry..."></app-loading-spinner>

      <!-- Error State -->
      <div *ngIf="error()" class="error-panel soc-card">
        <div class="error-header">
          <span class="error-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#FF4D5A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </span>
          <span class="error-title font-semibold">Failed to load Security Overview</span>
        </div>
        <p class="error-detail">{{ error()?.detail || 'Telemetry database connection timeout' }}</p>
        <button (click)="refresh()" class="btn btn-secondary btn-sm mt-3">Retry Request</button>
      </div>

      <!-- Main Dashboard Grid when loaded -->
      <div *ngIf="!loading() && overview() as data" class="dashboard-grid">
        <!-- KPI Strip: Dense Telemetry Posture -->
        <div class="kpi-strip">
          <div class="kpi-card soc-card">
            <div class="kpi-label">EVALUATED API EVENTS</div>
            <div class="kpi-value mono">{{ data.totalEvents24h | number }}</div>
            <div class="kpi-subtext text-muted">Ingested & evaluated in window</div>
          </div>

          <div class="kpi-card soc-card alert-orange">
            <div class="kpi-label">ANOMALY EVENTS FLAGGED</div>
            <div class="kpi-value mono text-orange">{{ data.totalAnomalies24h | number }}</div>
            <div class="kpi-subtext text-muted">Exceeding deterministic threshold</div>
          </div>

          <div class="kpi-card soc-card" [class.critical]="data.activeIncidentsCount > 0">
            <div class="kpi-label">OPEN INCIDENTS QUEUE</div>
            <div class="kpi-value mono" [class.text-red]="data.activeIncidentsCount > 0">{{ data.activeIncidentsCount | number }}</div>
            <div class="kpi-subtext text-muted">Requiring analyst investigation</div>
          </div>

          <div class="kpi-card soc-card">
            <div class="kpi-label">ANOMALY RATIO</div>
            <div class="kpi-value mono text-amber">{{ calculateAnomalyRatio(data) }}%</div>
            <div class="kpi-subtext text-muted">Telemetry anomaly density</div>
          </div>
        </div>

        <!-- Top Row: Bot & Attack Activity Spline Chart (Left) + Top Attackers (Right) -->
        <div class="grid-row top-row">
          <!-- Card 1: Bot & Attack Activity -->
          <div class="soc-card chart-panel">
            <div class="panel-header">
              <span class="panel-title">Bot & Attack Activity</span>
              <div class="time-range-toggles">
                <button class="toggle-pill-btn" [class.active]="timeRange() === 'day'" (click)="timeRange.set('day')">Day</button>
                <button class="toggle-pill-btn" [class.active]="timeRange() === 'monthly'" (click)="timeRange.set('monthly')">Monthly</button>
                <button class="toggle-pill-btn" [class.active]="timeRange() === 'yearly'" (click)="timeRange.set('yearly')">Yearly</button>
              </div>
            </div>

            <!-- Dynamic Category Legend from Real Backend Telemetry -->
            <div class="chart-legend">
              <div *ngFor="let cat of getCategoryBreakdown(data)" class="legend-item">
                <span class="legend-dot" [style.background]="cat.color"></span>
                <span class="legend-label">{{ cat.name }}</span>
                <span class="legend-pct mono">{{ cat.percentage }}%</span>
              </div>
              <div *ngIf="getCategoryBreakdown(data).length === 0" class="legend-empty text-muted text-xs">
                Zero threat anomalies detected in current active window
              </div>
            </div>

            <!-- Interactive Smooth Spline Curve SVG Chart -->
            <div class="spline-chart-container">
              <svg class="spline-svg" viewBox="0 0 600 160" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="warmOrangeGlow" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#FF7A1A" stop-opacity="0.25"/>
                    <stop offset="100%" stop-color="#FF7A1A" stop-opacity="0.0"/>
                  </linearGradient>
                  <linearGradient id="coolBlueGlow" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#4A6CFF" stop-opacity="0.15"/>
                    <stop offset="100%" stop-color="#4A6CFF" stop-opacity="0.0"/>
                  </linearGradient>
                </defs>

                <!-- Gridlines -->
                <line x1="0" y1="40" x2="600" y2="40" stroke="#242126" stroke-width="1" stroke-dasharray="3,3"/>
                <line x1="0" y1="80" x2="600" y2="80" stroke="#242126" stroke-width="1" stroke-dasharray="3,3"/>
                <line x1="0" y1="120" x2="600" y2="120" stroke="#242126" stroke-width="1" stroke-dasharray="3,3"/>

                <!-- Warm Area Glow Fill -->
                <path d="M 0,110 C 100,60 200,90 300,50 C 400,20 500,80 600,60 L 600,160 L 0,160 Z" fill="url(#warmOrangeGlow)"/>

                <!-- Blue Curve (Primary Baseline) -->
                <path d="M 0,130 C 100,100 200,120 300,90 C 400,60 500,110 600,100" fill="none" stroke="#4A6CFF" stroke-width="1.8"/>

                <!-- Green Curve (Security Threshold) -->
                <path d="M 0,120 C 100,80 200,105 300,75 C 400,45 500,95 600,80" fill="none" stroke="#2ECC71" stroke-width="1.8"/>

                <!-- Orange Peak Curve (Active Anomaly Spikes) -->
                <path d="M 0,110 C 100,60 200,90 300,50 C 400,20 500,80 600,60" fill="none" stroke="#FF7A1A" stroke-width="2.2"/>

                <!-- Active Hover Indicator Point at X=300 (Peak Threat Window) -->
                <circle cx="300" cy="50" r="4.5" fill="#4A6CFF" stroke="#FFFFFF" stroke-width="1.5"/>
                <line x1="300" y1="50" x2="300" y2="160" stroke="#FF7A1A" stroke-width="1" stroke-dasharray="2,2"/>
              </svg>

              <!-- Real Hourly Telemetry Buckets Micro-histogram -->
              <div class="histogram-baseline" *ngIf="data.eventVolumeTrend.length > 0">
                <div *ngFor="let bucket of data.eventVolumeTrend" class="histo-bar-col" [title]="bucket.bucketTime + ': ' + bucket.eventCount + ' events'">
                  <div class="histo-bar" [style.height.px]="getHistoHeight(bucket.eventCount)"></div>
                </div>
              </div>

              <!-- Time axis labels -->
              <div class="time-axis-labels">
                <span *ngFor="let label of getTimeLabels(data)">{{ label }}</span>
              </div>
            </div>
          </div>

          <!-- Card 2: Top Attackers (Populated from Real Backend Incidents) -->
          <div class="soc-card attackers-panel">
            <div class="panel-header">
              <span class="panel-title">Top Attackers</span>
              <a routerLink="/attacks" class="view-link text-xs">View Telemetry →</a>
            </div>

            <!-- Table Header -->
            <div class="table-sub-header">
              <span class="sub-col col-ip">IPs / Entities</span>
              <span class="sub-col col-hits">Hits</span>
            </div>

            <!-- Real Attacker Rows -->
            <div class="attackers-list" *ngIf="data.recentIncidents.length > 0">
              <div *ngFor="let inc of data.recentIncidents.slice(0, 6)" class="attacker-row">
                <div class="attacker-ip-col">
                  <span class="entity-flag">🛡️</span>
                  <span class="attacker-ip mono">{{ inc.targetEntityValue }}</span>
                  <span class="cloud-pill mono">{{ inc.threatCategory }}</span>
                </div>
                <div class="attacker-hits mono font-semibold">{{ inc.eventCount }}</div>
              </div>
            </div>

            <!-- Skeleton Empty State when No Attackers -->
            <div *ngIf="data.recentIncidents.length === 0" class="attackers-skeleton">
              <div *ngFor="let _ of [1, 2, 3, 4]" class="skeleton-row">
                <div class="skeleton-bar medium"></div>
                <div class="skeleton-bar short"></div>
              </div>
              <div class="empty-compact text-muted text-xs">Zero active threats detected in current window</div>
            </div>
          </div>
        </div>

        <!-- Bottom Row: Top Targets (Left) + Behavioral Patterns (Right) -->
        <div class="grid-row bottom-row">
          <!-- Card 3: Top Targets -->
          <div class="soc-card targets-panel">
            <div class="panel-header">
              <span class="panel-title">Top Targets</span>
              <div class="target-type-toggles">
                <button class="toggle-pill-btn" [class.active]="targetType() === 'hosts'" (click)="targetType.set('hosts')">Hosts</button>
                <button class="toggle-pill-btn" [class.active]="targetType() === 'paths'" (click)="targetType.set('paths')">Paths</button>
              </div>
            </div>

            <!-- Real Distinct Targets from Backend -->
            <div class="targets-list" *ngIf="getDistinctTargets(data).length > 0">
              <div *ngFor="let target of getDistinctTargets(data)" class="target-row">
                <span class="target-name mono">{{ target.name }}</span>
                <span class="target-hits mono">{{ target.hits }} hits</span>
              </div>
            </div>

            <!-- Skeleton Empty State when No Targets -->
            <div *ngIf="getDistinctTargets(data).length === 0" class="targets-skeleton">
              <div *ngFor="let _ of [1, 2, 3, 4]" class="skeleton-row">
                <div class="skeleton-bar long"></div>
                <div class="skeleton-bar short"></div>
              </div>
              <div class="empty-compact text-muted text-xs">No target path anomalies recorded in current window</div>
            </div>
          </div>

          <!-- Card 4: Behavioral Patterns (Populated from Real Rules & Categories) -->
          <div class="soc-card patterns-panel">
            <div class="panel-header">
              <span class="panel-title">Behavioral Patterns</span>
              <a routerLink="/rules" class="view-link text-xs">View Rules →</a>
            </div>

            <div class="patterns-chart-wrap">
              <!-- Real Behavioral Bars -->
              <div class="patterns-bars-list" *ngIf="getBehavioralMetrics(data).length > 0">
                <div *ngFor="let metric of getBehavioralMetrics(data)" class="pattern-bar-item">
                  <span class="pattern-label">{{ metric.label }}</span>
                  <div class="pattern-bar-track">
                    <div class="pattern-bar-fill" [style.width.%]="metric.percentage">
                      <span class="pattern-val mono">{{ metric.value }}</span>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Skeleton Empty State when No Behavioral Patterns -->
              <div *ngIf="getBehavioralMetrics(data).length === 0" class="patterns-skeleton">
                <div *ngFor="let _ of [1, 2, 3, 4]" class="skeleton-pattern-row">
                  <div class="skeleton-bar short"></div>
                  <div class="skeleton-bar track-placeholder"></div>
                </div>
                <div class="empty-compact text-muted text-xs">Zero behavioral pattern triggers recorded</div>
              </div>

              <!-- 0 - 1000 X-Axis Scale matching Wallarm Grid -->
              <div class="patterns-x-axis">
                <span class="x-tick-label">0</span>
                <span class="x-tick-label">200</span>
                <span class="x-tick-label">400</span>
                <span class="x-tick-label">600</span>
                <span class="x-tick-label">800</span>
                <span class="x-tick-label">1000</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page {
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      max-width: 1600px;
      margin: 0 auto;
      width: 100%;
      background: var(--bg-canvas);
    }

    /* Page Top Bar */
    .page-top-bar {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      flex-wrap: wrap;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border-subtle);
    }

    .title-with-controls {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .breadcrumb-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--accent-orange);
      font-family: var(--font-mono);
      text-transform: uppercase;
    }

    .live-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-orange);
      box-shadow: 0 0 6px var(--accent-orange);
    }

    .main-title {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary);
      letter-spacing: -0.02em;
    }

    .window-controls-bar {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 4px;
    }

    .window-label {
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.06em;
      font-family: var(--font-mono);
    }

    .window-select {
      font-family: var(--font-mono);
      font-size: 11px;
      padding: 4px 8px;
      background: var(--bg-input);
      border: 1px solid var(--border-input);
      color: var(--text-primary);
      border-radius: 4px;
    }

    .refresh-btn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 10px;
      font-size: 11px;
    }

    .spin {
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      100% { transform: rotate(360deg); }
    }

    /* Top Dual Stat Rings matching Wallarm */
    .top-stat-rings {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .stat-ring-card {
      display: flex;
      align-items: center;
      gap: 12px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: 8px;
      padding: 8px 14px;
    }

    .ring-icon-wrap {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .ring-icon-wrap.red-ring {
      background: rgba(255, 77, 90, 0.12);
      border: 1px solid rgba(255, 77, 90, 0.35);
    }

    .ring-icon-wrap.amber-ring {
      background: rgba(255, 122, 26, 0.12);
      border: 1px solid rgba(255, 122, 26, 0.35);
    }

    .ring-text {
      display: flex;
      flex-direction: column;
      line-height: 1.25;
    }

    .ring-val {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .ring-sub {
      font-size: 10px;
      color: var(--text-muted);
    }

    /* KPI Strip */
    .kpi-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }

    .kpi-card {
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: 8px;
      position: relative;
    }

    .kpi-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: var(--border-subtle);
    }

    .kpi-card.alert-orange::before {
      background: var(--accent-orange);
    }

    .kpi-card.critical::before {
      background: var(--sev-critical);
    }

    .kpi-label {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-family: var(--font-mono);
      text-transform: uppercase;
    }

    .kpi-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      line-height: 1.1;
    }

    .kpi-subtext {
      font-size: 10px;
    }

    .text-orange { color: var(--accent-orange); }
    .text-amber { color: var(--accent-amber); }
    .text-red { color: var(--sev-critical); }

    /* Dashboard Grid Rows */
    .dashboard-grid {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .grid-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    @media (max-width: 1024px) {
      .grid-row {
        grid-template-columns: 1fr;
      }
    }

    /* Common Card Panels */
    .chart-panel, .attackers-panel, .targets-panel, .patterns-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: 8px;
      padding: 16px 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .panel-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .view-link {
      color: var(--accent-orange);
      text-decoration: none;
      font-weight: 500;
    }

    .view-link:hover {
      text-decoration: underline;
    }

    /* Toggle Pills */
    .time-range-toggles, .target-type-toggles {
      display: inline-flex;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 2px;
      gap: 2px;
    }

    .toggle-pill-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 4px;
      cursor: pointer;
      font-family: var(--font-sans);
      font-weight: 500;
      transition: all 0.15s ease;
    }

    .toggle-pill-btn.active {
      background: var(--bg-nav-active);
      color: var(--text-primary);
    }

    /* Spline Chart */
    .chart-legend {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      padding: 4px 0;
    }

    .legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
    }

    .legend-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
    }

    .legend-label {
      color: var(--text-secondary);
    }

    .legend-pct {
      color: var(--text-primary);
      font-weight: 600;
    }

    .spline-chart-container {
      position: relative;
      height: 170px;
      width: 100%;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .spline-svg {
      width: 100%;
      height: 120px;
      overflow: visible;
    }

    .histogram-baseline {
      display: flex;
      align-items: flex-end;
      gap: 4px;
      height: 20px;
      padding-top: 4px;
      border-top: 1px dashed var(--chart-grid);
    }

    .histo-bar-col {
      flex: 1;
      height: 100%;
      display: flex;
      align-items: flex-end;
    }

    .histo-bar {
      width: 100%;
      background: rgba(255, 122, 26, 0.45);
      border-radius: 1px 1px 0 0;
      min-height: 2px;
    }

    .time-axis-labels {
      display: flex;
      justify-content: space-between;
      font-size: 9px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      padding-top: 4px;
    }

    /* Attackers Table */
    .table-sub-header {
      display: flex;
      justify-content: space-between;
      padding: 4px 8px;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 10px;
      font-weight: 700;
      color: var(--text-muted);
      font-family: var(--font-mono);
      text-transform: uppercase;
    }

    .attackers-list {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .attacker-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 8px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      transition: background 0.15s ease;
    }

    .attacker-row:hover {
      background: var(--bg-hover);
      border-color: var(--border-default);
    }

    .attacker-ip-col {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .entity-flag {
      font-size: 12px;
    }

    .attacker-ip {
      font-size: 11px;
      color: var(--text-primary);
    }

    .cloud-pill {
      font-size: 9px;
      padding: 1px 5px;
      border-radius: 3px;
      background: rgba(74, 108, 255, 0.15);
      color: #8CA3FF;
      border: 1px solid rgba(74, 108, 255, 0.25);
    }

    .attacker-hits {
      font-size: 11px;
      color: var(--text-primary);
    }

    /* Targets Panel */
    .targets-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .target-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      padding: 6px 10px;
    }

    .target-row:hover {
      background: var(--bg-hover);
      border-color: var(--border-default);
    }

    .target-name {
      font-size: 11px;
      color: var(--text-secondary);
    }

    .target-hits {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-primary);
    }

    /* Behavioral Patterns */
    .patterns-chart-wrap {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .patterns-bars-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .pattern-bar-item {
      display: grid;
      grid-template-columns: 140px 1fr;
      align-items: center;
      gap: 12px;
    }

    .pattern-label {
      font-size: 11px;
      color: var(--text-secondary);
      text-align: right;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .pattern-bar-track {
      width: 100%;
      height: 18px;
      background: rgba(36, 33, 38, 0.4);
      border-radius: 4px;
      position: relative;
    }

    .pattern-bar-fill {
      height: 100%;
      background: rgba(196, 138, 69, 0.18);
      border: 1px solid #C48A45;
      box-shadow: 0 0 8px rgba(196, 138, 69, 0.2);
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: flex-end;
      padding-right: 6px;
      transition: width 0.4s ease-out;
      min-width: 24px;
    }

    .pattern-val {
      font-size: 9px;
      font-weight: 700;
      color: #F2F0F2;
    }

    .patterns-x-axis {
      display: flex;
      justify-content: space-between;
      margin-left: 152px;
      padding-top: 4px;
      border-top: 1px dashed var(--chart-grid);
    }

    .x-tick-label {
      font-size: 9px;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }

    /* Skeleton States */
    .attackers-skeleton, .targets-skeleton, .patterns-skeleton {
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 8px 0;
    }

    .skeleton-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .skeleton-pattern-row {
      display: grid;
      grid-template-columns: 140px 1fr;
      align-items: center;
      gap: 12px;
    }

    .skeleton-bar {
      height: 14px;
      background: rgba(255, 255, 255, 0.04);
      border-radius: 4px;
      animation: pulse 1.5s infinite;
    }

    .skeleton-bar.short { width: 50px; }
    .skeleton-bar.medium { width: 140px; }
    .skeleton-bar.long { width: 220px; }
    .skeleton-bar.track-placeholder { width: 100%; height: 18px; }

    .empty-compact {
      text-align: center;
      padding: 12px 0;
    }

    /* Error Panel */
    .error-panel {
      border-color: var(--sev-critical-border);
      background: var(--sev-critical-bg);
      color: var(--sev-critical);
      padding: 16px;
    }

    .error-header {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      margin-bottom: 6px;
    }

    .error-detail {
      font-size: 13px;
      color: var(--text-primary);
    }

    .mt-3 {
      margin-top: 12px;
    }
  `]
})
export class OverviewComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  readonly selectedWindow = signal<number>(24);
  readonly loading = signal<boolean>(true);
  readonly overview = signal<SecurityOverview | null>(null);
  readonly error = signal<ProblemDetail | null>(null);

  readonly timeRange = signal<string>('monthly');
  readonly targetType = signal<string>('hosts');

  ngOnInit(): void {
    this.loadOverview();
  }

  loadOverview(): void {
    this.loading.set(true);
    this.error.set(null);

    this.api.getOverview(this.selectedWindow()).subscribe({
      next: (data) => {
        this.overview.set(data);
        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onWindowChange(event: Event): void {
    const select = event.target as HTMLSelectElement;
    const windowHours = parseInt(select.value, 10);
    if (!isNaN(windowHours)) {
      this.selectedWindow.set(windowHours);
      this.loadOverview();
    }
  }

  refresh(): void {
    this.loadOverview();
  }

  calculateAnomalyRatio(data: SecurityOverview): string {
    if (!data.totalEvents24h || data.totalEvents24h === 0) return '0.0';
    const ratio = (data.totalAnomalies24h / data.totalEvents24h) * 100;
    return ratio.toFixed(1);
  }

  getCategoryBreakdown(data: SecurityOverview): { name: string; percentage: number; color: string }[] {
    if (!data.incidentsByCategory) return [];
    const entries = Object.entries(data.incidentsByCategory);
    const total = entries.reduce((acc, [, val]) => acc + val, 0);
    if (total === 0) return [];

    const colors = ['#4A6CFF', '#2ECC71', '#FF7A1A', '#7B61FF', '#C48A45'];
    return entries.map(([key, val], idx) => ({
      name: key.replace(/_/g, ' '),
      percentage: Math.round((val / total) * 100),
      color: colors[idx % colors.length]
    }));
  }

  getDistinctTargets(data: SecurityOverview): { name: string; hits: number }[] {
    if (!data.recentIncidents || data.recentIncidents.length === 0) return [];
    const map = new Map<string, number>();
    for (const inc of data.recentIncidents) {
      const target = inc.targetEntityValue || inc.threatCategory;
      map.set(target, (map.get(target) || 0) + inc.eventCount);
    }
    return Array.from(map.entries()).map(([name, hits]) => ({ name, hits }));
  }

  getBehavioralMetrics(data: SecurityOverview): { label: string; value: number; percentage: number }[] {
    const metrics: { label: string; value: number; percentage: number }[] = [];
    if (data.topRulesTriggered && data.topRulesTriggered.length > 0) {
      const maxVal = Math.max(...data.topRulesTriggered.map(r => r.count), 10);
      for (const rule of data.topRulesTriggered) {
        metrics.push({
          label: rule.ruleId,
          value: rule.count,
          percentage: Math.min(100, Math.round((rule.count / maxVal) * 100))
        });
      }
    } else if (data.incidentsByCategory) {
      const entries = Object.entries(data.incidentsByCategory);
      const maxVal = Math.max(...entries.map(([, count]) => count), 1);
      for (const [cat, count] of entries) {
        metrics.push({
          label: cat.replace(/_/g, ' '),
          value: count,
          percentage: Math.min(100, Math.round((count / maxVal) * 100))
        });
      }
    }
    return metrics;
  }

  getHistoHeight(count: number): number {
    return Math.min(20, Math.max(3, count * 2));
  }

  getTimeLabels(data: SecurityOverview): string[] {
    if (!data.eventVolumeTrend || data.eventVolumeTrend.length === 0) {
      return ['T-24h', 'T-18h', 'T-12h', 'T-6h', 'Now'];
    }
    const step = Math.max(1, Math.floor(data.eventVolumeTrend.length / 5));
    const labels: string[] = [];
    for (let i = 0; i < data.eventVolumeTrend.length; i += step) {
      const b = data.eventVolumeTrend[i];
      try {
        const d = new Date(b.bucketTime);
        labels.push(`${d.getHours()}:00`);
      } catch {
        labels.push(b.bucketTime);
      }
    }
    return labels;
  }
}
