import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  SimulationScenario,
  SimulationCampaignTemplate,
  SimulationRunConfig,
  SimulationRunResponse,
  SimulationReport,
  SimulationStageResult,
  ExpectedVsActualAssertion
} from '../../core/models/security.models';

@Component({
  selector: 'app-simulation',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="soc-page-container">
      <!-- Header -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Simulation Center & Campaign Orchestrator</h1>
          <p class="soc-subtitle">
            Continuous reproducible security traffic generation against isolated testbed with telemetry correlation and assertion verification.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <polygon points="10 8 16 12 10 16 10 8"></polygon>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ activeRun ? activeRun.status : 'IDLE' }}</span>
              <span class="soc-stat-sub">Engine Status</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon purple">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                <polyline points="2 17 12 22 22 17"></polyline>
                <polyline points="2 12 12 17 22 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ activeRun ? activeRun.totalRequests : 0 }}</span>
              <span class="soc-stat-sub">Total Dispatched</span>
            </div>
          </div>

          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Invariant Safeguard Banner -->
      <div class="guardrail-banner">
        <div class="guardrail-item">
          <span class="guardrail-dot active"></span>
          <span>Target: <strong>Local Testbed (localhost:8000)</strong></span>
        </div>
        <div class="guardrail-item">
          <span class="guardrail-dot active"></span>
          <span>Provenance: <strong>X-Simulation-Run-Id Injected</strong></span>
        </div>
        <div class="guardrail-item">
          <span class="guardrail-dot active"></span>
          <span>Mode: <strong>Advisory & Safe Execution</strong></span>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="soc-tabs">
        <button
          class="soc-tab"
          [class.active]="currentTab === 'campaigns'"
          (click)="currentTab = 'campaigns'">
          Campaign Templates ({{ templates.length }})
        </button>
        <button
          class="soc-tab"
          [class.active]="currentTab === 'scenarios'"
          (click)="currentTab = 'scenarios'">
          Scenario Catalogue ({{ scenarios.length }})
        </button>
        <button
          class="soc-tab"
          [class.active]="currentTab === 'live'"
          (click)="currentTab = 'live'">
          Live Execution & Control
          <span *ngIf="activeRun && activeRun.status === 'RUNNING'" class="badge-pulse"></span>
        </button>
        <button
          class="soc-tab"
          [class.active]="currentTab === 'history'"
          (click)="currentTab = 'history'">
          Execution History ({{ executionHistory.length }})
        </button>
      </div>

      <!-- Tab 1: Campaign Templates -->
      <div *ngIf="currentTab === 'campaigns'" class="tab-content">
        <div class="campaign-grid">
          <div *ngFor="let tpl of templates" class="soc-card campaign-card">
            <div class="campaign-header">
              <div class="badge-row">
                <span class="badge" [ngClass]="getTrafficMixClass(tpl.trafficMix)">{{ tpl.trafficMix }}</span>
                <span class="badge badge-neutral">{{ tpl.stages.length }} STAGES</span>
              </div>
              <h3 class="campaign-name">{{ tpl.name }}</h3>
              <p class="campaign-desc">{{ tpl.description }}</p>
            </div>

            <div class="stage-timeline">
              <div *ngFor="let stage of tpl.stages" class="stage-step">
                <span class="step-num">{{ stage.stageNumber }}</span>
                <div class="step-info">
                  <div class="step-title">{{ stage.name }}</div>
                  <div class="step-meta">Scenario: <code>{{ stage.scenarioId }}</code> | {{ stage.iterations }} iterations</div>
                </div>
              </div>
            </div>

            <div class="campaign-footer">
              <div class="config-summary">
                <span>Rate: {{ tpl.defaultRequestRate }} req/s</span>
                <span>Concurrency: {{ tpl.defaultConcurrency }}</span>
              </div>
              <button (click)="launchTemplate(tpl)" class="btn btn-primary btn-sm" [disabled]="activeRun && activeRun.status === 'RUNNING'">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                Launch Campaign
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 2: Scenario Catalogue -->
      <div *ngIf="currentTab === 'scenarios'" class="tab-content">
        <div class="filter-bar">
          <div class="category-filters">
            <button
              *ngFor="let cat of scenarioCategories"
              class="btn-filter"
              [class.active]="selectedCategory === cat"
              (click)="selectedCategory = cat">
              {{ cat }}
            </button>
          </div>
          <input
            type="text"
            [(ngModel)]="scenarioSearch"
            placeholder="Search scenario by ID or name..."
            class="soc-input search-box" />
        </div>

        <div class="scenario-table-container soc-card">
          <table class="soc-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Scenario Name</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Target Endpoints</th>
                <th>Expected Outcomes</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let sc of filteredScenarios">
                <td><code>{{ sc.id }}</code></td>
                <td>
                  <strong>{{ sc.name }}</strong>
                  <div class="sub-text">{{ sc.description }}</div>
                </td>
                <td><span class="badge" [ngClass]="getCategoryBadgeClass(sc.category)">{{ sc.category }}</span></td>
                <td><span class="badge" [ngClass]="getSeverityBadgeClass(sc.severity)">{{ sc.severity }}</span></td>
                <td>
                  <div *ngFor="let ep of sc.targetEndpoints" class="endpoint-chip">
                    <code>{{ ep }}</code>
                  </div>
                </td>
                <td>
                  <div *ngFor="let out of sc.expectedOutcomes" class="outcome-chip">
                    {{ out }}
                  </div>
                </td>
                <td>
                  <button
                    (click)="runSingleScenario(sc.id)"
                    class="btn btn-secondary btn-sm"
                    [disabled]="activeRun && activeRun.status === 'RUNNING'">
                    Run Ad-hoc
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab 3: Live Execution & Control -->
      <div *ngIf="currentTab === 'live'" class="tab-content">
        <div *ngIf="!activeRun" class="soc-card empty-state">
          <div class="empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <polygon points="10 8 16 12 10 16 10 8"></polygon>
            </svg>
          </div>
          <h3>No Active Simulation Run</h3>
          <p>Select a campaign template or scenario to initiate automated traffic generation.</p>
          <button (click)="currentTab = 'campaigns'" class="btn btn-primary">Browse Templates</button>
        </div>

        <div *ngIf="activeRun" class="live-dashboard">
          <!-- Control Panel -->
          <div class="soc-card control-panel">
            <div class="run-header">
              <div>
                <div class="run-meta-row">
                  <span class="run-title">Run: <code>{{ activeRun.runId }}</code></span>
                  <span class="campaign-title">Campaign: <code>{{ activeRun.campaignId }}</code></span>
                  <span class="badge" [ngClass]="getStatusBadgeClass(activeRun.status)">{{ activeRun.status }}</span>
                </div>
                <div class="run-sub-meta">
                  Template: <strong>{{ activeRun.templateId }}</strong> | Started: {{ activeRun.startTime | date:'mediumTime' }}
                </div>
              </div>

              <div class="control-actions">
                <button
                  *ngIf="activeRun.status === 'RUNNING'"
                  (click)="pauseRun()"
                  class="btn btn-warning btn-sm">
                  Pause
                </button>
                <button
                  *ngIf="activeRun.status === 'PAUSED'"
                  (click)="resumeRun()"
                  class="btn btn-success btn-sm">
                  Resume
                </button>
                <button
                  *ngIf="activeRun.status === 'RUNNING' || activeRun.status === 'PAUSED'"
                  (click)="stopRun()"
                  class="btn btn-danger btn-sm">
                  Hard Stop
                </button>
                <button
                  *ngIf="activeRun.status === 'COMPLETED' || activeRun.status === 'STOPPED'"
                  (click)="viewReport(activeRun.runId)"
                  class="btn btn-primary btn-sm">
                  View Report
                </button>
              </div>
            </div>

            <!-- Metrics Bar -->
            <div class="metrics-row">
              <div class="metric-box">
                <span class="metric-num">{{ activeRun.totalRequests }}</span>
                <span class="metric-lbl">Total Requests</span>
              </div>
              <div class="metric-box success">
                <span class="metric-num">{{ activeRun.requests2xx }}</span>
                <span class="metric-lbl">2xx Successful</span>
              </div>
              <div class="metric-box warning">
                <span class="metric-num">{{ activeRun.requests4xx }}</span>
                <span class="metric-lbl">4xx Probed / Blocked</span>
              </div>
              <div class="metric-box danger">
                <span class="metric-num">{{ activeRun.requests5xx }}</span>
                <span class="metric-lbl">5xx Errors</span>
              </div>
              <div class="metric-box">
                <span class="metric-num">{{ activeRun.allAssertionsPassed ? '100%' : 'Verifying' }}</span>
                <span class="metric-lbl">Assertion Health</span>
              </div>
            </div>
          </div>

          <!-- Per-Stage Execution Pipeline -->
          <div class="soc-card stage-pipeline">
            <h3 class="section-title">Executed Stages ({{ activeRun.stages.length }})</h3>
            <div class="stage-card-list">
              <div *ngFor="let stg of activeRun.stages" class="stage-result-card" [class.failed]="stg.status === 'FAILED'">
                <div class="stg-header">
                  <span class="stg-badge">Stage {{ stg.stageNumber }}</span>
                  <strong class="stg-name">{{ stg.stageName }}</strong>
                  <span class="badge" [ngClass]="stg.status === 'PASSED' ? 'badge-success' : 'badge-danger'">{{ stg.status }}</span>
                </div>
                <div class="stg-metrics">
                  <span>Scenario: <code>{{ stg.scenarioId }}</code></span>
                  <span>Requests: {{ stg.totalRequests }} ({{ stg.successfulRequests }} 2xx, {{ stg.failedRequests }} err)</span>
                  <span>Duration: {{ stg.durationMs }} ms</span>
                </div>
                <div class="stg-assertions" *ngIf="stg.assertionResults && stg.assertionResults.length > 0">
                  <div class="assertion-title">Verified Assertions:</div>
                  <div *ngFor="let a of stg.assertionResults" class="assertion-row">
                    <span class="assert-icon" [class.passed]="a.passed">{{ a.passed ? '✓' : '✗' }}</span>
                    <span class="assert-type">[{{ a.assertionType }}]</span>
                    <span class="assert-target"><code>{{ a.targetIdentifier }}</code></span>
                    <span class="assert-detail">{{ a.details }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 4: Execution History & Reports -->
      <div *ngIf="currentTab === 'history'" class="tab-content">
        <div class="soc-card history-container">
          <table class="soc-table">
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Campaign ID</th>
                <th>Template</th>
                <th>Status</th>
                <th>Requests</th>
                <th>Assertions</th>
                <th>Timestamp</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let run of executionHistory">
                <td><code>{{ run.runId }}</code></td>
                <td><code>{{ run.campaignId }}</code></td>
                <td><strong>{{ run.templateId }}</strong></td>
                <td><span class="badge" [ngClass]="getStatusBadgeClass(run.status)">{{ run.status }}</span></td>
                <td>{{ run.totalRequests }} ({{ run.requests2xx }}/{{ run.requests4xx }}/{{ run.requests5xx }})</td>
                <td>
                  <span class="badge" [ngClass]="run.allAssertionsPassed ? 'badge-success' : 'badge-danger'">
                    {{ run.allAssertionsPassed ? 'ALL PASSED' : 'DISCREPANCY' }}
                  </span>
                </td>
                <td>{{ run.startTime | date:'medium' }}</td>
                <td>
                  <button (click)="viewReport(run.runId)" class="btn btn-secondary btn-sm">Report</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Report Modal / Drawer -->
      <div *ngIf="selectedReport" class="soc-modal-backdrop" (click)="selectedReport = null">
        <div class="soc-modal-content soc-card" (click)="$event.stopPropagation()">
          <div class="modal-header">
            <h3>Simulation Verification Report: <code>{{ selectedReport.runId }}</code></h3>
            <button (click)="selectedReport = null" class="btn-close">×</button>
          </div>
          <div class="modal-body">
            <div class="report-meta">
              <div><strong>Template:</strong> {{ selectedReport.templateId }}</div>
              <div><strong>Status:</strong> {{ selectedReport.status }}</div>
              <div><strong>Duration:</strong> {{ selectedReport.durationMs }} ms</div>
              <div><strong>Stages Passed:</strong> {{ selectedReport.passedStages }} / {{ selectedReport.totalStages }}</div>
            </div>
            <div class="markdown-preview">
              <pre>{{ selectedReport.markdownReport }}</pre>
            </div>
          </div>
          <div class="modal-footer">
            <button (click)="downloadReport(selectedReport)" class="btn btn-primary btn-sm">Download JSON</button>
            <button (click)="selectedReport = null" class="btn btn-secondary btn-sm">Close</button>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
    }
    .soc-title {
      font-size: 24px;
      font-weight: 700;
      color: #f1f5f9;
      margin: 0 0 6px 0;
    }
    .soc-subtitle {
      font-size: 14px;
      color: #94a3b8;
      margin: 0;
    }
    .header-stat-pills {
      display: flex;
      gap: 12px;
      align-items: center;
    }
    .soc-stat-pill {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 8px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .soc-stat-icon {
      width: 32px;
      height: 32px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .soc-stat-icon.teal { background: rgba(20, 184, 166, 0.15); color: #14b8a6; }
    .soc-stat-icon.purple { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
    .soc-stat-content {
      display: flex;
      flex-direction: column;
    }
    .soc-stat-val {
      font-size: 15px;
      font-weight: 700;
      color: #f8fafc;
    }
    .soc-stat-sub {
      font-size: 11px;
      color: #94a3b8;
    }
    .guardrail-banner {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid #1e293b;
      border-left: 4px solid #10b981;
      border-radius: 6px;
      padding: 10px 16px;
      display: flex;
      gap: 24px;
      font-size: 12px;
      color: #cbd5e1;
    }
    .guardrail-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .guardrail-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10b981;
    }
    .soc-tabs {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid #334155;
      padding-bottom: 2px;
    }
    .soc-tab {
      background: transparent;
      border: none;
      color: #94a3b8;
      padding: 10px 16px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      position: relative;
    }
    .soc-tab:hover { color: #f8fafc; }
    .soc-tab.active {
      color: #38bdf8;
      border-bottom-color: #38bdf8;
    }
    .badge-pulse {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #22c55e;
      display: inline-block;
      margin-left: 6px;
      animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); }
      70% { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); }
      100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
    }
    .campaign-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
      gap: 20px;
    }
    .soc-card {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 10px;
      padding: 20px;
    }
    .campaign-header { margin-bottom: 14px; }
    .badge-row { display: flex; gap: 8px; margin-bottom: 8px; }
    .campaign-name {
      font-size: 16px;
      font-weight: 700;
      color: #f1f5f9;
      margin: 0 0 6px 0;
    }
    .campaign-desc {
      font-size: 13px;
      color: #94a3b8;
      margin: 0;
      min-height: 38px;
    }
    .stage-timeline {
      display: flex;
      flex-direction: column;
      gap: 8px;
      margin: 14px 0;
      border-left: 2px solid #334155;
      padding-left: 12px;
    }
    .stage-step {
      display: flex;
      align-items: flex-start;
      gap: 8px;
    }
    .step-num {
      background: #1e293b;
      color: #38bdf8;
      font-size: 11px;
      font-weight: 700;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .step-title {
      font-size: 12px;
      font-weight: 600;
      color: #e2e8f0;
    }
    .step-meta {
      font-size: 11px;
      color: #64748b;
    }
    .campaign-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid #1e293b;
    }
    .config-summary {
      font-size: 12px;
      color: #94a3b8;
      display: flex;
      gap: 12px;
    }
    .filter-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .category-filters {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .btn-filter {
      background: #1e293b;
      border: 1px solid #334155;
      color: #94a3b8;
      font-size: 12px;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn-filter.active {
      background: #0284c7;
      color: #fff;
      border-color: #0284c7;
    }
    .search-box {
      min-width: 280px;
    }
    .soc-input {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 6px;
      color: #f8fafc;
      padding: 8px 12px;
      font-size: 13px;
    }
    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .soc-table th {
      text-align: left;
      padding: 12px 14px;
      color: #94a3b8;
      border-bottom: 1px solid #334155;
      font-weight: 600;
    }
    .soc-table td {
      padding: 12px 14px;
      border-bottom: 1px solid #1e293b;
      color: #cbd5e1;
    }
    .endpoint-chip {
      background: #1e293b;
      padding: 2px 6px;
      border-radius: 4px;
      margin-bottom: 2px;
      display: inline-block;
      font-size: 11px;
    }
    .outcome-chip {
      font-size: 11px;
      color: #94a3b8;
    }
    .btn {
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-sm { padding: 6px 10px; font-size: 12px; }
    .btn-primary { background: #0284c7; color: #fff; }
    .btn-secondary { background: #1e293b; border: 1px solid #334155; color: #cbd5e1; }
    .btn-warning { background: #d97706; color: #fff; }
    .btn-success { background: #16a34a; color: #fff; }
    .btn-danger { background: #dc2626; color: #fff; }
    .badge {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      display: inline-block;
    }
    .badge-info { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
    .badge-success { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
    .badge-warning { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
    .badge-danger { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .badge-neutral { background: #1e293b; color: #94a3b8; }
    .control-panel {
      margin-bottom: 20px;
    }
    .run-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 16px;
    }
    .run-meta-row {
      display: flex;
      gap: 16px;
      align-items: center;
      font-size: 15px;
      margin-bottom: 4px;
    }
    .run-sub-meta {
      font-size: 12px;
      color: #94a3b8;
    }
    .control-actions {
      display: flex;
      gap: 8px;
    }
    .metrics-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      padding-top: 14px;
      border-top: 1px solid #1e293b;
    }
    .metric-box {
      background: #1e293b;
      padding: 10px;
      border-radius: 6px;
      text-align: center;
    }
    .metric-box.success { border-left: 3px solid #22c55e; }
    .metric-box.warning { border-left: 3px solid #f59e0b; }
    .metric-box.danger { border-left: 3px solid #ef4444; }
    .metric-num {
      display: block;
      font-size: 20px;
      font-weight: 700;
      color: #f8fafc;
    }
    .metric-lbl {
      font-size: 11px;
      color: #94a3b8;
    }
    .stage-card-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: 12px;
    }
    .stage-result-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 14px;
    }
    .stage-result-card.failed {
      border-color: #ef4444;
    }
    .stg-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }
    .stg-badge {
      background: #0284c7;
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
    }
    .stg-metrics {
      display: flex;
      gap: 20px;
      font-size: 12px;
      color: #94a3b8;
      margin-bottom: 10px;
    }
    .stg-assertions {
      background: #0f172a;
      border-radius: 6px;
      padding: 10px;
      font-size: 12px;
    }
    .assertion-title {
      font-weight: 600;
      color: #cbd5e1;
      margin-bottom: 6px;
    }
    .assertion-row {
      display: flex;
      gap: 8px;
      align-items: center;
      margin-bottom: 4px;
    }
    .assert-icon.passed { color: #22c55e; }
    .assert-icon:not(.passed) { color: #ef4444; }
    .assert-type { color: #38bdf8; font-size: 11px; }
    .empty-state {
      text-align: center;
      padding: 60px 20px;
    }
    .empty-icon {
      color: #64748b;
      margin-bottom: 16px;
    }
    .soc-modal-backdrop {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999;
    }
    .soc-modal-content {
      width: 90%;
      max-width: 800px;
      max-height: 85vh;
      display: flex;
      flex-direction: column;
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #334155;
      padding-bottom: 12px;
    }
    .btn-close {
      background: transparent;
      border: none;
      color: #94a3b8;
      font-size: 24px;
      cursor: pointer;
    }
    .modal-body {
      overflow-y: auto;
      padding: 16px 0;
    }
    .report-meta {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
      font-size: 13px;
      margin-bottom: 14px;
      color: #cbd5e1;
    }
    .markdown-preview pre {
      background: #1e293b;
      padding: 14px;
      border-radius: 6px;
      color: #e2e8f0;
      font-size: 12px;
      white-space: pre-wrap;
    }
    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      border-top: 1px solid #334155;
      padding-top: 12px;
    }
  `]
})
export class SimulationComponent implements OnInit, OnDestroy {
  private readonly api = inject(SecurityApiService);

  currentTab: 'campaigns' | 'scenarios' | 'live' | 'history' = 'campaigns';
  loading = false;

  scenarios: SimulationScenario[] = [];
  templates: SimulationCampaignTemplate[] = [];
  activeRun: SimulationRunResponse | null = null;
  executionHistory: SimulationRunResponse[] = [];
  selectedReport: SimulationReport | null = null;

  scenarioCategories = ['ALL', 'BENIGN', 'BOLA', 'LEAKAGE', 'EXFILTRATION', 'PROBING', 'MIXED', 'INFRASTRUCTURE'];
  selectedCategory = 'ALL';
  scenarioSearch = '';

  private pollInterval: any = null;

  ngOnInit(): void {
    this.refresh();
    this.pollInterval = setInterval(() => {
      if (this.activeRun && (this.activeRun.status === 'RUNNING' || this.activeRun.status === 'PAUSED')) {
        this.pollActiveRun();
      }
    }, 2000);
  }

  ngOnDestroy(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
    }
  }

  refresh(): void {
    this.loading = true;
    this.api.getSimulationScenarios().subscribe({
      next: (sc) => {
        this.scenarios = sc;
        this.loading = false;
      },
      error: () => { this.loading = false; }
    });

    this.api.getSimulationTemplates().subscribe({
      next: (tpls) => { this.templates = tpls; },
      error: () => {}
    });

    this.api.getSimulationRuns().subscribe({
      next: (runs) => {
        this.executionHistory = runs;
        if (!this.activeRun && runs.length > 0) {
          const running = runs.find(r => r.status === 'RUNNING' || r.status === 'PAUSED');
          if (running) {
            this.activeRun = running;
            this.currentTab = 'live';
          }
        }
      },
      error: () => {}
    });
  }

  get filteredScenarios(): SimulationScenario[] {
    return this.scenarios.filter(sc => {
      const matchCat = this.selectedCategory === 'ALL' || sc.category.toUpperCase() === this.selectedCategory.toUpperCase();
      const query = this.scenarioSearch.toLowerCase();
      const matchSearch = !query || sc.id.toLowerCase().includes(query) || sc.name.toLowerCase().includes(query);
      return matchCat && matchSearch;
    });
  }

  launchTemplate(template: SimulationCampaignTemplate): void {
    const config: SimulationRunConfig = {
      templateId: template.id,
      durationSeconds: template.defaultDurationSeconds,
      requestRate: template.defaultRequestRate,
      concurrency: template.defaultConcurrency,
      trafficMix: template.trafficMix,
      deterministicSeed: 42,
      dryRun: false
    };

    this.api.startSimulationRun(config).subscribe({
      next: (run) => {
        this.activeRun = run;
        this.currentTab = 'live';
        this.executionHistory.unshift(run);
      },
      error: (err) => console.error('Failed to start run', err)
    });
  }

  runSingleScenario(scenarioId: string): void {
    const config: SimulationRunConfig = {
      scenarioIds: [scenarioId],
      durationSeconds: 30,
      requestRate: 5.0,
      concurrency: 1,
      trafficMix: 'SEQUENTIAL',
      deterministicSeed: 42,
      dryRun: false
    };

    this.api.startSimulationRun(config).subscribe({
      next: (run) => {
        this.activeRun = run;
        this.currentTab = 'live';
        this.executionHistory.unshift(run);
      },
      error: (err) => console.error('Failed to start ad-hoc run', err)
    });
  }

  pauseRun(): void {
    if (!this.activeRun) return;
    this.api.pauseSimulationRun(this.activeRun.runId).subscribe({
      next: (run) => { this.activeRun = run; }
    });
  }

  resumeRun(): void {
    if (!this.activeRun) return;
    this.api.resumeSimulationRun(this.activeRun.runId).subscribe({
      next: (run) => { this.activeRun = run; }
    });
  }

  stopRun(): void {
    if (!this.activeRun) return;
    this.api.stopSimulationRun(this.activeRun.runId).subscribe({
      next: (run) => { this.activeRun = run; }
    });
  }

  pollActiveRun(): void {
    if (!this.activeRun) return;
    this.api.getSimulationRun(this.activeRun.runId).subscribe({
      next: (run) => {
        this.activeRun = run;
        const idx = this.executionHistory.findIndex(r => r.runId === run.runId);
        if (idx >= 0) {
          this.executionHistory[idx] = run;
        }
      }
    });
  }

  viewReport(runId: string): void {
    this.api.getSimulationReport(runId).subscribe({
      next: (report) => { this.selectedReport = report; }
    });
  }

  downloadReport(report: SimulationReport): void {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const a = document.createElement('a');
    a.setAttribute('href', dataStr);
    a.setAttribute('download', `shieldops-sim-${report.runId}.json`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  getTrafficMixClass(mix: string): string {
    switch (mix) {
      case 'SEQUENTIAL': return 'badge-info';
      case 'CONCURRENT': return 'badge-warning';
      case 'MIXED': return 'badge-danger';
      default: return 'badge-neutral';
    }
  }

  getCategoryBadgeClass(category: string): string {
    switch (category) {
      case 'BENIGN': return 'badge-success';
      case 'BOLA': return 'badge-danger';
      case 'LEAKAGE': return 'badge-warning';
      case 'EXFILTRATION': return 'badge-danger';
      case 'PROBING': return 'badge-warning';
      case 'INFRASTRUCTURE': return 'badge-info';
      default: return 'badge-neutral';
    }
  }

  getSeverityBadgeClass(severity: string): string {
    switch (severity) {
      case 'CRITICAL': return 'badge-danger';
      case 'HIGH': return 'badge-warning';
      case 'MEDIUM': return 'badge-info';
      default: return 'badge-neutral';
    }
  }

  getStatusBadgeClass(status: string): string {
    switch (status) {
      case 'RUNNING': return 'badge-success';
      case 'PAUSED': return 'badge-warning';
      case 'STOPPED': return 'badge-danger';
      case 'COMPLETED': return 'badge-info';
      default: return 'badge-neutral';
    }
  }
}

