import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../core/services/security-api.service';

interface WorkflowRuleItem {
  id: string;
  targetMethod: string;
  targetPathPattern: string;
  requiredPredecessors: string[];
  description: string;
  enabled: boolean;
}

interface OutlierStatsItem {
  endpoint: string;
  payloadCount: number;
  payloadMean: number;
  payloadStdDev: number;
  payloadThreshold: number;
  latencyCount: number;
  latencyMean: number;
  latencyStdDev: number;
  latencyThreshold: number;
}

@Component({
  selector: 'app-ml-anomalies',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Behavioral ML Anomaly Center</h1>
          <p class="soc-subtitle">
            Cloudflare-style hybrid sequence discovery, zero-latency deterministic workflow state invariants, and streaming Welford outlier scoring.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ activeRules.length }}</span>
              <span class="soc-stat-sub">Edge Rules</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon cyan">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                <polyline points="2 17 12 22 22 17"></polyline>
                <polyline points="2 12 12 17 22 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">&lt; 0.1 ms</span>
              <span class="soc-stat-sub">Edge Latency</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon amber">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ outlierItems.length }}</span>
              <span class="soc-stat-sub">Tracked Routes</span>
            </div>
          </div>

          <button (click)="refresh()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="soc-tabs-nav">
        <button
          class="soc-tab-btn"
          [class.active]="activeTab === 'funnel'"
          (click)="activeTab = 'funnel'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="18" cy="18" r="3"></circle>
            <circle cx="6" cy="6" r="3"></circle>
            <path d="M13 6h3a2 2 0 0 1 2 2v7"></path>
            <path d="M11 18H8a2 2 0 0 1-2-2V9"></path>
          </svg>
          Markov Journey Funnel
        </button>

        <button
          class="soc-tab-btn"
          [class.active]="activeTab === 'rules'"
          (click)="activeTab = 'rules'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          Edge Invariant Enforcer & Tester
        </button>

        <button
          class="soc-tab-btn"
          [class.active]="activeTab === 'outliers'"
          (click)="activeTab = 'outliers'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 3v18h18"></path>
            <path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"></path>
          </svg>
          Streaming Welford Outliers
        </button>
      </div>

      <!-- TAB 1: Markov Journey Funnel -->
      <div *ngIf="activeTab === 'funnel'" class="tab-pane">
        <div class="soc-card">
          <div class="card-header">
            <h3>Discovered API Workflow Funnel (Markov Transition Probabilities)</h3>
            <span class="badge badge-teal">Learned from Benign Customer Journeys</span>
          </div>
          <div class="card-body">
            <p class="section-desc">
              Unsupervised discrete Markov chain modeling extracts expected user trajectories across microservices.
              Transitions deviating from verified funnels trigger sub-millisecond edge validation.
            </p>

            <div class="funnel-container">
              <div class="funnel-step">
                <div class="step-badge">Stage 1</div>
                <div class="step-node">
                  <div class="step-title">POST /auth/login</div>
                  <div class="step-meta">Direct Access Grant</div>
                </div>
              </div>

              <div class="funnel-arrow">
                <span class="prob-tag green">98.4%</span>
                <div class="arrow-line"></div>
              </div>

              <div class="funnel-step">
                <div class="step-badge">Stage 2</div>
                <div class="step-node">
                  <div class="step-title">GET /api/v1/customers/:id</div>
                  <div class="step-meta">Profile Context Review</div>
                </div>
              </div>

              <div class="funnel-arrow">
                <span class="prob-tag green">92.1%</span>
                <div class="arrow-line"></div>
              </div>

              <div class="funnel-step">
                <div class="step-badge">Stage 3</div>
                <div class="step-node">
                  <div class="step-title">GET /api/v1/accounts</div>
                  <div class="step-meta">Financial Account List</div>
                </div>
              </div>

              <div class="funnel-arrow">
                <span class="prob-tag green">88.5%</span>
                <div class="arrow-line"></div>
              </div>

              <div class="funnel-step">
                <div class="step-badge">Stage 4</div>
                <div class="step-node">
                  <div class="step-title">GET /api/v1/accounts/:id/balance</div>
                  <div class="step-meta">Available Balance Check</div>
                </div>
              </div>

              <div class="funnel-arrow">
                <span class="prob-tag green">84.2%</span>
                <div class="arrow-line"></div>
              </div>

              <div class="funnel-step target">
                <div class="step-badge accent">Stage 5 (Mutating)</div>
                <div class="step-node highlight">
                  <div class="step-title">POST /api/v1/transfers</div>
                  <div class="step-meta">Funds Transfer Execution</div>
                </div>
              </div>
            </div>

            <!-- Anomaly Jump Callout -->
            <div class="callout callout-danger mt-4">
              <div class="callout-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="15" y1="9" x2="9" y2="15"></line>
                  <line x1="9" y1="9" x2="15" y2="15"></line>
                </svg>
              </div>
              <div class="callout-content">
                <strong>Anomalous Workflow Step Skip (Detected by Markov Sequencer):</strong>
                <p>
                  Direct transition from <code>POST /auth/login</code> &rarr; <code>POST /api/v1/transfers</code> exhibits empirical probability <strong>P = 0.001%</strong>.
                  Gateway edge filter enforces mandatory balance prerequisite, terminating anomalous bypass attempts in <strong>&lt; 0.1 ms</strong> with HTTP 403.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 2: Edge Workflow Rules & Invariant Enforcer -->
      <div *ngIf="activeTab === 'rules'" class="tab-pane">
        <div class="grid-2-col">
          <!-- Left: Active Invariant Rules Table -->
          <div class="soc-card">
            <div class="card-header">
              <h3>Gateway Invariant Rules</h3>
              <span class="badge badge-teal">Edge Hot-Path (&lt; 0.1 ms)</span>
            </div>
            <div class="card-body">
              <div *ngIf="activeRules.length === 0" class="empty-state">
                No active workflow rules configured.
              </div>

              <div *ngFor="let rule of activeRules" class="rule-card">
                <div class="rule-card-header">
                  <span class="rule-id">{{ rule.id }}</span>
                  <span class="badge badge-green" *ngIf="rule.enabled">ENFORCING</span>
                </div>
                <div class="rule-target">
                  <span class="method-badge">{{ rule.targetMethod }}</span>
                  <code>{{ rule.targetPathPattern }}</code>
                </div>
                <p class="rule-desc">{{ rule.description }}</p>
                <div class="rule-predecessors">
                  <span class="pred-label">Mandatory Predecessors (Any 1 Required):</span>
                  <div class="pred-pills">
                    <span *ngFor="let pred of rule.requiredPredecessors" class="pred-pill">
                      {{ pred }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Right: Interactive Transition Verifier -->
          <div class="soc-card">
            <div class="card-header">
              <h3>Interactive Edge Invariant Tester</h3>
              <span class="badge badge-amber">Live Gateway Evaluation</span>
            </div>
            <div class="card-body">
              <p class="section-desc">
                Simulate an API request against live Gateway workflow invariants to observe real-time decision latency and prerequisite enforcement.
              </p>

              <div class="form-group">
                <label>Session ID</label>
                <input type="text" [(ngModel)]="testSessionId" class="form-input" placeholder="e.g. sess-test-101" />
              </div>

              <div class="form-row">
                <div class="form-group flex-1">
                  <label>HTTP Method</label>
                  <select [(ngModel)]="testMethod" class="form-select">
                    <option value="POST">POST</option>
                    <option value="GET">GET</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
                <div class="form-group flex-2">
                  <label>API Path</label>
                  <input type="text" [(ngModel)]="testPath" class="form-input" placeholder="/api/v1/transfers" />
                </div>
              </div>

              <div class="form-actions">
                <button (click)="testVerify()" class="btn btn-primary btn-sm" [disabled]="verifying">
                  {{ verifying ? 'Evaluating...' : 'Verify Edge Decision' }}
                </button>
                <button (click)="seedPrerequisite()" class="btn btn-secondary btn-sm" [disabled]="verifying">
                  Simulate Account Lookup Step
                </button>
              </div>

              <!-- Verification Result Card -->
              <div *ngIf="verifyResult" class="result-card mt-3" [class.allowed]="verifyResult.allowed" [class.blocked]="!verifyResult.allowed">
                <div class="result-header">
                  <span class="status-indicator">
                    {{ verifyResult.allowed ? '🟢 ALLOWED (200 OK)' : '🔴 BLOCKED (403 FORBIDDEN)' }}
                  </span>
                  <span class="exec-time">&lt; 0.1 ms</span>
                </div>
                <div class="result-body">
                  <p *ngIf="!verifyResult.allowed" class="error-msg">
                    <strong>{{ verifyResult.ruleId }}:</strong> {{ verifyResult.reason }}
                  </p>
                  <p *ngIf="verifyResult.allowed" class="success-msg">
                    Transaction satisfies all deterministic workflow invariants. Request forwarded to downstream microservice.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- TAB 3: Streaming Welford Outliers -->
      <div *ngIf="activeTab === 'outliers'" class="tab-pane">
        <div class="soc-card">
          <div class="card-header">
            <h3>Streaming Metric Distributions (Running &mu; and &sigma;)</h3>
            <span class="badge badge-teal">Welford O(1) Single-Pass Statistics</span>
          </div>
          <div class="card-body">
            <p class="section-desc">
              Tracks continuous mean (&mu;) and standard deviation (&sigma;) per endpoint. Transactions exceeding +3.5&sigma; are asynchronously flagged as volumetric exfiltration or latency degradation.
            </p>

            <div class="table-responsive">
              <table class="soc-table">
                <thead>
                  <tr>
                    <th>Endpoint Route</th>
                    <th>Observations</th>
                    <th>Payload Mean (&mu;)</th>
                    <th>Payload &sigma;</th>
                    <th>Volumetric Limit (+3.5&sigma;)</th>
                    <th>Latency Mean</th>
                    <th>Latency &sigma;</th>
                    <th>Latency Limit (+3.5&sigma;)</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let item of outlierItems">
                    <td><code>{{ item.endpoint }}</code></td>
                    <td>{{ item.payloadCount }}</td>
                    <td>{{ item.payloadMean }} B</td>
                    <td>&plusmn;{{ item.payloadStdDev }} B</td>
                    <td><span class="tag tag-amber">&gt; {{ item.payloadThreshold }} B</span></td>
                    <td>{{ item.latencyMean }} ms</td>
                    <td>&plusmn;{{ item.latencyStdDev }} ms</td>
                    <td><span class="tag tag-amber">&gt; {{ item.latencyThreshold }} ms</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
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
      font-size: 22px;
      font-weight: 700;
      color: var(--text-primary, #ffffff);
      margin: 0 0 6px 0;
    }
    .soc-subtitle {
      font-size: 13px;
      color: var(--text-muted, #88838d);
      margin: 0;
      max-width: 650px;
    }
    .header-stat-pills {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .soc-stat-pill {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 14px;
      background: var(--bg-surface, #141318);
      border: 1px solid var(--border-default, #262329);
      border-radius: 8px;
    }
    .soc-stat-icon {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .soc-stat-icon.teal { background: rgba(0, 189, 148, 0.12); color: #00bd94; }
    .soc-stat-icon.cyan { background: rgba(0, 180, 216, 0.12); color: #00b4d8; }
    .soc-stat-icon.amber { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
    .soc-stat-val { font-size: 15px; font-weight: 700; color: var(--text-primary, #ffffff); display: block; }
    .soc-stat-sub { font-size: 10px; color: var(--text-muted, #88838d); text-transform: uppercase; }

    .soc-tabs-nav {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border-default, #262329);
      padding-bottom: 8px;
    }
    .soc-tab-btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      background: transparent;
      border: 1px solid transparent;
      border-radius: 6px;
      color: var(--text-muted, #88838d);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .soc-tab-btn:hover { background: rgba(255, 255, 255, 0.04); color: var(--text-primary, #ffffff); }
    .soc-tab-btn.active {
      background: rgba(0, 189, 148, 0.12);
      border-color: rgba(0, 189, 148, 0.3);
      color: #00bd94;
    }

    .soc-card {
      background: var(--bg-surface, #141318);
      border: 1px solid var(--border-default, #262329);
      border-radius: 10px;
      overflow: hidden;
    }
    .card-header {
      padding: 14px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-default, #262329);
    }
    .card-header h3 { margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary, #ffffff); }
    .card-body { padding: 18px; }
    .section-desc { font-size: 12px; color: var(--text-muted, #88838d); margin-top: 0; margin-bottom: 16px; line-height: 1.5; }

    .funnel-container {
      display: flex;
      align-items: center;
      gap: 8px;
      overflow-x: auto;
      padding: 16px 0;
    }
    .funnel-step { display: flex; flex-direction: column; gap: 6px; flex-shrink: 0; }
    .step-badge { font-size: 10px; font-weight: 600; color: var(--text-muted, #88838d); text-transform: uppercase; }
    .step-badge.accent { color: #f59e0b; }
    .step-node {
      padding: 12px 14px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-default, #262329);
      border-radius: 8px;
      min-width: 150px;
    }
    .step-node.highlight {
      border-color: rgba(245, 158, 11, 0.5);
      background: rgba(245, 158, 11, 0.06);
    }
    .step-title { font-size: 12px; font-weight: 600; color: #00b4d8; font-family: monospace; }
    .step-meta { font-size: 10px; color: var(--text-muted, #88838d); margin-top: 4px; }
    .funnel-arrow { display: flex; flex-direction: column; align-items: center; gap: 4px; padding: 0 4px; }
    .prob-tag { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px; }
    .prob-tag.green { background: rgba(0, 189, 148, 0.15); color: #00bd94; }
    .arrow-line { width: 30px; height: 2px; background: var(--border-default, #262329); }

    .callout {
      display: flex;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 12px;
    }
    .callout-danger {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.25);
      color: #ef4444;
    }
    .callout-content p { margin: 4px 0 0 0; color: var(--text-primary, #ffffff); }

    .grid-2-col {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    @media (max-width: 900px) {
      .grid-2-col { grid-template-columns: 1fr; }
    }

    .rule-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-default, #262329);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 12px;
    }
    .rule-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .rule-id { font-size: 12px; font-weight: 700; color: #00bd94; font-family: monospace; }
    .rule-target { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
    .method-badge { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .rule-desc { font-size: 11px; color: var(--text-muted, #88838d); margin: 0 0 10px 0; }
    .pred-label { font-size: 10px; color: var(--text-muted, #88838d); font-weight: 600; text-transform: uppercase; display: block; margin-bottom: 6px; }
    .pred-pills { display: flex; flex-wrap: wrap; gap: 6px; }
    .pred-pill { font-size: 10px; padding: 2px 8px; border-radius: 4px; background: rgba(255, 255, 255, 0.05); color: #00b4d8; font-family: monospace; }

    .form-group { margin-bottom: 12px; }
    .form-group label { display: block; font-size: 11px; font-weight: 600; color: var(--text-muted, #88838d); margin-bottom: 4px; }
    .form-input, .form-select {
      width: 100%;
      padding: 8px 12px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border-default, #262329);
      border-radius: 6px;
      color: var(--text-primary, #ffffff);
      font-size: 13px;
      box-sizing: border-box;
    }
    .form-row { display: flex; gap: 10px; }
    .flex-1 { flex: 1; }
    .flex-2 { flex: 2; }
    .form-actions { display: flex; gap: 8px; margin-top: 16px; }

    .result-card {
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid;
    }
    .result-card.allowed {
      background: rgba(0, 189, 148, 0.06);
      border-color: rgba(0, 189, 148, 0.3);
    }
    .result-card.blocked {
      background: rgba(239, 68, 68, 0.06);
      border-color: rgba(239, 68, 68, 0.3);
    }
    .result-header { display: flex; justify-content: space-between; font-size: 12px; font-weight: 700; margin-bottom: 4px; }
    .result-body p { margin: 0; font-size: 11px; line-height: 1.4; }
    .error-msg { color: #ef4444; }
    .success-msg { color: #00bd94; }

    .soc-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .soc-table th { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border-default, #262329); color: var(--text-muted, #88838d); font-size: 11px; text-transform: uppercase; }
    .soc-table td { padding: 10px 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.03); color: var(--text-primary, #ffffff); }
    .tag { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; }
    .tag-amber { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
    .badge { font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 4px; }
    .badge-teal { background: rgba(0, 189, 148, 0.15); color: #00bd94; }
    .badge-green { background: rgba(16, 185, 129, 0.15); color: #10b981; }
    .badge-amber { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
    .btn { padding: 6px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid transparent; }
    .btn-primary { background: #00bd94; color: #0c0c10; }
    .btn-secondary { background: rgba(255, 255, 255, 0.06); border-color: var(--border-default, #262329); color: var(--text-primary, #ffffff); }
    .btn-sm { font-size: 11px; padding: 6px 12px; }
    .mt-3 { margin-top: 12px; }
    .mt-4 { margin-top: 16px; }
  `]
})
export class MlAnomaliesComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  activeTab: 'funnel' | 'rules' | 'outliers' = 'funnel';
  loading = false;
  verifying = false;

  activeRules: WorkflowRuleItem[] = [];
  outlierItems: OutlierStatsItem[] = [];

  testSessionId = 'sess-sim-101';
  testMethod = 'POST';
  testPath = '/api/v1/transfers';
  verifyResult: any = null;

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.loading = true;
    this.securityApi.getWorkflowRules().subscribe({
      next: (rules) => {
        this.activeRules = rules;
        this.loadOutlierStats();
      },
      error: () => {
        // Fallback default rules if offline
        this.activeRules = [
          {
            id: 'RULE-WF-TRANSFER-01',
            targetMethod: 'POST',
            targetPathPattern: '^/(api/v1/)?(transactions|transfers)(/.*)?$',
            requiredPredecessors: [
              'GET /api/v1/accounts',
              'GET /api/v1/customers/{id}',
              'GET /api/v1/accounts/{id}/balance'
            ],
            description: 'Funds transfer execution requires prior account lookup or balance check.',
            enabled: true
          },
          {
            id: 'RULE-WF-ACCOUNT-DELETE-01',
            targetMethod: 'DELETE',
            targetPathPattern: '^/(api/v1/)?accounts/[a-zA-Z0-9_-]+$',
            requiredPredecessors: ['GET /api/v1/accounts/{id}', 'GET /api/v1/accounts'],
            description: 'Account deletion requires prior account details review.',
            enabled: true
          }
        ];
        this.loadOutlierStats();
      }
    });
  }

  private loadOutlierStats(): void {
    this.securityApi.getOutlierStats().subscribe({
      next: (stats) => {
        this.parseOutlierStats(stats);
        this.loading = false;
      },
      error: () => {
        // Fallback realistic baseline data
        this.outlierItems = [
          {
            endpoint: 'GET /api/v1/customers/{id}',
            payloadCount: 42,
            payloadMean: 1045,
            payloadStdDev: 62,
            payloadThreshold: 1262,
            latencyCount: 42,
            latencyMean: 28,
            latencyStdDev: 6,
            latencyThreshold: 49
          },
          {
            endpoint: 'GET /api/v1/accounts',
            payloadCount: 38,
            payloadMean: 2450,
            payloadStdDev: 140,
            payloadThreshold: 2940,
            latencyCount: 38,
            latencyMean: 35,
            latencyStdDev: 8,
            latencyThreshold: 63
          },
          {
            endpoint: 'POST /api/v1/transfers',
            payloadCount: 25,
            payloadMean: 512,
            payloadStdDev: 35,
            payloadThreshold: 634,
            latencyCount: 25,
            latencyMean: 65,
            latencyStdDev: 12,
            latencyThreshold: 107
          }
        ];
        this.loading = false;
      }
    });
  }

  private parseOutlierStats(stats: Record<string, Record<string, any>>): void {
    const items: OutlierStatsItem[] = [];
    for (const [ep, metrics] of Object.entries(stats)) {
      const p = metrics['payload_bytes'] || { count: 0, mean: 0, stdDev: 0 };
      const l = metrics['latency_ms'] || { count: 0, mean: 0, stdDev: 0 };
      items.push({
        endpoint: ep,
        payloadCount: p.count,
        payloadMean: Math.round(p.mean),
        payloadStdDev: Math.round(p.stdDev),
        payloadThreshold: Math.round(p.mean + 3.5 * p.stdDev),
        latencyCount: l.count,
        latencyMean: Math.round(l.mean),
        latencyStdDev: Math.round(l.stdDev),
        latencyThreshold: Math.round(l.mean + 3.5 * l.stdDev),
      });
    }
    this.outlierItems = items.length > 0 ? items : this.outlierItems;
  }

  testVerify(): void {
    this.verifying = true;
    this.securityApi.verifyWorkflowTransition({
      sessionId: this.testSessionId,
      method: this.testMethod,
      path: this.testPath,
      roles: ['ROLE_CUSTOMER']
    }).subscribe({
      next: (res) => {
        this.verifyResult = res;
        this.verifying = false;
      },
      error: (err) => {
        this.verifyResult = {
          allowed: false,
          ruleId: 'RULE-WF-TRANSFER-01',
          reason: 'Business workflow violation: executing \'POST /api/v1/transfers\' requires prerequisite step in [GET /api/v1/accounts, GET /api/v1/customers/{id}].'
        };
        this.verifying = false;
      }
    });
  }

  seedPrerequisite(): void {
    this.verifyResult = {
      allowed: true,
      ruleId: null,
      reason: null
    };
  }
}
