import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityOverview } from '../../core/models/security.models';

interface RuleDefinition {
  id: string;
  name: string;
  category: string;
  owaspRef: string;
  mitreRef: string;
  slidingWindow: string;
  threshold: string;
  status: 'ACTIVE' | 'ADVISORY';
  description: string;
  triggerCount?: number;
}

@Component({
  selector: 'app-detection-rules',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Detection Rules</h1>
          <p class="soc-subtitle">
            Operational status, sliding-window thresholds, and detection telemetry for the 6 core Aegis correlation rules.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <polyline points="9 12 11 14 15 10"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">6 ACTIVE</span>
              <span class="soc-stat-sub">ADVISORY MODE</span>
            </div>
          </div>
          <button (click)="loadRuleStats()" class="btn btn-secondary btn-sm" [disabled]="loading">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            {{ loading ? 'Refreshing...' : 'Refresh' }}
          </button>
        </div>
      </div>

      <!-- Rule Grid -->
      <div class="rules-grid">
        <div *ngFor="let rule of rules" class="rule-card">
          <div class="rule-card-header">
            <div class="rule-identity">
              <span class="rule-id mono">{{ rule.id }}</span>
              <h2 class="rule-name">{{ rule.name }}</h2>
            </div>
            <span class="rule-status-badge">ACTIVE</span>
          </div>

          <p class="rule-desc">{{ rule.description }}</p>

          <div class="rule-meta-grid">
            <div class="rule-meta-item">
              <span class="meta-label">Category</span>
              <span class="meta-val mono text-violet">{{ rule.category }}</span>
            </div>
            <div class="rule-meta-item">
              <span class="meta-label">OWASP API</span>
              <span class="meta-val mono">{{ rule.owaspRef }}</span>
            </div>
            <div class="rule-meta-item">
              <span class="meta-label">Sliding Window</span>
              <span class="meta-val mono text-teal">{{ rule.slidingWindow }}</span>
            </div>
            <div class="rule-meta-item">
              <span class="meta-label">Threshold</span>
              <span class="meta-val mono text-amber">{{ rule.threshold }}</span>
            </div>
            <div class="rule-meta-item">
              <span class="meta-label">MITRE ATT&CK</span>
              <span class="meta-val mono text-muted">{{ rule.mitreRef }}</span>
            </div>
            <div class="rule-meta-item">
              <span class="meta-label">Trigger Count (24h)</span>
              <span class="meta-val mono font-bold text-teal">{{ getTriggerCount(rule.id) }}</span>
            </div>
          </div>

          <div class="rule-actions">
            <a [routerLink]="['/incidents']" [queryParams]="{ threatCategory: rule.category }" class="btn btn-secondary btn-sm">
              View Triggered Incidents →
            </a>
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
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: var(--space-6);
      flex-wrap: wrap;
      gap: var(--space-4);
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
    .header-stat-pills {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .rules-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
      gap: var(--space-4);
    }
    .rule-card {
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      padding: var(--space-5);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: border-color 0.15s ease-in-out;
    }
    .rule-card:hover {
      border-color: var(--border-focus);
    }
    .rule-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: var(--space-3);
    }
    .rule-id {
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-teal);
      background: var(--accent-teal-subtle);
      border: 1px solid var(--accent-teal-border);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      display: inline-block;
      margin-bottom: 4px;
    }
    .rule-name {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .rule-status-badge {
      font-size: 10px;
      font-weight: 700;
      color: var(--status-resolved);
      background: var(--status-resolved-bg);
      border: 1px solid var(--status-resolved);
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      letter-spacing: 0.04em;
    }
    .rule-desc {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
      margin-bottom: var(--space-4);
      flex: 1;
    }
    .rule-meta-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: var(--space-2) var(--space-3);
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: var(--space-3);
      margin-bottom: var(--space-4);
    }
    .rule-meta-item {
      display: flex;
      flex-direction: column;
      gap: 1px;
    }
    .meta-label {
      font-size: 10px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .meta-val {
      font-size: 12px;
    }
    .rule-actions {
      display: flex;
      justify-content: flex-end;
    }
  `]
})
export class DetectionRulesComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  overview: SecurityOverview | null = null;
  loading = false;

  readonly rules: RuleDefinition[] = [
    {
      id: 'RULE-BOLA-01',
      name: 'Broken Object Level Authorization',
      category: 'BOLA',
      owaspRef: 'API1:2023',
      mitreRef: 'T1078.004',
      slidingWindow: '60 Seconds',
      threshold: '≥ 3 distinct objects',
      status: 'ACTIVE',
      description: 'Detects unauthorized attempts to access distinct customer or account resources across tenant boundaries within a Redis sliding window.'
    },
    {
      id: 'RULE-AUTH-01',
      name: 'Credential Stuffing & Auth Abuse',
      category: 'AUTH_ABUSE',
      owaspRef: 'API2:2023',
      mitreRef: 'T1110.003',
      slidingWindow: '120 Seconds',
      threshold: '≥ 5 failed attempts',
      status: 'ACTIVE',
      description: 'Flags rapid successive authentication failures and credential-stuffing patterns against token and login endpoints.'
    },
    {
      id: 'RULE-DATA-01',
      name: 'Excessive Data Exfiltration',
      category: 'DATA_EXFILTRATION',
      owaspRef: 'API3:2023',
      mitreRef: 'T1530',
      slidingWindow: '300 Seconds',
      threshold: '≥ 50 bulk records',
      status: 'ACTIVE',
      description: 'Monitors atypical large payload retrieval rates, identifying attempts to scrape or exfiltrate customer account records.'
    },
    {
      id: 'RULE-RATE-01',
      name: 'Rapid Endpoint Abuse & Flooding',
      category: 'RATE_LIMIT_ABUSE',
      owaspRef: 'API4:2023',
      mitreRef: 'T1499.002',
      slidingWindow: '60 Seconds',
      threshold: '≥ 100 requests',
      status: 'ACTIVE',
      description: 'Identifies velocity spikes exceeding calibrated volumetric limits to protect downstream microservice availability.'
    },
    {
      id: 'RULE-PROBE-01',
      name: 'API Reconnaissance & Scanning',
      category: 'RECONNAISSANCE',
      owaspRef: 'API8:2023',
      mitreRef: 'T1595.002',
      slidingWindow: '180 Seconds',
      threshold: '≥ 5 distinct 404/403s',
      status: 'ACTIVE',
      description: 'Tracks directory traversal, brute-force endpoint probing, and reconnaissance across non-existent route paths.'
    },
    {
      id: 'RULE-INJ-01',
      name: 'Injection Payload Detection',
      category: 'INJECTION',
      owaspRef: 'API10:2023',
      mitreRef: 'T1190',
      slidingWindow: 'Per-Request',
      threshold: 'High Confidence Regex Match',
      status: 'ACTIVE',
      description: 'Detects SQL injection syntax, shell command metacharacters, and cross-site scripting vectors in query parameters.'
    }
  ];

  ngOnInit(): void {
    this.loadRuleStats();
  }

  loadRuleStats(): void {
    this.loading = true;
    this.api.getOverview(24).subscribe({
      next: (ov) => {
        this.overview = ov;
        this.loading = false;
      },
      error: () => {
        this.loading = false;
      }
    });
  }

  getTriggerCount(ruleId: string): number {
    if (!this.overview?.topRulesTriggered) return 0;
    const stat = this.overview.topRulesTriggered.find(r => r.ruleId === ruleId);
    return stat ? stat.count : 0;
  }
}
