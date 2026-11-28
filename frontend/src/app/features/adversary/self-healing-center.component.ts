import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  AdversaryCampaign,
  CandidatePolicy,
  AdversaryMutationStrategy
} from '../../core/models/security.models';

@Component({
  selector: 'app-self-healing-center',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Automated AI Adversary & Self-Healing Policy Center</h1>
          <p class="soc-subtitle">
            Autonomous closed-loop Red Team mutation probing, blue team candidate policy synthesis, shadow-mode zero-false-positive validation, and instant edge hot-loading.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon crimson">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="22" y1="12" x2="18" y2="12"></line>
                <line x1="6" y1="12" x2="2" y2="12"></line>
                <line x1="12" y1="6" x2="12" y2="2"></line>
                <line x1="12" y1="22" x2="12" y2="18"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ campaigns.length }}</span>
              <span class="soc-stat-sub">Red Team Probes</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ averageInterceptionRate | number:'1.1-1' }}%</span>
              <span class="soc-stat-sub">Edge Interception</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon amber">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                <polyline points="2 17 12 22 22 17"></polyline>
                <polyline points="2 12 12 17 22 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ candidateCount }}</span>
              <span class="soc-stat-sub">Synthesized Policies</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon cyan">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ promotedCount }}</span>
              <span class="soc-stat-sub">Healed Invariants</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="soc-tabs-nav">
        <button class="soc-tab-btn" [class.active]="activeTab === 'adversary'" (click)="activeTab = 'adversary'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line></svg>
          AI Adversary Probing Matrix ({{ campaigns.length }})
        </button>
        <button class="soc-tab-btn" [class.active]="activeTab === 'synthesizer'" (click)="activeTab = 'synthesizer'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline></svg>
          Self-Healing Policy Synthesizer ({{ candidates.length }})
        </button>
      </div>

      <!-- TAB 1: AI Adversary Probing Matrix -->
      <div *ngIf="activeTab === 'adversary'" class="soc-tab-content">
        <div class="actions-bar">
          <h3>Autonomous Red Team Campaigns</h3>
          <button class="btn btn-sm btn-crimson" (click)="showRunModal = true">+ Launch Probing Campaign</button>
        </div>

        <!-- Launch Modal / Inline Form -->
        <div *ngIf="showRunModal" class="soc-card inline-form-card">
          <div class="soc-card-header">
            <h3>Execute Red Team Mutation Probe</h3>
            <button class="btn-close" (click)="showRunModal = false">&times;</button>
          </div>
          <div class="soc-card-body form-grid">
            <div class="form-group">
              <label>Campaign Title</label>
              <input type="text" [(ngModel)]="newCampaign.name" placeholder="e.g. Beneficiary Step-Skipping Attack" />
            </div>
            <div class="form-group">
              <label>Target API Endpoint</label>
              <input type="text" [(ngModel)]="newCampaign.targetEndpoint" placeholder="e.g. POST /api/v1/beneficiaries" />
            </div>
            <div class="form-group">
              <label>Mutation Strategy</label>
              <select [(ngModel)]="newCampaign.strategy">
                <option value="STEP_SKIPPING">STEP_SKIPPING (Bypass prerequisites)</option>
                <option value="OUT_OF_ORDER_TRAVERSAL">OUT_OF_ORDER_TRAVERSAL (Arbitrary step ordering)</option>
                <option value="TOKEN_SUBSTITUTION">TOKEN_SUBSTITUTION (Swap subject identity)</option>
                <option value="PARAMETER_TAMPERING">PARAMETER_TAMPERING (Boundary & IDOR mutation)</option>
                <option value="RATE_JITTER">RATE_JITTER (Low & slow jitter)</option>
              </select>
            </div>
            <div class="form-group">
              <label>Synthetic Probe Count</label>
              <input type="number" [(ngModel)]="newCampaign.probeCount" min="1" max="100" />
            </div>
          </div>
          <div class="soc-card-footer">
            <button class="btn btn-secondary" (click)="showRunModal = false">Cancel</button>
            <button class="btn btn-crimson" [disabled]="!newCampaign.targetEndpoint" (click)="submitCampaign()">
              Execute Campaign
            </button>
          </div>
        </div>

        <!-- Campaigns Table -->
        <div class="soc-card">
          <div class="soc-table-wrapper">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Campaign ID</th>
                  <th>Title</th>
                  <th>Target Endpoint</th>
                  <th>Strategy</th>
                  <th>Total Probes</th>
                  <th>Blocked</th>
                  <th>Evaded</th>
                  <th>Evasion Rate</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let camp of campaigns">
                  <td class="font-mono text-muted">{{ camp.id }}</td>
                  <td class="font-bold">{{ camp.name }}</td>
                  <td class="font-mono text-cyan">{{ camp.targetEndpoint }}</td>
                  <td><span class="tag tag-purple">{{ camp.strategy }}</span></td>
                  <td>{{ camp.totalProbes }}</td>
                  <td class="text-teal font-bold">{{ camp.blockedProbes }}</td>
                  <td class="text-crimson font-bold">{{ camp.evadedProbes }}</td>
                  <td>
                    <span class="badge" [ngClass]="camp.evasionRate > 0 ? 'badge-danger' : 'badge-success'">
                      {{ (camp.evasionRate * 100) | number:'1.1-1' }}%
                    </span>
                  </td>
                  <td><span class="tag tag-gray">{{ camp.status }}</span></td>
                  <td>
                    <button *ngIf="camp.evadedProbes > 0" class="btn btn-xs btn-amber" (click)="triggerSynthesize(camp.id)">
                      Synthesize Policy
                    </button>
                    <span *ngIf="camp.evadedProbes === 0" class="text-muted text-xs">Fully Mitigated</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- TAB 2: Self-Healing Policy Synthesizer -->
      <div *ngIf="activeTab === 'synthesizer'" class="soc-tab-content">
        <div class="actions-bar">
          <h3>Synthesized Policy Candidates & Shadow Mode Ledger</h3>
        </div>

        <div class="soc-card">
          <div class="soc-table-wrapper">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Candidate ID</th>
                  <th>Generated Rule ID</th>
                  <th>Target Pattern</th>
                  <th>Inferred Predecessors</th>
                  <th>Confidence</th>
                  <th>Shadow Evals</th>
                  <th>Shadow FPR</th>
                  <th>Status</th>
                  <th>Mitigation Action</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let cand of candidates">
                  <td class="font-mono text-muted">{{ cand.id }}</td>
                  <td class="font-mono font-bold text-cyan">{{ cand.ruleId }}</td>
                  <td class="font-mono text-muted">{{ cand.targetMethod }} {{ cand.targetPathPattern }}</td>
                  <td>
                    <div class="predecessor-tags">
                      <span *ngFor="let pred of cand.requiredPredecessors" class="tag tag-gray">{{ pred }}</span>
                    </div>
                  </td>
                  <td><span class="tag tag-purple">{{ (cand.confidenceScore * 100) | number:'1.0-0' }}%</span></td>
                  <td>{{ cand.shadowEvaluationsCount }}</td>
                  <td>
                    <span class="badge" [ngClass]="cand.shadowFpr === 0 ? 'badge-success' : 'badge-danger'">
                      {{ (cand.shadowFpr * 100) | number:'1.2-2' }}%
                    </span>
                  </td>
                  <td>
                    <span class="badge" [ngClass]="{
                      'badge-info': cand.status === 'CANDIDATE',
                      'badge-warning': cand.status === 'EVALUATING',
                      'badge-success': cand.status === 'SAFE_FOR_PROMOTION',
                      'badge-teal': cand.status === 'PROMOTED',
                      'badge-danger': cand.status === 'REJECTED'
                    }">
                      {{ cand.status }}
                    </span>
                  </td>
                  <td>
                    <div class="action-btn-group">
                      <button *ngIf="cand.status === 'CANDIDATE' || cand.status === 'EVALUATING'" class="btn btn-xs btn-outline" (click)="evaluateShadow(cand.id)">
                        Shadow Eval (25)
                      </button>
                      <button *ngIf="cand.status === 'SAFE_FOR_PROMOTION'" class="btn btn-xs btn-teal" (click)="promotePolicy(cand.id)">
                        Promote to Edge
                      </button>
                      <span *ngIf="cand.status === 'PROMOTED'" class="text-teal font-mono text-xs">ACTIVE AT EDGE</span>
                    </div>
                  </td>
                </tr>
                <tr *ngIf="candidates.length === 0">
                  <td colspan="9" class="text-center text-muted p-4">No synthesized candidate policies. All perimeter routes protected.</td>
                </tr>
              </tbody>
            </table>
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
      max-width: 680px;
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
    .soc-stat-icon.crimson { background: rgba(239, 68, 68, 0.12); color: #ef4444; }
    .soc-stat-icon.teal { background: rgba(0, 189, 148, 0.12); color: #00bd94; }
    .soc-stat-icon.amber { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
    .soc-stat-icon.cyan { background: rgba(0, 180, 216, 0.12); color: #00b4d8; }
    .soc-stat-val { font-size: 15px; font-weight: 700; color: var(--text-primary, #ffffff); display: block; }
    .soc-stat-sub { font-size: 10px; color: var(--text-muted, #88838d); text-transform: uppercase; }

    .soc-tabs-nav {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border-default, #262329);
      padding-bottom: 8px;
      flex-wrap: wrap;
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
      background: rgba(0, 180, 216, 0.12);
      border-color: rgba(0, 180, 216, 0.3);
      color: #00b4d8;
    }

    .soc-tab-content { display: flex; flex-direction: column; gap: 16px; }

    .actions-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .actions-bar h3 { margin: 0; font-size: 15px; font-weight: 600; color: #fff; }

    .soc-card {
      background: var(--bg-surface, #141318);
      border: 1px solid var(--border-default, #262329);
      border-radius: 8px;
      overflow: hidden;
    }
    .soc-card-header {
      padding: 14px 18px;
      border-bottom: 1px solid var(--border-default, #262329);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .soc-card-header h3 { margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary, #ffffff); }
    .soc-card-body { padding: 18px; }
    .soc-card-footer {
      padding: 12px 18px;
      border-top: 1px solid var(--border-default, #262329);
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      background: rgba(0, 0, 0, 0.15);
    }

    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    .form-group label { font-size: 11px; text-transform: uppercase; color: var(--text-muted, #88838d); font-weight: 600; }
    .form-group input, .form-group select {
      background: #0d0c0f;
      border: 1px solid var(--border-default, #262329);
      border-radius: 6px;
      padding: 8px 12px;
      color: #fff;
      font-size: 13px;
    }

    .soc-table-wrapper { overflow-x: auto; }
    .soc-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .soc-table th {
      padding: 10px 14px;
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted, #88838d);
      border-bottom: 1px solid var(--border-default, #262329);
      background: rgba(0,0,0,0.2);
    }
    .soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      color: var(--text-primary, #ffffff);
    }

    .predecessor-tags { display: flex; gap: 4px; flex-wrap: wrap; }
    .action-btn-group { display: flex; gap: 6px; align-items: center; }

    .btn {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
    }
    .btn-sm { padding: 5px 10px; font-size: 11px; }
    .btn-xs { padding: 3px 8px; font-size: 10px; }
    .btn-outline { background: transparent; border-color: var(--border-default, #262329); color: #fff; }
    .btn-outline:hover { background: rgba(255,255,255,0.06); }
    .btn-crimson { background: #ef4444; color: #fff; }
    .btn-amber { background: #f59e0b; color: #000; }
    .btn-teal { background: #00bd94; color: #000; }
    .btn-secondary { background: #262329; color: #fff; }
    .btn-close { background: none; border: none; font-size: 20px; color: #888; cursor: pointer; }

    .font-mono { font-family: monospace; }
    .font-bold { font-weight: 600; }
    .text-crimson { color: #ef4444; }
    .text-teal { color: #00bd94; }
    .text-cyan { color: #00b4d8; }
    .text-muted { color: #88838d; }
    .text-xs { font-size: 11px; }

    .tag { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; }
    .tag-purple { background: rgba(168, 85, 247, 0.12); color: #a855f7; }
    .tag-gray { background: rgba(255,255,255,0.06); color: #aaa; }

    .badge { padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
    .badge-info { background: rgba(0, 180, 216, 0.2); color: #00b4d8; }
    .badge-success { background: rgba(0, 189, 148, 0.2); color: #00bd94; }
    .badge-teal { background: rgba(0, 189, 148, 0.3); color: #00bd94; border: 1px solid rgba(0, 189, 148, 0.4); }
  `]
})
export class SelfHealingCenterComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  activeTab: 'adversary' | 'synthesizer' = 'adversary';

  campaigns: AdversaryCampaign[] = [];
  candidates: CandidatePolicy[] = [];

  showRunModal = false;
  newCampaign = {
    name: '',
    targetEndpoint: 'POST /api/v1/beneficiaries',
    strategy: 'STEP_SKIPPING' as AdversaryMutationStrategy,
    probeCount: 15
  };

  get averageInterceptionRate(): number {
    if (this.campaigns.length === 0) return 100.0;
    const totalBlocked = this.campaigns.reduce((sum, c) => sum + c.blockedProbes, 0);
    const totalProbes = this.campaigns.reduce((sum, c) => sum + c.totalProbes, 0);
    return totalProbes > 0 ? (totalBlocked / totalProbes) * 100 : 100.0;
  }

  get candidateCount(): number {
    return this.candidates.filter(c => c.status !== 'PROMOTED').length;
  }

  get promotedCount(): number {
    return this.candidates.filter(c => c.status === 'PROMOTED').length;
  }

  ngOnInit(): void {
    this.loadData();
  }

  loadData(): void {
    this.securityApi.getAdversaryCampaigns().subscribe({
      next: camps => this.campaigns = camps ? [...camps] : [],
      error: () => this.campaigns = []
    });

    this.securityApi.getCandidatePolicies().subscribe({
      next: cands => this.candidates = cands ? [...cands] : [],
      error: () => this.candidates = []
    });
  }

  submitCampaign(): void {
    if (!this.newCampaign.targetEndpoint) return;
    this.securityApi.runAdversaryCampaign({
      name: this.newCampaign.name || 'Adversarial ' + this.newCampaign.strategy + ' Probe',
      targetEndpoint: this.newCampaign.targetEndpoint,
      strategy: this.newCampaign.strategy,
      probeCount: this.newCampaign.probeCount
    }).subscribe({
      next: created => {
        this.campaigns.unshift(created);
        this.showRunModal = false;
        this.newCampaign = {
          name: '',
          targetEndpoint: 'POST /api/v1/beneficiaries',
          strategy: 'STEP_SKIPPING',
          probeCount: 15
        };
      }
    });
  }

  triggerSynthesize(campaignId: string): void {
    this.securityApi.synthesizePolicy(campaignId).subscribe({
      next: candidate => {
        this.candidates.unshift(candidate);
        this.activeTab = 'synthesizer';
      }
    });
  }

  evaluateShadow(candidateId: string): void {
    this.securityApi.evaluateShadowFpr(candidateId, 25).subscribe({
      next: evaluated => {
        const idx = this.candidates.findIndex(c => c.id === candidateId);
        if (idx !== -1) {
          this.candidates[idx] = evaluated;
        }
      }
    });
  }

  promotePolicy(candidateId: string): void {
    this.securityApi.promoteCandidatePolicy(candidateId).subscribe({
      next: promoted => {
        const idx = this.candidates.findIndex(c => c.id === candidateId);
        if (idx !== -1) {
          this.candidates[idx] = promoted;
        }
      }
    });
  }
}
