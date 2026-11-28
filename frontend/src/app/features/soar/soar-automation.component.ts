import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  WafBanRule,
  TokenRevocationRecord,
  SoarTicket,
  ChallengeMetrics,
  AdaptiveChallengeSession
} from '../../core/models/security.models';

@Component({
  selector: 'app-soar-automation',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Autonomous SOAR & Closed-Loop Threat Mitigation</h1>
          <p class="soc-subtitle">
            Dynamic edge WAF blocklists, sub-microsecond in-memory JWT token revocation, automated Jira/PagerDuty ticketing, and adaptive step-up MFA challenge gates.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon crimson">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ wafRules.length }}</span>
              <span class="soc-stat-sub">Active IP Bans</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon amber">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ revokedTokens.length }}</span>
              <span class="soc-stat-sub">Revoked Tokens</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon cyan">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ openTicketsCount }}</span>
              <span class="soc-stat-sub">SOAR Tickets</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ challengeMetrics?.activeChallenges ?? 0 }}</span>
              <span class="soc-stat-sub">Active Challenges</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <div class="soc-tabs-nav">
        <button class="soc-tab-btn" [class.active]="activeTab === 'waf'" (click)="activeTab = 'waf'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>
          Dynamic Edge WAF ({{ wafRules.length }})
        </button>
        <button class="soc-tab-btn" [class.active]="activeTab === 'tokens'" (click)="activeTab = 'tokens'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          Token Revocation Ledger ({{ revokedTokens.length }})
        </button>
        <button class="soc-tab-btn" [class.active]="activeTab === 'tickets'" (click)="activeTab = 'tickets'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
          SOAR Ticketing Sync ({{ soarTickets.length }})
        </button>
        <button class="soc-tab-btn" [class.active]="activeTab === 'challenge'" (click)="activeTab = 'challenge'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          Adaptive MFA Gate
        </button>
      </div>

      <!-- TAB 1: Dynamic Edge WAF -->
      <div *ngIf="activeTab === 'waf'" class="soc-tab-content">
        <div class="actions-bar">
          <div class="export-actions">
            <span class="export-label">Export Blocklist:</span>
            <button class="btn btn-sm btn-outline" (click)="exportBlocklist('cloudflare')">Cloudflare IP List</button>
            <button class="btn btn-sm btn-outline" (click)="exportBlocklist('aws')">AWS WAF IPSet</button>
            <button class="btn btn-sm btn-outline" (click)="exportBlocklist('iptables')">Linux iptables</button>
          </div>
          <button class="btn btn-sm btn-crimson" (click)="showAddBanModal = true">
            + Ban IP / Subnet
          </button>
        </div>

        <!-- Add Ban Form / Modal -->
        <div *ngIf="showAddBanModal" class="soc-card inline-form-card">
          <div class="soc-card-header">
            <h3>Add Dynamic Edge IP Ban</h3>
            <button class="btn-close" (click)="showAddBanModal = false">&times;</button>
          </div>
          <div class="soc-card-body form-grid">
            <div class="form-group">
              <label>IP Address or CIDR Subnet</label>
              <input type="text" [(ngModel)]="newBan.ipOrCidr" placeholder="e.g. 203.0.113.42 or 198.51.100.0/24" />
            </div>
            <div class="form-group">
              <label>Reason / Detection Attribution</label>
              <input type="text" [(ngModel)]="newBan.reason" placeholder="e.g. Distributed BOLA Exfiltration Campaign" />
            </div>
            <div class="form-group">
              <label>Incident ID</label>
              <input type="text" [(ngModel)]="newBan.incidentId" placeholder="e.g. INC-BOLA-202611" />
            </div>
            <div class="form-group">
              <label>Ban Duration (Hours)</label>
              <input type="number" [(ngModel)]="newBan.ttlHours" min="1" max="720" />
            </div>
          </div>
          <div class="soc-card-footer">
            <button class="btn btn-secondary" (click)="showAddBanModal = false">Cancel</button>
            <button class="btn btn-crimson" [disabled]="!newBan.ipOrCidr || !newBan.reason" (click)="submitBan()">
              Apply Ban Rule
            </button>
          </div>
        </div>

        <!-- WAF Ban Table -->
        <div class="soc-card">
          <div class="soc-table-wrapper">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>IP / CIDR Target</th>
                  <th>Mitigation Reason</th>
                  <th>Incident Ref</th>
                  <th>TTL / Expiration</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let rule of wafRules">
                  <td class="font-mono text-muted">{{ rule.id }}</td>
                  <td class="font-mono text-crimson font-bold">{{ rule.ipOrCidr }}</td>
                  <td>{{ rule.reason }}</td>
                  <td><span class="tag tag-cyan">{{ rule.incidentId }}</span></td>
                  <td>{{ rule.expiresAt | date:'short' }}</td>
                  <td><span class="tag" [ngClass]="rule.source === 'SOAR' ? 'tag-purple' : 'tag-gray'">{{ rule.source }}</span></td>
                  <td>
                    <span class="badge" [ngClass]="rule.active ? 'badge-danger' : 'badge-neutral'">
                      {{ rule.active ? 'NULL-ROUTED' : 'EXPIRED' }}
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-xs btn-outline-danger" (click)="removeBan(rule.id)">Unban</button>
                  </td>
                </tr>
                <tr *ngIf="wafRules.length === 0">
                  <td colspan="8" class="text-center text-muted p-4">No active edge IP bans. Clean perimeter state.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- TAB 2: Token Revocation Ledger -->
      <div *ngIf="activeTab === 'tokens'" class="soc-tab-content">
        <div class="split-layout">
          <!-- Revocation Actions Card -->
          <div class="soc-card half-card">
            <div class="soc-card-header">
              <h3>Targeted JWT JTI Revocation</h3>
            </div>
            <div class="soc-card-body">
              <div class="form-group">
                <label>Token JTI (JWT ID)</label>
                <input type="text" [(ngModel)]="tokenRevokeForm.jti" placeholder="e.g. b48a6097-f050-4824-8aef-13b3d928aa29" />
              </div>
              <div class="form-group">
                <label>Subject (User ID)</label>
                <input type="text" [(ngModel)]="tokenRevokeForm.subject" placeholder="e.g. analyst.lead" />
              </div>
              <div class="form-group">
                <label>Revocation Rationale</label>
                <input type="text" [(ngModel)]="tokenRevokeForm.reason" placeholder="e.g. Device token compromised via API leak" />
              </div>
              <div class="form-group">
                <label>TTL Retention (Hours)</label>
                <input type="number" [(ngModel)]="tokenRevokeForm.ttlHours" />
              </div>
            </div>
            <div class="soc-card-footer">
              <button class="btn btn-amber" [disabled]="!tokenRevokeForm.jti || !tokenRevokeForm.reason" (click)="submitTokenRevocation()">
                Revoke Specific Token
              </button>
            </div>
          </div>

          <!-- Subject Cutoff Killswitch Card -->
          <div class="soc-card half-card">
            <div class="soc-card-header">
              <h3>Subject Killswitch (Account Takeover)</h3>
            </div>
            <div class="soc-card-body">
              <p class="text-muted text-sm">
                Instantly invalidates all access tokens issued for a specific user prior to the current timestamp across all distributed Gateway clusters.
              </p>
              <div class="form-group">
                <label>Subject (User Account)</label>
                <input type="text" [(ngModel)]="subjectRevokeForm.subject" placeholder="e.g. alex.morgan" />
              </div>
              <div class="form-group">
                <label>Incident Rationale</label>
                <input type="text" [(ngModel)]="subjectRevokeForm.reason" placeholder="e.g. Confirmed session hijacking / Credential stuffing" />
              </div>
            </div>
            <div class="soc-card-footer">
              <button class="btn btn-crimson" [disabled]="!subjectRevokeForm.subject || !subjectRevokeForm.reason" (click)="submitSubjectRevocation()">
                Enforce Subject Cutoff
              </button>
            </div>
          </div>
        </div>

        <!-- Revoked Tokens Ledger Table -->
        <div class="soc-card mt-4">
          <div class="soc-card-header">
            <h3>Active Revocation Ledger</h3>
          </div>
          <div class="soc-table-wrapper">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>JTI</th>
                  <th>Subject</th>
                  <th>Reason</th>
                  <th>Revoked At</th>
                  <th>Expires At</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let token of revokedTokens">
                  <td class="font-mono text-amber">{{ token.jti }}</td>
                  <td>{{ token.subject }}</td>
                  <td>{{ token.reason }}</td>
                  <td>{{ token.revokedAt | date:'short' }}</td>
                  <td>{{ token.expiresAt | date:'short' }}</td>
                </tr>
                <tr *ngIf="revokedTokens.length === 0">
                  <td colspan="5" class="text-center text-muted p-4">No actively revoked JWT tokens in the ledger.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- TAB 3: SOAR Ticketing Sync -->
      <div *ngIf="activeTab === 'tickets'" class="soc-tab-content">
        <div class="actions-bar">
          <h3>Automated Incident Response Tickets</h3>
          <button class="btn btn-sm btn-cyan" (click)="showNewTicketModal = true">+ Dispatch Ticket</button>
        </div>

        <div *ngIf="showNewTicketModal" class="soc-card inline-form-card">
          <div class="soc-card-header">
            <h3>Dispatch Outbound SOAR Ticket</h3>
            <button class="btn-close" (click)="showNewTicketModal = false">&times;</button>
          </div>
          <div class="soc-card-body form-grid">
            <div class="form-group">
              <label>Target System</label>
              <select [(ngModel)]="newTicket.externalSystem">
                <option value="JIRA">Jira Service Desk</option>
                <option value="PAGERDUTY">PagerDuty Incident</option>
                <option value="SERVICENOW">ServiceNow Security Ops</option>
                <option value="SLACK">Slack SecOps Channel</option>
              </select>
            </div>
            <div class="form-group">
              <label>Incident Ref</label>
              <input type="text" [(ngModel)]="newTicket.incidentId" placeholder="e.g. INC-CRIT-9921" />
            </div>
            <div class="form-group">
              <label>Severity</label>
              <select [(ngModel)]="newTicket.severity">
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
              </select>
            </div>
            <div class="form-group">
              <label>Ticket Summary / Title</label>
              <input type="text" [(ngModel)]="newTicket.title" placeholder="e.g. Multi-Stage BOLA Horizontal Probing" />
            </div>
          </div>
          <div class="soc-card-footer">
            <button class="btn btn-secondary" (click)="showNewTicketModal = false">Cancel</button>
            <button class="btn btn-cyan" [disabled]="!newTicket.title" (click)="submitTicket()">Dispatch Ticket</button>
          </div>
        </div>

        <div class="soc-card">
          <div class="soc-table-wrapper">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Ticket ID</th>
                  <th>External Key</th>
                  <th>Target Platform</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Assignee</th>
                  <th>Created At</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let t of soarTickets">
                  <td class="font-mono text-muted">{{ t.id }}</td>
                  <td class="font-mono font-bold text-cyan">{{ t.externalTicketId }}</td>
                  <td><span class="tag tag-purple">{{ t.externalSystem }}</span></td>
                  <td>{{ t.title }}</td>
                  <td>
                    <span class="badge" [ngClass]="{
                      'badge-danger': t.severity === 'CRITICAL',
                      'badge-warning': t.severity === 'HIGH',
                      'badge-info': t.severity === 'MEDIUM'
                    }">{{ t.severity }}</span>
                  </td>
                  <td>
                    <span class="tag" [ngClass]="t.status === 'RESOLVED' ? 'tag-teal' : 'tag-amber'">
                      {{ t.status }}
                    </span>
                  </td>
                  <td>{{ t.assignee }}</td>
                  <td>{{ t.createdAt | date:'short' }}</td>
                </tr>
                <tr *ngIf="soarTickets.length === 0">
                  <td colspan="8" class="text-center text-muted p-4">No SOAR tickets currently registered.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- TAB 4: Adaptive Step-Up Challenge Gate -->
      <div *ngIf="activeTab === 'challenge'" class="soc-tab-content">
        <div class="split-layout">
          <!-- Live Metrics Card -->
          <div class="soc-card half-card">
            <div class="soc-card-header">
              <h3>Adaptive Gate Operational Telemetry</h3>
            </div>
            <div class="soc-card-body metrics-grid">
              <div class="metric-box">
                <span class="metric-label">Total Challenges Issued</span>
                <span class="metric-value">{{ challengeMetrics?.totalIssued ?? 0 }}</span>
              </div>
              <div class="metric-box">
                <span class="metric-label">Challenges Cleared</span>
                <span class="metric-value text-teal">{{ challengeMetrics?.totalVerified ?? 0 }}</span>
              </div>
              <div class="metric-box">
                <span class="metric-label">Challenges Failed</span>
                <span class="metric-value text-crimson">{{ challengeMetrics?.totalFailed ?? 0 }}</span>
              </div>
              <div class="metric-box">
                <span class="metric-label">Active Clearances</span>
                <span class="metric-value text-cyan">{{ challengeMetrics?.activeClearances ?? 0 }}</span>
              </div>
            </div>
          </div>

          <!-- Step-Up Challenge Interactive Verification -->
          <div class="soc-card half-card">
            <div class="soc-card-header">
              <h3>Step-Up Verification Tester</h3>
            </div>
            <div class="soc-card-body">
              <div class="form-group">
                <label>Session ID</label>
                <input type="text" [(ngModel)]="challengeTest.sessionId" placeholder="e.g. test-session-001" />
              </div>
              <div class="form-group">
                <label>Threat Score (0.00 - 1.00)</label>
                <input type="number" step="0.05" [(ngModel)]="challengeTest.threatRisk" />
              </div>
              <button class="btn btn-sm btn-outline" (click)="issueTestChallenge()">Issue Challenge Nonce</button>

              <div *ngIf="lastIssuedSession" class="nonce-box mt-3">
                <span class="text-sm text-muted">Issued Nonce:</span>
                <code class="nonce-text">{{ lastIssuedSession.challengeNonce }}</code>
              </div>

              <div *ngIf="lastIssuedSession" class="form-group mt-3">
                <label>Verification Token / Nonce</label>
                <input type="text" [(ngModel)]="challengeTest.verifyToken" placeholder="Paste nonce or MFA passcode" />
                <button class="btn btn-sm btn-teal mt-2" (click)="verifyTestChallenge()">Verify Challenge</button>
              </div>

              <div *ngIf="challengeResult" class="result-box mt-2" [ngClass]="challengeResult.verified ? 'result-success' : 'result-failure'">
                Status: {{ challengeResult.status }} (Verified: {{ challengeResult.verified }})
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Export Modal -->
      <div *ngIf="showExportModal" class="modal-backdrop">
        <div class="modal-card">
          <div class="modal-header">
            <h3>{{ exportTitle }}</h3>
            <button class="btn-close" (click)="showExportModal = false">&times;</button>
          </div>
          <div class="modal-body">
            <pre class="export-preview">{{ exportContent }}</pre>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" (click)="showExportModal = false">Close</button>
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
    .soc-stat-icon.amber { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
    .soc-stat-icon.cyan { background: rgba(0, 180, 216, 0.12); color: #00b4d8; }
    .soc-stat-icon.teal { background: rgba(0, 189, 148, 0.12); color: #00bd94; }
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
      background: rgba(239, 68, 68, 0.12);
      border-color: rgba(239, 68, 68, 0.3);
      color: #ef4444;
    }

    .soc-tab-content { display: flex; flex-direction: column; gap: 16px; }

    .actions-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .export-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .export-label { font-size: 12px; color: var(--text-muted, #88838d); }

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

    .split-layout { display: flex; gap: 16px; flex-wrap: wrap; }
    .half-card { flex: 1; min-width: 320px; }

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

    .metrics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .metric-box {
      padding: 14px;
      background: #0d0c0f;
      border: 1px solid var(--border-default, #262329);
      border-radius: 6px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .metric-label { font-size: 11px; color: var(--text-muted, #88838d); }
    .metric-value { font-size: 20px; font-weight: 700; color: #fff; }

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
    .btn-cyan { background: #00b4d8; color: #000; }
    .btn-teal { background: #00bd94; color: #000; }
    .btn-secondary { background: #262329; color: #fff; }
    .btn-outline-danger { background: transparent; border-color: #ef4444; color: #ef4444; }
    .btn-outline-danger:hover { background: rgba(239, 68, 68, 0.15); }
    .btn-close { background: none; border: none; font-size: 20px; color: #888; cursor: pointer; }

    .font-mono { font-family: monospace; }
    .font-bold { font-weight: 600; }
    .text-crimson { color: #ef4444; }
    .text-amber { color: #f59e0b; }
    .text-cyan { color: #00b4d8; }
    .text-teal { color: #00bd94; }
    .text-muted { color: #88838d; }
    .mt-2 { margin-top: 8px; }
    .mt-3 { margin-top: 12px; }
    .mt-4 { margin-top: 16px; }

    .tag { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; }
    .tag-cyan { background: rgba(0, 180, 216, 0.12); color: #00b4d8; }
    .tag-purple { background: rgba(168, 85, 247, 0.12); color: #a855f7; }
    .tag-teal { background: rgba(0, 189, 148, 0.12); color: #00bd94; }
    .tag-amber { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
    .tag-gray { background: rgba(255,255,255,0.06); color: #aaa; }

    .badge { padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
    .badge-info { background: rgba(0, 180, 216, 0.2); color: #00b4d8; }
    .badge-neutral { background: rgba(255, 255, 255, 0.1); color: #888; }

    .nonce-box { padding: 8px 12px; background: #000; border-radius: 6px; border: 1px solid #262329; display: flex; flex-direction: column; gap: 4px; }
    .nonce-text { color: #00bd94; font-size: 14px; font-weight: bold; }
    .result-box { padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; }
    .result-success { background: rgba(0, 189, 148, 0.15); color: #00bd94; }
    .result-failure { background: rgba(239, 68, 68, 0.15); color: #ef4444; }

    .modal-backdrop {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000;
    }
    .modal-card {
      background: #141318; border: 1px solid #262329; border-radius: 8px; width: 600px; max-width: 90vw;
    }
    .modal-header { padding: 14px 18px; border-bottom: 1px solid #262329; display: flex; justify-content: space-between; align-items: center; }
    .modal-header h3 { margin: 0; font-size: 15px; color: #fff; }
    .modal-body { padding: 18px; max-height: 400px; overflow-y: auto; }
    .modal-footer { padding: 12px 18px; border-top: 1px solid #262329; display: flex; justify-content: flex-end; }
    .export-preview { background: #000; padding: 12px; border-radius: 6px; color: #00bd94; font-size: 11px; white-space: pre-wrap; font-family: monospace; }
  `]
})
export class SoarAutomationComponent implements OnInit {
  private readonly securityApi = inject(SecurityApiService);

  activeTab: 'waf' | 'tokens' | 'tickets' | 'challenge' = 'waf';

  wafRules: WafBanRule[] = [];
  revokedTokens: TokenRevocationRecord[] = [];
  soarTickets: SoarTicket[] = [];
  challengeMetrics: ChallengeMetrics | null = null;

  showAddBanModal = false;
  newBan = { ipOrCidr: '', reason: '', incidentId: '', ttlHours: 24 };

  tokenRevokeForm = { jti: '', subject: '', reason: '', ttlHours: 24 };
  subjectRevokeForm = { subject: '', reason: '', retentionHours: 24 };

  showNewTicketModal = false;
  newTicket = { incidentId: '', externalSystem: 'JIRA', title: '', severity: 'HIGH', assignee: 'security.lead' };

  challengeTest = { sessionId: 'session-soar-test', threatRisk: 0.82, verifyToken: '' };
  lastIssuedSession: AdaptiveChallengeSession | null = null;
  challengeResult: { verified: boolean; status: string } | null = null;

  showExportModal = false;
  exportTitle = '';
  exportContent = '';

  get openTicketsCount(): number {
    return this.soarTickets.filter(t => t.status !== 'RESOLVED').length;
  }

  ngOnInit(): void {
    this.loadAllData();
  }

  loadAllData(): void {
    this.securityApi.getWafRules().subscribe({
      next: rules => this.wafRules = rules ? [...rules] : [],
      error: () => this.wafRules = []
    });

    this.securityApi.getRevokedTokens().subscribe({
      next: tokens => this.revokedTokens = tokens ? [...tokens] : [],
      error: () => this.revokedTokens = []
    });

    this.securityApi.getSoarTickets().subscribe({
      next: tickets => this.soarTickets = tickets ? [...tickets] : [],
      error: () => this.soarTickets = []
    });

    this.securityApi.getChallengeMetrics().subscribe({
      next: metrics => this.challengeMetrics = metrics,
      error: () => this.challengeMetrics = null
    });
  }

  submitBan(): void {
    if (!this.newBan.ipOrCidr || !this.newBan.reason) return;
    this.securityApi.addWafBan({
      ipOrCidr: this.newBan.ipOrCidr,
      reason: this.newBan.reason,
      incidentId: this.newBan.incidentId || 'INC-MANUAL',
      ttlHours: this.newBan.ttlHours,
      source: 'MANUAL'
    }).subscribe({
      next: created => {
        this.wafRules.unshift(created);
        this.showAddBanModal = false;
        this.newBan = { ipOrCidr: '', reason: '', incidentId: '', ttlHours: 24 };
      }
    });
  }

  removeBan(id: string): void {
    this.securityApi.deleteWafBan(id).subscribe({
      next: () => {
        this.wafRules = this.wafRules.filter(r => r.id !== id);
      }
    });
  }

  exportBlocklist(type: 'cloudflare' | 'aws' | 'iptables'): void {
    if (type === 'cloudflare') {
      this.securityApi.getCloudflareWafExport().subscribe(res => {
        this.exportTitle = 'Cloudflare IP List Export';
        this.exportContent = JSON.stringify(res, null, 2);
        this.showExportModal = true;
      });
    } else if (type === 'aws') {
      this.securityApi.getAwsWafExport().subscribe(res => {
        this.exportTitle = 'AWS WAF IPSet JSON Export';
        this.exportContent = JSON.stringify(res, null, 2);
        this.showExportModal = true;
      });
    } else {
      this.securityApi.getIptablesExport().subscribe(rules => {
        this.exportTitle = 'Linux iptables Firewall Script Export';
        this.exportContent = (rules ?? []).join('\n');
        this.showExportModal = true;
      });
    }
  }

  submitTokenRevocation(): void {
    if (!this.tokenRevokeForm.jti || !this.tokenRevokeForm.reason) return;
    this.securityApi.revokeToken({
      jti: this.tokenRevokeForm.jti,
      subject: this.tokenRevokeForm.subject || 'unknown',
      reason: this.tokenRevokeForm.reason,
      ttlHours: this.tokenRevokeForm.ttlHours
    }).subscribe({
      next: record => {
        this.revokedTokens.unshift(record);
        this.tokenRevokeForm = { jti: '', subject: '', reason: '', ttlHours: 24 };
      }
    });
  }

  submitSubjectRevocation(): void {
    if (!this.subjectRevokeForm.subject || !this.subjectRevokeForm.reason) return;
    this.securityApi.revokeSubject({
      subject: this.subjectRevokeForm.subject,
      reason: this.subjectRevokeForm.reason,
      retentionHours: this.subjectRevokeForm.retentionHours
    }).subscribe({
      next: () => {
        this.subjectRevokeForm = { subject: '', reason: '', retentionHours: 24 };
        this.securityApi.getRevokedTokens().subscribe(t => this.revokedTokens = t ?? []);
      }
    });
  }

  submitTicket(): void {
    if (!this.newTicket.title) return;
    this.securityApi.createSoarTicket({
      incidentId: this.newTicket.incidentId || 'INC-MANUAL',
      externalSystem: this.newTicket.externalSystem,
      title: this.newTicket.title,
      severity: this.newTicket.severity,
      assignee: this.newTicket.assignee
    }).subscribe({
      next: ticket => {
        this.soarTickets.unshift(ticket);
        this.showNewTicketModal = false;
        this.newTicket = { incidentId: '', externalSystem: 'JIRA', title: '', severity: 'HIGH', assignee: 'security.lead' };
      }
    });
  }

  issueTestChallenge(): void {
    this.securityApi.issueChallenge({
      sessionId: this.challengeTest.sessionId,
      threatRisk: this.challengeTest.threatRisk,
      reason: 'Behavioral sequence anomaly detected'
    }).subscribe({
      next: session => {
        this.lastIssuedSession = session;
        this.challengeTest.verifyToken = session.challengeNonce;
        this.challengeResult = null;
      }
    });
  }

  verifyTestChallenge(): void {
    this.securityApi.verifyChallenge({
      sessionId: this.challengeTest.sessionId,
      responseToken: this.challengeTest.verifyToken
    }).subscribe({
      next: res => {
        this.challengeResult = res;
        this.securityApi.getChallengeMetrics().subscribe(m => this.challengeMetrics = m);
      }
    });
  }
}
