import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  FederationNode,
  FederatedPolicyPayload,
  ConsensusVerificationResult,
  FederatedPolicyType,
  FederatedPolicyAction
} from '../../core/models/security.models';

@Component({
  selector: 'app-federation-center',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Multi-Region Federated Policy Consensus</h1>
          <p class="soc-subtitle">
            Cross-cluster gossip, vector clock causality, cryptographic Merkle state verification, and zero-downtime policy synchronization across multi-cloud regions.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon cyan">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="2" y1="12" x2="22" y2="12"></line>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ nodes.length }}</span>
              <span class="soc-stat-sub">Active Regions</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon teal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ healthyNodeCount }} / {{ nodes.length }}</span>
              <span class="soc-stat-sub">Healthy Nodes</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon amber">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                <line x1="8" y1="21" x2="16" y2="21"></line>
                <line x1="12" y1="17" x2="12" y2="21"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ policies.length }}</span>
              <span class="soc-stat-sub">Synced Policies</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon purple">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ averageLatencyMs | number:'1.0-0' }} ms</span>
              <span class="soc-stat-sub">Avg WAN Latency</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Consensus State Banner -->
      <div class="consensus-banner" [ngClass]="{'synchronized': consensus?.synchronizedStatus, 'divergent': !consensus?.synchronizedStatus}">
        <div class="consensus-banner-left">
          <div class="status-indicator-dot" [ngClass]="{'active': consensus?.synchronizedStatus}"></div>
          <div>
            <div class="consensus-banner-title">
              {{ consensus?.synchronizedStatus ? 'FEDERATED CONSENSUS ACHIEVED' : 'STATE DIVERGENCE DETECTED' }}
            </div>
            <div class="consensus-banner-desc">
              {{ consensus?.synchronizedStatus 
                  ? 'All active cluster edge nodes share an identical cryptographic SHA-256 Merkle root. Zero policy drift across regions.' 
                  : 'Policy drift detected in ' + consensus?.divergentNodeCount + ' node(s). Cross-cluster reconciliation required.' }}
            </div>
          </div>
        </div>

        <div class="consensus-banner-right">
          <div class="merkle-root-box">
            <span class="merkle-label">GLOBAL MERKLE ROOT:</span>
            <code class="merkle-hash" title="{{ consensus?.globalMerkleRoot }}">{{ truncateHash(consensus?.globalMerkleRoot) }}</code>
            <button class="btn-copy" (click)="copyHash(consensus?.globalMerkleRoot)">
              {{ copySuccess ? 'Copied!' : 'Copy' }}
            </button>
          </div>
          <button class="soc-btn soc-btn-primary" (click)="reconcileCluster()" [disabled]="reconciling">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
            </svg>
            {{ reconciling ? 'Reconciling...' : 'Reconcile Drift' }}
          </button>
        </div>
      </div>

      <!-- Cluster Topology Grid -->
      <div class="section-title-row">
        <h2 class="soc-section-title">Edge Node Topology & Merkle Fingerprints</h2>
        <div class="soc-actions-group">
          <button class="soc-btn soc-btn-secondary" (click)="loadFederationData()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M23 4v6h-6"></path>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
            </svg>
            Refresh
          </button>
          <button class="soc-btn soc-btn-primary" (click)="openBroadcastModal = true">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"></line>
              <line x1="5" y1="12" x2="19" y2="12"></line>
            </svg>
            Broadcast Policy
          </button>
        </div>
      </div>

      <div class="topology-grid">
        <div *ngFor="let node of nodes" class="node-card" [ngClass]="{'local': node.nodeId === localNodeId, 'drifted': node.stateMerkleRoot !== consensus?.globalMerkleRoot}">
          <div class="node-card-header">
            <div class="node-region-pill">
              <span class="region-flag">{{ getRegionFlag(node.region) }}</span>
              <span>{{ node.region }}</span>
            </div>
            <span class="node-status-pill" [ngClass]="node.status.toLowerCase()">{{ node.status }}</span>
          </div>

          <div class="node-id-row">
            <span class="node-id">{{ node.nodeId }}</span>
            <span *ngIf="node.nodeId === localNodeId" class="local-badge">PRIMARY</span>
          </div>

          <div class="node-metrics-list">
            <div class="node-metric-row">
              <span class="metric-label">WAN Latency:</span>
              <span class="metric-value font-mono">{{ node.latencyMs }} ms</span>
            </div>
            <div class="node-metric-row">
              <span class="metric-label">Epoch Counter:</span>
              <span class="metric-value font-mono">Epoch {{ node.epoch }}</span>
            </div>
            <div class="node-metric-row">
              <span class="metric-label">Endpoint URL:</span>
              <span class="metric-value text-muted truncate">{{ node.endpointUrl }}</span>
            </div>
          </div>

          <div class="node-merkle-section">
            <div class="node-merkle-label">
              <span>Merkle State Hash</span>
              <span *ngIf="node.stateMerkleRoot === consensus?.globalMerkleRoot" class="match-badge">VERIFIED</span>
              <span *ngIf="node.stateMerkleRoot !== consensus?.globalMerkleRoot" class="drift-badge">DRIFT</span>
            </div>
            <code class="node-merkle-val" title="{{ node.stateMerkleRoot }}">{{ truncateHash(node.stateMerkleRoot) }}</code>
          </div>
        </div>
      </div>

      <!-- Synchronized Policies Section -->
      <div class="section-title-row mt-6">
        <h2 class="soc-section-title">Federated Security Policies & Vector Clocks</h2>
        <div class="filter-pills">
          <button class="filter-pill" [ngClass]="{'active': selectedFilter === 'ALL'}" (click)="setFilter('ALL')">All ({{ policies.length }})</button>
          <button class="filter-pill" [ngClass]="{'active': selectedFilter === 'WAF_IP_BAN'}" (click)="setFilter('WAF_IP_BAN')">WAF Bans</button>
          <button class="filter-pill" [ngClass]="{'active': selectedFilter === 'TOKEN_REVOCATION'}" (click)="setFilter('TOKEN_REVOCATION')">Token Revocations</button>
          <button class="filter-pill" [ngClass]="{'active': selectedFilter === 'WORKFLOW_RULE'}" (click)="setFilter('WORKFLOW_RULE')">Workflow Invariants</button>
        </div>
      </div>

      <div class="soc-table-card">
        <table class="soc-table">
          <thead>
            <tr>
              <th>POLICY ID</th>
              <th>TYPE</th>
              <th>ACTION</th>
              <th>ORIGIN CLUSTER</th>
              <th>EPOCH</th>
              <th>CRYPTOGRAPHIC SIGNATURE</th>
              <th>TIMESTAMP</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let pol of filteredPolicies">
              <td class="font-mono text-cyan">{{ pol.policyId }}</td>
              <td>
                <span class="type-pill" [ngClass]="pol.policyType.toLowerCase()">{{ pol.policyType }}</span>
              </td>
              <td>
                <span class="action-pill" [ngClass]="pol.action.toLowerCase()">{{ pol.action }}</span>
              </td>
              <td class="font-mono text-muted">{{ pol.originNodeId }}</td>
              <td class="font-mono">#{{ pol.originEpoch }}</td>
              <td class="font-mono text-muted">
                <span class="sig-verified">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                  {{ truncateHash(pol.cryptographicSignature) }}
                </span>
              </td>
              <td class="text-muted">{{ pol.timestamp | date:'HH:mm:ss dd-MMM' }}</td>
            </tr>
            <tr *ngIf="filteredPolicies.length === 0">
              <td colspan="7" class="text-center text-muted py-4">No federated policies match the selected filter.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Broadcast Modal -->
      <div *ngIf="openBroadcastModal" class="soc-modal-backdrop">
        <div class="soc-modal">
          <div class="soc-modal-header">
            <h3>Broadcast Cross-Cluster Federated Policy</h3>
            <button class="btn-close" (click)="openBroadcastModal = false">&times;</button>
          </div>
          <div class="soc-modal-body">
            <div class="form-group">
              <label>Policy Type</label>
              <select [(ngModel)]="broadcastForm.type" class="soc-input">
                <option value="WAF_IP_BAN">WAF IP Ban</option>
                <option value="TOKEN_REVOCATION">Token Revocation</option>
                <option value="WORKFLOW_RULE">Workflow Rule Invariant</option>
              </select>
            </div>
            <div class="form-group">
              <label>Target Identifier / JSON Payload</label>
              <textarea [(ngModel)]="broadcastForm.payloadJson" class="soc-textarea" rows="4" placeholder='{"ip":"203.0.113.10","reason":"Distributed credential brute-force"}'></textarea>
            </div>
          </div>
          <div class="soc-modal-footer">
            <button class="soc-btn soc-btn-secondary" (click)="openBroadcastModal = false">Cancel</button>
            <button class="soc-btn soc-btn-primary" (click)="broadcastPolicy()" [disabled]="broadcasting">
              {{ broadcasting ? 'Broadcasting...' : 'Broadcast to Cluster' }}
            </button>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      padding: 1.5rem;
      color: #e2e8f0;
      background: #090d16;
      min-height: calc(100vh - 4rem);
    }
    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 1.5rem;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .soc-title {
      font-size: 1.5rem;
      font-weight: 700;
      color: #f8fafc;
      margin: 0 0 0.35rem 0;
    }
    .soc-subtitle {
      font-size: 0.875rem;
      color: #94a3b8;
      margin: 0;
      max-width: 750px;
      line-height: 1.4;
    }
    .header-stat-pills {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .soc-stat-pill {
      background: #131c2e;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 0.5rem 0.85rem;
      display: flex;
      align-items: center;
      gap: 0.65rem;
    }
    .soc-stat-icon {
      width: 32px;
      height: 32px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .soc-stat-icon.cyan { background: rgba(6, 182, 212, 0.15); color: #06b6d4; }
    .soc-stat-icon.teal { background: rgba(20, 184, 166, 0.15); color: #14b8a6; }
    .soc-stat-icon.amber { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
    .soc-stat-icon.purple { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
    .soc-stat-val { font-size: 1.15rem; font-weight: 700; color: #f1f5f9; display: block; }
    .soc-stat-sub { font-size: 0.72rem; color: #64748b; display: block; }

    /* Consensus Banner */
    .consensus-banner {
      border-radius: 10px;
      padding: 1rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      gap: 1.5rem;
      flex-wrap: wrap;
    }
    .consensus-banner.synchronized {
      background: linear-gradient(90deg, rgba(16, 185, 129, 0.12), rgba(13, 148, 136, 0.08));
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .consensus-banner.divergent {
      background: linear-gradient(90deg, rgba(239, 68, 68, 0.15), rgba(185, 28, 28, 0.08));
      border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .consensus-banner-left {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .status-indicator-dot {
      width: 14px;
      height: 14px;
      border-radius: 50%;
      background: #ef4444;
      box-shadow: 0 0 10px rgba(239, 68, 68, 0.7);
    }
    .status-indicator-dot.active {
      background: #10b981;
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.7);
    }
    .consensus-banner-title {
      font-size: 1rem;
      font-weight: 700;
      color: #f8fafc;
      letter-spacing: 0.05em;
    }
    .consensus-banner-desc {
      font-size: 0.8rem;
      color: #cbd5e1;
      margin-top: 0.2rem;
    }
    .consensus-banner-right {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .merkle-root-box {
      background: #0b1120;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 0.4rem 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .merkle-label {
      font-size: 0.7rem;
      font-weight: 700;
      color: #64748b;
    }
    .merkle-hash {
      color: #38bdf8;
      font-size: 0.8rem;
    }
    .btn-copy {
      background: #1e293b;
      border: none;
      color: #94a3b8;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      cursor: pointer;
    }
    .btn-copy:hover { color: #f8fafc; }

    /* Section Headers */
    .section-title-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .soc-section-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: #f1f5f9;
      margin: 0;
    }
    .soc-actions-group {
      display: flex;
      gap: 0.5rem;
    }
    .mt-6 { margin-top: 2rem; }

    /* Topology Grid */
    .topology-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1rem;
    }
    .node-card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 1.15rem;
      transition: all 0.2s ease;
    }
    .node-card.local {
      border-color: rgba(6, 182, 212, 0.4);
      background: linear-gradient(180deg, #131d2e 0%, #111827 100%);
    }
    .node-card.drifted {
      border-color: rgba(239, 68, 68, 0.5);
    }
    .node-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    .node-region-pill {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      background: #1e293b;
      padding: 0.2rem 0.6rem;
      border-radius: 12px;
      font-size: 0.75rem;
      color: #94a3b8;
    }
    .node-status-pill {
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 10px;
      text-transform: uppercase;
    }
    .node-status-pill.healthy { background: rgba(16, 185, 129, 0.15); color: #10b981; }
    .node-status-pill.syncing { background: rgba(6, 182, 212, 0.15); color: #06b6d4; }
    .node-status-pill.degraded { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
    .node-id-row {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.85rem;
    }
    .node-id {
      font-size: 1rem;
      font-weight: 600;
      color: #f8fafc;
      font-family: monospace;
    }
    .local-badge {
      font-size: 0.65rem;
      font-weight: 700;
      background: #0e7490;
      color: #cffafe;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
    }
    .node-metrics-list {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      margin-bottom: 0.85rem;
      border-top: 1px solid #1e293b;
      border-bottom: 1px solid #1e293b;
      padding: 0.6rem 0;
    }
    .node-metric-row {
      display: flex;
      justify-content: space-between;
      font-size: 0.78rem;
    }
    .metric-label { color: #64748b; }
    .metric-value { color: #cbd5e1; }
    .truncate { max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .node-merkle-section {
      background: #0b1120;
      padding: 0.5rem 0.65rem;
      border-radius: 6px;
    }
    .node-merkle-label {
      display: flex;
      justify-content: space-between;
      font-size: 0.68rem;
      color: #64748b;
      margin-bottom: 0.25rem;
    }
    .match-badge { color: #10b981; font-weight: 700; }
    .drift-badge { color: #ef4444; font-weight: 700; }
    .node-merkle-val { font-size: 0.72rem; color: #38bdf8; }

    /* Tables */
    .soc-table-card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      overflow-x: auto;
    }
    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .soc-table th {
      background: #1e293b;
      color: #94a3b8;
      font-weight: 600;
      text-align: left;
      padding: 0.75rem 1rem;
      font-size: 0.72rem;
      letter-spacing: 0.05em;
    }
    .soc-table td {
      padding: 0.75rem 1rem;
      border-top: 1px solid #1f2937;
      color: #cbd5e1;
    }
    .font-mono { font-family: monospace; }
    .text-cyan { color: #38bdf8; }
    .text-muted { color: #64748b; }
    .type-pill, .action-pill {
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
    }
    .type-pill.waf_ip_ban { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .type-pill.token_revocation { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .type-pill.workflow_rule { background: rgba(6, 182, 212, 0.15); color: #38bdf8; }
    .action-pill.upsert { background: rgba(16, 185, 129, 0.15); color: #34d399; }
    .sig-verified {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      color: #10b981;
    }

    /* Buttons */
    .soc-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.45rem 0.9rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: all 0.15s ease;
    }
    .soc-btn-primary { background: #0284c7; color: white; }
    .soc-btn-primary:hover { background: #0369a1; }
    .soc-btn-secondary { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
    .soc-btn-secondary:hover { background: #334155; color: white; }
    .soc-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    /* Filter Pills */
    .filter-pills { display: flex; gap: 0.4rem; }
    .filter-pill {
      background: #1e293b;
      border: 1px solid #334155;
      color: #94a3b8;
      border-radius: 14px;
      padding: 0.25rem 0.7rem;
      font-size: 0.75rem;
      cursor: pointer;
    }
    .filter-pill.active {
      background: #0284c7;
      color: white;
      border-color: #0284c7;
    }

    /* Modal */
    .soc-modal-backdrop {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .soc-modal {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      width: 480px;
      max-width: 90vw;
    }
    .soc-modal-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid #1f2937;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .soc-modal-header h3 { margin: 0; font-size: 1.1rem; color: #f8fafc; }
    .btn-close { background: none; border: none; font-size: 1.5rem; color: #94a3b8; cursor: pointer; }
    .soc-modal-body { padding: 1.25rem; display: flex; flex-direction: column; gap: 1rem; }
    .soc-modal-footer {
      padding: 1rem 1.25rem;
      border-top: 1px solid #1f2937;
      display: flex;
      justify-content: flex-end;
      gap: 0.5rem;
    }
    .form-group label { display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.35rem; }
    .soc-input, .soc-textarea {
      width: 100%;
      background: #0b1120;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
      color: #e2e8f0;
      font-size: 0.85rem;
    }
  `]
})
export class FederationCenterComponent implements OnInit {
  private securityApi = inject(SecurityApiService);

  localNodeId = 'node-us-east-primary';
  nodes: FederationNode[] = [];
  policies: FederatedPolicyPayload[] = [];
  consensus: ConsensusVerificationResult | null = null;

  selectedFilter: 'ALL' | FederatedPolicyType = 'ALL';
  copySuccess = false;
  reconciling = false;
  broadcasting = false;
  openBroadcastModal = false;

  broadcastForm: {
    type: FederatedPolicyType;
    action: FederatedPolicyAction;
    payloadJson: string;
  } = {
    type: 'WAF_IP_BAN',
    action: 'UPSERT',
    payloadJson: '{"ip":"198.51.100.99","reason":"Distributed credential stuffing","incidentId":"INC-FED-MANUAL"}'
  };

  ngOnInit(): void {
    this.loadFederationData();
  }

  loadFederationData(): void {
    this.securityApi.getFederationNodes().subscribe({
      next: (nodes) => this.nodes = nodes,
      error: () => this.nodes = []
    });

    this.securityApi.getFederationConsensus().subscribe({
      next: (res) => this.consensus = res,
      error: () => this.consensus = null
    });

    this.securityApi.getFederatedPolicies().subscribe({
      next: (pols) => this.policies = pols,
      error: () => this.policies = []
    });
  }

  get healthyNodeCount(): number {
    return this.nodes.filter(n => n.status === 'HEALTHY').length;
  }

  get averageLatencyMs(): number {
    if (this.nodes.length === 0) return 0;
    const total = this.nodes.reduce((acc, n) => acc + n.latencyMs, 0);
    return total / this.nodes.length;
  }

  get filteredPolicies(): FederatedPolicyPayload[] {
    if (this.selectedFilter === 'ALL') {
      return this.policies;
    }
    return this.policies.filter(p => p.policyType === this.selectedFilter);
  }

  setFilter(filter: 'ALL' | FederatedPolicyType): void {
    this.selectedFilter = filter;
  }

  reconcileCluster(): void {
    this.reconciling = true;
    this.securityApi.reconcileFederationCluster().subscribe({
      next: (res) => {
        this.consensus = res;
        this.reconciling = false;
        this.nodes = this.nodes.map(n => ({
          ...n,
          status: 'HEALTHY' as const,
          stateMerkleRoot: res.globalMerkleRoot
        }));
      },
      error: () => {
        this.reconciling = false;
      }
    });
  }

  broadcastPolicy(): void {
    this.broadcasting = true;
    this.securityApi.broadcastFederatedPolicy(this.broadcastForm).subscribe({
      next: (newPolicy) => {
        this.policies.unshift(newPolicy);
        this.broadcasting = false;
        this.openBroadcastModal = false;
      },
      error: () => {
        this.broadcasting = false;
      }
    });
  }

  truncateHash(hash?: string): string {
    if (!hash) return '—';
    if (hash.length <= 16) return hash;
    return hash.substring(0, 8) + '...' + hash.substring(hash.length - 8);
  }

  copyHash(hash?: string): void {
    if (!hash) return;
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(hash);
    }
    this.copySuccess = true;
    setTimeout(() => this.copySuccess = false, 2000);
  }

  getRegionFlag(region: string): string {
    if (region.startsWith('us-')) return '🇺🇸';
    if (region.startsWith('eu-')) return '🇪🇺';
    if (region.startsWith('ap-')) return '🇮🇳';
    return '🌐';
  }
}
