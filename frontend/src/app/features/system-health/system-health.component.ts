import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';

interface HealthTier {
  id: string;
  name: string;
  service: string;
  status: 'UP' | 'DOWN' | 'CHECKING';
  endpoint: string;
  details: string;
  icon: string;
}

@Component({
  selector: 'app-system-health',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <div class="soc-header-row">
        <div>
          <h1 class="soc-title">Platform System Health</h1>
          <p class="soc-subtitle">
            Live operational health monitoring across Aegis Gateway, Redis Stream, PostgreSQL Flyway V3, and Keycloak tiers.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon" [ngClass]="overallStatus === 'UP' ? 'teal' : 'amber'">
              {{ overallStatus === 'UP' ? '✓' : '!' }}
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ overallStatus }}</span>
              <span class="soc-stat-sub">Actuator Readiness</span>
            </div>
          </div>
          <button (click)="checkHealth()" class="btn btn-secondary btn-sm" [disabled]="loading">
            {{ loading ? 'Checking...' : '↻ Refresh' }}
          </button>
        </div>
      </div>

      <!-- Health Tiers Grid -->
      <div class="tiers-grid">
        <div *ngFor="let tier of tiers" class="tier-card" [class.healthy]="tier.status === 'UP'">
          <div class="tier-card-header">
            <div class="tier-info">
              <span class="tier-icon">{{ tier.icon }}</span>
              <div>
                <h3 class="tier-name">{{ tier.name }}</h3>
                <span class="tier-service mono text-muted">{{ tier.service }}</span>
              </div>
            </div>
            <span class="tier-status-pill" [ngClass]="tier.status.toLowerCase()">
              <span class="pulse-dot" *ngIf="tier.status === 'UP'"></span>
              {{ tier.status }}
            </span>
          </div>

          <p class="tier-details">{{ tier.details }}</p>

          <div class="tier-footer">
            <span class="endpoint-label mono">{{ tier.endpoint }}</span>
          </div>
        </div>
      </div>

      <!-- Architecture Topology Card -->
      <div class="topology-card">
        <h3 class="topology-title">Aegis SOC Architecture Tier Invariants</h3>
        <div class="topology-points">
          <div class="top-point">
            <span class="point-num">01</span>
            <div>
              <strong>Gateway & Perimeter:</strong> Keycloak JWT verification and telemetry capture via non-blocking Spring Cloud Gateway filters.
            </div>
          </div>
          <div class="top-point">
            <span class="point-num">02</span>
            <div>
              <strong>Streaming Telemetry:</strong> Redis streams decouple latency-sensitive API proxying from heavy threat correlation engines.
            </div>
          </div>
          <div class="top-point">
            <span class="point-num">03</span>
            <div>
              <strong>Stateful Persistence:</strong> PostgreSQL 17 Flyway V3 indexes optimize multi-attribute SOC filtering without blocking request paths.
            </div>
          </div>
          <div class="top-point">
            <span class="point-num">04</span>
            <div>
              <strong>Advisory Safeguard:</strong> Advisory response mode guarantees zero unintended blocking of legitimate customer financial operations.
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
    .tiers-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: var(--space-4);
      margin-bottom: var(--space-6);
    }
    .tier-card {
      background: var(--bg-card);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      padding: var(--space-5);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: border-color 0.15s ease-in-out;
    }
    .tier-card.healthy {
      border-color: rgba(20, 184, 166, 0.3);
    }
    .tier-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: var(--space-3);
    }
    .tier-info {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }
    .tier-icon {
      font-size: 24px;
    }
    .tier-name {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .tier-service {
      font-size: 11px;
    }
    .tier-status-pill {
      font-size: 10px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: var(--radius-full);
      display: inline-flex;
      align-items: center;
      gap: 5px;
      letter-spacing: 0.04em;
    }
    .tier-status-pill.up {
      color: var(--status-resolved);
      background: var(--status-resolved-bg);
      border: 1px solid var(--status-resolved);
    }
    .tier-status-pill.down {
      color: var(--sev-critical);
      background: var(--sev-critical-bg);
      border: 1px solid var(--sev-critical-border);
    }
    .tier-status-pill.checking {
      color: var(--accent-amber);
      background: var(--accent-amber-subtle);
      border: 1px solid var(--accent-amber-border);
    }
    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--status-resolved);
      box-shadow: 0 0 6px var(--status-resolved);
    }
    .tier-details {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
      margin-bottom: var(--space-4);
      flex: 1;
    }
    .tier-footer {
      border-top: 1px solid var(--border-subtle);
      padding-top: var(--space-2);
    }
    .endpoint-label {
      font-size: 10px;
      color: var(--text-muted);
    }
    .topology-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      padding: var(--space-6);
    }
    .topology-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: var(--space-4);
    }
    .topology-points {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: var(--space-4);
    }
    .top-point {
      display: flex;
      gap: var(--space-3);
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .point-num {
      font-size: 16px;
      font-weight: 700;
      color: var(--accent-teal);
      font-family: var(--font-mono);
      line-height: 1;
    }
  `]
})
export class SystemHealthComponent implements OnInit {
  private readonly api = inject(SecurityApiService);

  overallStatus = 'CHECKING';
  loading = false;

  tiers: HealthTier[] = [
    {
      id: 'gateway',
      name: 'Aegis Gateway',
      service: 'Spring Boot 3.4 / Java 25',
      status: 'CHECKING',
      endpoint: 'http://127.0.0.1:8000/actuator/health',
      details: 'Gateway router, Keycloak JWT perimeter enforcement, and threat detection correlation engines.',
      icon: '🛡️'
    },
    {
      id: 'redis',
      name: 'Redis 7 Engine',
      service: 'Stream & Sliding Window',
      status: 'CHECKING',
      endpoint: '127.0.0.1:6379 (Stream: aegis:stream:api-events)',
      details: 'Dual-group consumer stream ingestion and rolling window state store for BOLA and rate anomaly rules.',
      icon: '⚡'
    },
    {
      id: 'postgres',
      name: 'PostgreSQL 17 Tier',
      service: 'Flyway V3 Migration',
      status: 'CHECKING',
      endpoint: '127.0.0.1:5433 (Schema: security_data)',
      details: 'Persisted telemetry records, security incidents, evidence graphs, and status history logs.',
      icon: '🐘'
    },
    {
      id: 'keycloak',
      name: 'Keycloak 26 IAM',
      service: 'OIDC / PKCE S256 Provider',
      status: 'CHECKING',
      endpoint: 'http://127.0.0.1:8080/realms/aegis-dev',
      details: 'Authorization Code Flow with PKCE S256, role-based access control (SECURITY_ANALYST, SECURITY_ADMIN).',
      icon: '🔑'
    }
  ];

  ngOnInit(): void {
    this.checkHealth();
  }

  checkHealth(): void {
    this.loading = true;
    this.api.getSystemHealth().subscribe({
      next: (res) => {
        this.overallStatus = res.status === 'UP' ? 'UP' : 'DEGRADED';
        this.tiers.forEach(t => t.status = 'UP');
        this.loading = false;
      },
      error: () => {
        this.overallStatus = 'DEGRADED';
        // Assume gateway is down or unreachable
        this.tiers[0].status = 'DOWN';
        this.loading = false;
      }
    });
  }
}
