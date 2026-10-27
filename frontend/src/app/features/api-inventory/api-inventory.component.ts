import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-api-inventory',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="planned-container">
      <div class="planned-banner">
        <div class="planned-badge-header">
          <span>🛠️</span>
          <span>PLANNED CAPABILITY — Phase 6 Roadmap</span>
        </div>
        <h1 class="planned-title">Automated API Inventory & Discovery Engine</h1>
        <p class="planned-desc">
          Automated endpoint discovery, runtime service cataloging, and shadow API classification are scheduled
          for Phase 6 implementation. Aegis currently enforces security perimeters and captures telemetry across
          registered Spring Cloud Gateway routing contracts.
        </p>

        <div class="planned-specs-grid">
          <div class="spec-card">
            <div class="spec-card-icon">🔍</div>
            <div class="spec-card-title">Passive Traffic Dissection</div>
            <div class="spec-card-detail">
              Reconstructs undocumented API endpoints by parsing continuous gateway telemetry without modifying backend services.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">👻</div>
            <div class="spec-card-title">Shadow & Zombie API Detection</div>
            <div class="spec-card-detail">
              Identifies legacy and unmonitored endpoints receiving traffic outside declared development catalogs.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">🏷️</div>
            <div class="spec-card-title">Data Sensitivity Tagging</div>
            <div class="spec-card-detail">
              Automated classification of endpoints serving PII, financial transactions, and account credentials.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">📋</div>
            <div class="spec-card-title">Service Boundary Mapping</div>
            <div class="spec-card-detail">
              Visual topology of downstream microservices (Customer, Account, Transaction) connected through Aegis Gateway.
            </div>
          </div>
        </div>

        <div class="planned-actions">
          <a routerLink="/events" class="btn btn-primary btn-sm">Inspect Real API Events →</a>
          <a routerLink="/overview" class="btn btn-secondary btn-sm">SOC Overview</a>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .planned-actions {
      display: flex;
      gap: var(--space-3);
      margin-top: var(--space-6);
    }
  `]
})
export class ApiInventoryComponent {}
