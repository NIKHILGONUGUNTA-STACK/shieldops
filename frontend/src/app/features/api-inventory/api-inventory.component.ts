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
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
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
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#FF7A1A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            </div>
            <div class="spec-card-title">Passive Traffic Dissection</div>
            <div class="spec-card-detail">
              Reconstructs undocumented API endpoints by parsing continuous gateway telemetry without modifying backend services.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#7B61FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/></svg>
            </div>
            <div class="spec-card-title">Shadow & Zombie API Detection</div>
            <div class="spec-card-detail">
              Identifies legacy and unmonitored endpoints receiving traffic outside declared development catalogs.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#C48A45" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>
            </div>
            <div class="spec-card-title">Data Sensitivity Tagging</div>
            <div class="spec-card-detail">
              Automated classification of endpoints serving PII, financial transactions, and account credentials.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4A6CFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
            </div>
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
