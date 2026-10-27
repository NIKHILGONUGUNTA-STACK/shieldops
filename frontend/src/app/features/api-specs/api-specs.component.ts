import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-api-specs',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="planned-container">
      <div class="planned-banner">
        <div class="planned-badge-header">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          <span>PLANNED CAPABILITY — Phase 6 Roadmap</span>
        </div>
        <h1 class="planned-title">API Specification Conformance & Contract Validation</h1>
        <p class="planned-desc">
          Automated OpenAPI 3.0 / 3.1 specification ingestion, JSON schema drift detection, and contract validation
          are scheduled for Phase 6. The planned engine will validate incoming payloads and responses against declared schemas
          to catch parameter injection and undocumented parameters before they hit internal microservices.
        </p>

        <div class="planned-specs-grid">
          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#FF7A1A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
            </div>
            <div class="spec-card-title">Real-Time Payload Validation</div>
            <div class="spec-card-detail">
              Validates JSON request bodies and query parameters against official OpenAPI 3.0 schemas.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#FF4D5A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/><polyline points="17 18 23 18 23 12"/></svg>
            </div>
            <div class="spec-card-title">Contract Drift Detection</div>
            <div class="spec-card-detail">
              Flags undocumented headers, rogue query parameters, and unversioned breaking schema changes.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2ECC71" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div class="spec-card-title">OWASP API9:2023 Defense</div>
            <div class="spec-card-detail">
              Prevents Improper Inventory Management vulnerabilities by aligning actual wire traffic with declared documentation.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4A6CFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </div>
            <div class="spec-card-title">CI/CD Schema Ingestion</div>
            <div class="spec-card-detail">
              GitOps integration to pull Swagger/OpenAPI specifications directly from backend service build pipelines.
            </div>
          </div>
        </div>

        <div class="planned-actions">
          <a routerLink="/events" class="btn btn-primary btn-sm">Inspect Real API Events →</a>
          <a routerLink="/detection-rules" class="btn btn-secondary btn-sm">Active Detection Rules</a>
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
export class ApiSpecsComponent {}
