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
          <span>📑</span>
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
            <div class="spec-card-icon">⚡</div>
            <div class="spec-card-title">Real-Time Payload Validation</div>
            <div class="spec-card-detail">
              Validates JSON request bodies and query parameters against official OpenAPI 3.0 schemas.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">📉</div>
            <div class="spec-card-title">Contract Drift Detection</div>
            <div class="spec-card-detail">
              Flags undocumented headers, rogue query parameters, and unversioned breaking schema changes.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">🛡️</div>
            <div class="spec-card-title">OWASP API9:2023 Defense</div>
            <div class="spec-card-detail">
              Prevents Improper Inventory Management vulnerabilities by aligning actual wire traffic with declared documentation.
            </div>
          </div>

          <div class="spec-card">
            <div class="spec-card-icon">🔄</div>
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
