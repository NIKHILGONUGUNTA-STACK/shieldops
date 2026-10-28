import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  ApiSpecificationResponse,
  DeclaredOperationResponse,
  ProblemDetail
} from '../../core/models/security.models';

@Component({
  selector: 'app-api-specs',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="soc-page-container">
      <!-- Header Row -->
      <div class="soc-header-row">
        <div>
          <div class="breadcrumb-tag">
            <span class="spec-dot"></span>
            DOCUMENTED CONTRACT INVENTORY
          </div>
          <h1 class="soc-title">OpenAPI Specifications & Declared Operations</h1>
          <p class="soc-subtitle">
            Ingest, parse, and catalog declared OpenAPI 3.0.x and 3.1.x contracts (JSON/YAML) to maintain
            an authoritative baseline of documented microservice endpoints and operations.
          </p>
        </div>

        <div class="header-stat-pills">
          <div class="soc-stat-pill">
            <div class="soc-stat-icon blue">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ totalSpecifications() }}</span>
              <span class="soc-stat-sub">Imported Specs</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon green">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ totalDeclaredOperations() | number }}</span>
              <span class="soc-stat-sub">Declared Operations</span>
            </div>
          </div>

          <div class="soc-stat-pill">
            <div class="soc-stat-icon purple">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                <line x1="6" y1="18" x2="6.01" y2="18"></line>
              </svg>
            </div>
            <div class="soc-stat-content">
              <span class="soc-stat-val">{{ activeServicesCount() }}</span>
              <span class="soc-stat-sub">Microservice Specs</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Upload Ingestion Section -->
      <div class="upload-section soc-card">
        <div class="upload-header">
          <div class="upload-title-wrap">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="17 8 12 3 7 8"></polyline>
              <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            <span class="upload-title">Ingest OpenAPI Specification</span>
          </div>
          <span class="upload-hint mono">Accepted formats: OpenAPI 3.0 / 3.1 (.json, .yaml, .yml) · Max 5MB</span>
        </div>

        <div
          class="dropzone-area"
          [class.drag-over]="isDragOver()"
          (dragover)="onDragOver($event)"
          (dragleave)="onDragLeave($event)"
          (drop)="onFileDrop($event)"
        >
          <input
            #fileInput
            type="file"
            accept=".json,.yaml,.yml,application/json,application/x-yaml,text/yaml"
            (change)="onFileSelected($event)"
            style="display: none;"
          />
          <div class="dropzone-content">
            <div class="dropzone-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="12" y1="18" x2="12" y2="12"></line>
                <polyline points="9 15 12 12 15 15"></polyline>
              </svg>
            </div>
            <div class="dropzone-text">
              <span class="primary-drop-text">Drag & drop OpenAPI contract file here, or</span>
              <button
                type="button"
                (click)="fileInput.click()"
                class="btn btn-outline btn-sm browse-btn"
                [disabled]="isUploading()"
              >
                Browse Files
              </button>
            </div>
            <div *ngIf="isUploading()" class="uploading-indicator">
              <span class="spin-icon">⏳</span> Validating structural AST, resolving local references, and extracting operations...
            </div>
          </div>
        </div>

        <!-- Ingestion Status Messages -->
        <div *ngIf="uploadSuccessMessage()" class="alert-success-banner">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          <span>{{ uploadSuccessMessage() }}</span>
          <button type="button" class="close-alert-btn" (click)="uploadSuccessMessage.set(null)">×</button>
        </div>

        <div *ngIf="uploadErrorMessage()" class="alert-error-banner">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <div class="alert-content">
            <span class="alert-error-title">{{ uploadErrorTitle() || 'Specification Ingestion Failed' }}</span>
            <span class="alert-error-detail">{{ uploadErrorMessage() }}</span>
          </div>
          <button type="button" class="close-alert-btn" (click)="uploadErrorMessage.set(null)">×</button>
        </div>
      </div>

      <!-- Controls & Filter Toolbar -->
      <div class="inventory-controls-bar">
        <div class="search-input-wrapper">
          <svg class="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input
            type="text"
            [(ngModel)]="searchQuery"
            (ngModelChange)="onSearchChange()"
            placeholder="Search specifications by name or description..."
            class="soc-search-input"
          />
        </div>

        <div class="filter-controls">
          <button (click)="loadSpecifications(currentPage())" class="btn btn-secondary btn-sm refresh-btn" [disabled]="loading()">
            <svg [class.spin]="loading()" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="23 4 23 10 17 10"></polyline>
              <polyline points="1 20 1 14 7 14"></polyline>
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Error State -->
      <div *ngIf="error()" class="error-banner">
        <div class="error-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        </div>
        <div class="error-content">
          <div class="error-title">{{ error()?.title || 'Specification Inventory Unavailable' }}</div>
          <div class="error-detail">{{ error()?.detail || 'Unable to load OpenAPI specifications from the backend service.' }}</div>
        </div>
        <button (click)="loadSpecifications(currentPage())" class="btn btn-outline btn-sm">Retry</button>
      </div>

      <!-- Main Specifications Table -->
      <div class="soc-card">
        <div class="table-container">
          <table class="soc-table">
            <thead>
              <tr>
                <th>Specification Name</th>
                <th style="width: 100px;">Format</th>
                <th style="width: 120px;">OpenAPI Ver</th>
                <th style="width: 110px; text-align: right;">Operations</th>
                <th style="width: 140px;">Content Hash</th>
                <th style="width: 150px;">Imported At</th>
                <th style="width: 120px;">Imported By</th>
                <th style="width: 160px; text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody>
              <!-- Loading Skeleton -->
              <ng-container *ngIf="loading()">
                <tr *ngFor="let s of [1,2,3,4]" class="skeleton-row">
                  <td><div class="skeleton-bar w-70"></div></td>
                  <td><div class="skeleton-pill"></div></td>
                  <td><div class="skeleton-bar w-50"></div></td>
                  <td><div class="skeleton-bar w-30 ml-auto"></div></td>
                  <td><div class="skeleton-bar w-60"></div></td>
                  <td><div class="skeleton-bar w-50"></div></td>
                  <td><div class="skeleton-bar w-40"></div></td>
                  <td><div class="skeleton-bar w-50 ml-auto"></div></td>
                </tr>
              </ng-container>

              <!-- Data Rows -->
              <ng-container *ngIf="!loading() && specifications().length > 0">
                <tr *ngFor="let spec of specifications(); trackBy: trackBySpecId" class="spec-row">
                  <td>
                    <div class="spec-name-cell">
                      <span class="spec-title-text">{{ spec.name }}</span>
                      <span class="spec-version-badge mono">v{{ spec.version }}</span>
                    </div>
                    <div *ngIf="spec.description" class="spec-description-text" [title]="spec.description">
                      {{ spec.description }}
                    </div>
                  </td>
                  <td>
                    <span class="format-badge" [ngClass]="spec.format.toLowerCase()">
                      {{ spec.format }}
                    </span>
                  </td>
                  <td>
                    <span class="oas-version-pill mono">{{ spec.openapiVersion }}</span>
                  </td>
                  <td class="req-cell">
                    <span class="operations-count mono">{{ spec.operationCount | number }}</span>
                  </td>
                  <td>
                    <span class="hash-tag mono" [title]="spec.contentHash">
                      {{ truncateHash(spec.contentHash) }}
                    </span>
                  </td>
                  <td class="time-cell mono">
                    {{ formatTimestamp(spec.importedAt) }}
                  </td>
                  <td class="actor-cell mono">
                    <span class="actor-badge">{{ spec.importedBy || 'system' }}</span>
                  </td>
                  <td class="actions-cell">
                    <button
                      (click)="openOperationsDrawer(spec)"
                      class="btn btn-secondary btn-xs action-btn"
                      title="Inspect Declared Operations"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                      </svg>
                      Operations
                    </button>
                    <button
                      (click)="deleteSpecification(spec)"
                      class="btn btn-danger-outline btn-xs action-btn delete-btn"
                      title="Delete Specification"
                      [disabled]="deletingId() === spec.id"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                      </svg>
                      Delete
                    </button>
                  </td>
                </tr>
              </ng-container>

              <!-- Empty State -->
              <tr *ngIf="!loading() && specifications().length === 0 && !error()">
                <td colspan="8" class="empty-state-cell">
                  <div class="empty-state-wrapper">
                    <div class="empty-icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                      </svg>
                    </div>
                    <div class="empty-title">No OpenAPI Specifications Imported</div>
                    <p class="empty-desc">
                      Upload your microservice OpenAPI 3.0.x or 3.1.x specifications (JSON or YAML) using the dropzone above
                      to build an inventory of declared API contracts.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Footer -->
        <div *ngIf="totalElements() > 0" class="pagination-footer">
          <div class="pagination-info mono">
            Showing {{ pageStart() }}–{{ pageEnd() }} of {{ totalElements() }} specifications
          </div>
          <div class="pagination-buttons">
            <button
              (click)="loadSpecifications(currentPage() - 1)"
              [disabled]="!hasPrevious() || loading()"
              class="btn btn-secondary btn-sm"
            >
              Previous
            </button>
            <span class="page-current mono">Page {{ currentPage() + 1 }} of {{ totalPages() || 1 }}</span>
            <button
              (click)="loadSpecifications(currentPage() + 1)"
              [disabled]="!hasNext() || loading()"
              class="btn btn-secondary btn-sm"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      <!-- Slide-in Drawer: Operations Explorer -->
      <div *ngIf="selectedSpec()" class="drawer-backdrop" (click)="closeOperationsDrawer()">
        <div class="drawer-panel" (click)="$event.stopPropagation()">
          <div class="drawer-header">
            <div class="drawer-title-group">
              <div class="drawer-pretitle mono">OPENAPI CONTRACT OPERATIONS</div>
              <h2 class="drawer-title">{{ selectedSpec()?.name }}</h2>
              <div class="drawer-meta">
                <span class="spec-version-badge mono">v{{ selectedSpec()?.version }}</span>
                <span class="format-badge" [ngClass]="selectedSpec()?.format?.toLowerCase() || ''">{{ selectedSpec()?.format }}</span>
                <span class="oas-version-pill mono">{{ selectedSpec()?.openapiVersion }}</span>
                <span class="drawer-ops-count mono">{{ specOperations().length }} declared operations</span>
              </div>
            </div>
            <button type="button" class="close-drawer-btn" (click)="closeOperationsDrawer()">×</button>
          </div>

          <!-- Drawer Filter -->
          <div class="drawer-search-bar">
            <input
              type="text"
              [ngModel]="operationFilter()"
              (ngModelChange)="operationFilter.set($event)"
              placeholder="Filter operations by method, route, or operation ID..."
              class="soc-search-input drawer-search"
            />
          </div>

          <!-- Drawer Operations Content -->
          <div class="drawer-content">
            <div *ngIf="loadingOperations()" class="drawer-loading">
              <span class="spin-icon">⏳</span> Loading declared operations...
            </div>

            <div *ngIf="operationsError()" class="error-banner">
              <div class="error-detail">{{ operationsError() }}</div>
            </div>

            <div *ngIf="!loadingOperations() && filteredOperations().length === 0" class="empty-drawer-state">
              No declared operations match the filter criteria.
            </div>

            <div *ngIf="!loadingOperations() && filteredOperations().length > 0" class="ops-list">
              <div *ngFor="let op of filteredOperations()" class="op-card">
                <div class="op-main-line">
                  <span class="method-badge" [ngClass]="op.httpMethod.toLowerCase()">{{ op.httpMethod }}</span>
                  <span class="op-route mono">{{ op.pathPattern }}</span>
                  <span class="service-pill" [ngClass]="getServiceClass(op.serviceBoundary)">{{ op.serviceBoundary }}</span>
                </div>

                <div *ngIf="op.normalizedRoute !== op.pathPattern" class="op-normalized-line mono">
                  <span class="sub-label">Normalized route:</span> {{ op.normalizedRoute }}
                </div>

                <div *ngIf="op.operationId" class="op-id-line mono">
                  <span class="sub-label">operationId:</span> {{ op.operationId }}
                </div>

                <div *ngIf="op.summary" class="op-summary-text">
                  {{ op.summary }}
                </div>

                <div *ngIf="op.tags" class="op-tags-row">
                  <span *ngFor="let tag of getTagList(op.tags)" class="tag-chip mono">{{ tag }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .soc-page-container {
      display: flex;
      flex-direction: column;
      gap: var(--space-5);
      padding: var(--space-6);
      max-width: 1400px;
      margin: 0 auto;
      font-weight: 400;
    }

    .soc-header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: var(--space-6);
      flex-wrap: wrap;
    }

    .breadcrumb-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 10px;
      letter-spacing: 0.08em;
      color: #3b82f6;
      font-family: var(--font-mono);
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .spec-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #3b82f6;
      box-shadow: 0 0 6px #3b82f6;
    }

    .soc-title {
      font-size: 20px;
      font-weight: 400;
      color: var(--text-primary);
      margin: 0 0 4px 0;
      letter-spacing: -0.01em;
    }

    .soc-subtitle {
      font-size: 13px;
      font-weight: 400;
      color: var(--text-secondary);
      margin: 0;
      max-width: 720px;
      line-height: 1.45;
    }

    .header-stat-pills {
      display: flex;
      gap: var(--space-3);
      flex-wrap: wrap;
    }

    .soc-stat-pill {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      padding: 8px 14px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      min-width: 150px;
    }

    .soc-stat-icon {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
    }

    .soc-stat-icon.blue { color: #3b82f6; }
    .soc-stat-icon.green { color: #00E5A3; }
    .soc-stat-icon.purple { color: #9D7BFF; }

    .soc-stat-content {
      display: flex;
      flex-direction: column;
    }

    .soc-stat-val {
      font-size: 16px;
      font-weight: 400;
      color: var(--text-primary);
      font-family: var(--font-mono);
      line-height: 1.2;
    }

    .soc-stat-sub {
      font-size: 11px;
      color: var(--text-muted);
    }

    .upload-section {
      padding: var(--space-4);
      display: flex;
      flex-direction: column;
      gap: var(--space-3);
    }

    .upload-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: var(--space-2);
    }

    .upload-title-wrap {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      color: var(--text-primary);
      font-size: 14px;
    }

    .upload-hint {
      font-size: 11px;
      color: var(--text-muted);
    }

    .dropzone-area {
      border: 1px dashed var(--border-subtle);
      border-radius: var(--radius-md);
      background: var(--bg-surface-elevated);
      padding: var(--space-5);
      text-align: center;
      cursor: pointer;
    }

    .dropzone-area.drag-over {
      border-color: #3b82f6;
      background: rgba(59, 130, 246, 0.05);
    }

    .dropzone-content {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: var(--space-2);
    }

    .dropzone-icon {
      color: var(--text-secondary);
    }

    .dropzone-text {
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: 13px;
      color: var(--text-secondary);
    }

    .browse-btn {
      font-weight: 400;
      cursor: pointer;
    }

    .uploading-indicator {
      font-size: 12px;
      color: #3b82f6;
      margin-top: var(--space-2);
    }

    .alert-success-banner {
      display: flex;
      align-items: center;
      gap: var(--space-3);
      padding: 10px 14px;
      background: rgba(0, 229, 163, 0.1);
      border: 1px solid rgba(0, 229, 163, 0.3);
      border-radius: var(--radius-sm);
      color: #00E5A3;
      font-size: 13px;
    }

    .alert-error-banner {
      display: flex;
      align-items: flex-start;
      gap: var(--space-3);
      padding: 10px 14px;
      background: rgba(255, 77, 90, 0.1);
      border: 1px solid rgba(255, 77, 90, 0.3);
      border-radius: var(--radius-sm);
      color: #FF4D5A;
      font-size: 13px;
    }

    .alert-content {
      display: flex;
      flex-direction: column;
      flex: 1;
      gap: 2px;
    }

    .alert-error-detail {
      font-size: 12px;
      color: var(--text-secondary);
    }

    .close-alert-btn {
      background: none;
      border: none;
      color: inherit;
      font-size: 18px;
      cursor: pointer;
      line-height: 1;
    }

    .inventory-controls-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-4);
      flex-wrap: wrap;
    }

    .search-input-wrapper {
      position: relative;
      flex: 1;
      max-width: 440px;
    }

    .search-icon {
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      pointer-events: none;
    }

    .soc-search-input {
      width: 100%;
      padding: 7px 12px 7px 34px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-primary);
      font-size: 13px;
      outline: none;
    }

    .soc-search-input:focus {
      border-color: #3b82f6;
    }

    .filter-controls {
      display: flex;
      align-items: center;
      gap: var(--space-3);
    }

    .refresh-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .error-banner {
      display: flex;
      align-items: center;
      gap: var(--space-4);
      padding: 12px 16px;
      background: rgba(255, 77, 90, 0.08);
      border: 1px solid rgba(255, 77, 90, 0.3);
      border-radius: var(--radius-md);
      color: #FF4D5A;
    }

    .error-content { flex: 1; }
    .error-title { font-size: 13px; margin-bottom: 2px; }
    .error-detail { font-size: 12px; color: var(--text-secondary); }

    .table-container { overflow-x: auto; }
    .soc-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .soc-table th {
      padding: 10px 14px;
      font-size: 11px;
      font-weight: 400;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
      white-space: nowrap;
    }
    .soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-primary);
      vertical-align: middle;
    }
    .soc-table tr:last-child td { border-bottom: none; }
    .spec-row:hover { background: rgba(255, 255, 255, 0.015); }

    .spec-name-cell { display: flex; align-items: center; gap: var(--space-2); }
    .spec-title-text { font-size: 13px; color: var(--text-primary); }
    .spec-version-badge {
      font-size: 10px;
      padding: 1px 6px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
    }
    .spec-description-text {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
      max-width: 380px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .format-badge {
      display: inline-block;
      padding: 2px 7px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      text-transform: uppercase;
    }
    .format-badge.json { background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.25); color: #60a5fa; }
    .format-badge.yaml { background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.25); color: #c084fc; }
    .oas-version-pill { font-size: 11px; color: var(--text-secondary); }
    .operations-count { display: block; text-align: right; font-size: 13px; color: #00E5A3; }

    .hash-tag {
      font-size: 11px;
      color: var(--text-muted);
      background: var(--bg-surface-elevated);
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
    }
    .time-cell, .actor-cell { font-size: 11px; color: var(--text-secondary); white-space: nowrap; }
    .actor-badge {
      padding: 2px 6px;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
    }
    .actions-cell { text-align: right; white-space: nowrap; }
    .action-btn {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      margin-left: 6px;
      font-size: 11px;
      padding: 4px 8px;
      font-weight: 400;
      cursor: pointer;
    }
    .btn-danger-outline {
      background: transparent;
      border: 1px solid rgba(255, 77, 90, 0.3);
      color: #FF4D5A;
      border-radius: var(--radius-sm);
    }
    .btn-danger-outline:hover:not(:disabled) { background: rgba(255, 77, 90, 0.15); }

    .empty-state-cell { padding: 48px 16px !important; text-align: center; }
    .empty-state-wrapper { display: flex; flex-direction: column; align-items: center; gap: var(--space-3); max-width: 480px; margin: 0 auto; }
    .empty-icon { color: var(--text-muted); }
    .empty-title { font-size: 15px; color: var(--text-primary); }
    .empty-desc { font-size: 13px; color: var(--text-secondary); margin: 0; line-height: 1.45; }

    .skeleton-row td { padding: 14px; }
    .skeleton-pill, .skeleton-bar {
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      animation: pulse 1.5s infinite;
    }
    .skeleton-pill { height: 20px; width: 50px; }
    .skeleton-bar { height: 12px; }
    .w-30 { width: 30%; } .w-40 { width: 40%; } .w-50 { width: 50%; } .w-60 { width: 60%; } .w-70 { width: 70%; } .ml-auto { margin-left: auto; }
    @keyframes pulse { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.8; } }
    .spin { animation: spin-anim 1s linear infinite; }
    @keyframes spin-anim { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

    .pagination-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      background: var(--bg-surface-elevated);
      border-top: 1px solid var(--border-subtle);
      font-size: 12px;
    }
    .pagination-info { color: var(--text-secondary); }
    .pagination-buttons { display: flex; align-items: center; gap: var(--space-3); }
    .page-current { color: var(--text-muted); font-size: 12px; }

    .drawer-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.65);
      z-index: 1000;
      display: flex;
      justify-content: flex-end;
    }
    .drawer-panel {
      width: 100%;
      max-width: 640px;
      height: 100%;
      background: var(--bg-surface);
      border-left: 1px solid var(--border-subtle);
      box-shadow: -4px 0 24px rgba(0, 0, 0, 0.5);
      display: flex;
      flex-direction: column;
    }
    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding: var(--space-5);
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
    }
    .drawer-title-group { display: flex; flex-direction: column; gap: 4px; }
    .drawer-pretitle { font-size: 10px; letter-spacing: 0.08em; color: #3b82f6; }
    .drawer-title { font-size: 18px; color: var(--text-primary); margin: 0; font-weight: 400; }
    .drawer-meta { display: flex; align-items: center; gap: var(--space-2); margin-top: 4px; flex-wrap: wrap; }
    .drawer-ops-count { font-size: 11px; color: var(--text-secondary); }
    .close-drawer-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 24px;
      line-height: 1;
      cursor: pointer;
      padding: 0 4px;
    }
    .close-drawer-btn:hover { color: var(--text-primary); }
    .drawer-search-bar { padding: var(--space-3) var(--space-5); border-bottom: 1px solid var(--border-subtle); background: var(--bg-surface); }
    .drawer-search { width: 100%; padding-left: 12px !important; }
    .drawer-content { flex: 1; overflow-y: auto; padding: var(--space-5); display: flex; flex-direction: column; gap: var(--space-3); }
    .drawer-loading, .empty-drawer-state { padding: 32px; text-align: center; font-size: 13px; color: var(--text-muted); }
    .ops-list { display: flex; flex-direction: column; gap: var(--space-3); }
    .op-card {
      padding: var(--space-3) var(--space-4);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .op-main-line { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
    .op-route { font-size: 13px; color: var(--text-primary); word-break: break-all; flex: 1; }
    .op-normalized-line, .op-id-line { font-size: 11px; color: var(--text-secondary); word-break: break-all; }
    .sub-label { color: var(--text-muted); }
    .op-summary-text { font-size: 12px; color: var(--text-secondary); line-height: 1.4; }
    .op-tags-row { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 2px; }
    .tag-chip { font-size: 10px; padding: 1px 6px; border-radius: var(--radius-sm); background: var(--bg-surface); border: 1px solid var(--border-subtle); color: var(--text-muted); }
  `]
})
export class ApiSpecsComponent implements OnInit {
  private readonly securityApiService = inject(SecurityApiService);

  // Specifications Table State
  readonly specifications = signal<ApiSpecificationResponse[]>([]);
  readonly totalSpecifications = signal<number>(0);
  readonly totalDeclaredOperations = signal<number>(0);
  readonly activeServicesCount = signal<number>(0);

  readonly loading = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  readonly currentPage = signal<number>(0);
  readonly pageSize = signal<number>(10);
  readonly totalPages = signal<number>(0);
  readonly totalElements = signal<number>(0);
  readonly hasNext = signal<boolean>(false);
  readonly hasPrevious = signal<boolean>(false);

  searchQuery = '';

  // Upload State
  readonly isUploading = signal<boolean>(false);
  readonly isDragOver = signal<boolean>(false);
  readonly uploadSuccessMessage = signal<string | null>(null);
  readonly uploadErrorTitle = signal<string | null>(null);
  readonly uploadErrorMessage = signal<string | null>(null);

  // Deletion State
  readonly deletingId = signal<string | null>(null);

  // Operations Drawer State
  readonly selectedSpec = signal<ApiSpecificationResponse | null>(null);
  readonly specOperations = signal<DeclaredOperationResponse[]>([]);
  readonly loadingOperations = signal<boolean>(false);
  readonly operationsError = signal<string | null>(null);
  readonly operationFilter = signal<string>('');

  readonly filteredOperations = computed(() => {
    const ops = this.specOperations();
    const q = this.operationFilter().trim().toLowerCase();
    if (!q) return ops;
    return ops.filter(op =>
      op.httpMethod.toLowerCase().includes(q) ||
      op.pathPattern.toLowerCase().includes(q) ||
      op.normalizedRoute.toLowerCase().includes(q) ||
      (op.operationId && op.operationId.toLowerCase().includes(q)) ||
      (op.serviceBoundary && op.serviceBoundary.toLowerCase().includes(q)) ||
      (op.summary && op.summary.toLowerCase().includes(q))
    );
  });

  ngOnInit(): void {
    this.loadSpecifications(0);
  }

  loadSpecifications(page: number): void {
    this.loading.set(true);
    this.error.set(null);

    this.securityApiService.getSpecifications({
      page,
      size: this.pageSize(),
      search: this.searchQuery.trim() || undefined
    }).subscribe({
      next: (res) => {
        this.specifications.set(res.content);
        this.currentPage.set(res.page);
        this.totalPages.set(res.totalPages);
        this.totalElements.set(res.totalElements);
        this.hasNext.set(res.hasNext);
        this.hasPrevious.set(res.hasPrevious);
        this.totalSpecifications.set(res.totalSpecifications);
        this.totalDeclaredOperations.set(res.totalOperations);

        // Approximate distinct microservice count from specs or fallback
        const services = new Set(res.content.map(s => s.name));
        this.activeServicesCount.set(services.size);

        this.loading.set(false);
      },
      error: (err: ProblemDetail) => {
        this.error.set(err);
        this.loading.set(false);
      }
    });
  }

  onSearchChange(): void {
    this.loadSpecifications(0);
  }

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragOver.set(true);
  }

  onDragLeave(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragOver.set(false);
  }

  onFileDrop(event: DragEvent): void {
    event.preventDefault();
    event.stopPropagation();
    this.isDragOver.set(false);

    if (event.dataTransfer?.files && event.dataTransfer.files.length > 0) {
      this.uploadFile(event.dataTransfer.files[0]);
    }
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.uploadFile(input.files[0]);
      input.value = ''; // Reset input to allow selecting same file again if needed
    }
  }

  uploadFile(file: File): void {
    const maxSizeBytes = 5 * 1024 * 1024;
    if (file.size > maxSizeBytes) {
      this.uploadErrorTitle.set('File Size Limit Exceeded');
      this.uploadErrorMessage.set('The uploaded specification exceeds the maximum permitted size of 5 MB.');
      return;
    }

    const lowerName = file.name.toLowerCase();
    if (!lowerName.endsWith('.json') && !lowerName.endsWith('.yaml') && !lowerName.endsWith('.yml')) {
      this.uploadErrorTitle.set('Unsupported File Type');
      this.uploadErrorMessage.set('Only OpenAPI specification files with .json, .yaml, or .yml extensions are supported.');
      return;
    }

    this.isUploading.set(true);
    this.uploadSuccessMessage.set(null);
    this.uploadErrorTitle.set(null);
    this.uploadErrorMessage.set(null);

    this.securityApiService.uploadSpecification(file).subscribe({
      next: (res) => {
        this.isUploading.set(false);
        this.uploadSuccessMessage.set(
          `Specification "${res.name}" (v${res.version}) successfully imported with ${res.operationCount} declared operations.`
        );
        this.loadSpecifications(0);
      },
      error: (err: ProblemDetail) => {
        this.isUploading.set(false);
        this.uploadErrorTitle.set(err.title || 'Specification Ingestion Failed');
        this.uploadErrorMessage.set(err.detail || 'The specification could not be parsed or validated.');
      }
    });
  }

  openOperationsDrawer(spec: ApiSpecificationResponse): void {
    this.selectedSpec.set(spec);
    this.loadingOperations.set(true);
    this.operationsError.set(null);
    this.specOperations.set([]);
    this.operationFilter.set('');

    this.securityApiService.getSpecificationOperations(spec.id).subscribe({
      next: (ops) => {
        this.specOperations.set(ops);
        this.loadingOperations.set(false);
      },
      error: (err: ProblemDetail) => {
        this.operationsError.set(err.detail || 'Failed to load declared operations for this specification.');
        this.loadingOperations.set(false);
      }
    });
  }

  closeOperationsDrawer(): void {
    this.selectedSpec.set(null);
    this.specOperations.set([]);
    this.operationFilter.set('');
  }

  deleteSpecification(spec: ApiSpecificationResponse): void {
    const confirmed = window.confirm(
      `Delete specification "${spec.name}" (v${spec.version})? All associated declared operations will be removed.`
    );
    if (!confirmed) return;

    this.deletingId.set(spec.id);
    this.securityApiService.deleteSpecification(spec.id).subscribe({
      next: () => {
        this.deletingId.set(null);
        if (this.selectedSpec()?.id === spec.id) {
          this.closeOperationsDrawer();
        }
        this.loadSpecifications(this.currentPage());
      },
      error: (err: ProblemDetail) => {
        this.deletingId.set(null);
        alert(`Failed to delete specification: ${err.detail || 'Server error'}`);
      }
    });
  }

  trackBySpecId(_index: number, spec: ApiSpecificationResponse): string {
    return spec.id;
  }

  pageStart(): number {
    return this.currentPage() * this.pageSize() + 1;
  }

  pageEnd(): number {
    return Math.min((this.currentPage() + 1) * this.pageSize(), this.totalElements());
  }

  truncateHash(hash: string): string {
    if (!hash || hash.length <= 12) return hash || '';
    return hash.substring(0, 10) + '…';
  }

  formatTimestamp(isoStr: string): string {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return isoStr;
    }
  }

  getTagList(tags: string | null): string[] {
    if (!tags) return [];
    return tags.split(',').map(t => t.trim()).filter(t => !!t);
  }

  getServiceClass(serviceName: string): string {
    if (!serviceName) return 'service-default';
    const lower = serviceName.toLowerCase();
    if (lower.includes('customer')) return 'service-customer';
    if (lower.includes('account')) return 'service-account';
    if (lower.includes('transaction')) return 'service-transaction';
    return 'service-default';
  }
}
