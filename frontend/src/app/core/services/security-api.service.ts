import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Observable, catchError, throwError } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  SecurityOverview,
  SecurityEventResponse,
  SecurityEventPageResponse,
  IncidentResponse,
  IncidentPageResponse,
  EvidenceResponse,
  IncidentStatusHistoryResponse,
  IncidentStatusUpdateRequest,
  PolicyDecisionResponse,
  EventFilterParams,
  IncidentFilterParams,
  ProblemDetail,
  DiscoveredEndpointResponse,
  DiscoveredEndpointPageResponse,
  EndpointFilterParams,
  DeclaredOperationResponse,
  ApiSpecificationResponse,
  ApiSpecificationPageResponse,
  SpecificationFilterParams,
  ReconciliationCategory,
  ReconciliationItemResponse,
  ReconciliationSummaryResponse,
  ReconciliationPageResponse,
  ReconciliationFilterParams,
  ReconciliationInvestigationResponse,
  EndpointIntelligenceResponse,
  EndpointObservationHistoryResponse,
  EndpointSecurityHistoryResponse,
  SpecificationDiffResponse,
  EndpointPostureResponse,
  PostureSummaryResponse,
  PosturePageResponse,
  PostureFilterParams,
  SensitiveDataInventoryPageResponse,
  SensitiveDataInventorySummary,
  EndpointDataClassification,
  SensitiveDataFilterParams,
  DataLeakageSummaryResponse,
  DataLeakageRuleInfoResponse,
  DataLeakageFilterParams,
  ComparativeBenchmarkResponse,
  ExtractionAnalyticsResponse
} from '../models/security.models';

@Injectable({
  providedIn: 'root'
})
export class SecurityApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = environment.apiBaseUrl;

  /**
   * GET /api/v1/security/overview?windowHours={windowHours}
   * Fetches database-aggregated metrics for the SOC dashboard.
   */
  getOverview(windowHours = 24): Observable<SecurityOverview> {
    const params = new HttpParams().set('windowHours', windowHours.toString());
    return this.http.get<SecurityOverview>(`${this.baseUrl}/api/v1/security/overview`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/events
   * Searches security events with composite filtering and pagination.
   */
  getEvents(filterParams?: EventFilterParams): Observable<SecurityEventPageResponse> {
    let params = new HttpParams();

    if (filterParams) {
      if (filterParams.page !== undefined) params = params.set('page', filterParams.page.toString());
      if (filterParams.size !== undefined) params = params.set('size', filterParams.size.toString());
      if (filterParams.statusCode !== undefined) params = params.set('statusCode', filterParams.statusCode.toString());
      if (filterParams.httpMethod) params = params.set('httpMethod', filterParams.httpMethod);
      if (filterParams.customerId) params = params.set('customerId', filterParams.customerId);
      if (filterParams.sourceIp) params = params.set('sourceIp', filterParams.sourceIp);
      if (filterParams.anomalyFlags) params = params.set('anomalyFlags', filterParams.anomalyFlags);
      if (filterParams.resourceType) params = params.set('resourceType', filterParams.resourceType);
      if (filterParams.correlationId) params = params.set('correlationId', filterParams.correlationId);
      if (filterParams.from) params = params.set('from', filterParams.from);
      if (filterParams.to) params = params.set('to', filterParams.to);
    }

    return this.http.get<SecurityEventPageResponse>(`${this.baseUrl}/api/v1/security/events`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/events/{id}
   * Retrieves single security event details.
   */
  getEventById(id: string): Observable<SecurityEventResponse> {
    return this.http.get<SecurityEventResponse>(`${this.baseUrl}/api/v1/security/events/${encodeURIComponent(id)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/incidents
   * Retrieves paginated, sorted, and filtered incident queue.
   */
  getIncidents(filterParams?: IncidentFilterParams): Observable<IncidentPageResponse> {
    let params = new HttpParams();

    if (filterParams) {
      if (filterParams.page !== undefined) params = params.set('page', filterParams.page.toString());
      if (filterParams.size !== undefined) params = params.set('size', filterParams.size.toString());
      if (filterParams.status) params = params.set('status', filterParams.status);
      if (filterParams.severity) params = params.set('severity', filterParams.severity);
      if (filterParams.threatCategory) params = params.set('threatCategory', filterParams.threatCategory);
      const sort = filterParams.sortBy || filterParams.sortField;
      if (sort) params = params.set('sortBy', sort);
      if (filterParams.sortDirection) params = params.set('sortDirection', filterParams.sortDirection.toUpperCase());
      if (filterParams.from) params = params.set('from', filterParams.from);
      if (filterParams.to) params = params.set('to', filterParams.to);
    }

    return this.http.get<IncidentPageResponse>(`${this.baseUrl}/api/v1/security/incidents`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/incidents/{id}
   * Retrieves single incident details.
   */
  getIncidentById(id: string): Observable<IncidentResponse> {
    return this.http.get<IncidentResponse>(`${this.baseUrl}/api/v1/security/incidents/${encodeURIComponent(id)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/incidents/{id}/evidence
   * Retrieves contextual correlation evidence for an incident.
   */
  getIncidentEvidence(id: string): Observable<EvidenceResponse[]> {
    return this.http.get<EvidenceResponse[]>(`${this.baseUrl}/api/v1/security/incidents/${encodeURIComponent(id)}/evidence`)
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/incidents/{id}/history
   * Retrieves status lifecycle audit history for an incident.
   */
  getIncidentHistory(id: string): Observable<IncidentStatusHistoryResponse[]> {
    return this.http.get<IncidentStatusHistoryResponse[]>(`${this.baseUrl}/api/v1/security/incidents/${encodeURIComponent(id)}/history`)
      .pipe(catchError(this.handleError));
  }

  /**
   * PATCH /api/v1/security/incidents/{id}/status
   * Transitions incident lifecycle state with mandatory reason.
   */
  updateIncidentStatus(id: string, request: IncidentStatusUpdateRequest): Observable<IncidentResponse> {
    return this.http.patch<IncidentResponse>(
      `${this.baseUrl}/api/v1/security/incidents/${encodeURIComponent(id)}/status`,
      request
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/incidents/{id}/policy-decisions
   * Retrieves advisory policy decisions triggered for an incident.
   */
  getIncidentPolicyDecisions(id: string): Observable<PolicyDecisionResponse[]> {
    return this.http.get<PolicyDecisionResponse[]>(
      `${this.baseUrl}/api/v1/security/incidents/${encodeURIComponent(id)}/policy-decisions`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/policy-decisions
   * Retrieves recent global advisory policy decisions.
   */
  getRecentPolicyDecisions(page: number = 0, size: number = 50): Observable<PolicyDecisionResponse[]> {
    const params = new HttpParams()
      .set('page', page.toString())
      .set('size', size.toString());
    return this.http.get<PolicyDecisionResponse[]>(`${this.baseUrl}/api/v1/security/policy-decisions`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/discovery/endpoints
   * Retrieves discovered API endpoints with filtering and pagination.
   */
  getDiscoveredEndpoints(filterParams?: EndpointFilterParams): Observable<DiscoveredEndpointPageResponse> {
    let params = new HttpParams();

    if (filterParams) {
      if (filterParams.page !== undefined) params = params.set('page', filterParams.page.toString());
      if (filterParams.size !== undefined) params = params.set('size', filterParams.size.toString());
      if (filterParams.method) params = params.set('method', filterParams.method);
      if (filterParams.service) params = params.set('service', filterParams.service);
      if (filterParams.search) params = params.set('search', filterParams.search);
      if (filterParams.sortBy) params = params.set('sortBy', filterParams.sortBy);
      if (filterParams.sortDirection) params = params.set('sortDirection', filterParams.sortDirection);
    }

    return this.http.get<DiscoveredEndpointPageResponse>(`${this.baseUrl}/api/v1/security/discovery/endpoints`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/discovery/endpoints/{id}
   * Retrieves single discovered endpoint details.
   */
  getDiscoveredEndpointById(id: string): Observable<DiscoveredEndpointResponse> {
    return this.http.get<DiscoveredEndpointResponse>(`${this.baseUrl}/api/v1/security/discovery/endpoints/${encodeURIComponent(id)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * POST /api/v1/security/specs/upload
   * Uploads an OpenAPI 3.0.x / 3.1.x specification file (JSON or YAML).
   */
  uploadSpecification(file: File): Observable<ApiSpecificationResponse> {
    const formData = new FormData();
    formData.append('file', file, file.name);

    return this.http.post<ApiSpecificationResponse>(`${this.baseUrl}/api/v1/security/specs/upload`, formData)
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/specs
   * Lists imported OpenAPI specifications with pagination, search, and filtering.
   */
  getSpecifications(filterParams?: SpecificationFilterParams): Observable<ApiSpecificationPageResponse> {
    let params = new HttpParams();

    if (filterParams) {
      if (filterParams.page !== undefined) params = params.set('page', filterParams.page.toString());
      if (filterParams.size !== undefined) params = params.set('size', filterParams.size.toString());
      if (filterParams.search) params = params.set('search', filterParams.search);
      if (filterParams.status) params = params.set('status', filterParams.status);
    }

    return this.http.get<ApiSpecificationPageResponse>(`${this.baseUrl}/api/v1/security/specs`, { params })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/specs/{id}
   * Retrieves single specification details including declared operations.
   */
  getSpecificationById(id: string): Observable<ApiSpecificationResponse> {
    return this.http.get<ApiSpecificationResponse>(`${this.baseUrl}/api/v1/security/specs/${encodeURIComponent(id)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/specs/{id}/operations
   * Retrieves declared operations of an imported specification.
   */
  getSpecificationOperations(id: string): Observable<DeclaredOperationResponse[]> {
    return this.http.get<DeclaredOperationResponse[]>(`${this.baseUrl}/api/v1/security/specs/${encodeURIComponent(id)}/operations`)
      .pipe(catchError(this.handleError));
  }

  /**
   * DELETE /api/v1/security/specs/{id}
   * Deletes an imported specification and cascaded operations.
   */
  deleteSpecification(id: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/api/v1/security/specs/${encodeURIComponent(id)}`)
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/reconciliation
   * Reconciles declared OpenAPI contracts against passive wire telemetry.
   */
  getReconciliation(params: ReconciliationFilterParams = {}): Observable<ReconciliationPageResponse> {
    let httpParams = new HttpParams();
    if (params.page !== undefined) httpParams = httpParams.set('page', params.page.toString());
    if (params.size !== undefined) httpParams = httpParams.set('size', params.size.toString());
    if (params.specId) httpParams = httpParams.set('specId', params.specId);
    if (params.service) httpParams = httpParams.set('service', params.service);
    if (params.method) httpParams = httpParams.set('method', params.method);
    if (params.category) httpParams = httpParams.set('category', params.category);
    if (params.priority) httpParams = httpParams.set('priority', params.priority);
    if (params.windowHours !== undefined) httpParams = httpParams.set('windowHours', params.windowHours.toString());
    if (params.from) httpParams = httpParams.set('from', params.from);
    if (params.to) httpParams = httpParams.set('to', params.to);
    if (params.search) httpParams = httpParams.set('search', params.search);
    if (params.sortBy) httpParams = httpParams.set('sortBy', params.sortBy);
    if (params.sortDirection) httpParams = httpParams.set('sortDirection', params.sortDirection);

    return this.http.get<ReconciliationPageResponse>(`${this.baseUrl}/api/v1/security/reconciliation`, { params: httpParams })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/reconciliation/{id}
   * Returns deep investigation details and evidence for a single reconciliation finding.
   */
  getReconciliationInvestigation(
    id: string,
    params: { specId?: string; windowHours?: number; from?: string; to?: string } = {}
  ): Observable<ReconciliationInvestigationResponse> {
    let httpParams = new HttpParams();
    if (params.specId) httpParams = httpParams.set('specId', params.specId);
    if (params.windowHours !== undefined) httpParams = httpParams.set('windowHours', params.windowHours.toString());
    if (params.from) httpParams = httpParams.set('from', params.from);
    if (params.to) httpParams = httpParams.set('to', params.to);

    return this.http.get<ReconciliationInvestigationResponse>(`${this.baseUrl}/api/v1/security/reconciliation/${id}`, { params: httpParams })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/reconciliation/summary
   * Returns reconciliation coverage summary metrics.
   */
  getReconciliationSummary(params: { specId?: string; windowHours?: number; from?: string; to?: string } = {}): Observable<ReconciliationSummaryResponse> {
    let httpParams = new HttpParams();
    if (params.specId) httpParams = httpParams.set('specId', params.specId);
    if (params.windowHours !== undefined) httpParams = httpParams.set('windowHours', params.windowHours.toString());
    if (params.from) httpParams = httpParams.set('from', params.from);
    if (params.to) httpParams = httpParams.set('to', params.to);

    return this.http.get<ReconciliationSummaryResponse>(`${this.baseUrl}/api/v1/security/reconciliation/summary`, { params: httpParams })
      .pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/discovery/endpoints/{id}/intelligence
   * Retrieves unified endpoint intelligence dossier.
   */
  getEndpointIntelligence(
    id: string,
    params: { windowHours?: number } = {}
  ): Observable<EndpointIntelligenceResponse> {
    let httpParams = new HttpParams();
    if (params.windowHours !== undefined) {
      httpParams = httpParams.set('windowHours', params.windowHours.toString());
    }
    return this.http.get<EndpointIntelligenceResponse>(
      `${this.baseUrl}/api/v1/security/discovery/endpoints/${encodeURIComponent(id)}/intelligence`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/discovery/endpoints/{id}/history
   * Retrieves continuous time-bucketed observation history.
   */
  getEndpointObservationHistory(
    id: string,
    params: { windowHours?: number; bucketMinutes?: number } = {}
  ): Observable<EndpointObservationHistoryResponse> {
    let httpParams = new HttpParams();
    if (params.windowHours !== undefined) {
      httpParams = httpParams.set('windowHours', params.windowHours.toString());
    }
    if (params.bucketMinutes !== undefined) {
      httpParams = httpParams.set('bucketMinutes', params.bucketMinutes.toString());
    }
    return this.http.get<EndpointObservationHistoryResponse>(
      `${this.baseUrl}/api/v1/security/discovery/endpoints/${encodeURIComponent(id)}/history`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/discovery/endpoints/{id}/security
   * Retrieves security event history and linked incidents for the endpoint.
   */
  getEndpointSecurityHistory(
    id: string,
    params: { windowHours?: number } = {}
  ): Observable<EndpointSecurityHistoryResponse> {
    let httpParams = new HttpParams();
    if (params.windowHours !== undefined) {
      httpParams = httpParams.set('windowHours', params.windowHours.toString());
    }
    return this.http.get<EndpointSecurityHistoryResponse>(
      `${this.baseUrl}/api/v1/security/discovery/endpoints/${encodeURIComponent(id)}/security`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/specs/{id}/revisions
   * Retrieves specification revision history by ID.
   */
  getSpecificationRevisions(id: string): Observable<ApiSpecificationResponse[]> {
    return this.http.get<ApiSpecificationResponse[]>(
      `${this.baseUrl}/api/v1/security/specs/${encodeURIComponent(id)}/revisions`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/specs/compare
   * Performs semantic diff comparison between base and target revisions.
   */
  compareSpecifications(baseId: string, targetId: string): Observable<SpecificationDiffResponse> {
    const params = new HttpParams()
      .set('baseId', baseId)
      .set('targetId', targetId);
    return this.http.get<SpecificationDiffResponse>(
      `${this.baseUrl}/api/v1/security/specs/compare`,
      { params }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/posture
   * Retrieves paginated security posture assessments across endpoints.
   */
  getPosturePage(params?: PostureFilterParams): Observable<PosturePageResponse> {
    let httpParams = new HttpParams();
    if (params) {
      if (params.page !== undefined) httpParams = httpParams.set('page', params.page.toString());
      if (params.size !== undefined) httpParams = httpParams.set('size', params.size.toString());
      if (params.service) httpParams = httpParams.set('service', params.service);
      if (params.posture) httpParams = httpParams.set('posture', params.posture);
      if (params.dimension) httpParams = httpParams.set('dimension', params.dimension);
      if (params.dimensionStatus) httpParams = httpParams.set('dimensionStatus', params.dimensionStatus);
      if (params.search) httpParams = httpParams.set('search', params.search);
      if (params.windowHours !== undefined) httpParams = httpParams.set('windowHours', params.windowHours.toString());
    }
    return this.http.get<PosturePageResponse>(
      `${this.baseUrl}/api/v1/security/posture`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/posture/{id}
   * Retrieves full security posture assessment dossier for a specific endpoint.
   */
  getEndpointPosture(id: string, params?: { windowHours?: number }): Observable<EndpointPostureResponse> {
    let httpParams = new HttpParams();
    if (params?.windowHours !== undefined) {
      httpParams = httpParams.set('windowHours', params.windowHours.toString());
    }
    return this.http.get<EndpointPostureResponse>(
      `${this.baseUrl}/api/v1/security/posture/${id}`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/posture/summary
   * Retrieves high-level API security posture summary metrics across services.
   */
  getPostureSummary(params?: { service?: string; windowHours?: number }): Observable<PostureSummaryResponse> {
    let httpParams = new HttpParams();
    if (params?.service) httpParams = httpParams.set('service', params.service);
    if (params?.windowHours !== undefined) httpParams = httpParams.set('windowHours', params.windowHours.toString());
    return this.http.get<PostureSummaryResponse>(
      `${this.baseUrl}/api/v1/security/posture/summary`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/classification/inventory
   * Retrieves paginated endpoint sensitive data classification inventory.
   */
  getSensitiveDataInventory(filterParams?: SensitiveDataFilterParams): Observable<SensitiveDataInventoryPageResponse> {
    let httpParams = new HttpParams();
    if (filterParams) {
      if (filterParams.page !== undefined) httpParams = httpParams.set('page', filterParams.page.toString());
      if (filterParams.size !== undefined) httpParams = httpParams.set('size', filterParams.size.toString());
      if (filterParams.service) httpParams = httpParams.set('service', filterParams.service);
      if (filterParams.sensitivity) httpParams = httpParams.set('sensitivity', filterParams.sensitivity);
      if (filterParams.manualReviewRequired !== undefined) {
        httpParams = httpParams.set('manualReviewRequired', filterParams.manualReviewRequired.toString());
      }
      if (filterParams.search) httpParams = httpParams.set('search', filterParams.search);
      if (filterParams.sortBy) httpParams = httpParams.set('sortBy', filterParams.sortBy);
      if (filterParams.sortDirection) httpParams = httpParams.set('sortDirection', filterParams.sortDirection);
    }
    return this.http.get<SensitiveDataInventoryPageResponse>(
      `${this.baseUrl}/api/v1/security/classification/inventory`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/classification/summary
   * Retrieves top-level sensitive data inventory summary across services.
   */
  getSensitiveDataSummary(service?: string): Observable<SensitiveDataInventorySummary> {
    let httpParams = new HttpParams();
    if (service) httpParams = httpParams.set('service', service);
    return this.http.get<SensitiveDataInventorySummary>(
      `${this.baseUrl}/api/v1/security/classification/summary`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/classification/endpoints/{id}
   * Retrieves single endpoint classification dossier with all field mappings.
   */
  getEndpointClassificationDetails(id: string): Observable<EndpointDataClassification> {
    return this.http.get<EndpointDataClassification>(
      `${this.baseUrl}/api/v1/security/classification/endpoints/${encodeURIComponent(id)}`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/leakage/summary
   * Retrieves summary metrics on data leakage, BOLA, and exfiltration incidents.
   */
  getDataLeakageSummary(): Observable<DataLeakageSummaryResponse> {
    return this.http.get<DataLeakageSummaryResponse>(
      `${this.baseUrl}/api/v1/security/leakage/summary`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/leakage/incidents
   * Retrieves paginated data leakage detection incidents.
   */
  getDataLeakageIncidents(filterParams?: DataLeakageFilterParams): Observable<IncidentPageResponse> {
    let httpParams = new HttpParams();
    if (filterParams) {
      if (filterParams.page !== undefined) httpParams = httpParams.set('page', filterParams.page.toString());
      if (filterParams.size !== undefined) httpParams = httpParams.set('size', filterParams.size.toString());
      if (filterParams.category) httpParams = httpParams.set('category', filterParams.category);
      if (filterParams.severity) httpParams = httpParams.set('severity', filterParams.severity);
      if (filterParams.status) httpParams = httpParams.set('status', filterParams.status);
      if (filterParams.search) httpParams = httpParams.set('search', filterParams.search);
    }
    return this.http.get<IncidentPageResponse>(
      `${this.baseUrl}/api/v1/security/leakage/incidents`,
      { params: httpParams }
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/leakage/incidents/{id}/evidence
   * Retrieves full forensic evidence chain for a specific leakage incident.
   */
  getDataLeakageEvidence(id: string): Observable<EvidenceResponse[]> {
    return this.http.get<EvidenceResponse[]>(
      `${this.baseUrl}/api/v1/security/leakage/incidents/${encodeURIComponent(id)}/evidence`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/leakage/rules
   * Retrieves all data leakage and BOLA detection rules metadata.
   */
  getDataLeakageRules(): Observable<DataLeakageRuleInfoResponse[]> {
    return this.http.get<DataLeakageRuleInfoResponse[]>(
      `${this.baseUrl}/api/v1/security/leakage/rules`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/leakage/evaluation/benchmark
   * Retrieves comparative evaluation and adversarial robustness research metrics.
   */
  getComparativeBenchmark(): Observable<ComparativeBenchmarkResponse> {
    return this.http.get<ComparativeBenchmarkResponse>(
      `${this.baseUrl}/api/v1/security/leakage/evaluation/benchmark`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /api/v1/security/leakage/extraction/analytics
   * Retrieves analytics on excessive data exposure and advanced bulk extraction vectors.
   */
  getExtractionAnalytics(): Observable<ExtractionAnalyticsResponse> {
    return this.http.get<ExtractionAnalyticsResponse>(
      `${this.baseUrl}/api/v1/security/leakage/extraction/analytics`
    ).pipe(catchError(this.handleError));
  }

  /**
   * GET /actuator/health
   * Retrieves live platform tier health status.
   */
  getSystemHealth(): Observable<{ status: string; groups?: string[] }> {
    return this.http.get<{ status: string; groups?: string[] }>(`${this.baseUrl}/actuator/health`)
      .pipe(catchError(this.handleError));
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    let problem: ProblemDetail;

    if (error.error && typeof error.error === 'object' && error.error.title) {
      problem = error.error as ProblemDetail;
    } else {
      problem = {
        title: error.statusText || 'Network Error',
        status: error.status || 0,
        detail: error.message || 'An unexpected error occurred while communicating with the ShieldOps API.'
      };
    }

    return throwError(() => problem);
  }
}
