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
  SpecificationFilterParams
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
