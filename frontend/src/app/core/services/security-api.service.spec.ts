import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SecurityApiService } from './security-api.service';
import { environment } from '../../../environments/environment';
import {
  SecurityOverview,
  SecurityEventPageResponse,
  IncidentResponse,
  EvidenceResponse,
  IncidentStatusHistoryResponse,
  PolicyDecisionResponse
} from '../models/security.models';

describe('SecurityApiService', () => {
  let service: SecurityApiService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        SecurityApiService,
        provideHttpClient(),
        provideHttpClientTesting()
      ]
    });

    service = TestBed.inject(SecurityApiService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getOverview', () => {
    it('should query /api/v1/security/overview with windowHours param', () => {
      const mockOverview: SecurityOverview = {
        totalEvents24h: 1250,
        totalAnomalies24h: 42,
        activeIncidentsCount: 3,
        incidentsBySeverity: { HIGH: 2, CRITICAL: 1 },
        incidentsByCategory: { BOLA: 3 },
        recentIncidents: [],
        topRulesTriggered: [{ ruleId: 'RULE-BOLA-01', count: 12 }],
        eventVolumeTrend: [{ bucketTime: '2026-10-27T00:00:00Z', eventCount: 100 }]
      };

      service.getOverview(48).subscribe(data => {
        expect(data.totalEvents24h).toBe(1250);
        expect(data.activeIncidentsCount).toBe(3);
        expect(data.topRulesTriggered.length).toBe(1);
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/overview?windowHours=48`);
      expect(req.request.method).toBe('GET');
      req.flush(mockOverview);
    });
  });

  describe('getEvents', () => {
    it('should query /api/v1/security/events with composite filters', () => {
      const mockEventsPage: SecurityEventPageResponse = {
        events: [],
        page: 1,
        size: 50,
        totalElements: 0,
        totalPages: 0,
        first: true,
        last: true
      };

      service.getEvents({ statusCode: 403, customerId: 'cust-123', page: 1, size: 50 }).subscribe(data => {
        expect(data.page).toBe(1);
        expect(data.size).toBe(50);
      });

      const req = httpTesting.expectOne(req =>
        req.url === `${environment.apiBaseUrl}/api/v1/security/events` &&
        req.params.get('statusCode') === '403' &&
        req.params.get('customerId') === 'cust-123' &&
        req.params.get('page') === '1' &&
        req.params.get('size') === '50'
      );
      expect(req.request.method).toBe('GET');
      req.flush(mockEventsPage);
    });
  });

  describe('getEventById', () => {
    it('should query single event by ID', () => {
      service.getEventById('evt-001').subscribe(event => {
        expect(event.id).toBe('evt-001');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/events/evt-001`);
      expect(req.request.method).toBe('GET');
      req.flush({ id: 'evt-001', httpMethod: 'GET', statusCode: 200 });
    });
  });

  describe('getIncidents', () => {
    it('should query /api/v1/security/incidents with filter and sorting params', () => {
      service.getIncidents({ status: 'OPEN', severity: 'CRITICAL', sortField: 'created_at', sortDirection: 'desc' }).subscribe();

      const req = httpTesting.expectOne(req =>
        req.url === `${environment.apiBaseUrl}/api/v1/security/incidents` &&
        req.params.get('status') === 'OPEN' &&
        req.params.get('severity') === 'CRITICAL' &&
        req.params.get('sortBy') === 'created_at' &&
        req.params.get('sortDirection') === 'DESC'
      );
      expect(req.request.method).toBe('GET');
      req.flush({ incidents: [], page: 0, size: 20, totalElements: 0, totalPages: 0, first: true, last: true });
    });
  });

  describe('getIncidentEvidence', () => {
    it('should retrieve evidence for an incident', () => {
      const mockEvidence: EvidenceResponse[] = [
        {
          id: 'ev-1',
          incidentId: 'inc-1',
          ruleId: 'RULE-BOLA-01',
          ruleVersion: '1.0.0',
          evaluatedAt: '2026-10-27T00:00:00Z',
          confidenceScore: 0.95,
          severity: 'HIGH',
          triggerCondition: '3 cross-resource unauthorized attempts',
          distinctResourcesCount: 3,
          contributingEventIds: ['evt-1', 'evt-2', 'evt-3'],
          mitreTechnique: 'T1078.004',
          createdAt: '2026-10-27T00:00:00Z'
        }
      ];

      service.getIncidentEvidence('inc-1').subscribe(evidence => {
        expect(evidence.length).toBe(1);
        expect(evidence[0].confidenceScore).toBe(0.95);
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/incidents/inc-1/evidence`);
      expect(req.request.method).toBe('GET');
      req.flush(mockEvidence);
    });
  });

  describe('updateIncidentStatus', () => {
    it('should send PATCH request with status and mandatory reason', () => {
      service.updateIncidentStatus('inc-1', {
        targetStatus: 'INVESTIGATING',
        reason: 'Analyst assigned and actively reviewing telemetry logs'
      }).subscribe(res => {
        expect(res.status).toBe('INVESTIGATING');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/incidents/inc-1/status`);
      expect(req.request.method).toBe('PATCH');
      expect(req.request.body.targetStatus).toBe('INVESTIGATING');
      expect(req.request.body.reason).toContain('Analyst assigned');
      req.flush({ id: 'inc-1', status: 'INVESTIGATING' });
    });
  });

  describe('getSystemHealth', () => {
    it('should query /actuator/health for live platform health', () => {
      service.getSystemHealth().subscribe(health => {
        expect(health.status).toBe('UP');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/actuator/health`);
      expect(req.request.method).toBe('GET');
      req.flush({ status: 'UP', groups: ['liveness', 'readiness'] });
    });
  });

  describe('getRecentPolicyDecisions', () => {
    it('should query /api/v1/security/policy-decisions with page and size', () => {
      service.getRecentPolicyDecisions(0, 20).subscribe(decisions => {
        expect(decisions.length).toBe(1);
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/policy-decisions?page=0&size=20`);
      expect(req.request.method).toBe('GET');
      req.flush([{ id: 'pd-1', recommendedAction: 'LOG_ALERT', reason: 'Advisory logging only' }]);
    });
  });

  describe('getDiscoveredEndpoints', () => {
    it('should query /api/v1/security/discovery/endpoints with filter params', () => {
      const mockDiscovery = {
        content: [
          {
            id: 'ep_test123',
            httpMethod: 'GET',
            routeTemplate: '/api/v1/customers/{customerId}',
            serviceName: 'customer-service',
            firstObservedAt: '2026-10-28T10:00:00Z',
            lastObservedAt: '2026-10-28T10:30:00Z',
            totalRequests: 42,
            statusDistribution: { '2xx': 40, '4xx': 2, '5xx': 0 },
            distinctStatusCodes: [200, 404],
            averageLatencyMs: 25.4
          }
        ],
        page: 0,
        size: 20,
        totalElements: 1,
        totalPages: 1,
        hasNext: false,
        hasPrevious: false,
        totalObservedEndpoints: 1,
        totalObservedRequests: 42,
        totalMonitoredServices: 1
      };

      service.getDiscoveredEndpoints({
        page: 0,
        size: 20,
        method: 'GET',
        service: 'customer-service',
        search: 'customers'
      }).subscribe(res => {
        expect(res.totalElements).toBe(1);
        expect(res.content[0].routeTemplate).toBe('/api/v1/customers/{customerId}');
        expect(res.content[0].serviceName).toBe('customer-service');
      });

      const req = httpTesting.expectOne(r => r.url.includes('/api/v1/security/discovery/endpoints'));
      expect(req.request.method).toBe('GET');
      expect(req.request.params.get('method')).toBe('GET');
      expect(req.request.params.get('service')).toBe('customer-service');
      expect(req.request.params.get('search')).toBe('customers');
      req.flush(mockDiscovery);
    });

    it('should query single endpoint by ID', () => {
      service.getDiscoveredEndpointById('ep_123').subscribe(ep => {
        expect(ep.id).toBe('ep_123');
        expect(ep.httpMethod).toBe('POST');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/discovery/endpoints/ep_123`);
      expect(req.request.method).toBe('GET');
      req.flush({
        id: 'ep_123',
        httpMethod: 'POST',
        routeTemplate: '/api/v1/transfers',
        serviceName: 'transaction-service',
        firstObservedAt: '2026-10-28T10:00:00Z',
        lastObservedAt: '2026-10-28T10:30:00Z',
        totalRequests: 10,
        statusDistribution: { '2xx': 10 },
        distinctStatusCodes: [200],
        averageLatencyMs: 45.0
      });
    });
  });

  describe('OpenAPI Specifications API', () => {
    it('should upload a specification file via POST /api/v1/security/specs/upload', () => {
      const mockFile = new File(['{"openapi":"3.0.0"}'], 'spec.json', { type: 'application/json' });
      const mockResponse = {
        id: 'spec-1',
        name: 'Customer API',
        version: '1.0.0',
        openapiVersion: '3.0.0',
        sourceFilename: 'spec.json',
        format: 'JSON',
        status: 'VALID',
        operationCount: 5,
        pathCount: 3,
        validationSummary: 'Valid',
        importedAt: '2026-10-28T12:00:00Z',
        importedBy: 'admin',
        contentHash: 'hash-1'
      };

      service.uploadSpecification(mockFile).subscribe(res => {
        expect(res.id).toBe('spec-1');
        expect(res.name).toBe('Customer API');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/specs/upload`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body instanceof FormData).toBeTrue();
      req.flush(mockResponse);
    });

    it('should query specifications page via GET /api/v1/security/specs', () => {
      const mockPage = {
        content: [],
        page: 0,
        size: 10,
        totalElements: 0,
        totalPages: 0,
        hasNext: false,
        hasPrevious: false,
        totalSpecifications: 0,
        totalOperations: 0
      };

      service.getSpecifications({ page: 0, size: 10, search: 'customer' }).subscribe(res => {
        expect(res.totalElements).toBe(0);
      });

      const req = httpTesting.expectOne(r => r.url.includes('/api/v1/security/specs') && r.params.get('search') === 'customer');
      expect(req.request.method).toBe('GET');
      req.flush(mockPage);
    });

    it('should query single spec by ID via GET /api/v1/security/specs/{id}', () => {
      service.getSpecificationById('spec-123').subscribe(res => {
        expect(res.id).toBe('spec-123');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/specs/spec-123`);
      expect(req.request.method).toBe('GET');
      req.flush({ id: 'spec-123', name: 'Test Spec' });
    });

    it('should query spec operations via GET /api/v1/security/specs/{id}/operations', () => {
      service.getSpecificationOperations('spec-123').subscribe(ops => {
        expect(ops.length).toBe(1);
        expect(ops[0].httpMethod).toBe('GET');
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/specs/spec-123/operations`);
      expect(req.request.method).toBe('GET');
      req.flush([{
        id: 'op-1',
        specificationId: 'spec-123',
        httpMethod: 'GET',
        pathPattern: '/api/v1/users',
        normalizedRoute: '/api/v1/users',
        operationId: 'listUsers',
        summary: 'List users',
        description: null,
        tags: 'Users',
        deprecated: false,
        serviceBoundary: 'user-service'
      }]);
    });

    it('should delete a specification via DELETE /api/v1/security/specs/{id}', () => {
      service.deleteSpecification('spec-123').subscribe();

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/specs/spec-123`);
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });

  describe('API Reconciliation API', () => {
    it('should query /api/v1/security/reconciliation with composite filters', () => {
      const mockReconciliationPage = {
        content: [],
        page: 0,
        size: 20,
        totalElements: 0,
        totalPages: 0,
        hasNext: false,
        hasPrevious: false,
        summary: {
          matchedCount: 0,
          observedUndocumentedCount: 0,
          documentedUnobservedCount: 0,
          methodMismatchCount: 0,
          ambiguousCount: 0,
          totalEvaluated: 0,
          coveragePercentage: 0,
          windowHours: 24,
          windowStart: '2026-10-28T12:00:00Z',
          windowEnd: '2026-10-29T12:00:00Z',
          specificationId: null,
          specificationName: null
        }
      };

      service.getReconciliation({
        page: 0,
        size: 20,
        category: 'MATCHED',
        service: 'customer-service',
        windowHours: 48,
        search: 'customer'
      }).subscribe(res => {
        expect(res.totalElements).toBe(0);
        expect(res.summary.windowHours).toBe(24);
      });

      const req = httpTesting.expectOne(r =>
        r.url === `${environment.apiBaseUrl}/api/v1/security/reconciliation` &&
        r.params.get('category') === 'MATCHED' &&
        r.params.get('service') === 'customer-service' &&
        r.params.get('windowHours') === '48' &&
        r.params.get('search') === 'customer'
      );
      expect(req.request.method).toBe('GET');
      req.flush(mockReconciliationPage);
    });

    it('should query /api/v1/security/reconciliation/summary', () => {
      const mockSummary = {
        matchedCount: 5,
        observedUndocumentedCount: 2,
        documentedUnobservedCount: 3,
        methodMismatchCount: 1,
        ambiguousCount: 0,
        totalEvaluated: 11,
        coveragePercentage: 62.5,
        windowHours: 72,
        windowStart: '2026-10-26T12:00:00Z',
        windowEnd: '2026-10-29T12:00:00Z',
        specificationId: 'spec-1',
        specificationName: 'Customer API'
      };

      service.getReconciliationSummary({ specId: 'spec-1', windowHours: 72 }).subscribe(res => {
        expect(res.matchedCount).toBe(5);
        expect(res.coveragePercentage).toBe(62.5);
      });

      const req = httpTesting.expectOne(r =>
        r.url === `${environment.apiBaseUrl}/api/v1/security/reconciliation/summary` &&
        r.params.get('specId') === 'spec-1' &&
        r.params.get('windowHours') === '72'
      );
      expect(req.request.method).toBe('GET');
      req.flush(mockSummary);
    });
  });

  describe('Error Handling', () => {
    it('should map RFC 7807 ProblemDetail from HTTP error', () => {
      service.getOverview(24).subscribe({
        next: () => fail('Should have failed with 403 ProblemDetail'),
        error: (err) => {
          expect(err.status).toBe(403);
          expect(err.title).toBe('Forbidden');
          expect(err.detail).toContain('Insufficient privileges');
        }
      });

      const req = httpTesting.expectOne(`${environment.apiBaseUrl}/api/v1/security/overview?windowHours=24`);
      req.flush(
        { title: 'Forbidden', status: 403, detail: 'Insufficient privileges: Requires SECURITY_ANALYST' },
        { status: 403, statusText: 'Forbidden' }
      );
    });
  });
});
