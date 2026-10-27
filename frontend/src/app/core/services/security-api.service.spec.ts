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
