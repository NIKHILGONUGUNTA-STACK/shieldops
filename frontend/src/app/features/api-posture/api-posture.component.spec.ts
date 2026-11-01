import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiPostureComponent } from './api-posture.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  PosturePageResponse,
  EndpointPostureResponse,
  ProblemDetail
} from '../../core/models/security.models';

describe('ApiPostureComponent', () => {
  let component: ApiPostureComponent;
  let fixture: ComponentFixture<ApiPostureComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockEndpointPosture: EndpointPostureResponse = {
    endpointId: 'ep_test_1',
    httpMethod: 'GET',
    normalizedRoute: '/api/v1/customers/{customerId}',
    serviceBoundary: 'customer-service',
    assessmentTimestamp: '2026-11-01T20:00:00Z',
    assessmentRuleVersion: 'v1.0.0',
    overallPosture: 'ADEQUATE',
    evidenceCoveragePercentage: 66.7,
    dimensions: {
      EXPOSURE: {
        dimension: 'EXPOSURE',
        status: 'VERIFIED',
        summary: 'Documented and actively observed on gateway wire telemetry',
        evidence: [
          {
            sourceType: 'OPENAPI_SPEC',
            description: 'Operation declared in specification Customer API',
            metricValue: null,
            observedAt: null
          }
        ],
        limitations: 'Gateway observability is bounded by selected telemetry window',
        recommendedActions: []
      },
      AUTHENTICATION: {
        dimension: 'AUTHENTICATION',
        status: 'VERIFIED',
        summary: 'Perimeter authentication enforced by Gateway Security Filter Chain',
        evidence: [
          {
            sourceType: 'GATEWAY_CONFIG',
            description: 'Perimeter authentication enforced',
            metricValue: null,
            observedAt: null
          }
        ],
        limitations: 'Gateway perimeter authentication does not verify session invalidation timing',
        recommendedActions: []
      },
      AUTHORIZATION: {
        dimension: 'AUTHORIZATION',
        status: 'UNKNOWN',
        summary: 'No authorization anomalies or BOLA findings detected',
        evidence: [],
        limitations: 'Gateway cannot verify application-layer data ownership validation on successful 200 responses',
        recommendedActions: ['Perform periodic authorization testing']
      },
      DATA_SENSITIVITY: {
        dimension: 'DATA_SENSITIVITY',
        status: 'UNKNOWN',
        summary: 'No explicit data sensitivity or PII classification metadata configured',
        evidence: [],
        limitations: 'Automatic keyword inference is prohibited to avoid speculative classification',
        recommendedActions: ['Assign data classification in OpenAPI specification']
      },
      BEHAVIORAL: {
        dimension: 'BEHAVIORAL',
        status: 'VERIFIED',
        summary: 'Clean operational telemetry with zero correlated security anomalies',
        evidence: [
          {
            sourceType: 'WIRE_TELEMETRY',
            description: 'Observed request traffic within window',
            metricValue: '120 requests',
            observedAt: '2026-11-01T20:00:00Z'
          }
        ],
        limitations: 'Behavioral analysis reflects aggregate window metrics only',
        recommendedActions: []
      },
      SPECIFICATION: {
        dimension: 'SPECIFICATION',
        status: 'VERIFIED',
        summary: 'Matched active OpenAPI contract: Customer API rev 1',
        evidence: [
          {
            sourceType: 'OPENAPI_SPEC',
            description: 'Operation matched to specification Customer API',
            metricValue: null,
            observedAt: null
          }
        ],
        limitations: 'Reconciliation verifies method and path pattern congruence only',
        recommendedActions: []
      }
    },
    totalFindingsCount: 0,
    confirmedVulnerability: false,
    overallExplanation: 'Endpoint security posture is adequate across observed dimensions.',
    recommendedSteps: ['Endpoint posture is adequate with 66.7% evidence coverage.'],
    lastObservedAt: '2026-11-01T20:00:00Z',
    firstObservedAt: '2026-10-31T20:00:00Z',
    totalRequests: 120
  };

  const mockPosturePage: PosturePageResponse = {
    content: [mockEndpointPosture],
    page: 0,
    size: 20,
    totalElements: 1,
    totalPages: 1,
    hasNext: false,
    hasPrevious: false,
    summary: {
      totalAssessedEndpoints: 1,
      adequateCount: 1,
      attentionRequiredCount: 0,
      insufficientEvidenceCount: 0,
      verifiedDimensionsCount: 4,
      findingDimensionsCount: 0,
      unknownDimensionsCount: 2,
      averageEvidenceCoveragePercentage: 66.7,
      distributionByService: { 'customer-service': 1 },
      distributionByPosture: { 'ADEQUATE': 1 },
      assessmentRuleVersion: 'v1.0.0',
      assessedAt: '2026-11-01T20:00:00Z'
    }
  };

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj<SecurityApiService>('SecurityApiService', [
      'getPosturePage',
      'getEndpointPosture',
      'getPostureSummary'
    ]);

    mockSecurityApi.getPosturePage.and.returnValue(of(mockPosturePage));

    await TestBed.configureTestingModule({
      imports: [ApiPostureComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(ApiPostureComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component and fetch initial posture data', () => {
    expect(component).toBeTruthy();
    expect(mockSecurityApi.getPosturePage).toHaveBeenCalledWith(jasmine.objectContaining({
      page: 0,
      size: 20,
      windowHours: 24
    }));
    expect(component.items().length).toBe(1);
    expect(component.summary()?.totalAssessedEndpoints).toBe(1);
  });

  it('should render KPI metrics and table rows', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const cards = compiled.querySelectorAll('.summary-card');
    expect(cards.length).toBe(5);

    const rows = compiled.querySelectorAll('.posture-row');
    expect(rows.length).toBe(1);

    const routeSpan = compiled.querySelector('.route-template');
    expect(routeSpan?.textContent).toContain('/api/v1/customers/{customerId}');

    const postureChip = compiled.querySelector('.posture-chip');
    expect(postureChip?.textContent).toContain('Adequate');
  });

  it('should filter when search query is changed', fakeAsync(() => {
    component.searchQuery = 'accounts';
    component.onSearchChange();
    tick();

    expect(mockSecurityApi.getPosturePage).toHaveBeenCalledWith(jasmine.objectContaining({
      search: 'accounts',
      page: 0
    }));
  }));

  it('should filter by posture when KPI card is clicked', () => {
    component.setPostureFilter('ATTENTION_REQUIRED');
    expect(component.selectedPosture).toBe('ATTENTION_REQUIRED');
    expect(mockSecurityApi.getPosturePage).toHaveBeenCalledWith(jasmine.objectContaining({
      posture: 'ATTENTION_REQUIRED',
      page: 0
    }));
  });

  it('should open slide-out drawer when endpoint is inspected and verify invariant attestation', () => {
    component.inspectEndpoint(mockEndpointPosture);
    fixture.detectChanges();

    expect(component.selectedEndpoint()).toBe(mockEndpointPosture);

    const compiled = fixture.nativeElement as HTMLElement;
    const drawer = compiled.querySelector('.dossier-drawer');
    expect(drawer).toBeTruthy();

    const attestation = compiled.querySelector('.safety-pill');
    expect(attestation?.textContent).toContain('CONFIRMED VULNERABILITY: NO');

    const title = compiled.querySelector('.drawer-title');
    expect(title?.textContent).toContain('GET /api/v1/customers/{customerId}');

    const dimCards = compiled.querySelectorAll('.dimension-card');
    expect(dimCards.length).toBe(6);

    // Close drawer
    component.closeDrawer();
    fixture.detectChanges();
    expect(component.selectedEndpoint()).toBeNull();
  });

  it('should handle API errors gracefully', () => {
    const errorProblem: ProblemDetail = {
      title: 'Gateway Error',
      status: 500,
      detail: 'Failed to compute security posture'
    };
    mockSecurityApi.getPosturePage.and.returnValue(throwError(() => errorProblem));

    component.loadPostureData(0);
    expect(component.loading()).toBeFalse();
    expect(component.error()).toEqual(errorProblem);
  });
});

