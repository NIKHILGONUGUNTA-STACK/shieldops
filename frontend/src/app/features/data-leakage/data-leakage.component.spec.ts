import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { DataLeakageComponent } from './data-leakage.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  DataLeakageSummaryResponse,
  DataLeakageRuleInfoResponse,
  IncidentResponse,
  EvidenceResponse
} from '../../core/models/security.models';

describe('DataLeakageComponent', () => {
  let component: DataLeakageComponent;
  let fixture: ComponentFixture<DataLeakageComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockIncidents: IncidentResponse[] = [
    {
      id: 'inc-leak-001',
      incidentFingerprint: 'fp-12345',
      ruleId: 'RULE-BOLA-CONFIRMED-01',
      ruleVersion: '1.0.0',
      threatCategory: 'BOLA_CONFIRMED_LEAK',
      severity: 'CRITICAL',
      status: 'OPEN',
      targetEntityType: 'CUSTOMER',
      targetEntityValue: 'cust-victim-001',
      firstDetectedAt: '2026-11-11T10:00:00Z',
      lastEventAt: '2026-11-11T10:00:00Z',
      eventCount: 3,
      summary: 'BOLA Confirmed Leak: Customer Cross-Owner Access',
      createdAt: '2026-11-11T10:00:00Z',
      updatedAt: '2026-11-11T10:00:00Z'
    }
  ];

  const mockSummary: DataLeakageSummaryResponse = {
    totalLeakageIncidents: 6,
    confirmedBolaLeaks: 2,
    deniedBolaAttempts: 2,
    sensitiveDataExposures: 1,
    bulkExtractionEvents: 1,
    multiStageCampaigns: 0,
    incidentsBySeverity: {
      CRITICAL: 2,
      HIGH: 4
    },
    incidentsByStatus: {
      OPEN: 6
    },
    recentIncidents: mockIncidents,
    generatedAt: '2026-11-11T12:00:00Z'
  };

  const mockEvidence: EvidenceResponse[] = [
    {
      id: 'ev-01',
      incidentId: 'inc-leak-001',
      ruleId: 'RULE-BOLA-CONFIRMED-01',
      ruleVersion: '1.0.0',
      evaluatedAt: '2026-11-11T10:00:00Z',
      confidenceScore: 0.95,
      severity: 'CRITICAL',
      triggerCondition: 'HTTP 200 returned on cross-owner customer resource',
      distinctResourcesCount: 1,
      contributingEventIds: ['evt-1', 'evt-2'],
      mitreTechnique: 'T1530',
      createdAt: '2026-11-11T10:00:00Z'
    }
  ];

  const mockRules: DataLeakageRuleInfoResponse[] = [
    {
      ruleId: 'RULE-BOLA-CONFIRMED-01',
      ruleVersion: '1.0.0',
      name: 'BOLA Confirmed Leak Detection',
      description: 'Detects successful cross-owner customer or account access',
      threatCategory: 'BOLA_CONFIRMED_LEAK',
      defaultSeverity: 'CRITICAL',
      enabled: true,
      triggerConditionExplanation: 'Cross-owner request succeeded with HTTP 200'
    }
  ];

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getDataLeakageSummary',
      'getDataLeakageIncidents',
      'getDataLeakageEvidence',
      'getDataLeakageRules',
      'getComparativeBenchmark',
      'getExtractionAnalytics'
    ]);

    const mockExtractionAnalytics = {
      totalExtractionIncidents: 4,
      rapidExtractionCount: 1,
      lowAndSlowExtractionCount: 1,
      distributedExtractionCount: 1,
      paginationExtractionCount: 1,
      multiResourceExtractionCount: 0,
      excessiveDataExposureCount: 1,
      highRiskFieldsExposedCount: 1,
      schemaDriftCount: 1,
      generatedAt: '2026-11-13T12:00:00Z'
    };

    const mockBenchmark = {
      datasetSize: 23,
      isolatedRules: { mode: 'ISOLATED_RULES', precision: 0.8333, recall: 0.9091, f1Score: 0.8696 },
      contextualCorrelation: { mode: 'CONTEXTUAL_CORRELATION', precision: 1.0, recall: 1.0, f1Score: 1.0 },
      robustnessFindings: [
        { testCase: 'Sliding Window', category: 'Boundary', expectedBehavior: '', observedBehavior: '', passed: true, details: '' }
      ],
      generatedAt: '2026-11-12T12:00:00Z'
    };

    mockSecurityApi.getDataLeakageSummary.and.returnValue(of(mockSummary));
    mockSecurityApi.getDataLeakageIncidents.and.returnValue(of({
      incidents: mockIncidents,
      content: mockIncidents,
      page: 1,
      size: 25,
      totalElements: 1,
      totalPages: 1,
      first: true,
      last: true
    }));
    mockSecurityApi.getDataLeakageEvidence.and.returnValue(of(mockEvidence));
    mockSecurityApi.getDataLeakageRules.and.returnValue(of(mockRules));
    mockSecurityApi.getComparativeBenchmark.and.returnValue(of(mockBenchmark as any));
    mockSecurityApi.getExtractionAnalytics.and.returnValue(of(mockExtractionAnalytics as any));

    await TestBed.configureTestingModule({
      imports: [DataLeakageComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(DataLeakageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create and load summary and incidents', () => {
    expect(component).toBeTruthy();
    expect(component.summary()).toEqual(mockSummary);
    expect(component.incidents().length).toBe(1);
    expect(component.loading()).toBeFalse();
  });

  it('should filter by category when filter is clicked', () => {
    component.setCategoryFilter('BOLA_CONFIRMED_LEAK');
    expect(component.selectedCategory).toBe('BOLA_CONFIRMED_LEAK');
    expect(mockSecurityApi.getDataLeakageIncidents).toHaveBeenCalled();
  });

  it('should open evidence drawer when incident is clicked', () => {
    component.toggleIncident(mockIncidents[0]);
    expect(component.selectedIncident()).toEqual(mockIncidents[0]);
    expect(mockSecurityApi.getDataLeakageEvidence).toHaveBeenCalledWith('inc-leak-001');
    expect(component.currentEvidence().length).toBe(1);
  });

  it('should close evidence drawer on toggle', () => {
    component.toggleIncident(mockIncidents[0]);
    expect(component.selectedIncident()).not.toBeNull();
    component.toggleIncident(mockIncidents[0]);
    expect(component.selectedIncident()).toBeNull();
  });

  it('should load comparative benchmark data on refresh', () => {
    expect(mockSecurityApi.getComparativeBenchmark).toHaveBeenCalled();
    expect(component.benchmarkData()).not.toBeNull();
    expect(component.benchmarkData()?.datasetSize).toBe(23);
  });

  it('should switch between incidents and benchmark views', () => {
    expect(component.activeView()).toBe('incidents');
    component.activeView.set('benchmark');
    expect(component.activeView()).toBe('benchmark');
  });

  it('should load extraction analytics and switch to extraction view', () => {
    expect(mockSecurityApi.getExtractionAnalytics).toHaveBeenCalled();
    expect(component.extractionAnalytics()).not.toBeNull();
    expect(component.extractionAnalytics()?.totalExtractionIncidents).toBe(4);
    component.activeView.set('extraction');
    expect(component.activeView()).toBe('extraction');
  });
});
