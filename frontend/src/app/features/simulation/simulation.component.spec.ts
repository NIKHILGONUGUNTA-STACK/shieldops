import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { SimulationComponent } from './simulation.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SimulationScenario, SimulationCampaignTemplate, SimulationRunResponse } from '../../core/models/security.models';

describe('SimulationComponent', () => {
  let component: SimulationComponent;
  let fixture: ComponentFixture<SimulationComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  const mockScenario: SimulationScenario = {
    id: 'SCEN-BOLA-01',
    name: 'Classic Cross-Tenant BOLA Access',
    description: 'Attacker attempts unauthorized access to another tenant account.',
    category: 'BOLA',
    severity: 'HIGH',
    isImplemented: true,
    tags: ['bola', 'idor'],
    targetEndpoints: ['/accounts/{victim_id}'],
    expectedOutcomes: ['HTTP 403/404', 'RULE-BOLA-01 alert']
  };

  const mockTemplate: SimulationCampaignTemplate = {
    id: 'TPL-BENIGN-WORKDAY',
    name: 'Standard Benign Business Workday',
    description: 'Comprehensive benign workload simulating normal customer banking operations.',
    stages: [
      {
        stageNumber: 1,
        name: 'Customer Logins & Profile Fetch',
        scenarioId: 'SCEN-BENIGN-01',
        iterations: 5,
        delayBetweenRequestsMs: 200,
        expectedDetectionRules: [],
        expectedIncidents: 0,
        expectedCampaigns: 0,
        expectedPolicyActions: [],
        timeoutSeconds: 30
      }
    ],
    trafficMix: 'SEQUENTIAL',
    defaultRequestRate: 5.0,
    defaultConcurrency: 2,
    defaultDurationSeconds: 60,
    tags: ['benign', 'baseline']
  };

  const mockRun: SimulationRunResponse = {
    runId: 'SIM-RUN-12345678',
    campaignId: 'SIM-CAMP-87654321',
    templateId: 'TPL-BENIGN-WORKDAY',
    status: 'RUNNING',
    startTime: '2026-11-15T10:00:00Z',
    config: {
      templateId: 'TPL-BENIGN-WORKDAY',
      durationSeconds: 60,
      requestRate: 5.0,
      concurrency: 2,
      trafficMix: 'SEQUENTIAL',
      deterministicSeed: 42
    },
    stages: [],
    totalRequests: 10,
    requests2xx: 10,
    requests4xx: 0,
    requests5xx: 0,
    allAssertionsPassed: true,
    provenanceMetadata: { environment: 'local-testbed' }
  };

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', [
      'getSimulationScenarios',
      'getSimulationTemplates',
      'getSimulationRuns',
      'startSimulationRun',
      'pauseSimulationRun',
      'resumeSimulationRun',
      'stopSimulationRun',
      'getSimulationRun',
      'getSimulationReport'
    ]);

    apiServiceSpy.getSimulationScenarios.and.returnValue(of([mockScenario]));
    apiServiceSpy.getSimulationTemplates.and.returnValue(of([mockTemplate]));
    apiServiceSpy.getSimulationRuns.and.returnValue(of([mockRun]));
    apiServiceSpy.startSimulationRun.and.returnValue(of(mockRun));
    apiServiceSpy.pauseSimulationRun.and.returnValue(of({ ...mockRun, status: 'PAUSED' }));
    apiServiceSpy.resumeSimulationRun.and.returnValue(of({ ...mockRun, status: 'RUNNING' }));
    apiServiceSpy.stopSimulationRun.and.returnValue(of({ ...mockRun, status: 'STOPPED' }));

    await TestBed.configureTestingModule({
      imports: [SimulationComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SimulationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create simulation component and load scenarios and templates', () => {
    expect(component).toBeTruthy();
    expect(component.scenarios.length).toBe(1);
    expect(component.templates.length).toBe(1);
    expect(component.templates[0].id).toBe('TPL-BENIGN-WORKDAY');
  });

  it('should display guardrail banner enforcing localhost target and provenance', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.guardrail-banner')).toBeTruthy();
    expect(compiled.textContent).toContain('Local Testbed (localhost:8000)');
    expect(compiled.textContent).toContain('X-Simulation-Run-Id Injected');
  });

  it('should launch campaign template and switch to live tab', () => {
    component.launchTemplate(mockTemplate);
    expect(apiServiceSpy.startSimulationRun).toHaveBeenCalled();
    expect(component.currentTab).toBe('live');
    expect(component.activeRun?.runId).toBe('SIM-RUN-12345678');
  });

  it('should support pause, resume, and stop controls', () => {
    component.activeRun = mockRun;
    component.pauseRun();
    expect(apiServiceSpy.pauseSimulationRun).toHaveBeenCalledWith('SIM-RUN-12345678');

    component.resumeRun();
    expect(apiServiceSpy.resumeSimulationRun).toHaveBeenCalledWith('SIM-RUN-12345678');

    component.stopRun();
    expect(apiServiceSpy.stopSimulationRun).toHaveBeenCalledWith('SIM-RUN-12345678');
  });
});

