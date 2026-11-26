import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { MlAnomaliesComponent } from './ml-anomalies.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('MlAnomaliesComponent', () => {
  let component: MlAnomaliesComponent;
  let fixture: ComponentFixture<MlAnomaliesComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getWorkflowRules',
      'getOutlierStats',
      'verifyWorkflowTransition',
      'getWorkflowSessionSteps',
    ]);

    mockSecurityApi.getWorkflowRules.and.returnValue(of([
      {
        id: 'RULE-WF-TRANSFER-01',
        targetMethod: 'POST',
        targetPathPattern: '^/(api/v1/)?(transactions|transfers)(/.*)?$',
        requiredPredecessors: ['GET /api/v1/accounts'],
        description: 'Test rule',
        enabled: true
      }
    ]));

    mockSecurityApi.getOutlierStats.and.returnValue(of({
      'GET /api/v1/accounts': {
        payload_bytes: { count: 10, mean: 1200, stdDev: 50 },
        latency_ms: { count: 10, mean: 30, stdDev: 5 }
      }
    }));

    await TestBed.configureTestingModule({
      imports: [MlAnomaliesComponent],
      providers: [
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(MlAnomaliesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('should load workflow rules and outlier statistics on init', () => {
    expect(mockSecurityApi.getWorkflowRules).toHaveBeenCalled();
    expect(mockSecurityApi.getOutlierStats).toHaveBeenCalled();
    expect(component.activeRules.length).toBe(1);
    expect(component.outlierItems.length).toBe(1);
    expect(component.outlierItems[0].endpoint).toBe('GET /api/v1/accounts');
  });

  it('should allow switching between tabs', () => {
    expect(component.activeTab).toBe('funnel');

    component.activeTab = 'rules';
    expect(component.activeTab).toBe('rules');

    component.activeTab = 'outliers';
    expect(component.activeTab).toBe('outliers');
  });

  it('should evaluate transition and store result on testVerify', () => {
    mockSecurityApi.verifyWorkflowTransition.and.returnValue(of({
      allowed: false,
      ruleId: 'RULE-WF-TRANSFER-01',
      reason: 'Missing prerequisite'
    }));

    component.testVerify();
    expect(mockSecurityApi.verifyWorkflowTransition).toHaveBeenCalled();
    expect(component.verifyResult).toBeDefined();
    expect(component.verifyResult.allowed).toBeFalse();
    expect(component.verifyResult.ruleId).toBe('RULE-WF-TRANSFER-01');
  });

  it('should seed prerequisite and mark allowed', () => {
    component.seedPrerequisite();
    expect(component.verifyResult).toBeDefined();
    expect(component.verifyResult.allowed).toBeTrue();
  });

  it('should use fallback rules if API returns error', () => {
    mockSecurityApi.getWorkflowRules.and.returnValue(throwError(() => new Error('API Error')));
    mockSecurityApi.getOutlierStats.and.returnValue(throwError(() => new Error('API Error')));

    component.refresh();
    expect(component.activeRules.length).toBeGreaterThan(0);
    expect(component.outlierItems.length).toBeGreaterThan(0);
  });
});
