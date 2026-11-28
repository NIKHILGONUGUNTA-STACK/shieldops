import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { SelfHealingCenterComponent } from './self-healing-center.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  AdversaryCampaign,
  CandidatePolicy
} from '../../core/models/security.models';

describe('SelfHealingCenterComponent', () => {
  let component: SelfHealingCenterComponent;
  let fixture: ComponentFixture<SelfHealingCenterComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getAdversaryCampaigns',
      'runAdversaryCampaign',
      'getCandidatePolicies',
      'synthesizePolicy',
      'evaluateShadowFpr',
      'promoteCandidatePolicy'
    ]);

    mockSecurityApi.getAdversaryCampaigns.and.callFake(() => of([
      {
        id: 'ADV-CAMP-001',
        name: 'Transfer Step-Skipping Probing',
        targetEndpoint: 'POST /api/v1/transfers',
        strategy: 'STEP_SKIPPING',
        totalProbes: 20,
        blockedProbes: 20,
        evadedProbes: 0,
        evasionRate: 0.0,
        status: 'COMPLETED',
        startedAt: new Date().toISOString(),
        evasionTraces: []
      },
      {
        id: 'ADV-CAMP-002',
        name: 'Beneficiary Creation Out-of-Order Exploitation',
        targetEndpoint: 'POST /api/v1/beneficiaries',
        strategy: 'OUT_OF_ORDER_TRAVERSAL',
        totalProbes: 15,
        blockedProbes: 5,
        evadedProbes: 10,
        evasionRate: 0.667,
        status: 'COMPLETED',
        startedAt: new Date().toISOString(),
        evasionTraces: []
      }
    ]));

    mockSecurityApi.getCandidatePolicies.and.callFake(() => of([
      {
        id: 'CAND-POL-001',
        ruleId: 'RULE-WF-BENEFICIARY-01',
        targetMethod: 'POST',
        targetPathPattern: '^/(api/v1/)?beneficiaries(/.*)?$',
        requiredPredecessors: ['GET /api/v1/accounts'],
        description: 'Auto-synthesized invariant',
        confidenceScore: 0.94,
        shadowEvaluationsCount: 20,
        shadowFalsePositives: 0,
        shadowFpr: 0.0,
        status: 'SAFE_FOR_PROMOTION',
        createdAt: new Date().toISOString(),
        synthesizedFromCampaignId: 'ADV-CAMP-002'
      }
    ]));

    await TestBed.configureTestingModule({
      imports: [SelfHealingCenterComponent],
      providers: [
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SelfHealingCenterComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('should load adversary campaigns and candidate policies on init', () => {
    expect(mockSecurityApi.getAdversaryCampaigns).toHaveBeenCalled();
    expect(mockSecurityApi.getCandidatePolicies).toHaveBeenCalled();
    expect(component.campaigns.length).toBe(2);
    expect(component.candidates.length).toBe(1);
    expect(component.candidateCount).toBe(1);
    expect(component.promotedCount).toBe(0);
    expect(component.averageInterceptionRate).toBeGreaterThan(0);
  });

  it('should toggle between adversary and synthesizer tabs', () => {
    expect(component.activeTab).toBe('adversary');
    component.activeTab = 'synthesizer';
    expect(component.activeTab).toBe('synthesizer');
  });

  it('should submit and add a new adversary campaign', () => {
    const createdCampaign: AdversaryCampaign = {
      id: 'ADV-CAMP-003',
      name: 'Custom Parameter Fuzzing',
      targetEndpoint: 'POST /api/v1/accounts',
      strategy: 'PARAMETER_TAMPERING',
      totalProbes: 10,
      blockedProbes: 10,
      evadedProbes: 0,
      evasionRate: 0.0,
      status: 'COMPLETED',
      startedAt: new Date().toISOString(),
      evasionTraces: []
    };
    mockSecurityApi.runAdversaryCampaign.and.returnValue(of(createdCampaign));

    component.newCampaign = {
      name: 'Custom Parameter Fuzzing',
      targetEndpoint: 'POST /api/v1/accounts',
      strategy: 'PARAMETER_TAMPERING',
      probeCount: 10
    };
    component.submitCampaign();

    expect(mockSecurityApi.runAdversaryCampaign).toHaveBeenCalled();
    expect(component.campaigns[0].id).toBe('ADV-CAMP-003');
    expect(component.showRunModal).toBeFalse();
  });

  it('should trigger policy synthesis from campaign and switch to synthesizer tab', () => {
    const synthesized: CandidatePolicy = {
      id: 'CAND-POL-NEW',
      ruleId: 'RULE-WF-SYNTH-99',
      targetMethod: 'POST',
      targetPathPattern: '^/(api/v1/)?beneficiaries(/.*)?$',
      requiredPredecessors: ['GET /api/v1/accounts'],
      description: 'Auto-synthesized',
      confidenceScore: 0.95,
      shadowEvaluationsCount: 0,
      shadowFalsePositives: 0,
      shadowFpr: 0.0,
      status: 'CANDIDATE',
      createdAt: new Date().toISOString(),
      synthesizedFromCampaignId: 'ADV-CAMP-002'
    };
    mockSecurityApi.synthesizePolicy.and.returnValue(of(synthesized));

    component.triggerSynthesize('ADV-CAMP-002');
    expect(mockSecurityApi.synthesizePolicy).toHaveBeenCalledWith('ADV-CAMP-002');
    expect(component.candidates[0].id).toBe('CAND-POL-NEW');
    expect(component.activeTab).toBe('synthesizer');
  });

  it('should evaluate shadow FPR and promote candidate to edge', () => {
    const evaluated: CandidatePolicy = {
      ...component.candidates[0],
      shadowEvaluationsCount: 25,
      shadowFalsePositives: 0,
      shadowFpr: 0.0,
      status: 'SAFE_FOR_PROMOTION'
    };
    mockSecurityApi.evaluateShadowFpr.and.returnValue(of(evaluated));

    component.evaluateShadow('CAND-POL-001');
    expect(mockSecurityApi.evaluateShadowFpr).toHaveBeenCalledWith('CAND-POL-001', 25);
    expect(component.candidates[0].status).toBe('SAFE_FOR_PROMOTION');

    const promoted: CandidatePolicy = {
      ...evaluated,
      status: 'PROMOTED',
      promotedAt: new Date().toISOString()
    };
    mockSecurityApi.promoteCandidatePolicy.and.returnValue(of(promoted));

    component.promotePolicy('CAND-POL-001');
    expect(mockSecurityApi.promoteCandidatePolicy).toHaveBeenCalledWith('CAND-POL-001');
    expect(component.candidates[0].status).toBe('PROMOTED');
    expect(component.promotedCount).toBe(1);
  });
});
