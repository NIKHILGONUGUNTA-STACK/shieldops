import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, ActivatedRoute } from '@angular/router';
import { of, throwError } from 'rxjs';
import { IncidentDetailComponent } from './incident-detail.component';
import { SecurityApiService } from '../../../core/services/security-api.service';
import { AuthService } from '../../../core/auth/auth.service';
import {
  IncidentResponse,
  EvidenceResponse,
  IncidentStatusHistoryResponse,
  PolicyDecisionResponse
} from '../../../core/models/security.models';

describe('IncidentDetailComponent', () => {
  let component: IncidentDetailComponent;
  let fixture: ComponentFixture<IncidentDetailComponent>;
  let apiSpy: jasmine.SpyObj<SecurityApiService>;
  let authSpy: jasmine.SpyObj<AuthService>;

  const mockIncident: IncidentResponse = {
    id: 'inc-123',
    incidentFingerprint: 'fp-12345678',
    ruleId: 'RULE-BOLA-01',
    ruleVersion: '1.0.0',
    threatCategory: 'BOLA',
    severity: 'HIGH',
    status: 'OPEN',
    targetEntityType: 'CUSTOMER',
    targetEntityValue: 'cust-uuid-456',
    firstDetectedAt: '2026-10-27T08:00:00Z',
    lastEventAt: '2026-10-27T08:05:00Z',
    eventCount: 3,
    summary: 'BOLA Violation: 3 unauthorized customer profile attempts',
    createdAt: '2026-10-27T08:00:00Z',
    updatedAt: '2026-10-27T08:05:00Z'
  };

  const mockEvidence: EvidenceResponse[] = [
    {
      id: 'ev-1',
      incidentId: 'inc-123',
      ruleId: 'RULE-BOLA-01',
      ruleVersion: '1.0.0',
      evaluatedAt: '2026-10-27T08:05:00Z',
      confidenceScore: 0.95,
      severity: 'HIGH',
      triggerCondition: 'Cross-resource attempt threshold reached',
      distinctResourcesCount: 3,
      contributingEventIds: ['evt-1', 'evt-2', 'evt-3'],
      mitreTechnique: 'T1078.004',
      createdAt: '2026-10-27T08:05:00Z'
    }
  ];

  const mockHistory: IncidentStatusHistoryResponse[] = [
    {
      id: 'hist-1',
      incidentId: 'inc-123',
      previousStatus: 'OPEN',
      newStatus: 'INVESTIGATING',
      changedBy: 'analyst',
      changeReason: 'Reviewing customer telemetry',
      changedAt: '2026-10-27T08:10:00Z'
    }
  ];

  const mockPolicies: PolicyDecisionResponse[] = [
    {
      id: 'pol-1',
      incidentId: 'inc-123',
      targetEntityType: 'CUSTOMER',
      targetEntityValue: 'cust-uuid-456',
      recommendedAction: 'LOG_ALERT',
      enforcementLevel: 'ADVISORY',
      reason: 'Advisory alert logged for review',
      confidenceScore: 0.95,
      createdAt: '2026-10-27T08:05:00Z'
    }
  ];

  beforeEach(async () => {
    apiSpy = jasmine.createSpyObj('SecurityApiService', [
      'getIncidentById',
      'getIncidentEvidence',
      'getIncidentHistory',
      'getIncidentPolicyDecisions',
      'updateIncidentStatus'
    ]);

    authSpy = jasmine.createSpyObj('AuthService', ['isSecurityAdmin', 'isSecurityAnalyst', 'isAuthenticated']);

    await TestBed.configureTestingModule({
      imports: [IncidentDetailComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiSpy },
        { provide: AuthService, useValue: authSpy },
        {
          provide: ActivatedRoute,
          useValue: {
            paramMap: of(new Map([['id', 'inc-123']]))
          }
        }
      ]
    }).compileComponents();
  });

  it('should load incident details, evidence, history, and policy decisions', () => {
    apiSpy.getIncidentById.and.returnValue(of(mockIncident));
    apiSpy.getIncidentEvidence.and.returnValue(of(mockEvidence));
    apiSpy.getIncidentHistory.and.returnValue(of(mockHistory));
    apiSpy.getIncidentPolicyDecisions.and.returnValue(of(mockPolicies));

    fixture = TestBed.createComponent(IncidentDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component).toBeTruthy();
    expect(component.incident()?.id).toBe('inc-123');
    expect(component.evidence().length).toBe(1);
    expect(component.history().length).toBe(1);
    expect(component.policyDecisions().length).toBe(1);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('fp-12345678');
    expect(compiled.textContent).toContain('RULE-BOLA-01');
    expect(compiled.textContent).toContain('T1078.004');
    expect(compiled.textContent).toContain('Reviewing customer telemetry');
  });

  it('should display error panel when incident ID does not exist (404)', () => {
    apiSpy.getIncidentById.and.returnValue(throwError(() => ({
      title: 'Incident Not Found',
      status: 404,
      detail: 'No incident registered with ID: inc-123'
    })));

    fixture = TestBed.createComponent(IncidentDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.loading()).toBeFalse();
    expect(component.error()?.status).toBe(404);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-panel')).toBeTruthy();
    expect(compiled.textContent).toContain('No incident registered with ID');
  });

  it('should calculate allowed target statuses for OPEN incident', () => {
    apiSpy.getIncidentById.and.returnValue(of(mockIncident));
    apiSpy.getIncidentEvidence.and.returnValue(of([]));
    apiSpy.getIncidentHistory.and.returnValue(of([]));
    apiSpy.getIncidentPolicyDecisions.and.returnValue(of([]));

    fixture = TestBed.createComponent(IncidentDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    const allowed = component.allowedTargetStatuses();
    expect(allowed).toContain('INVESTIGATING');
    expect(allowed).toContain('RESOLVED');
    expect(allowed).toContain('FALSE_POSITIVE');
    expect(allowed).not.toContain('CONTAINED');
  });

  it('should validate mandatory reason length (5 to 512 chars)', () => {
    apiSpy.getIncidentById.and.returnValue(of(mockIncident));
    apiSpy.getIncidentEvidence.and.returnValue(of([]));
    apiSpy.getIncidentHistory.and.returnValue(of([]));
    apiSpy.getIncidentPolicyDecisions.and.returnValue(of([]));

    fixture = TestBed.createComponent(IncidentDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    component.selectedTargetStatus = 'INVESTIGATING';
    component.transitionReason = 'tiny'; // 4 chars
    expect(component.canSubmitTransition()).toBeFalse();

    component.transitionReason = 'Valid reason for investigation'; // > 5 chars
    expect(component.canSubmitTransition()).toBeTrue();
  });

  it('should restrict reopening terminal incidents to SECURITY_ADMIN', () => {
    const resolvedIncident: IncidentResponse = { ...mockIncident, status: 'RESOLVED' };
    apiSpy.getIncidentById.and.returnValue(of(resolvedIncident));
    apiSpy.getIncidentEvidence.and.returnValue(of([]));
    apiSpy.getIncidentHistory.and.returnValue(of([]));
    apiSpy.getIncidentPolicyDecisions.and.returnValue(of([]));

    authSpy.isSecurityAdmin.and.returnValue(false); // Only Analyst

    fixture = TestBed.createComponent(IncidentDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    component.selectedTargetStatus = 'INVESTIGATING';
    component.transitionReason = 'Attempting reopen as analyst';

    expect(component.isTerminalStatus()).toBeTrue();
    expect(component.canSubmitTransition()).toBeFalse(); // Forbidden for non-admin

    authSpy.isSecurityAdmin.and.returnValue(true); // Elevate to Admin
    expect(component.canSubmitTransition()).toBeTrue();
  });

  it('should submit status transition and refresh history', () => {
    apiSpy.getIncidentById.and.returnValue(of(mockIncident));
    apiSpy.getIncidentEvidence.and.returnValue(of([]));
    apiSpy.getIncidentHistory.and.returnValue(of([]));
    apiSpy.getIncidentPolicyDecisions.and.returnValue(of([]));

    const updatedIncident: IncidentResponse = { ...mockIncident, status: 'INVESTIGATING' };
    apiSpy.updateIncidentStatus.and.returnValue(of(updatedIncident));

    fixture = TestBed.createComponent(IncidentDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    component.openStatusModal();
    expect(component.showStatusModal()).toBeTrue();

    component.selectedTargetStatus = 'INVESTIGATING';
    component.transitionReason = 'Triage completed, investigation opened';

    component.submitStatusTransition();

    expect(apiSpy.updateIncidentStatus).toHaveBeenCalledWith('inc-123', {
      targetStatus: 'INVESTIGATING',
      reason: 'Triage completed, investigation opened'
    });
    expect(component.incident()?.status).toBe('INVESTIGATING');
    expect(component.showStatusModal()).toBeFalse();
  });
});
