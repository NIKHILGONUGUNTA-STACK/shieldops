import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { CampaignsComponent } from './campaigns.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import { CampaignResponse, CampaignTimelineEvent, CampaignRiskAssessment, CampaignEvidenceDetailsResponse, CampaignStatusHistory } from '../../core/models/security.models';

describe('CampaignsComponent', () => {
  let component: CampaignsComponent;
  let fixture: ComponentFixture<CampaignsComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  const mockCampaign: CampaignResponse = {
    id: 'camp-123',
    name: 'Multi-Stage Exfiltration: Recon -> Probing -> Extraction',
    tenantId: 'tenant-aegis',
    correlationIdentity: 'cust-alex-123',
    status: 'OPEN',
    riskScore: 92.5,
    riskCategory: 'CRITICAL',
    severity: 'CRITICAL',
    stagesObserved: ['RECONNAISSANCE', 'AUTHORIZATION_PROBING', 'BULK_EXTRACTION'],
    currentStage: 'BULK_EXTRACTION',
    evidenceCompleteness: 'COMPLETE',
    firstObservedAt: '2026-11-14T10:00:00Z',
    lastObservedAt: '2026-11-14T10:12:00Z',
    eventCount: 15,
    distinctServices: 3,
    distinctResources: 4,
    description: 'Coordinated reconnaissance probing followed by cross-domain bulk extraction.'
  };

  const mockTimelineEvent: CampaignTimelineEvent = {
    id: 'te-1',
    campaignId: 'camp-123',
    eventId: 'ev-1',
    eventTimestamp: '2026-11-14T10:00:00Z',
    stage: 'RECONNAISSANCE',
    httpMethod: 'GET',
    route: '/actuator/env',
    statusCode: 404,
    details: 'Unauthenticated actuator probing',
    riskContribution: 10.0
  };

  const mockRisk: CampaignRiskAssessment = {
    riskScore: 92.5,
    riskCategory: 'CRITICAL',
    severity: 'CRITICAL',
    scoreBreakdown: { 'Stage 1: Reconnaissance': 10.0, 'Stage 5: Bulk Exfiltration': 25.0 },
    keyRiskIndicators: ['Rapid bulk harvesting detected', 'Cross-resource enumeration confirmed']
  };

  const mockEvidence: CampaignEvidenceDetailsResponse = {
    campaignId: 'camp-123',
    incidentIds: ['inc-1', 'inc-2'],
    evidenceUris: ['telemetry://events/ev-1'],
    missingEvidenceReasons: [],
    completeness: 'COMPLETE'
  };

  const mockHistory: CampaignStatusHistory = {
    id: 'csh-1',
    campaignId: 'camp-123',
    fromStatus: 'OPEN',
    toStatus: 'INVESTIGATING',
    transitionReason: 'Analyst initiated investigation',
    changedBy: 'analyst-bob',
    changedAt: '2026-11-14T10:15:00Z'
  };

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', [
      'getCampaigns',
      'getCampaignTimeline',
      'getCampaignRisk',
      'getCampaignEvidence',
      'getCampaignHistory',
      'updateCampaignStatus'
    ]);

    apiServiceSpy.getCampaigns.and.returnValue(of({
      content: [mockCampaign],
      totalElements: 1,
      totalPages: 1,
      page: 0,
      size: 50
    }));

    apiServiceSpy.getCampaignTimeline.and.returnValue(of([mockTimelineEvent]));
    apiServiceSpy.getCampaignRisk.and.returnValue(of(mockRisk));
    apiServiceSpy.getCampaignEvidence.and.returnValue(of(mockEvidence));
    apiServiceSpy.getCampaignHistory.and.returnValue(of([mockHistory]));

    await TestBed.configureTestingModule({
      imports: [CampaignsComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(CampaignsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create campaigns component and load campaigns', () => {
    expect(component).toBeTruthy();
    expect(component.campaigns.length).toBe(1);
    expect(component.activeCampaignsCount).toBe(1);
    expect(component.criticalRiskCount).toBe(1);
  });

  it('should render campaign table and display kill-chain stages', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.campaign-title')?.textContent).toContain('Multi-Stage Exfiltration');
    expect(compiled.querySelector('.risk-score-pill')?.textContent).toContain('92.5');
    expect(compiled.querySelectorAll('.stage-chip').length).toBeGreaterThan(0);
  });

  it('should select campaign and load detail tabs', () => {
    component.selectCampaign(mockCampaign);
    fixture.detectChanges();

    expect(component.selectedCampaign).toBe(mockCampaign);
    expect(apiServiceSpy.getCampaignTimeline).toHaveBeenCalledWith('camp-123');
    expect(apiServiceSpy.getCampaignRisk).toHaveBeenCalledWith('camp-123');
    expect(apiServiceSpy.getCampaignEvidence).toHaveBeenCalledWith('camp-123');
    expect(apiServiceSpy.getCampaignHistory).toHaveBeenCalledWith('camp-123');
  });

  it('should filter campaigns by status and risk score', () => {
    component.statusFilter = 'RESOLVED';
    component.applyFilters();
    expect(component.filteredCampaigns.length).toBe(0);

    component.statusFilter = 'ALL';
    component.minRiskFilter = 95;
    component.applyFilters();
    expect(component.filteredCampaigns.length).toBe(0);

    component.minRiskFilter = 90;
    component.applyFilters();
    expect(component.filteredCampaigns.length).toBe(1);
  });

  it('should transition campaign status with reason audit log', () => {
    const updatedCampaign: CampaignResponse = {
      ...mockCampaign,
      status: 'INVESTIGATING'
    };
    apiServiceSpy.updateCampaignStatus.and.returnValue(of(updatedCampaign));

    component.selectCampaign(mockCampaign);
    component.newStatus = 'INVESTIGATING';
    component.transitionReason = 'Reviewing high-volume extraction sequence';
    component.submitTransition();

    expect(apiServiceSpy.updateCampaignStatus).toHaveBeenCalledWith('camp-123', {
      targetStatus: 'INVESTIGATING',
      transitionReason: 'Reviewing high-volume extraction sequence'
    });
    expect(component.selectedCampaign?.status).toBe('INVESTIGATING');
  });
});
