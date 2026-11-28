import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { SoarAutomationComponent } from './soar-automation.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  WafBanRule,
  TokenRevocationRecord,
  SoarTicket,
  ChallengeMetrics
} from '../../core/models/security.models';

describe('SoarAutomationComponent', () => {
  let component: SoarAutomationComponent;
  let fixture: ComponentFixture<SoarAutomationComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockWafRules: WafBanRule[] = [
    {
      id: 'BAN-001',
      ipOrCidr: '198.51.100.42',
      reason: 'Credential stuffing attack',
      incidentId: 'INC-SEC-01',
      bannedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      source: 'SOAR',
      active: true
    }
  ];

  const mockRevokedTokens: TokenRevocationRecord[] = [
    {
      jti: 'jti-token-xyz',
      subject: 'user.compromised',
      reason: 'Stolen device token',
      revokedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    }
  ];

  const mockTickets: SoarTicket[] = [
    {
      id: 'SOAR-TCK-001',
      incidentId: 'INC-SEC-01',
      externalSystem: 'JIRA',
      externalTicketId: 'SEC-1049',
      title: 'Active API Exfiltration Campaign',
      severity: 'CRITICAL',
      status: 'OPEN',
      assignee: 'security.lead',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
  ];

  const mockMetrics: ChallengeMetrics = {
    totalIssued: 10,
    totalVerified: 8,
    totalFailed: 2,
    activeChallenges: 1,
    activeClearances: 7
  };

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getWafRules',
      'addWafBan',
      'deleteWafBan',
      'getCloudflareWafExport',
      'getAwsWafExport',
      'getIptablesExport',
      'getRevokedTokens',
      'revokeToken',
      'revokeSubject',
      'getSoarTickets',
      'createSoarTicket',
      'issueChallenge',
      'verifyChallenge',
      'getChallengeMetrics'
    ]);

    mockSecurityApi.getWafRules.and.callFake(() => of([
      {
        id: 'BAN-001',
        ipOrCidr: '198.51.100.42',
        reason: 'Credential stuffing attack',
        incidentId: 'INC-SEC-01',
        bannedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        source: 'SOAR',
        active: true
      }
    ]));
    mockSecurityApi.getRevokedTokens.and.callFake(() => of([
      {
        jti: 'jti-token-xyz',
        subject: 'user.compromised',
        reason: 'Stolen device token',
        revokedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      }
    ]));
    mockSecurityApi.getSoarTickets.and.callFake(() => of([
      {
        id: 'SOAR-TCK-001',
        incidentId: 'INC-SEC-01',
        externalSystem: 'JIRA',
        externalTicketId: 'SEC-1049',
        title: 'Active API Exfiltration Campaign',
        severity: 'CRITICAL',
        status: 'OPEN',
        assignee: 'security.lead',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
    ]));
    mockSecurityApi.getChallengeMetrics.and.returnValue(of(mockMetrics));

    await TestBed.configureTestingModule({
      imports: [SoarAutomationComponent],
      providers: [
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SoarAutomationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create the component', () => {
    expect(component).toBeTruthy();
  });

  it('should load initial data across all 4 SOAR domains on init', () => {
    expect(mockSecurityApi.getWafRules).toHaveBeenCalled();
    expect(mockSecurityApi.getRevokedTokens).toHaveBeenCalled();
    expect(mockSecurityApi.getSoarTickets).toHaveBeenCalled();
    expect(mockSecurityApi.getChallengeMetrics).toHaveBeenCalled();

    expect(component.wafRules.length).toBe(1);
    expect(component.wafRules[0].ipOrCidr).toBe('198.51.100.42');
    expect(component.revokedTokens.length).toBe(1);
    expect(component.soarTickets.length).toBe(1);
    expect(component.openTicketsCount).toBe(1);
    expect(component.challengeMetrics?.activeChallenges).toBe(1);
  });

  it('should toggle between operational tabs', () => {
    expect(component.activeTab).toBe('waf');

    component.activeTab = 'tokens';
    expect(component.activeTab).toBe('tokens');

    component.activeTab = 'tickets';
    expect(component.activeTab).toBe('tickets');

    component.activeTab = 'challenge';
    expect(component.activeTab).toBe('challenge');
  });

  it('should add a dynamic WAF ban rule', () => {
    const createdBan: WafBanRule = {
      id: 'BAN-002',
      ipOrCidr: '203.0.113.99',
      reason: 'Manual SOC ban',
      incidentId: 'INC-MANUAL',
      bannedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      source: 'MANUAL',
      active: true
    };
    mockSecurityApi.addWafBan.and.returnValue(of(createdBan));

    component.newBan = { ipOrCidr: '203.0.113.99', reason: 'Manual SOC ban', incidentId: 'INC-MANUAL', ttlHours: 24 };
    component.submitBan();

    expect(mockSecurityApi.addWafBan).toHaveBeenCalled();
    expect(component.wafRules[0].ipOrCidr).toBe('203.0.113.99');
    expect(component.showAddBanModal).toBeFalse();
  });

  it('should remove a WAF ban rule', () => {
    mockSecurityApi.deleteWafBan.and.returnValue(of(void 0));
    component.removeBan('BAN-001');

    expect(mockSecurityApi.deleteWafBan).toHaveBeenCalledWith('BAN-001');
    expect(component.wafRules.length).toBe(0);
  });

  it('should revoke a token JTI', () => {
    const newRevocation: TokenRevocationRecord = {
      jti: 'jti-new-leak',
      subject: 'target.user',
      reason: 'Leak investigation',
      revokedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    };
    mockSecurityApi.revokeToken.and.returnValue(of(newRevocation));

    component.tokenRevokeForm = { jti: 'jti-new-leak', subject: 'target.user', reason: 'Leak investigation', ttlHours: 24 };
    component.submitTokenRevocation();

    expect(mockSecurityApi.revokeToken).toHaveBeenCalled();
    expect(component.revokedTokens[0].jti).toBe('jti-new-leak');
  });

  it('should dispatch an outbound SOAR ticket', () => {
    const createdTicket: SoarTicket = {
      id: 'SOAR-TCK-002',
      incidentId: 'INC-CRIT-9921',
      externalSystem: 'PAGERDUTY',
      externalTicketId: 'PD-55441',
      title: 'High-severity breach detected',
      severity: 'CRITICAL',
      status: 'OPEN',
      assignee: 'oncall.engineer',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    mockSecurityApi.createSoarTicket.and.returnValue(of(createdTicket));

    component.newTicket = { incidentId: 'INC-CRIT-9921', externalSystem: 'PAGERDUTY', title: 'High-severity breach detected', severity: 'CRITICAL', assignee: 'oncall.engineer' };
    component.submitTicket();

    expect(mockSecurityApi.createSoarTicket).toHaveBeenCalled();
    expect(component.soarTickets[0].externalTicketId).toBe('PD-55441');
    expect(component.showNewTicketModal).toBeFalse();
  });

  it('should issue and verify an adaptive challenge', () => {
    mockSecurityApi.issueChallenge.and.returnValue(of({
      sessionId: 'session-soar-test',
      challengeNonce: 'CHAL-TEST1234',
      reason: 'Anomaly',
      threatRisk: 0.82,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 300000).toISOString(),
      verified: false
    }));

    mockSecurityApi.verifyChallenge.and.returnValue(of({
      sessionId: 'session-soar-test',
      verified: true,
      status: 'CLEARED'
    }));

    component.issueTestChallenge();
    expect(mockSecurityApi.issueChallenge).toHaveBeenCalled();
    expect(component.lastIssuedSession?.challengeNonce).toBe('CHAL-TEST1234');
    expect(component.challengeTest.verifyToken).toBe('CHAL-TEST1234');

    component.verifyTestChallenge();
    expect(mockSecurityApi.verifyChallenge).toHaveBeenCalled();
    expect(component.challengeResult?.verified).toBeTrue();
  });
});
