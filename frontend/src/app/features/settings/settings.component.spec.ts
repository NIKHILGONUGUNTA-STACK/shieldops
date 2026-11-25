import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { SettingsComponent } from './settings.component';
import { AuthService } from '../../core/auth/auth.service';
import { TenantService } from '../../core/services/tenant.service';
import { WebhookService } from '../../core/services/webhook.service';
import { Tenant, TenantPageResponse, TenantUsageResponse } from '../../core/models/tenant.model';
import { WebhookSubscription, WebhookDispatchResult } from '../../core/models/webhook.model';

describe('SettingsComponent', () => {
  let component: SettingsComponent;
  let fixture: ComponentFixture<SettingsComponent>;
  let authServiceSpy: jasmine.SpyObj<AuthService>;
  let tenantServiceSpy: jasmine.SpyObj<TenantService>;
  let webhookServiceSpy: jasmine.SpyObj<WebhookService>;

  const mockTenants: Tenant[] = [
    {
      id: 'tenant-fintech-us',
      name: 'FinTech US Core',
      tier: 'ENTERPRISE',
      status: 'ACTIVE',
      rateLimitRpm: 10000,
      maxIncidentsRetentionDays: 365,
      allowedIpRanges: ['0.0.0.0/0'],
      contactEmail: 'secops@fintech.us',
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z'
    },
    {
      id: 'tenant-retail-eu',
      name: 'Retail EU Online',
      tier: 'PROFESSIONAL',
      status: 'SUSPENDED',
      rateLimitRpm: 5000,
      maxIncidentsRetentionDays: 90,
      allowedIpRanges: ['10.0.0.0/8'],
      contactEmail: 'admin@retail.eu',
      createdAt: '2026-02-01T00:00:00Z',
      updatedAt: '2026-02-01T00:00:00Z'
    }
  ];

  const mockTenantPage: TenantPageResponse = {
    content: mockTenants,
    page: 0,
    size: 50,
    totalElements: 2,
    totalPages: 1
  };

  const mockWebhooks: WebhookSubscription[] = [
    {
      id: 'sub-slack-001',
      tenantId: 'tenant-fintech-us',
      name: 'SOC Slack Alerts',
      targetUrl: 'https://hooks.slack.com/services/T00/B00/X00',
      eventTypes: ['INCIDENT_CREATED', 'INCIDENT_CRITICAL'],
      enabled: true,
      createdAt: '2026-01-01T00:00:00Z',
      lastTriggeredAt: '2026-01-02T12:00:00Z',
      lastStatusCode: 200,
      successCount: 15,
      failureCount: 0
    }
  ];

  const mockDispatchResult: WebhookDispatchResult = {
    subscriptionId: 'sub-slack-001',
    targetUrl: 'https://hooks.slack.com/services/T00/B00/X00',
    statusCode: 200,
    success: true,
    message: 'Delivered HTTP 200 OK',
    latencyMs: 142,
    timestamp: new Date().toISOString()
  };

  const mockTenantUsage: TenantUsageResponse = {
    tenantId: 'tenant-fintech-us',
    tenantName: 'FinTech US Core',
    rateLimitRpm: 10000,
    currentWindowRequests: 240,
    rateLimitUtilizationPercent: 2.4,
    totalRecordedEvents: 15420,
    activeIncidentsCount: 3,
    activeCampaignsCount: 1,
    evaluatedAt: new Date().toISOString()
  };

  beforeEach(async () => {
    authServiceSpy = jasmine.createSpyObj('AuthService', ['isSecurityAdmin', 'userProfile']);
    authServiceSpy.isSecurityAdmin.and.returnValue(true);
    authServiceSpy.userProfile.and.returnValue({ username: 'admin-user', email: 'admin@aegis.dev', roles: ['SECURITY_ADMIN'] });

    tenantServiceSpy = jasmine.createSpyObj('TenantService', [
      'getTenants',
      'getTenant',
      'createTenant',
      'updateStatus',
      'updateQuotas',
      'getTenantUsage'
    ]);
    tenantServiceSpy.getTenants.and.returnValue(of(mockTenantPage));
    tenantServiceSpy.getTenantUsage.and.returnValue(of(mockTenantUsage));
    tenantServiceSpy.createTenant.and.returnValue(of(mockTenants[0]));
    tenantServiceSpy.updateStatus.and.returnValue(of({ ...mockTenants[0], status: 'SUSPENDED' }));

    webhookServiceSpy = jasmine.createSpyObj('WebhookService', [
      'getSubscriptions',
      'getSubscription',
      'createSubscription',
      'deleteSubscription',
      'triggerTest',
      'testDispatch'
    ]);
    webhookServiceSpy.getSubscriptions.and.returnValue(of(mockWebhooks));
    webhookServiceSpy.triggerTest.and.returnValue(of(mockDispatchResult));
    webhookServiceSpy.createSubscription.and.returnValue(of(mockWebhooks[0]));
    webhookServiceSpy.deleteSubscription.and.returnValue(of(void 0));

    await TestBed.configureTestingModule({
      imports: [SettingsComponent],
      providers: [
        { provide: AuthService, useValue: authServiceSpy },
        { provide: TenantService, useValue: tenantServiceSpy },
        { provide: WebhookService, useValue: webhookServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SettingsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create settings component', () => {
    expect(component).toBeTruthy();
  });

  it('should display immutable ADVISORY ONLY mode invariant in default invariants tab', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(component.activeTab).toBe('invariants');
    expect(compiled.textContent).toContain('ADVISORY ONLY');
    expect(compiled.textContent).toContain('DISABLED (BY DESIGN)');
    expect(compiled.textContent).toContain('LOG_ALERT');
  });

  it('should display Keycloak realm and S256 PKCE method', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('aegis-dev');
    expect(compiled.textContent).toContain('S256 (SHA-256)');
  });

  it('should switch to Tenant Administration tab and display tenants', () => {
    component.switchTab('tenants');
    fixture.detectChanges();

    expect(component.activeTab).toBe('tenants');
    expect(tenantServiceSpy.getTenants).toHaveBeenCalled();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('tenant-fintech-us');
    expect(compiled.textContent).toContain('FinTech US Core');
    expect(compiled.textContent).toContain('ENTERPRISE');
    expect(compiled.textContent).toContain('tenant-retail-eu');
  });

  it('should switch to Webhook Integrations tab and display webhooks', () => {
    component.switchTab('webhooks');
    fixture.detectChanges();

    expect(component.activeTab).toBe('webhooks');
    expect(webhookServiceSpy.getSubscriptions).toHaveBeenCalled();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('SOC Slack Alerts');
    expect(compiled.textContent).toContain('https://hooks.slack.com');
  });

  it('should trigger test ping on webhook and report result', () => {
    component.switchTab('webhooks');
    fixture.detectChanges();

    component.triggerWebhookTest('sub-slack-001');
    expect(webhookServiceSpy.triggerTest).toHaveBeenCalledWith('sub-slack-001');
    expect(component.testPingResult).toEqual(mockDispatchResult);
    expect(component.testPingResult?.success).toBeTrue();
  });

  it('should toggle tenant status between ACTIVE and SUSPENDED', () => {
    component.switchTab('tenants');
    fixture.detectChanges();

    const activeTenant = mockTenants[0];
    component.toggleTenantStatus(activeTenant);
    expect(tenantServiceSpy.updateStatus).toHaveBeenCalledWith(
      'tenant-fintech-us',
      jasmine.objectContaining({ status: 'SUSPENDED' })
    );
  });

  it('should inspect tenant usage and open modal', () => {
    component.inspectTenantUsage('tenant-fintech-us');
    expect(tenantServiceSpy.getTenantUsage).toHaveBeenCalledWith('tenant-fintech-us');
    expect(component.selectedTenantUsage).toEqual(mockTenantUsage);

    component.closeUsageModal();
    expect(component.selectedTenantUsage).toBeNull();
  });

  it('should open and close new tenant modal', () => {
    component.openNewTenantModal();
    expect(component.showNewTenantModal).toBeTrue();
    expect(component.newTenant.id).toBe('');

    component.closeNewTenantModal();
    expect(component.showNewTenantModal).toBeFalse();
  });

  it('should open and close new webhook modal and toggle event selections', () => {
    component.openNewWebhookModal();
    expect(component.showNewWebhookModal).toBeTrue();

    expect(component.isEventSelected('INCIDENT_CREATED')).toBeTrue();
    component.toggleEventSelection('INCIDENT_CREATED');
    expect(component.isEventSelected('INCIDENT_CREATED')).toBeFalse();

    component.toggleEventSelection('INCIDENT_CREATED');
    expect(component.isEventSelected('INCIDENT_CREATED')).toBeTrue();

    component.closeNewWebhookModal();
    expect(component.showNewWebhookModal).toBeFalse();
  });
});
