import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TenantService } from './tenant.service';
import { Tenant, TenantPageResponse, TenantCreateRequest } from '../models/tenant.model';

describe('TenantService', () => {
  let service: TenantService;
  let httpMock: HttpTestingController;

  const mockTenant: Tenant = {
    id: 'tenant-fintech-us',
    name: 'Fintech US Production',
    tier: 'ENTERPRISE',
    status: 'ACTIVE',
    rateLimitRpm: 10000,
    maxIncidentsRetentionDays: 365,
    allowedIpRanges: ['10.0.0.0/8'],
    contactEmail: 'admin@fintech-us.shieldops.internal',
    createdAt: '2026-11-01T00:00:00Z',
    updatedAt: '2026-11-24T00:00:00Z'
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [TenantService]
    });
    service = TestBed.inject(TenantService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should retrieve paged tenants with filters', () => {
    const mockPage: TenantPageResponse = {
      content: [mockTenant],
      page: 0,
      size: 10,
      totalElements: 1,
      totalPages: 1
    };

    service.getTenants({ page: 0, size: 10, tier: 'ENTERPRISE', status: 'ACTIVE' }).subscribe(res => {
      expect(res.content.length).toBe(1);
      expect(res.content[0].id).toBe('tenant-fintech-us');
    });

    const req = httpMock.expectOne(r => r.url === '/api/v1/admin/tenants' && r.params.get('tier') === 'ENTERPRISE');
    expect(req.request.method).toBe('GET');
    req.flush(mockPage);
  });

  it('should retrieve single tenant by ID', () => {
    service.getTenant('tenant-fintech-us').subscribe(t => {
      expect(t.name).toBe('Fintech US Production');
    });

    const req = httpMock.expectOne('/api/v1/admin/tenants/tenant-fintech-us');
    expect(req.request.method).toBe('GET');
    req.flush(mockTenant);
  });

  it('should provision a new tenant via POST', () => {
    const createReq: TenantCreateRequest = {
      id: 'tenant-neo',
      name: 'Neo Digital',
      rateLimitRpm: 5000,
      maxIncidentsRetentionDays: 90
    };

    service.createTenant(createReq).subscribe(t => {
      expect(t.id).toBe('tenant-neo');
    });

    const req = httpMock.expectOne('/api/v1/admin/tenants');
    expect(req.request.method).toBe('POST');
    req.flush({ ...mockTenant, id: 'tenant-neo', name: 'Neo Digital' });
  });

  it('should update tenant status and quotas', () => {
    service.updateStatus('tenant-fintech-us', { status: 'SUSPENDED' }).subscribe(t => {
      expect(t.status).toBe('SUSPENDED');
    });

    const req1 = httpMock.expectOne('/api/v1/admin/tenants/tenant-fintech-us/status');
    expect(req1.request.method).toBe('PATCH');
    req1.flush({ ...mockTenant, status: 'SUSPENDED' });

    service.updateQuotas('tenant-fintech-us', { rateLimitRpm: 12000, maxIncidentsRetentionDays: 180 }).subscribe(t => {
      expect(t.rateLimitRpm).toBe(12000);
    });

    const req2 = httpMock.expectOne('/api/v1/admin/tenants/tenant-fintech-us/quotas');
    expect(req2.request.method).toBe('PUT');
    req2.flush({ ...mockTenant, rateLimitRpm: 12000 });
  });

  it('should retrieve tenant usage metrics', () => {
    service.getTenantUsage('tenant-fintech-us').subscribe(u => {
      expect(u.tenantId).toBe('tenant-fintech-us');
      expect(u.rateLimitRpm).toBe(10000);
    });

    const req = httpMock.expectOne('/api/v1/admin/tenants/tenant-fintech-us/usage');
    expect(req.request.method).toBe('GET');
    req.flush({
      tenantId: 'tenant-fintech-us',
      tenantName: 'Fintech US Production',
      rateLimitRpm: 10000,
      currentWindowRequests: 540,
      rateLimitUtilizationPercent: 5.4,
      totalRecordedEvents: 12000,
      activeIncidentsCount: 2,
      activeCampaignsCount: 1,
      evaluatedAt: '2026-11-24T12:00:00Z'
    });
  });
});
