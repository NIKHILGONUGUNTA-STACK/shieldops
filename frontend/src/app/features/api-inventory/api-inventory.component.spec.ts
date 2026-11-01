import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiInventoryComponent } from './api-inventory.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import { DiscoveredEndpointPageResponse, ProblemDetail } from '../../core/models/security.models';

describe('ApiInventoryComponent', () => {
  let component: ApiInventoryComponent;
  let fixture: ComponentFixture<ApiInventoryComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockEndpointsPage: DiscoveredEndpointPageResponse = {
    content: [
      {
        id: 'ep_1',
        httpMethod: 'GET',
        routeTemplate: '/api/v1/customers/{customerId}/profile',
        serviceName: 'customer-service',
        firstObservedAt: '2026-10-28T09:00:00Z',
        lastObservedAt: '2026-10-28T10:15:00Z',
        totalRequests: 120,
        statusDistribution: { '2xx': 118, '4xx': 2, '5xx': 0 },
        distinctStatusCodes: [200, 403],
        averageLatencyMs: 32.5
      },
      {
        id: 'ep_2',
        httpMethod: 'POST',
        routeTemplate: '/api/v1/transfers',
        serviceName: 'transaction-service',
        firstObservedAt: '2026-10-28T09:30:00Z',
        lastObservedAt: '2026-10-28T10:20:00Z',
        totalRequests: 45,
        statusDistribution: { '2xx': 40, '4xx': 5, '5xx': 0 },
        distinctStatusCodes: [200, 400],
        averageLatencyMs: 65.2
      }
    ],
    page: 0,
    size: 20,
    totalElements: 2,
    totalPages: 1,
    hasNext: false,
    hasPrevious: false,
    totalObservedEndpoints: 2,
    totalObservedRequests: 165,
    totalMonitoredServices: 2
  };

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getDiscoveredEndpoints',
      'getEndpointIntelligence',
      'getEndpointObservationHistory',
      'getEndpointSecurityHistory'
    ]);
    mockSecurityApi.getDiscoveredEndpoints.and.returnValue(of(mockEndpointsPage));
    mockSecurityApi.getEndpointIntelligence.and.returnValue(of({
      endpointId: 'ep_1',
      httpMethod: 'GET',
      normalizedRoute: '/api/v1/customers/{customerId}/profile',
      serviceBoundary: 'customer-service',
      stableHash: 'hash1',
      firstObservedAt: '2026-10-28T09:00:00Z',
      lastObservedAt: '2026-10-28T10:15:00Z',
      totalRequests: 120,
      distinctStatusCodes: [200, 403],
      statusDistribution: { '2xx': 118, '4xx': 2 },
      averageLatencyMs: 32.5,
      minLatencyMs: 12.0,
      maxLatencyMs: 80.0,
      specification: null,
      reconciliation: null,
      discrepancyPrioritization: null,
      relatedIncidents: [],
      inferredService: false,
      confirmedVulnerability: false,
      telemetryWindowHours: 24
    }));
    mockSecurityApi.getEndpointObservationHistory.and.returnValue(of({
      endpointId: 'ep_1',
      httpMethod: 'GET',
      normalizedRoute: '/api/v1/customers/{customerId}/profile',
      serviceBoundary: 'customer-service',
      windowHours: 24,
      bucketIntervalMinutes: 60,
      totalRequestsInWindow: 120,
      retentionLimitHours: 720,
      windowStart: '2026-10-27T10:15:00Z',
      windowEnd: '2026-10-28T10:15:00Z',
      buckets: []
    }));
    mockSecurityApi.getEndpointSecurityHistory.and.returnValue(of({
      endpointId: 'ep_1',
      httpMethod: 'GET',
      normalizedRoute: '/api/v1/customers/{customerId}/profile',
      windowHours: 24,
      totalAuthFailures: 2,
      totalAnomalies: 0,
      totalBlocked: 0,
      confirmedVulnerability: false,
      recentSecurityEvents: [],
      linkedIncidents: []
    }));

    await TestBed.configureTestingModule({
      imports: [ApiInventoryComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(ApiInventoryComponent);
    component = fixture.componentInstance;
  });

  it('should create API inventory component', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should fetch and display discovered API endpoints on init', () => {
    fixture.detectChanges();

    expect(mockSecurityApi.getDiscoveredEndpoints).toHaveBeenCalled();
    const compiled = fixture.nativeElement as HTMLElement;

    // Check KPI stat counts
    const statValues = Array.from(compiled.querySelectorAll('.soc-stat-val')).map(el => el.textContent?.trim());
    expect(statValues[0]).toBe('2'); // Observed Endpoints
    expect(statValues[1]).toContain('165'); // Indexed Requests
    expect(statValues[2]).toBe('2'); // Backend Services

    // Check Table Rows
    const rows = compiled.querySelectorAll('.endpoint-row');
    expect(rows.length).toBe(2);

    // First Row Route & Method
    expect(rows[0].querySelector('.method-badge')?.textContent?.trim()).toBe('GET');
    expect(rows[0].querySelector('.route-template')?.textContent?.trim()).toBe('/api/v1/customers/{customerId}/profile');
    expect(rows[0].querySelector('.service-pill')?.textContent?.trim()).toBe('customer-service');

    // Second Row Route & Method
    expect(rows[1].querySelector('.method-badge')?.textContent?.trim()).toBe('POST');
    expect(rows[1].querySelector('.route-template')?.textContent?.trim()).toBe('/api/v1/transfers');
    expect(rows[1].querySelector('.service-pill')?.textContent?.trim()).toBe('transaction-service');
  });

  it('should render clean empty state when no endpoints have been observed', () => {
    const emptyPage: DiscoveredEndpointPageResponse = {
      content: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
      hasNext: false,
      hasPrevious: false,
      totalObservedEndpoints: 0,
      totalObservedRequests: 0,
      totalMonitoredServices: 0
    };
    mockSecurityApi.getDiscoveredEndpoints.and.returnValue(of(emptyPage));

    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelectorAll('.endpoint-row').length).toBe(0);
    expect(compiled.querySelector('.empty-title')?.textContent).toContain('No API Endpoints Discovered Yet');
    expect(compiled.querySelector('.empty-desc')?.textContent).toContain('automatically appear in this inventory');
  });

  it('should render error state with retry button when API fails', () => {
    const errorDetail: ProblemDetail = {
      title: 'Telemetry Store Unavailable',
      status: 503,
      detail: 'API discovery telemetry store is currently unavailable'
    };
    mockSecurityApi.getDiscoveredEndpoints.and.returnValue(throwError(() => errorDetail));

    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-banner')).toBeTruthy();
    expect(compiled.querySelector('.error-title')?.textContent).toContain('Telemetry Store Unavailable');

    // Clicking retry calls getDiscoveredEndpoints again
    mockSecurityApi.getDiscoveredEndpoints.and.returnValue(of(mockEndpointsPage));
    const retryBtn = compiled.querySelector('.error-banner button') as HTMLButtonElement;
    retryBtn.click();
    fixture.detectChanges();

    expect(mockSecurityApi.getDiscoveredEndpoints).toHaveBeenCalledTimes(2);
  });

  it('should trigger search filter when search query changes', fakeAsync(() => {
    fixture.detectChanges();

    component.searchQuery = 'transfers';
    component.onSearchChange();
    tick(300);

    expect(mockSecurityApi.getDiscoveredEndpoints).toHaveBeenCalledWith(jasmine.objectContaining({
      search: 'transfers'
    }));
  }));

  it('should filter by HTTP method when dropdown changes', () => {
    fixture.detectChanges();

    component.selectedMethod = 'POST';
    component.loadEndpoints(0);

    expect(mockSecurityApi.getDiscoveredEndpoints).toHaveBeenCalledWith(jasmine.objectContaining({
      method: 'POST'
    }));
  });

  it('should filter by service when service dropdown changes', () => {
    fixture.detectChanges();

    component.selectedService = 'customer-service';
    component.loadEndpoints(0);

    expect(mockSecurityApi.getDiscoveredEndpoints).toHaveBeenCalledWith(jasmine.objectContaining({
      service: 'customer-service'
    }));
  });

  it('should open intelligence drawer when an endpoint row is selected', () => {
    fixture.detectChanges();

    const firstRow = fixture.nativeElement.querySelector('.endpoint-row') as HTMLElement;
    firstRow.click();
    fixture.detectChanges();

    expect(mockSecurityApi.getEndpointIntelligence).toHaveBeenCalledWith('ep_1', jasmine.any(Object));
    expect(component.selectedEndpoint()?.id).toBe('ep_1');
    expect(component.intelligence()?.confirmedVulnerability).toBe(false);

    const drawer = fixture.nativeElement.querySelector('.intelligence-drawer');
    expect(drawer).toBeTruthy();
    expect(drawer.textContent).toContain('CONFIRMED VULNERABILITY: NO');
  });
});
