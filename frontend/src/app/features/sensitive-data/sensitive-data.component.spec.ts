import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { SensitiveDataComponent } from './sensitive-data.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  SensitiveDataInventorySummary,
  SensitiveDataInventoryPageResponse,
  EndpointDataClassification,
  ProblemDetail
} from '../../core/models/security.models';

describe('SensitiveDataComponent', () => {
  let component: SensitiveDataComponent;
  let fixture: ComponentFixture<SensitiveDataComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockEndpoint: EndpointDataClassification = {
    endpointId: 'ep_cust_view',
    serviceBoundary: 'customer-service',
    httpMethod: 'GET',
    routeTemplate: '/api/v1/customers/{customerId}',
    highestSensitivity: 'CONFIDENTIAL',
    totalFields: 3,
    classifiedFieldsCount: 3,
    unclassifiedFieldsCount: 0,
    manualReviewRequiredCount: 0,
    fields: [
      {
        serviceBoundary: 'customer-service',
        httpMethod: 'GET',
        routeTemplate: '/api/v1/customers/{customerId}',
        fieldPath: 'email',
        dataClassification: 'CONFIDENTIAL',
        classificationRationale: 'Direct personally identifiable customer contact',
        approvedAccessRoles: ['ROLE_CUSTOMER', 'SECURITY_ANALYST'],
        resourceOwnershipRequirements: 'OWNER_CUSTOMER',
        schemaSource: 'OPENAPI_DECLARED',
        confidence: 'CONFIRMED',
        policyVersion: 'v1.0.0-deterministic',
        manualReviewRequired: false
      }
    ],
    lastEvaluatedAt: '2026-11-10T12:00:00Z'
  };

  const mockSummary: SensitiveDataInventorySummary = {
    totalMonitoredEndpoints: 10,
    totalDiscoveredFields: 45,
    totalClassifiedFields: 45,
    totalUnclassifiedFields: 0,
    overallCoveragePercentage: 100.0,
    totalManualReviewRequired: 0,
    sensitivityBreakdown: {
      RESTRICTED: 5,
      CONFIDENTIAL: 25,
      INTERNAL: 10,
      PUBLIC: 5
    },
    services: [
      {
        serviceBoundary: 'customer-service',
        totalEndpoints: 3,
        totalFields: 12,
        classifiedFields: 12,
        unclassifiedFields: 0,
        coveragePercentage: 100.0,
        manualReviewRequiredCount: 0,
        sensitivityBreakdown: { RESTRICTED: 0, CONFIDENTIAL: 10, INTERNAL: 2, PUBLIC: 0 }
      }
    ],
    generatedAt: '2026-11-10T12:00:00Z'
  };

  const mockPageResponse: SensitiveDataInventoryPageResponse = {
    endpoints: [mockEndpoint],
    page: 0,
    size: 20,
    totalElements: 1,
    totalPages: 1,
    first: true,
    last: true,
    summary: mockSummary
  };

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getSensitiveDataInventory',
      'getSensitiveDataSummary',
      'getEndpointClassificationDetails'
    ]);

    mockSecurityApi.getSensitiveDataInventory.and.returnValue(of(mockPageResponse));
    mockSecurityApi.getSensitiveDataSummary.and.returnValue(of(mockSummary));

    await TestBed.configureTestingModule({
      imports: [SensitiveDataComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SensitiveDataComponent);
    component = fixture.componentInstance;
  });

  it('should create and load initial summary and inventory', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
    expect(mockSecurityApi.getSensitiveDataSummary).toHaveBeenCalled();
    expect(mockSecurityApi.getSensitiveDataInventory).toHaveBeenCalled();
    expect(component.summary()?.totalMonitoredEndpoints).toBe(10);
    expect(component.endpoints().length).toBe(1);
    expect(component.endpoints()[0].endpointId).toBe('ep_cust_view');
  });

  it('should toggle endpoint dossier expansion', () => {
    fixture.detectChanges();
    expect(component.selectedEndpoint()).toBeNull();

    component.toggleEndpoint(mockEndpoint);
    expect(component.selectedEndpoint()?.endpointId).toBe('ep_cust_view');

    component.toggleEndpoint(mockEndpoint);
    expect(component.selectedEndpoint()).toBeNull();
  });

  it('should filter by sensitivity level when clicked', () => {
    fixture.detectChanges();

    component.setSensitivityFilter('RESTRICTED');
    expect(component.selectedSensitivity).toBe('RESTRICTED');
    expect(mockSecurityApi.getSensitiveDataInventory).toHaveBeenCalledWith(
      jasmine.objectContaining({ sensitivity: 'RESTRICTED' })
    );

    // Toggle off
    component.setSensitivityFilter('RESTRICTED');
    expect(component.selectedSensitivity).toBe('');
  });

  it('should filter by service boundary', () => {
    fixture.detectChanges();

    component.setServiceFilter('customer-service');
    expect(component.selectedService).toBe('customer-service');
    expect(mockSecurityApi.getSensitiveDataInventory).toHaveBeenCalledWith(
      jasmine.objectContaining({ service: 'customer-service' })
    );
  });

  it('should handle API error gracefully', () => {
    const errorProblem: ProblemDetail = {
      title: 'Service Unavailable',
      status: 503,
      detail: 'Classification service temporarily unavailable'
    };
    mockSecurityApi.getSensitiveDataInventory.and.returnValue(throwError(() => errorProblem));

    component.loadInventory(0);
    expect(component.error()?.title).toBe('Service Unavailable');
    expect(component.loading()).toBeFalse();
  });

  it('should reset filters properly', () => {
    fixture.detectChanges();
    component.searchQuery = 'email';
    component.selectedService = 'customer-service';
    component.selectedSensitivity = 'CONFIDENTIAL';
    component.manualReviewOnly = true;

    expect(component.hasActiveFilters).toBeTrue();

    component.resetFilters();

    expect(component.searchQuery).toBe('');
    expect(component.selectedService).toBe('');
    expect(component.selectedSensitivity).toBe('');
    expect(component.manualReviewOnly).toBeFalse();
    expect(component.hasActiveFilters).toBeFalse();
  });
});

