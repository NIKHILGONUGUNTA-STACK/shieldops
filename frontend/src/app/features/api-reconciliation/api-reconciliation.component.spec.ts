import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiReconciliationComponent } from './api-reconciliation.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  ReconciliationPageResponse,
  ApiSpecificationPageResponse,
  ProblemDetail
} from '../../core/models/security.models';

describe('ApiReconciliationComponent', () => {
  let component: ApiReconciliationComponent;
  let fixture: ComponentFixture<ApiReconciliationComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockSpecsResponse: ApiSpecificationPageResponse = {
    content: [
      {
        id: 'spec_1',
        name: 'Customer API',
        description: 'Customer microservice spec',
        version: '1.0.0',
        openapiVersion: '3.0.3',
        sourceFilename: 'customer-api.json',
        format: 'JSON',
        status: 'VALID',
        operationCount: 5,
        pathCount: 3,
        validationSummary: 'Valid OpenAPI spec',
        importedAt: '2026-10-28T10:00:00Z',
        importedBy: 'admin',
        contentHash: 'abc123hash'
      }
    ],
    page: 0,
    size: 100,
    totalElements: 1,
    totalPages: 1,
    hasNext: false,
    hasPrevious: false,
    totalSpecifications: 1,
    totalOperations: 5
  };

  const mockReconciliationResponse: ReconciliationPageResponse = {
    content: [
      {
        id: 'rec_1',
        category: 'MATCHED',
        httpMethod: 'GET',
        normalizedRoute: '/api/v1/customers/{customerId}',
        pathPattern: '/api/v1/customers/{customerId}',
        serviceBoundary: 'customer-service',
        specificationId: 'spec_1',
        specificationName: 'Customer API',
        specificationVersion: '1.0.0',
        operationId: 'getCustomerById',
        totalRequests: 250,
        statusDistribution: { '2xx': 245, '4xx': 5, '5xx': 0 },
        firstObservedAt: '2026-10-28T00:00:00Z',
        lastObservedAt: '2026-10-29T10:00:00Z',
        declaredMethodsForRoute: ['GET'],
        observedMethodsForRoute: ['GET'],
        windowStart: '2026-10-28T10:00:00Z',
        windowEnd: '2026-10-29T10:00:00Z',
        explanation: 'Observed HTTP method and route match declared OpenAPI contract.'
      },
      {
        id: 'rec_2',
        category: 'OBSERVED_UNDOCUMENTED',
        httpMethod: 'POST',
        normalizedRoute: '/api/v1/internal/debug',
        pathPattern: '/api/v1/internal/debug',
        serviceBoundary: 'customer-service',
        specificationId: null,
        specificationName: null,
        specificationVersion: null,
        operationId: null,
        totalRequests: 42,
        statusDistribution: { '2xx': 42, '4xx': 0, '5xx': 0 },
        firstObservedAt: '2026-10-28T02:00:00Z',
        lastObservedAt: '2026-10-29T08:00:00Z',
        declaredMethodsForRoute: [],
        observedMethodsForRoute: ['POST'],
        windowStart: '2026-10-28T10:00:00Z',
        windowEnd: '2026-10-29T10:00:00Z',
        explanation: 'Active telemetry observed on wire but route is absent from active OpenAPI specifications.'
      },
      {
        id: 'rec_3',
        category: 'DOCUMENTED_UNOBSERVED',
        httpMethod: 'DELETE',
        normalizedRoute: '/api/v1/customers/{customerId}/delete',
        pathPattern: '/api/v1/customers/{customerId}/delete',
        serviceBoundary: 'customer-service',
        specificationId: 'spec_1',
        specificationName: 'Customer API',
        specificationVersion: '1.0.0',
        operationId: 'deleteCustomer',
        totalRequests: 0,
        statusDistribution: {},
        firstObservedAt: null,
        lastObservedAt: null,
        declaredMethodsForRoute: ['DELETE'],
        observedMethodsForRoute: [],
        windowStart: '2026-10-28T10:00:00Z',
        windowEnd: '2026-10-29T10:00:00Z',
        explanation: 'Declared in OpenAPI specification but zero telemetry observed in the past 24 hours.'
      }
    ],
    page: 0,
    size: 20,
    totalElements: 3,
    totalPages: 1,
    hasNext: false,
    hasPrevious: false,
    summary: {
      totalEvaluated: 3,
      matchedCount: 1,
      observedUndocumentedCount: 1,
      documentedUnobservedCount: 1,
      methodMismatchCount: 0,
      ambiguousCount: 0,
      coveragePercentage: 33.3,
      windowStart: '2026-10-28T10:00:00Z',
      windowEnd: '2026-10-29T10:00:00Z',
      windowHours: 24,
      specificationId: null,
      specificationName: null
    }
  };

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getSpecifications',
      'getReconciliation'
    ]);
    mockSecurityApi.getSpecifications.and.returnValue(of(mockSpecsResponse));
    mockSecurityApi.getReconciliation.and.returnValue(of(mockReconciliationResponse));

    await TestBed.configureTestingModule({
      imports: [ApiReconciliationComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(ApiReconciliationComponent);
    component = fixture.componentInstance;
  });

  it('should create API reconciliation component', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should fetch and display reconciliation items and KPI metrics on init', () => {
    fixture.detectChanges();

    expect(mockSecurityApi.getSpecifications).toHaveBeenCalledWith({ page: 0, size: 100 });
    expect(mockSecurityApi.getReconciliation).toHaveBeenCalledWith(jasmine.objectContaining({
      page: 0,
      size: 20,
      windowHours: 24
    }));

    const compiled = fixture.nativeElement as HTMLElement;

    // Check KPI summary card values
    const summaryValues = Array.from(compiled.querySelectorAll('.summary-val')).map(el => el.textContent?.trim());
    expect(summaryValues[0]).toBe('3');      // Total Evaluated
    expect(summaryValues[1]).toBe('1');      // Matched
    expect(summaryValues[2]).toBe('1');      // Observed Undocumented
    expect(summaryValues[3]).toBe('1');      // Documented Unobserved
    expect(summaryValues[4]).toBe('0');      // Method Mismatch
    expect(summaryValues[5]).toBe('33.3%');  // Contract Coverage

    // Check Table Rows
    const rows = compiled.querySelectorAll('.recon-row');
    expect(rows.length).toBe(3);

    // Row 1: Matched GET /api/v1/customers/{customerId}
    expect(rows[0].querySelector('.method-badge')?.textContent?.trim()).toBe('GET');
    expect(rows[0].querySelector('.route-template')?.textContent?.trim()).toBe('/api/v1/customers/{customerId}');
    expect(rows[0].querySelector('.op-id-tag')?.textContent?.trim()).toBe('getCustomerById');
    expect(rows[0].querySelector('.category-chip')?.textContent?.trim()).toContain('Matched');
    expect(rows[0].querySelector('.service-pill')?.textContent?.trim()).toBe('customer-service');
    expect(rows[0].querySelector('.spec-name-tag')?.textContent?.trim()).toBe('Customer API');

    // Row 2: Undocumented POST /api/v1/internal/debug
    expect(rows[1].querySelector('.method-badge')?.textContent?.trim()).toBe('POST');
    expect(rows[1].querySelector('.route-template')?.textContent?.trim()).toBe('/api/v1/internal/debug');
    expect(rows[1].querySelector('.category-chip')?.textContent?.trim()).toContain('Undocumented');
    expect(rows[1].querySelector('.unspec-text')?.textContent?.trim()).toBe('None (Undocumented)');

    // Row 3: Unobserved DELETE /api/v1/customers/{customerId}/delete
    expect(rows[2].querySelector('.method-badge')?.textContent?.trim()).toBe('DELETE');
    expect(rows[2].querySelector('.category-chip')?.textContent?.trim()).toContain('Unobserved');
    expect(rows[2].querySelector('.zero-traffic')?.textContent?.trim()).toBe('0 requests');
  });

  it('should render empty state when no items match filters', () => {
    const emptyResponse: ReconciliationPageResponse = {
      content: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
      hasNext: false,
      hasPrevious: false,
      summary: {
        totalEvaluated: 0,
        matchedCount: 0,
        observedUndocumentedCount: 0,
        documentedUnobservedCount: 0,
        methodMismatchCount: 0,
        ambiguousCount: 0,
        coveragePercentage: 0.0,
        windowStart: '2026-10-28T10:00:00Z',
        windowEnd: '2026-10-29T10:00:00Z',
        windowHours: 24,
        specificationId: null,
        specificationName: null
      }
    };
    mockSecurityApi.getReconciliation.and.returnValue(of(emptyResponse));

    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.empty-state-wrapper')).toBeTruthy();
    expect(compiled.textContent).toContain('No Reconciled Operations Match Filters');
  });

  it('should render RFC 7807 error banner on backend failure and retry on button click', () => {
    const problemDetail: ProblemDetail = {
      type: 'https://api.aegis.shieldops.io/errors/reconciliation-failed',
      title: 'Reconciliation Engine Failure',
      status: 503,
      detail: 'Database connection timed out during telemetry aggregation'
    };
    mockSecurityApi.getReconciliation.and.returnValue(throwError(() => problemDetail));

    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-banner')).toBeTruthy();
    expect(compiled.textContent).toContain('Reconciliation Engine Failure');
    expect(compiled.textContent).toContain('Database connection timed out during telemetry aggregation');

    // Test retry
    mockSecurityApi.getReconciliation.and.returnValue(of(mockReconciliationResponse));
    const retryBtn = compiled.querySelector('.error-banner button') as HTMLButtonElement;
    retryBtn.click();
    fixture.detectChanges();

    expect(compiled.querySelector('.error-banner')).toBeFalsy();
    expect(compiled.querySelectorAll('.recon-row').length).toBe(3);
  });

  it('should update category filter and reload data when KPI summary card is clicked', () => {
    fixture.detectChanges();

    // Click "Observed Undocumented" card
    component.setCategoryFilter('OBSERVED_UNDOCUMENTED');
    fixture.detectChanges();

    expect(component.selectedCategory).toBe('OBSERVED_UNDOCUMENTED');
    expect(mockSecurityApi.getReconciliation).toHaveBeenCalledWith(jasmine.objectContaining({
      category: 'OBSERVED_UNDOCUMENTED',
      page: 0
    }));
  });

  it('should reload data when observation window is changed', () => {
    fixture.detectChanges();

    component.selectedWindowHours = 168; // 7 days
    component.loadReconciliation(0);
    fixture.detectChanges();

    expect(mockSecurityApi.getReconciliation).toHaveBeenCalledWith(jasmine.objectContaining({
      windowHours: 168,
      page: 0
    }));
  });

  it('should search query change reload data', fakeAsync(() => {
    fixture.detectChanges();

    component.searchQuery = 'customer';
    component.onSearchChange();
    tick();

    expect(mockSecurityApi.getReconciliation).toHaveBeenCalledWith(jasmine.objectContaining({
      search: 'customer',
      page: 0
    }));
  }));

  it('should format category names and styling classes correctly', () => {
    expect(component.formatCategory('MATCHED')).toBe('Matched');
    expect(component.formatCategory('OBSERVED_UNDOCUMENTED')).toBe('Undocumented');
    expect(component.formatCategory('DOCUMENTED_UNOBSERVED')).toBe('Unobserved');
    expect(component.formatCategory('METHOD_MISMATCH')).toBe('Method Mismatch');
    expect(component.formatCategory('AMBIGUOUS')).toBe('Ambiguous');

    expect(component.getCategoryClass('MATCHED')).toBe('cat-matched');
    expect(component.getCategoryClass('OBSERVED_UNDOCUMENTED')).toBe('cat-undocumented');
    expect(component.getCategoryClass('DOCUMENTED_UNOBSERVED')).toBe('cat-unobserved');
    expect(component.getCategoryClass('METHOD_MISMATCH')).toBe('cat-mismatch');
    expect(component.getCategoryClass('AMBIGUOUS')).toBe('cat-ambiguous');

    expect(component.getServiceClass('customer-service')).toBe('service-customer');
    expect(component.getServiceClass('account-service')).toBe('service-account');
    expect(component.getServiceClass('transaction-service')).toBe('service-transaction');
    expect(component.getServiceClass('unknown-service')).toBe('service-default');
  });

  it('should handle pagination next and previous clicks', () => {
    const multiPageResponse: ReconciliationPageResponse = {
      ...mockReconciliationResponse,
      page: 0,
      totalPages: 3,
      hasNext: true,
      hasPrevious: false
    };
    mockSecurityApi.getReconciliation.and.returnValue(of(multiPageResponse));

    fixture.detectChanges();

    expect(component.hasNext()).toBeTrue();
    expect(component.hasPrevious()).toBeFalse();

    // Next page
    component.loadReconciliation(1);
    expect(mockSecurityApi.getReconciliation).toHaveBeenCalledWith(jasmine.objectContaining({
      page: 1
    }));
  });
});
