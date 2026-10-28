import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiSpecsComponent } from './api-specs.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  ApiSpecificationResponse,
  ApiSpecificationPageResponse,
  DeclaredOperationResponse,
  ProblemDetail
} from '../../core/models/security.models';

describe('ApiSpecsComponent', () => {
  let component: ApiSpecsComponent;
  let fixture: ComponentFixture<ApiSpecsComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  const mockSpecsPage: ApiSpecificationPageResponse = {
    content: [
      {
        id: 'spec_1',
        name: 'Customer Service API',
        description: 'Customer microservice contract',
        version: '1.2.0',
        openapiVersion: '3.0.3',
        sourceFilename: 'customer-spec.json',
        format: 'JSON',
        status: 'VALID',
        operationCount: 4,
        pathCount: 2,
        validationSummary: 'Valid OpenAPI 3.0.3 specification',
        importedAt: '2026-10-28T10:00:00Z',
        importedBy: 'admin',
        contentHash: 'a1b2c3d4e5f6789012345678abcdef12'
      },
      {
        id: 'spec_2',
        name: 'Transaction Gateway API',
        description: 'Transaction microservice contract',
        version: '2.0.0',
        openapiVersion: '3.1.0',
        sourceFilename: 'tx-spec.yaml',
        format: 'YAML',
        status: 'VALID',
        operationCount: 7,
        pathCount: 4,
        validationSummary: 'Valid OpenAPI 3.1.0 specification',
        importedAt: '2026-10-28T11:30:00Z',
        importedBy: 'sec_admin',
        contentHash: 'f6e5d4c3b2a10987654321fedcba3456'
      }
    ],
    page: 0,
    size: 10,
    totalElements: 2,
    totalPages: 1,
    hasNext: false,
    hasPrevious: false,
    totalSpecifications: 2,
    totalOperations: 11
  };

  const mockOperations: DeclaredOperationResponse[] = [
    {
      id: 'op_1',
      specificationId: 'spec_1',
      httpMethod: 'GET',
      pathPattern: '/api/v1/customers/{id}',
      normalizedRoute: '/api/v1/customers/{customerId}',
      operationId: 'getCustomerById',
      summary: 'Retrieve customer details by ID',
      description: null,
      serviceBoundary: 'customer-service',
      tags: 'Customers',
      deprecated: false
    },
    {
      id: 'op_2',
      specificationId: 'spec_1',
      httpMethod: 'POST',
      pathPattern: '/api/v1/customers',
      normalizedRoute: '/api/v1/customers',
      operationId: 'createCustomer',
      summary: 'Register a new customer account',
      description: null,
      serviceBoundary: 'customer-service',
      tags: 'Customers',
      deprecated: false
    }
  ];

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getSpecifications',
      'uploadSpecification',
      'getSpecificationOperations',
      'deleteSpecification'
    ]);
    mockSecurityApi.getSpecifications.and.returnValue(of(mockSpecsPage));
    mockSecurityApi.getSpecificationOperations.and.returnValue(of(mockOperations));
    mockSecurityApi.deleteSpecification.and.returnValue(of(undefined as unknown as void));

    await TestBed.configureTestingModule({
      imports: [ApiSpecsComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(ApiSpecsComponent);
    component = fixture.componentInstance;
  });

  it('should create API specs component', () => {
    fixture.detectChanges();
    expect(component).toBeTruthy();
  });

  it('should fetch and display specifications on init with KPI stat counts', () => {
    fixture.detectChanges();

    expect(mockSecurityApi.getSpecifications).toHaveBeenCalled();
    const compiled = fixture.nativeElement as HTMLElement;

    // Check KPI stat counts
    const statValues = Array.from(compiled.querySelectorAll('.soc-stat-val')).map(el => el.textContent?.trim());
    expect(statValues[0]).toBe('2'); // Imported Specs
    expect(statValues[1]).toContain('11'); // Declared Operations
    expect(statValues[2]).toBe('2'); // Microservice Specs

    // Check Table Rows
    const rows = compiled.querySelectorAll('.spec-row');
    expect(rows.length).toBe(2);

    expect(rows[0].querySelector('.spec-title-text')?.textContent?.trim()).toBe('Customer Service API');
    expect(rows[0].querySelector('.spec-version-badge')?.textContent?.trim()).toBe('v1.2.0');
    expect(rows[0].querySelector('.format-badge')?.textContent?.trim()).toBe('JSON');
    expect(rows[0].querySelector('.oas-version-pill')?.textContent?.trim()).toBe('3.0.3');
    expect(rows[0].querySelector('.operations-count')?.textContent?.trim()).toBe('4');

    expect(rows[1].querySelector('.spec-title-text')?.textContent?.trim()).toBe('Transaction Gateway API');
    expect(rows[1].querySelector('.spec-version-badge')?.textContent?.trim()).toBe('v2.0.0');
    expect(rows[1].querySelector('.format-badge')?.textContent?.trim()).toBe('YAML');
    expect(rows[1].querySelector('.oas-version-pill')?.textContent?.trim()).toBe('3.1.0');
    expect(rows[1].querySelector('.operations-count')?.textContent?.trim()).toBe('7');
  });

  it('should render clean empty state when no specifications are imported', () => {
    const emptyPage: ApiSpecificationPageResponse = {
      content: [],
      page: 0,
      size: 10,
      totalElements: 0,
      totalPages: 0,
      hasNext: false,
      hasPrevious: false,
      totalSpecifications: 0,
      totalOperations: 0
    };
    mockSecurityApi.getSpecifications.and.returnValue(of(emptyPage));

    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.empty-title')?.textContent).toContain('No OpenAPI Specifications Imported');
    expect(compiled.querySelectorAll('.spec-row').length).toBe(0);
  });

  it('should render RFC 7807 error banner on backend failure', () => {
    const problemDetail: ProblemDetail = {
      type: 'about:blank',
      title: 'Specifications Service Unavailable',
      status: 503,
      detail: 'Failed to connect to database repository.'
    };
    mockSecurityApi.getSpecifications.and.returnValue(throwError(() => problemDetail));

    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-banner')).toBeTruthy();
    expect(compiled.querySelector('.error-title')?.textContent).toContain('Specifications Service Unavailable');
    expect(compiled.querySelector('.error-detail')?.textContent).toContain('Failed to connect to database repository.');
  });

  it('should upload a specification file and reload specifications list', () => {
    fixture.detectChanges();

    const newSpec: ApiSpecificationResponse = {
      id: 'spec_3',
      name: 'Auth Service API',
      description: null,
      version: '1.0.0',
      openapiVersion: '3.0.0',
      sourceFilename: 'auth-spec.json',
      format: 'JSON',
      status: 'VALID',
      operationCount: 5,
      pathCount: 2,
      validationSummary: 'Valid',
      importedAt: '2026-10-28T12:00:00Z',
      importedBy: 'admin',
      contentHash: 'abcdef1234567890'
    };
    mockSecurityApi.uploadSpecification.and.returnValue(of(newSpec));

    const file = new File(['{"openapi":"3.0.0"}'], 'auth-spec.json', { type: 'application/json' });
    component.uploadFile(file);

    expect(mockSecurityApi.uploadSpecification).toHaveBeenCalledWith(file);
    expect(component.uploadSuccessMessage()).toContain('Auth Service API');
    expect(component.uploadSuccessMessage()).toContain('5 declared operations');
  });

  it('should reject file exceeding 5MB without calling upload API', () => {
    fixture.detectChanges();

    // Create a 6MB dummy file
    const largeBlob = new Blob([new Uint8Array(6 * 1024 * 1024)], { type: 'application/json' });
    const largeFile = new File([largeBlob], 'huge.json', { type: 'application/json' });

    component.uploadFile(largeFile);

    expect(mockSecurityApi.uploadSpecification).not.toHaveBeenCalled();
    expect(component.uploadErrorTitle()).toBe('File Size Limit Exceeded');
    expect(component.uploadErrorMessage()).toContain('exceeds the maximum permitted size of 5 MB');
  });

  it('should reject non-OpenAPI file extensions without calling upload API', () => {
    fixture.detectChanges();

    const badFile = new File(['binary content'], 'exploit.exe', { type: 'application/octet-stream' });
    component.uploadFile(badFile);

    expect(mockSecurityApi.uploadSpecification).not.toHaveBeenCalled();
    expect(component.uploadErrorTitle()).toBe('Unsupported File Type');
    expect(component.uploadErrorMessage()).toContain('Only OpenAPI specification files with .json, .yaml, or .yml');
  });

  it('should open operations drawer and display declared operations', () => {
    fixture.detectChanges();

    const targetSpec = mockSpecsPage.content[0];
    component.openOperationsDrawer(targetSpec);
    fixture.detectChanges();

    expect(mockSecurityApi.getSpecificationOperations).toHaveBeenCalledWith('spec_1');
    expect(component.selectedSpec()).toEqual(targetSpec);
    expect(component.specOperations().length).toBe(2);

    const compiled = fixture.nativeElement as HTMLElement;
    const drawer = compiled.querySelector('.drawer-panel');
    expect(drawer).toBeTruthy();
    expect(drawer?.querySelector('.drawer-title')?.textContent?.trim()).toBe('Customer Service API');

    const opCards = drawer?.querySelectorAll('.op-card');
    expect(opCards?.length).toBe(2);
    expect(opCards?.[0].querySelector('.op-route')?.textContent?.trim()).toBe('/api/v1/customers/{id}');
    expect(opCards?.[0].querySelector('.method-badge')?.textContent?.trim()).toBe('GET');
  });

  it('should filter operations inside drawer by search query', () => {
    fixture.detectChanges();
    component.openOperationsDrawer(mockSpecsPage.content[0]);
    fixture.detectChanges();

    component.operationFilter.set('create');
    expect(component.filteredOperations().length).toBe(1);
    expect(component.filteredOperations()[0].operationId).toBe('createCustomer');

    component.operationFilter.set('nonexistent');
    expect(component.filteredOperations().length).toBe(0);
  });

  it('should delete a specification after confirmation', () => {
    fixture.detectChanges();
    spyOn(window, 'confirm').and.returnValue(true);

    const targetSpec = mockSpecsPage.content[0];
    component.deleteSpecification(targetSpec);

    expect(mockSecurityApi.deleteSpecification).toHaveBeenCalledWith('spec_1');
  });

  it('should not delete a specification if user cancels confirmation', () => {
    fixture.detectChanges();
    spyOn(window, 'confirm').and.returnValue(false);

    const targetSpec = mockSpecsPage.content[0];
    component.deleteSpecification(targetSpec);

    expect(mockSecurityApi.deleteSpecification).not.toHaveBeenCalled();
  });
});
