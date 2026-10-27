import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { IncidentsListComponent } from './incidents-list.component';
import { SecurityApiService } from '../../../core/services/security-api.service';
import { IncidentPageResponse } from '../../../core/models/security.models';

describe('IncidentsListComponent', () => {
  let component: IncidentsListComponent;
  let fixture: ComponentFixture<IncidentsListComponent>;
  let apiSpy: jasmine.SpyObj<SecurityApiService>;

  const mockPageResponse: IncidentPageResponse = {
    incidents: [
      {
        id: 'inc-001',
        incidentFingerprint: 'fp-001',
        ruleId: 'RULE-BOLA-01',
        ruleVersion: '1.0.0',
        threatCategory: 'BOLA',
        severity: 'CRITICAL',
        status: 'OPEN',
        targetEntityType: 'CUSTOMER',
        targetEntityValue: 'cust-uuid-1',
        firstDetectedAt: '2026-10-27T08:00:00Z',
        lastEventAt: '2026-10-27T08:05:00Z',
        eventCount: 5,
        summary: 'BOLA Violation: 5 cross-customer attempts',
        createdAt: '2026-10-27T08:00:00Z',
        updatedAt: '2026-10-27T08:05:00Z'
      }
    ],
    page: 0,
    size: 20,
    totalElements: 1,
    totalPages: 1,
    first: true,
    last: true
  };

  beforeEach(async () => {
    apiSpy = jasmine.createSpyObj('SecurityApiService', ['getIncidents']);

    await TestBed.configureTestingModule({
      imports: [IncidentsListComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiSpy }
      ]
    }).compileComponents();
  });

  it('should load incidents on initialization', () => {
    apiSpy.getIncidents.and.returnValue(of(mockPageResponse));
    fixture = TestBed.createComponent(IncidentsListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component).toBeTruthy();
    expect(component.loading()).toBeFalse();
    expect(component.pageData()?.incidents.length).toBe(1);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('RULE-BOLA-01');
    expect(compiled.textContent).toContain('BOLA Violation');
    expect(compiled.textContent).toContain('cust-uuid-1');
  });

  it('should display empty state when zero incidents match filters', () => {
    apiSpy.getIncidents.and.returnValue(of({
      incidents: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
      first: true,
      last: true
    }));

    fixture = TestBed.createComponent(IncidentsListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.loading()).toBeFalse();
    expect(component.pageData()?.incidents.length).toBe(0);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('app-empty-state')).toBeTruthy();
    expect(compiled.textContent).toContain('No Incidents Match Filters');
  });

  it('should display error panel when getIncidents fails', () => {
    apiSpy.getIncidents.and.returnValue(throwError(() => ({
      title: 'Database Error',
      status: 500,
      detail: 'Failed to query incidents repository'
    })));

    fixture = TestBed.createComponent(IncidentsListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.loading()).toBeFalse();
    expect(component.error()?.status).toBe(500);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-panel')).toBeTruthy();
    expect(compiled.textContent).toContain('Failed to query incidents repository');
  });

  it('should update filters and trigger re-fetch', () => {
    apiSpy.getIncidents.and.returnValue(of(mockPageResponse));
    fixture = TestBed.createComponent(IncidentsListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    const select = fixture.nativeElement.querySelector('#statusFilter') as HTMLSelectElement;
    select.value = 'INVESTIGATING';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();

    expect(component.selectedStatus()).toBe('INVESTIGATING');
    expect(component.hasActiveFilters()).toBeTrue();
  });

  it('should reset filters when reset is called', () => {
    apiSpy.getIncidents.and.returnValue(of(mockPageResponse));
    fixture = TestBed.createComponent(IncidentsListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    component.selectedStatus.set('OPEN');
    component.selectedSeverity.set('CRITICAL');
    expect(component.hasActiveFilters()).toBeTrue();

    component.resetFilters();
    expect(component.selectedStatus()).toBe('');
    expect(component.selectedSeverity()).toBe('');
    expect(component.hasActiveFilters()).toBeFalse();
  });
});
