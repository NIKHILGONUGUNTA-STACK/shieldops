import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { EventsComponent } from './events.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityEventPageResponse } from '../../core/models/security.models';

describe('EventsComponent', () => {
  let component: EventsComponent;
  let fixture: ComponentFixture<EventsComponent>;
  let apiSpy: jasmine.SpyObj<SecurityApiService>;

  const mockEventsPage: SecurityEventPageResponse = {
    events: [
      {
        id: 'evt-101',
        correlationId: 'corr-uuid-101',
        timestamp: '2026-10-27T08:00:00Z',
        httpMethod: 'GET',
        requestUri: '/api/v1/customers/10000000-0000-4000-8000-000000000002',
        routePattern: '/api/v1/customers/{id}',
        statusCode: 403,
        durationMs: 45,
        customerId: '10000000-0000-4000-8000-000000000001',
        subject: 'alex.morgan',
        sourceIp: '192.168.1.50',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        anomalyFlags: 'BOLA_VIOLATION',
        resourceType: 'CUSTOMER',
        resourceId: '10000000-0000-4000-8000-000000000002',
        errorCode: 'BOLA_CROSS_CUSTOMER_ACCESS'
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
    apiSpy = jasmine.createSpyObj('SecurityApiService', ['getEvents']);

    await TestBed.configureTestingModule({
      imports: [EventsComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiSpy }
      ]
    }).compileComponents();
  });

  it('should load events on initialization', () => {
    apiSpy.getEvents.and.returnValue(of(mockEventsPage));
    fixture = TestBed.createComponent(EventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component).toBeTruthy();
    expect(component.loading()).toBeFalse();
    expect(component.pageData()?.events.length).toBe(1);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('/api/v1/customers/10000000-0000-4000-8000-000000000002');
    expect(compiled.textContent).toContain('403');
    expect(compiled.textContent).toContain('192.168.1.50');
    expect(compiled.textContent).toContain('BOLA_VIOLATION');
  });

  it('should open and close event detail drawer when row is selected', () => {
    apiSpy.getEvents.and.returnValue(of(mockEventsPage));
    fixture = TestBed.createComponent(EventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.selectedEvent()).toBeNull();

    component.selectEvent(mockEventsPage.events[0]);
    fixture.detectChanges();

    expect(component.selectedEvent()?.id).toBe('evt-101');
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.detail-drawer')).toBeTruthy();
    expect(compiled.textContent).toContain('corr-uuid-101');
    expect(compiled.textContent).toContain('BOLA_CROSS_CUSTOMER_ACCESS');

    component.closeDrawer();
    fixture.detectChanges();

    expect(component.selectedEvent()).toBeNull();
    expect(compiled.querySelector('.detail-drawer')).toBeFalsy();
  });

  it('should filter by correlation ID', () => {
    apiSpy.getEvents.and.returnValue(of(mockEventsPage));
    fixture = TestBed.createComponent(EventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    component.filterByCorrelationId('flow-999');
    expect(component.correlationIdFilter).toBe('flow-999');
    expect(component.hasActiveFilters()).toBeTrue();
  });

  it('should display empty state when zero events match', () => {
    apiSpy.getEvents.and.returnValue(of({
      events: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
      first: true,
      last: true
    }));

    fixture = TestBed.createComponent(EventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.loading()).toBeFalse();
    expect(component.pageData()?.events.length).toBe(0);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('app-empty-state')).toBeTruthy();
    expect(compiled.textContent).toContain('Zero Matching Events');
  });

  it('should display error panel when getEvents fails', () => {
    apiSpy.getEvents.and.returnValue(throwError(() => ({
      title: 'Bad Request',
      status: 400,
      detail: 'Invalid time range: from timestamp must not be after to timestamp'
    })));

    fixture = TestBed.createComponent(EventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.loading()).toBeFalse();
    expect(component.error()?.status).toBe(400);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-panel')).toBeTruthy();
    expect(compiled.textContent).toContain('Invalid time range');
  });

  it('should reset filters when reset is called', () => {
    apiSpy.getEvents.and.returnValue(of(mockEventsPage));
    fixture = TestBed.createComponent(EventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    component.selectedStatusCode.set('403');
    component.selectedMethod.set('POST');
    component.sourceIpInput = '10.0.0.1';
    expect(component.hasActiveFilters()).toBeTrue();

    component.resetFilters();
    expect(component.selectedStatusCode()).toBe('');
    expect(component.selectedMethod()).toBe('');
    expect(component.sourceIpInput).toBe('');
    expect(component.hasActiveFilters()).toBeFalse();
  });
});
