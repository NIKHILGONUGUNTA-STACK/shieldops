import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { AttacksComponent } from './attacks.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('AttacksComponent', () => {
  let component: AttacksComponent;
  let fixture: ComponentFixture<AttacksComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getEvents', 'getOverview']);
    apiServiceSpy.getEvents.and.returnValue(of({
      events: [
        {
          id: 'ev-1',
          correlationId: 'corr-1',
          timestamp: '2026-10-27T10:00:00Z',
          httpMethod: 'POST',
          requestUri: '/api/v1/customers/101',
          routePattern: '/customers/**',
          statusCode: 403,
          durationMs: 45,
          customerId: 'cust-101',
          subject: 'sub-1',
          sourceIp: '198.51.100.12',
          userAgent: 'Mozilla/5.0',
          anomalyFlags: 'BOLA_ATTEMPT',
          resourceType: 'CUSTOMER',
          resourceId: '101',
          errorCode: null
        }
      ],
      page: 0,
      size: 50,
      totalElements: 1,
      totalPages: 1,
      first: true,
      last: true
    }));
    apiServiceSpy.getOverview.and.returnValue(of({
      totalEvents24h: 100,
      totalAnomalies24h: 12,
      activeIncidentsCount: 2,
      incidentsBySeverity: {},
      incidentsByCategory: {},
      recentIncidents: [],
      topRulesTriggered: [],
      eventVolumeTrend: []
    }));

    await TestBed.configureTestingModule({
      imports: [AttacksComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(AttacksComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create attacks component and load attack activity', () => {
    expect(component).toBeTruthy();
    expect(component.events.length).toBe(1);
    expect(component.getUniqueIpsCount()).toBe(1);
  });

  it('should render attack events in table', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.uri-cell')?.textContent).toContain('/api/v1/customers/101');
    expect(compiled.querySelector('.anomaly-pill')?.textContent).toContain('BOLA_ATTEMPT');
  });

  it('should handle API errors with problem detail banner', () => {
    apiServiceSpy.getEvents.and.returnValue(throwError(() => ({
      title: 'Service Unavailable',
      detail: 'Telemetry engine down',
      status: 503
    })));

    component.loadAttackActivity();
    fixture.detectChanges();

    expect(component.error?.title).toBe('Service Unavailable');
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-banner')).toBeTruthy();
  });
});
