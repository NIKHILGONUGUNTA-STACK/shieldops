import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { OverviewComponent } from './overview.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import { SecurityOverview } from '../../core/models/security.models';

describe('OverviewComponent', () => {
  let component: OverviewComponent;
  let fixture: ComponentFixture<OverviewComponent>;
  let apiSpy: jasmine.SpyObj<SecurityApiService>;

  const mockOverviewData: SecurityOverview = {
    totalEvents24h: 5400,
    totalAnomalies24h: 312,
    activeIncidentsCount: 4,
    incidentsBySeverity: { CRITICAL: 1, HIGH: 2, MEDIUM: 1 },
    incidentsByCategory: { BOLA: 3, RECON_PROBE: 1 },
    recentIncidents: [
      {
        id: 'inc-001',
        incidentFingerprint: 'fp-001',
        ruleId: 'RULE-BOLA-01',
        threatCategory: 'BOLA',
        severity: 'HIGH',
        status: 'OPEN',
        targetEntityValue: '10000000-0000-4000-8000-000000000001',
        eventCount: 3,
        firstDetectedAt: '2026-10-27T08:00:00Z',
        lastEventAt: '2026-10-27T08:02:00Z',
        summary: 'BOLA Violation: 3 unauthorized attempts'
      }
    ],
    topRulesTriggered: [{ ruleId: 'RULE-BOLA-01', count: 12 }],
    eventVolumeTrend: [{ bucketTime: '2026-10-27T08:00:00Z', eventCount: 45 }]
  };

  beforeEach(async () => {
    apiSpy = jasmine.createSpyObj('SecurityApiService', ['getOverview']);

    await TestBed.configureTestingModule({
      imports: [OverviewComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiSpy }
      ]
    }).compileComponents();
  });

  it('should create and load overview data on initialization', () => {
    apiSpy.getOverview.and.returnValue(of(mockOverviewData));
    fixture = TestBed.createComponent(OverviewComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component).toBeTruthy();
    expect(component.loading()).toBeFalse();
    expect(component.overview()?.totalEvents24h).toBe(5400);
    expect(component.overview()?.activeIncidentsCount).toBe(4);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.kpi-strip')).toBeTruthy();
    expect(compiled.textContent).toContain('5,400');
    expect(compiled.textContent).toContain('312');
  });

  it('should display error panel when overview API call fails', () => {
    apiSpy.getOverview.and.returnValue(throwError(() => ({
      title: 'Service Unavailable',
      status: 503,
      detail: 'Telemetry database connection timeout'
    })));

    fixture = TestBed.createComponent(OverviewComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(component.loading()).toBeFalse();
    expect(component.error()?.status).toBe(503);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-panel')).toBeTruthy();
    expect(compiled.textContent).toContain('Telemetry database connection timeout');
  });

  it('should reload data when time window changes', () => {
    apiSpy.getOverview.and.returnValue(of(mockOverviewData));
    fixture = TestBed.createComponent(OverviewComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();

    expect(apiSpy.getOverview).toHaveBeenCalledWith(24);

    const select = fixture.nativeElement.querySelector('#windowHoursSelect') as HTMLSelectElement;
    select.value = '48';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();

    expect(component.selectedWindow()).toBe(48);
    expect(apiSpy.getOverview).toHaveBeenCalledWith(48);
  });
});
