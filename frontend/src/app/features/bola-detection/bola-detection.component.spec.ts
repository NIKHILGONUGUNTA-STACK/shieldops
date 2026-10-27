import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { BolaDetectionComponent } from './bola-detection.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('BolaDetectionComponent', () => {
  let component: BolaDetectionComponent;
  let fixture: ComponentFixture<BolaDetectionComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getIncidents']);
    apiServiceSpy.getIncidents.and.returnValue(of({
      incidents: [
        {
          id: 'bola-inc-1',
          incidentFingerprint: 'FP-BOLA-01',
          ruleId: 'RULE-BOLA-01',
          ruleVersion: '1.0.0',
          threatCategory: 'BOLA',
          severity: 'HIGH',
          status: 'OPEN',
          targetEntityType: 'ACCOUNT_ID',
          targetEntityValue: 'acc-404',
          firstDetectedAt: '2026-10-27T10:00:00Z',
          lastEventAt: '2026-10-27T10:05:00Z',
          eventCount: 4,
          summary: 'BOLA violation across multiple financial accounts',
          createdAt: '2026-10-27T10:00:00Z',
          updatedAt: '2026-10-27T10:05:00Z'
        }
      ],
      page: 0,
      size: 20,
      totalElements: 1,
      totalPages: 1,
      first: true,
      last: true
    }));

    await TestBed.configureTestingModule({
      imports: [BolaDetectionComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(BolaDetectionComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create BOLA detection component and load BOLA incidents', () => {
    expect(component).toBeTruthy();
    expect(component.incidents.length).toBe(1);
    expect(component.incidents[0].threatCategory).toBe('BOLA');
  });

  it('should render architecture cards for Redis sliding window and anti-affinity defense', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const cards = compiled.querySelectorAll('.mech-card');
    expect(cards.length).toBe(3);
    expect(compiled.textContent).toContain('Anti-Affinity Cross-Tenant Defense');
    expect(compiled.textContent).toContain('Redis Sliding Window');
    expect(compiled.textContent).toContain('WINDOW: 300s');
  });

  it('should render authorization outcome breach distinction notice', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.bola-interpretation-banner')).toBeTruthy();
    expect(compiled.textContent).toContain('Authorization Outcome & Breach Distinction');
    expect(compiled.textContent).toContain('403 Forbidden outcome confirms unauthorized requests were rejected');
  });

  it('should render empty state when zero BOLA incidents exist', () => {
    apiServiceSpy.getIncidents.and.returnValue(of({
      incidents: [],
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
      first: true,
      last: true
    }));

    component.loadBolaIncidents();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(component.incidents.length).toBe(0);
    expect(compiled.querySelector('.empty-state')).toBeTruthy();
    expect(compiled.textContent).toContain('Zero BOLA Incidents');
  });

  it('should display error banner and zero fabricated incidents on HTTP failure', () => {
    apiServiceSpy.getIncidents.and.returnValue(throwError(() => ({
      title: 'Service Error',
      detail: 'Cannot reach incident repository',
      status: 500
    })));

    component.loadBolaIncidents();
    fixture.detectChanges();

    expect(component.error?.title).toBe('Service Error');
    expect(component.incidents.length).toBe(0);
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-banner')).toBeTruthy();
    expect(compiled.querySelector('.soc-table')).toBeNull();
  });
});
