import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
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
  });
});
