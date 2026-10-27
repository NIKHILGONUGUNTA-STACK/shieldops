import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { EvidenceComponent } from './evidence.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('EvidenceComponent', () => {
  let component: EvidenceComponent;
  let fixture: ComponentFixture<EvidenceComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getIncidents', 'getIncidentEvidence']);
    apiServiceSpy.getIncidents.and.returnValue(of({
      incidents: [
        {
          id: 'inc-100',
          incidentFingerprint: 'FP-1',
          ruleId: 'RULE-BOLA-01',
          ruleVersion: '1.0.0',
          threatCategory: 'BOLA',
          severity: 'HIGH',
          status: 'OPEN',
          targetEntityType: 'CUSTOMER_ID',
          targetEntityValue: 'cust-1',
          firstDetectedAt: '2026-10-27T10:00:00Z',
          lastEventAt: '2026-10-27T10:05:00Z',
          eventCount: 3,
          summary: 'BOLA Violation',
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
    apiServiceSpy.getIncidentEvidence.and.returnValue(of([
      {
        id: 'evid-1',
        incidentId: 'inc-100',
        ruleId: 'RULE-BOLA-01',
        ruleVersion: '1.0.0',
        evaluatedAt: '2026-10-27T10:00:00Z',
        confidenceScore: 0.92,
        severity: 'HIGH',
        triggerCondition: 'Cross-tenant access to 3 customer records',
        distinctResourcesCount: 3,
        contributingEventIds: ['evt-1', 'evt-2'],
        mitreTechnique: 'T1078.004',
        createdAt: '2026-10-27T10:00:00Z'
      }
    ]));

    await TestBed.configureTestingModule({
      imports: [EvidenceComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(EvidenceComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create evidence component and load evidence records', () => {
    expect(component).toBeTruthy();
    expect(component.evidenceList.length).toBe(1);
    expect(component.evidenceList[0].ruleId).toBe('RULE-BOLA-01');
  });

  it('should display heuristic confidence and trigger conditions', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.rule-id-pill')?.textContent).toContain('RULE-BOLA-01');
    expect(compiled.querySelector('.confidence-val')?.textContent).toContain('92%');
    expect(compiled.querySelector('.condition-cell')?.textContent).toContain('Cross-tenant access');
  });
});
