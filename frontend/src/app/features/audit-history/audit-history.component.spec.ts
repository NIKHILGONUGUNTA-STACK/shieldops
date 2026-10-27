import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { AuditHistoryComponent } from './audit-history.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('AuditHistoryComponent', () => {
  let component: AuditHistoryComponent;
  let fixture: ComponentFixture<AuditHistoryComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getIncidents', 'getIncidentHistory']);
    apiServiceSpy.getIncidents.and.returnValue(of({
      incidents: [
        {
          id: 'inc-audit-1',
          incidentFingerprint: 'FP-1',
          ruleId: 'RULE-BOLA-01',
          ruleVersion: '1.0.0',
          threatCategory: 'BOLA',
          severity: 'HIGH',
          status: 'INVESTIGATING',
          targetEntityType: 'CUSTOMER_ID',
          targetEntityValue: 'cust-1',
          firstDetectedAt: '2026-10-27T10:00:00Z',
          lastEventAt: '2026-10-27T10:05:00Z',
          eventCount: 3,
          summary: 'BOLA audit',
          createdAt: '2026-10-27T10:00:00Z',
          updatedAt: '2026-10-27T10:05:00Z'
        }
      ],
      page: 0,
      size: 25,
      totalElements: 1,
      totalPages: 1,
      first: true,
      last: true
    }));
    apiServiceSpy.getIncidentHistory.and.returnValue(of([
      {
        id: 'hist-1',
        incidentId: 'inc-audit-1',
        previousStatus: 'OPEN',
        newStatus: 'INVESTIGATING',
        changedBy: 'analyst-user',
        changeReason: 'Assigned to analyst for investigation of cross-tenant accesses',
        changedAt: '2026-10-27T10:10:00Z'
      }
    ]));

    await TestBed.configureTestingModule({
      imports: [AuditHistoryComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(AuditHistoryComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create audit history component and compile audit timeline', () => {
    expect(component).toBeTruthy();
    expect(component.historyRecords.length).toBe(1);
    expect(component.historyRecords[0].changedBy).toBe('analyst-user');
  });

  it('should render actor and transition reason in audit table', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.actor-badge')?.textContent).toContain('analyst-user');
    expect(compiled.querySelector('.reason-cell')?.textContent).toContain('Assigned to analyst');
  });
});
