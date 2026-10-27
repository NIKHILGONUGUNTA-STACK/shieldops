import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { CampaignsComponent } from './campaigns.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('CampaignsComponent', () => {
  let component: CampaignsComponent;
  let fixture: ComponentFixture<CampaignsComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getIncidents']);
    apiServiceSpy.getIncidents.and.returnValue(of({
      incidents: [
        {
          id: 'camp-1',
          incidentFingerprint: 'FP-CAMPAIGN-001',
          ruleId: 'RULE-BOLA-01',
          ruleVersion: '1.0.0',
          threatCategory: 'MULTI_VECTOR_CAMPAIGN',
          severity: 'CRITICAL',
          status: 'OPEN',
          targetEntityType: 'CUSTOMER_ID',
          targetEntityValue: 'cust-999',
          firstDetectedAt: '2026-10-27T10:00:00Z',
          lastEventAt: '2026-10-27T10:05:00Z',
          eventCount: 25,
          summary: 'Multi-Vector Escalation across Account and Transfer APIs',
          createdAt: '2026-10-27T10:00:00Z',
          updatedAt: '2026-10-27T10:05:00Z'
        }
      ],
      page: 0,
      size: 50,
      totalElements: 1,
      totalPages: 1,
      first: true,
      last: true
    }));

    await TestBed.configureTestingModule({
      imports: [CampaignsComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(CampaignsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create campaigns component and load correlated campaigns', () => {
    expect(component).toBeTruthy();
    expect(component.campaigns.length).toBe(1);
    expect(component.campaigns[0].threatCategory).toBe('MULTI_VECTOR_CAMPAIGN');
  });

  it('should render campaign row with link to incident detail', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.campaign-title-link')?.textContent).toContain('Multi-Vector Escalation');
    expect(compiled.querySelector('.category-chip')?.textContent).toContain('MULTI_VECTOR_CAMPAIGN');
  });
});
