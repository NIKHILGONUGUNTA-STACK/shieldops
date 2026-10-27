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

  it('should strictly filter out non-campaign single-vector incidents', () => {
    apiServiceSpy.getIncidents.and.returnValue(of({
      incidents: [
        {
          id: 'single-inc-1',
          incidentFingerprint: 'FP-SINGLE-01',
          ruleId: 'RULE-RATE-01',
          ruleVersion: '1.0.0',
          threatCategory: 'RATE_LIMIT_ABUSE',
          severity: 'MEDIUM',
          status: 'OPEN',
          targetEntityType: 'IP_ADDRESS',
          targetEntityValue: '198.51.100.4',
          firstDetectedAt: '2026-10-27T10:00:00Z',
          lastEventAt: '2026-10-27T10:05:00Z',
          eventCount: 1,
          summary: 'Single rate limit breach',
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

    component.loadCampaigns();
    fixture.detectChanges();

    expect(component.campaigns.length).toBe(0);
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.empty-state')).toBeTruthy();
    expect(compiled.textContent).toContain('No Correlated Campaigns Detected');
  });

  it('should display error banner and zero fabricated campaigns on HTTP failure', () => {
    apiServiceSpy.getIncidents.and.returnValue(throwError(() => ({
      title: 'Database Unreachable',
      detail: 'Cannot query incident table',
      status: 503
    })));

    component.loadCampaigns();
    fixture.detectChanges();

    expect(component.error?.title).toBe('Database Unreachable');
    expect(component.campaigns.length).toBe(0);
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error-banner')).toBeTruthy();
    expect(compiled.querySelector('.soc-table')).toBeNull();
  });
});
