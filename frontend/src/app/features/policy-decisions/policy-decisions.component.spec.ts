import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { PolicyDecisionsComponent } from './policy-decisions.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('PolicyDecisionsComponent', () => {
  let component: PolicyDecisionsComponent;
  let fixture: ComponentFixture<PolicyDecisionsComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getRecentPolicyDecisions']);
    apiServiceSpy.getRecentPolicyDecisions.and.returnValue(of([
      {
        id: 'pol-1',
        incidentId: 'inc-99',
        targetEntityType: 'CUSTOMER_ID',
        targetEntityValue: 'cust-123',
        recommendedAction: 'LOG_ALERT',
        enforcementLevel: 'ADVISORY',
        reason: 'Empirical Bayesian correlation exceeded threshold 0.85',
        confidenceScore: 0.88,
        createdAt: '2026-10-27T10:00:00Z'
      }
    ]));

    await TestBed.configureTestingModule({
      imports: [PolicyDecisionsComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(PolicyDecisionsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create policy decisions component and load advisory decisions', () => {
    expect(component).toBeTruthy();
    expect(component.decisions.length).toBe(1);
    expect(component.decisions[0].recommendedAction).toBe('LOG_ALERT');
  });

  it('should display non-intrusive advisory mode banner and decision rationale', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.advisory-banner')).toBeTruthy();
    expect(compiled.querySelector('.action-pill')?.textContent).toContain('LOG_ALERT');
    expect(compiled.querySelector('.rationale-cell')?.textContent).toContain('Empirical Bayesian correlation');
  });
});
