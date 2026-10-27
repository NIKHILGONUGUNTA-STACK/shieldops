import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { SystemHealthComponent } from './system-health.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('SystemHealthComponent', () => {
  let component: SystemHealthComponent;
  let fixture: ComponentFixture<SystemHealthComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getSystemHealth']);
    apiServiceSpy.getSystemHealth.and.returnValue(of({
      status: 'UP',
      groups: ['liveness', 'readiness']
    }));

    await TestBed.configureTestingModule({
      imports: [SystemHealthComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SystemHealthComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create system health component and query /actuator/health', () => {
    expect(component).toBeTruthy();
    expect(component.overallStatus).toBe('UP');
    expect(component.tiers.length).toBe(4);
  });

  it('should render all 4 platform tiers (Gateway, Redis, Postgres, Keycloak)', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const tierCards = compiled.querySelectorAll('.tier-card');
    expect(tierCards.length).toBe(4);
    expect(compiled.textContent).toContain('Aegis Gateway');
    expect(compiled.textContent).toContain('Redis 7 Engine');
    expect(compiled.textContent).toContain('PostgreSQL 17 Tier');
    expect(compiled.textContent).toContain('Keycloak 26 IAM');
  });
});
