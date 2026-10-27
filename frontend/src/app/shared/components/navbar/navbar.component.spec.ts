import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { NavbarComponent } from './navbar.component';
import { AuthService } from '../../../core/auth/auth.service';
import { LayoutService } from '../../../core/services/layout.service';

describe('NavbarComponent', () => {
  let component: NavbarComponent;
  let fixture: ComponentFixture<NavbarComponent>;
  let authServiceSpy: jasmine.SpyObj<AuthService>;
  let router: Router;

  beforeEach(async () => {
    authServiceSpy = jasmine.createSpyObj('AuthService', ['isAuthenticated', 'isSecurityAdmin', 'logout', 'userProfile']);
    authServiceSpy.isAuthenticated.and.returnValue(true);
    authServiceSpy.isSecurityAdmin.and.returnValue(false);
    authServiceSpy.userProfile.and.returnValue({ username: 'analyst-user', email: 'analyst@aegis.dev', roles: ['SECURITY_ANALYST'] });

    await TestBed.configureTestingModule({
      imports: [NavbarComponent],
      providers: [
        provideRouter([]),
        LayoutService,
        { provide: AuthService, useValue: authServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(NavbarComponent);
    component = fixture.componentInstance;
    router = TestBed.inject(Router);
    spyOn(router, 'navigate');
    fixture.detectChanges();
  });

  it('should create the navbar component', () => {
    expect(component).toBeTruthy();
  });

  it('should display brand shield and active recon environment', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.brand-name')?.textContent).toContain('AEGIS');
    expect(compiled.querySelector('.env-pill')?.textContent).toContain('ACTIVE RECON');
  });

  it('should display Wallarm-style global search input', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const searchInput = compiled.querySelector('.global-search-input') as HTMLInputElement;
    expect(searchInput).toBeTruthy();
    expect(searchInput.placeholder).toContain('Search telemetry');
  });

  it('should navigate to events on search enter', () => {
    component.onSearch({ target: { value: 'corr-xyz-123' } });
    expect(router.navigate).toHaveBeenCalledWith(['/events'], { queryParams: { correlationId: 'corr-xyz-123' } });
  });

  it('should display ADVISORY MODE indicator', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.threat-label')?.textContent).toContain('ENGINE: ADVISORY MODE');
  });

  it('should display authenticated user details and trigger logout', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.username')?.textContent).toContain('analyst-user');
    expect(compiled.querySelector('.user-role-badge')?.textContent).toContain('ANALYST');

    const logoutBtn = compiled.querySelector('.logout-btn') as HTMLButtonElement;
    logoutBtn.click();
    expect(authServiceSpy.logout).toHaveBeenCalled();
  });
});
