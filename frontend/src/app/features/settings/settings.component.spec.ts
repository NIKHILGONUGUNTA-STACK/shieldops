import { ComponentFixture, TestBed } from '@angular/core/testing';
import { SettingsComponent } from './settings.component';
import { AuthService } from '../../core/auth/auth.service';

describe('SettingsComponent', () => {
  let component: SettingsComponent;
  let fixture: ComponentFixture<SettingsComponent>;
  let authServiceSpy: jasmine.SpyObj<AuthService>;

  beforeEach(async () => {
    authServiceSpy = jasmine.createSpyObj('AuthService', ['isSecurityAdmin', 'userProfile']);
    authServiceSpy.isSecurityAdmin.and.returnValue(true);
    authServiceSpy.userProfile.and.returnValue({ username: 'admin-user', email: 'admin@aegis.dev', roles: ['SECURITY_ADMIN'] });

    await TestBed.configureTestingModule({
      imports: [SettingsComponent],
      providers: [
        { provide: AuthService, useValue: authServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(SettingsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create settings component', () => {
    expect(component).toBeTruthy();
  });

  it('should display immutable ADVISORY ONLY mode invariant', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('ADVISORY ONLY');
    expect(compiled.textContent).toContain('DISABLED (BY DESIGN)');
    expect(compiled.textContent).toContain('LOG_ALERT');
  });

  it('should display Keycloak realm and S256 PKCE method', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('aegis-dev');
    expect(compiled.textContent).toContain('S256 (SHA-256)');
  });
});
