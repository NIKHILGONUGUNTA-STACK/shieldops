import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';
import { NavbarComponent } from './navbar.component';
import { AuthService } from '../../../core/auth/auth.service';
import { LayoutService } from '../../../core/services/layout.service';
import { SocWebSocketService } from '../../../core/services/soc-websocket.service';

describe('NavbarComponent', () => {
  let component: NavbarComponent;
  let fixture: ComponentFixture<NavbarComponent>;
  let authServiceSpy: jasmine.SpyObj<AuthService>;
  let wsSpy: jasmine.SpyObj<SocWebSocketService>;
  let router: Router;

  beforeEach(async () => {
    authServiceSpy = jasmine.createSpyObj('AuthService', ['isAuthenticated', 'isSecurityAdmin', 'logout', 'userProfile']);
    authServiceSpy.isAuthenticated.and.returnValue(true);
    authServiceSpy.isSecurityAdmin.and.returnValue(false);
    authServiceSpy.userProfile.and.returnValue({ username: 'analyst-user', email: 'analyst@aegis.dev', roles: ['SECURITY_ANALYST'] });

    wsSpy = jasmine.createSpyObj('SocWebSocketService', ['dismissAlert', 'clearAllAlerts'], {
      connectionStatus$: of('CONNECTED'),
      activeAlerts$: of([{ id: '1', title: 'Live Alert', severity: 'HIGH', message: 'Test live alert', timestamp: new Date().toISOString() }]),
      notifications$: of()
    });

    await TestBed.configureTestingModule({
      imports: [NavbarComponent],
      providers: [
        provideRouter([]),
        LayoutService,
        { provide: AuthService, useValue: authServiceSpy },
        { provide: SocWebSocketService, useValue: wsSpy }
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

  it('should render clean navbar layout with search input placed first', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.brand-name')).toBeFalsy();
    expect(compiled.querySelector('.global-search-input')).toBeTruthy();
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

  it('should display real-time live stream status badge', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.stream-text')?.textContent).toContain('STREAM: LIVE');
  });

  it('should toggle live alerts popover when clicking notification bell', () => {
    expect(component.showNotifications).toBeFalse();
    component.toggleNotifications();
    expect(component.showNotifications).toBeTrue();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.notifications-dropdown')).toBeTruthy();
    expect(compiled.querySelector('.notif-item-title')?.textContent).toContain('Live Alert');
  });
});
