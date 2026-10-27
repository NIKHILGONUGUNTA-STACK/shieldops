import { TestBed } from '@angular/core/testing';
import { Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { authGuard } from './auth.guard';
import { AuthService } from './auth.service';

describe('authGuard', () => {
  let authServiceSpy: jasmine.SpyObj<AuthService>;
  let routerSpy: jasmine.SpyObj<Router>;

  beforeEach(() => {
    authServiceSpy = jasmine.createSpyObj('AuthService', ['isAuthenticated', 'init', 'hasRole']);
    routerSpy = jasmine.createSpyObj('Router', ['navigate']);

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authServiceSpy },
        { provide: Router, useValue: routerSpy }
      ]
    });
  });

  it('should allow navigation when authenticated', async () => {
    authServiceSpy.isAuthenticated.and.returnValue(true);

    const route = {} as ActivatedRouteSnapshot;
    const state = { url: '/overview' } as RouterStateSnapshot;

    const result = await TestBed.runInInjectionContext(() => authGuard(route, state));
    expect(result).toBeTrue();
    expect(routerSpy.navigate).not.toHaveBeenCalled();
  });

  it('should redirect to /login when not authenticated', async () => {
    authServiceSpy.isAuthenticated.and.returnValue(false);
    authServiceSpy.init.and.returnValue(Promise.resolve(false));

    const route = {} as ActivatedRouteSnapshot;
    const state = { url: '/overview' } as RouterStateSnapshot;

    const result = await TestBed.runInInjectionContext(() => authGuard(route, state));
    expect(result).toBeFalse();
    expect(routerSpy.navigate).toHaveBeenCalledWith(['/login'], { queryParams: { returnUrl: '/overview' } });
  });

  it('should reject and redirect when user lacks required role', async () => {
    authServiceSpy.isAuthenticated.and.returnValue(true);
    authServiceSpy.hasRole.and.returnValue(false);

    const route = { data: { roles: ['SECURITY_ADMIN'] } } as unknown as ActivatedRouteSnapshot;
    const state = { url: '/overview' } as RouterStateSnapshot;

    const result = await TestBed.runInInjectionContext(() => authGuard(route, state));
    expect(result).toBeFalse();
    expect(routerSpy.navigate).toHaveBeenCalledWith(['/login'], { queryParams: { error: 'insufficient_role' } });
  });
});
