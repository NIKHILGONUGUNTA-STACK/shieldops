import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = async (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // If not yet initialized, attempt SSO check
  if (!authService.isAuthenticated()) {
    await authService.init();
  }

  if (authService.isAuthenticated()) {
    // Check role requirements if specified on route data
    const expectedRoles = route.data?.['roles'] as string[] | undefined;
    if (expectedRoles && expectedRoles.length > 0) {
      const hasRequiredRole = expectedRoles.some(role => authService.hasRole(role));
      if (!hasRequiredRole) {
        console.warn(`[Aegis AuthGuard] User lacks required roles: ${expectedRoles.join(', ')}`);
        router.navigate(['/login'], { queryParams: { error: 'insufficient_role' } });
        return false;
      }
    }
    return true;
  }

  // Not authenticated, redirect to login
  router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  return false;
};
