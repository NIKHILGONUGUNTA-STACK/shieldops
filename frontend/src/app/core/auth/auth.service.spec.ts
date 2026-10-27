import { TestBed } from '@angular/core/testing';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [AuthService]
    });
    service = TestBed.inject(AuthService);
  });

  it('should be created with unauthenticated initial state', () => {
    expect(service).toBeTruthy();
    expect(service.isAuthenticated()).toBeFalse();
    expect(service.roles().length).toBe(0);
    expect(service.isSecurityAnalyst()).toBeFalse();
    expect(service.isSecurityAdmin()).toBeFalse();
  });

  it('should correctly set simulated analyst authentication', () => {
    service.setMockAuthenticated({
      username: 'analyst',
      email: 'analyst@aegis.local',
      roles: ['SECURITY_ANALYST']
    });

    expect(service.isAuthenticated()).toBeTrue();
    expect(service.userProfile()?.username).toBe('analyst');
    expect(service.isSecurityAnalyst()).toBeTrue();
    expect(service.isSecurityAdmin()).toBeFalse();
    expect(service.hasRole('SECURITY_ANALYST')).toBeTrue();
    expect(service.hasRole('SECURITY_ADMIN')).toBeFalse();
  });

  it('should correctly set simulated admin authentication', () => {
    service.setMockAuthenticated({
      username: 'admin',
      email: 'admin@aegis.local',
      roles: ['SECURITY_ADMIN', 'SECURITY_ANALYST']
    });

    expect(service.isAuthenticated()).toBeTrue();
    expect(service.isSecurityAdmin()).toBeTrue();
    expect(service.isSecurityAnalyst()).toBeTrue();
  });
});
