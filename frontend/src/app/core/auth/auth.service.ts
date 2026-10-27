import { Injectable, signal, computed } from '@angular/core';
import Keycloak from 'keycloak-js';
import { environment } from '../../../environments/environment';

export interface UserProfile {
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  roles: string[];
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private keycloak: Keycloak | null = null;
  private isInitialized = false;

  readonly isAuthenticated = signal<boolean>(false);
  readonly userProfile = signal<UserProfile | null>(null);
  readonly roles = signal<string[]>([]);
  readonly isSecurityAnalyst = computed(() => this.roles().includes('SECURITY_ANALYST'));
  readonly isSecurityAdmin = computed(() => this.roles().includes('SECURITY_ADMIN'));

  constructor() {
    this.initKeycloakInstance();
  }

  private initKeycloakInstance(): void {
    if (typeof window !== 'undefined') {
      this.keycloak = new Keycloak({
        url: environment.keycloak.url,
        realm: environment.keycloak.realm,
        clientId: environment.keycloak.clientId
      });
    }
  }

  async init(): Promise<boolean> {
    if (this.isInitialized) {
      return this.isAuthenticated();
    }

    if (!this.keycloak) {
      return false;
    }

    try {
      const authenticated = await this.keycloak.init({
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri: `${window.location.origin}/assets/silent-check-sso.html`,
        pkceMethod: 'S256',
        checkLoginIframe: false,
        enableLogging: false
      });

      this.isInitialized = true;
      this.isAuthenticated.set(authenticated);

      if (authenticated) {
        this.extractUserDetails();
      }

      return authenticated;
    } catch (err) {
      console.warn('[Aegis Auth] Keycloak SSO initialization skipped or unavailable:', err);
      this.isInitialized = true;
      this.isAuthenticated.set(false);
      return false;
    }
  }

  private extractUserDetails(): void {
    if (!this.keycloak) return;

    const tokenParsed = this.keycloak.tokenParsed as any;
    const realmRoles: string[] = tokenParsed?.realm_access?.roles || [];
    this.roles.set(realmRoles);

    const profile: UserProfile = {
      username: tokenParsed?.preferred_username || tokenParsed?.sub || 'analyst',
      email: tokenParsed?.email,
      firstName: tokenParsed?.given_name,
      lastName: tokenParsed?.family_name,
      roles: realmRoles
    };
    this.userProfile.set(profile);
  }

  async login(redirectUri?: string): Promise<void> {
    if (!this.keycloak) return;
    await this.keycloak.login({
      redirectUri: redirectUri || `${window.location.origin}/overview`
    });
  }

  async logout(): Promise<void> {
    if (!this.keycloak) return;
    this.isAuthenticated.set(false);
    this.userProfile.set(null);
    this.roles.set([]);
    await this.keycloak.logout({
      redirectUri: `${window.location.origin}/login`
    });
  }

  async getToken(): Promise<string | null> {
    if (!this.keycloak || !this.keycloak.token) {
      return null;
    }

    try {
      // Refresh token if expiring within 30 seconds
      await this.keycloak.updateToken(30);
      return this.keycloak.token || null;
    } catch {
      console.warn('[Aegis Auth] Token refresh failed; re-authentication required.');
      return null;
    }
  }

  hasRole(role: string): boolean {
    return this.roles().includes(role);
  }

  /**
   * For integration testing or offline demonstration fallback when Keycloak redirect cannot occur
   */
  setMockAuthenticated(profile: UserProfile, mockToken = 'mock-bearer-token'): void {
    this.isAuthenticated.set(true);
    this.userProfile.set(profile);
    this.roles.set(profile.roles);
  }
}
