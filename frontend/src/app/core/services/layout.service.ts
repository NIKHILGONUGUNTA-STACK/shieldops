import { Injectable, signal } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class LayoutService {
  /**
   * Tracks whether the persistent desktop sidebar is in compact/collapsed (icon-only) mode.
   */
  readonly isSidebarCollapsed = signal<boolean>(false);

  /**
   * Tracks whether the mobile off-canvas drawer is currently open.
   */
  readonly isMobileOpen = signal<boolean>(false);

  toggleSidebar(): void {
    this.isSidebarCollapsed.update(val => !val);
  }

  toggleMobile(): void {
    this.isMobileOpen.update(val => !val);
  }

  closeMobile(): void {
    this.isMobileOpen.set(false);
  }
}
