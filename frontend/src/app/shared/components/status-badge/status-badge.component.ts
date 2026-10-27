import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IncidentStatus } from '../../../core/models/security.models';

@Component({
  selector: 'app-status-badge',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span class="badge" [ngClass]="badgeClass">
      {{ formattedStatus }}
    </span>
  `
})
export class StatusBadgeComponent {
  @Input() status: IncidentStatus | string = 'OPEN';

  get formattedStatus(): string {
    return (this.status || 'OPEN').replace('_', ' ');
  }

  get badgeClass(): string {
    const s = (this.status || 'OPEN').toUpperCase();
    switch (s) {
      case 'OPEN': return 'badge-open';
      case 'INVESTIGATING': return 'badge-investigating';
      case 'CONTAINED': return 'badge-contained';
      case 'RESOLVED': return 'badge-resolved';
      case 'FALSE_POSITIVE': return 'badge-false-positive';
      default: return 'badge-open';
    }
  }
}
