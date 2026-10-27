import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { IncidentSeverity } from '../../../core/models/security.models';

@Component({
  selector: 'app-severity-badge',
  standalone: true,
  imports: [CommonModule],
  template: `
    <span class="badge" [ngClass]="badgeClass">
      <span class="severity-dot"></span>
      {{ severity || 'INFO' }}
    </span>
  `,
  styles: [`
    .severity-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background-color: currentColor;
      display: inline-block;
    }
  `]
})
export class SeverityBadgeComponent {
  @Input() severity: IncidentSeverity | string = 'INFO';

  get badgeClass(): string {
    const sev = (this.severity || 'INFO').toUpperCase();
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-info';
    }
  }
}
