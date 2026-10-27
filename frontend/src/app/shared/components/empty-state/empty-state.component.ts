import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-empty-state',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="empty-state-box">
      <div class="empty-icon">🛡️</div>
      <h3 class="empty-title">{{ title }}</h3>
      <p class="empty-message">{{ message }}</p>
    </div>
  `,
  styles: [`
    .empty-state-box {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: var(--space-8);
      background: var(--bg-card);
      border: 1px dashed var(--border-default);
      border-radius: var(--radius-md);
      text-align: center;
      gap: var(--space-2);
    }
    .empty-icon {
      font-size: 28px;
      margin-bottom: var(--space-2);
      opacity: 0.8;
    }
    .empty-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .empty-message {
      font-size: 13px;
      color: var(--text-muted);
      max-width: 400px;
    }
  `]
})
export class EmptyStateComponent {
  @Input() title = 'No Data Available';
  @Input() message = 'No matching security records found in the evaluated time window.';
}
