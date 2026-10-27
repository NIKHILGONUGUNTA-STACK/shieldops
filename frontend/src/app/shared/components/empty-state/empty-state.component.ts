import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-empty-state',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="empty-state-box">
      <div class="empty-icon">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <polyline points="9 12 11 14 15 10"></polyline>
        </svg>
      </div>
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
