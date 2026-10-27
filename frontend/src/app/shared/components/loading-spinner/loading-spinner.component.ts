import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-loading-spinner',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="spinner-container">
      <div class="soc-spinner"></div>
      <span class="spinner-text">{{ message }}</span>
    </div>
  `,
  styles: [`
    .spinner-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: var(--space-8);
      gap: var(--space-3);
    }
    .soc-spinner {
      width: 28px;
      height: 28px;
      border: 3px solid var(--border-subtle);
      border-top-color: var(--accent-teal);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    .spinner-text {
      font-size: 13px;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      letter-spacing: 0.02em;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  `]
})
export class LoadingSpinnerComponent {
  @Input() message = 'Aggregating security telemetry...';
}
