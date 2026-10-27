import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/login/login.component').then(m => m.LoginComponent)
  },
  // DASHBOARD
  {
    path: 'overview',
    loadComponent: () => import('./features/overview/overview.component').then(m => m.OverviewComponent),
    canActivate: [authGuard]
  },
  // ATTACKS & INVESTIGATION
  {
    path: 'incidents',
    loadComponent: () => import('./features/incidents/incidents-list/incidents-list.component').then(m => m.IncidentsListComponent),
    canActivate: [authGuard]
  },
  {
    path: 'incidents/:id',
    loadComponent: () => import('./features/incidents/incident-detail/incident-detail.component').then(m => m.IncidentDetailComponent),
    canActivate: [authGuard]
  },
  {
    path: 'attacks',
    loadComponent: () => import('./features/attacks/attacks.component').then(m => m.AttacksComponent),
    canActivate: [authGuard]
  },
  {
    path: 'campaigns',
    loadComponent: () => import('./features/campaigns/campaigns.component').then(m => m.CampaignsComponent),
    canActivate: [authGuard]
  },
  {
    path: 'evidence',
    loadComponent: () => import('./features/evidence/evidence.component').then(m => m.EvidenceComponent),
    canActivate: [authGuard]
  },
  // API SECURITY
  {
    path: 'api-inventory',
    loadComponent: () => import('./features/api-inventory/api-inventory.component').then(m => m.ApiInventoryComponent),
    canActivate: [authGuard]
  },
  {
    path: 'events',
    loadComponent: () => import('./features/events/events.component').then(m => m.EventsComponent),
    canActivate: [authGuard]
  },
  {
    path: 'api-specs',
    loadComponent: () => import('./features/api-specs/api-specs.component').then(m => m.ApiSpecsComponent),
    canActivate: [authGuard]
  },
  {
    path: 'data-access',
    loadComponent: () => import('./features/data-access/data-access.component').then(m => m.DataAccessComponent),
    canActivate: [authGuard]
  },
  // DETECTION & RESPONSE
  {
    path: 'detection-rules',
    loadComponent: () => import('./features/detection-rules/detection-rules.component').then(m => m.DetectionRulesComponent),
    canActivate: [authGuard]
  },
  {
    path: 'bola-detection',
    loadComponent: () => import('./features/bola-detection/bola-detection.component').then(m => m.BolaDetectionComponent),
    canActivate: [authGuard]
  },
  {
    path: 'policy-decisions',
    loadComponent: () => import('./features/policy-decisions/policy-decisions.component').then(m => m.PolicyDecisionsComponent),
    canActivate: [authGuard]
  },
  // GOVERNANCE & OPERATIONS
  {
    path: 'audit-history',
    loadComponent: () => import('./features/audit-history/audit-history.component').then(m => m.AuditHistoryComponent),
    canActivate: [authGuard]
  },
  {
    path: 'system-health',
    loadComponent: () => import('./features/system-health/system-health.component').then(m => m.SystemHealthComponent),
    canActivate: [authGuard]
  },
  {
    path: 'settings',
    loadComponent: () => import('./features/settings/settings.component').then(m => m.SettingsComponent),
    canActivate: [authGuard]
  },
  // Fallbacks
  {
    path: '',
    redirectTo: '/overview',
    pathMatch: 'full'
  },
  {
    path: '**',
    redirectTo: '/overview'
  }
];
