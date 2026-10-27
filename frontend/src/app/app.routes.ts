import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/login/login.component').then(m => m.LoginComponent)
  },
  {
    path: 'overview',
    loadComponent: () => import('./features/overview/overview.component').then(m => m.OverviewComponent),
    canActivate: [authGuard]
  },
  {
    path: 'events',
    loadComponent: () => import('./features/events/events.component').then(m => m.EventsComponent),
    canActivate: [authGuard]
  },
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
    path: '',
    redirectTo: '/overview',
    pathMatch: 'full'
  },
  {
    path: '**',
    redirectTo: '/overview'
  }
];
