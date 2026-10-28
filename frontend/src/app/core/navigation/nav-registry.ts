export interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: string;
  availability: 'implemented' | 'planned';
  description: string;
  badge?: string;
}

export interface NavSection {
  id: string;
  title: string;
  items: NavItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'dashboard',
    title: 'DASHBOARD',
    items: [
      {
        id: 'overview',
        label: 'Overview',
        path: '/overview',
        icon: 'dashboard',
        availability: 'implemented',
        description: 'High-level SOC security posture, real-time threat KPIs, and recent alerts'
      }
    ]
  },
  {
    id: 'attacks',
    title: 'ATTACKS & INVESTIGATION',
    items: [
      {
        id: 'incidents',
        label: 'Incidents',
        path: '/incidents',
        icon: 'alert-triangle',
        availability: 'implemented',
        description: 'Interactive incident triage queue, server-side filtering, and status workflows'
      },
      {
        id: 'attack-activity',
        label: 'Attack Activity',
        path: '/attacks',
        icon: 'activity',
        availability: 'implemented',
        description: 'Live anomalous API event feed, top attacker source IPs, and attack vector telemetry'
      },
      {
        id: 'attack-campaigns',
        label: 'Attack Campaigns',
        path: '/campaigns',
        icon: 'git-merge',
        availability: 'implemented',
        description: 'Correlated multi-vector campaigns, multi-resource BOLA attacks, and campaign timelines'
      },
      {
        id: 'evidence-explorer',
        label: 'Evidence Explorer',
        path: '/evidence',
        icon: 'file-search',
        availability: 'implemented',
        description: 'Aggregated forensic evidence records, rule attributions, and contributing event correlation'
      }
    ]
  },
  {
    id: 'api-security',
    title: 'API SECURITY',
    items: [
      {
        id: 'api-inventory',
        label: 'API Inventory',
        path: '/api-inventory',
        icon: 'layers',
        availability: 'implemented',
        description: 'Passive endpoint discovery, runtime service cataloging, and telemetry-derived inventory'
      },
      {
        id: 'api-events',
        label: 'API Event Explorer',
        path: '/events',
        icon: 'list-filter',
        availability: 'implemented',
        description: 'Raw API gateway telemetry explorer, composite filters, and slide-in inspection drawer'
      },
      {
        id: 'api-specs',
        label: 'API Specifications',
        path: '/api-specs',
        icon: 'file-code',
        availability: 'planned',
        badge: 'PLANNED',
        description: 'OpenAPI 3.0 contract drift analysis and shadow endpoint detection (Phase 6 Roadmap)'
      },
      {
        id: 'data-access',
        label: 'Data Access Monitoring',
        path: '/data-access',
        icon: 'database',
        availability: 'implemented',
        description: 'Privacy-conscious telemetry model, token redaction, PII protection invariants, and payload inspection'
      }
    ]
  },
  {
    id: 'detection-response',
    title: 'DETECTION & RESPONSE',
    items: [
      {
        id: 'detection-rules',
        label: 'Detection Rules',
        path: '/detection-rules',
        icon: 'sliders',
        availability: 'implemented',
        description: 'Operational status, sliding windows, and trigger stats for all 6 ShieldOps detection rules'
      },
      {
        id: 'bola-detection',
        label: 'BOLA Detection',
        path: '/bola-detection',
        icon: 'shield-lock',
        availability: 'implemented',
        description: 'Dedicated Broken Object Level Authorization engine telemetry, anti-affinity isolation, and incidents'
      },
      {
        id: 'policy-decisions',
        label: 'Policy Decisions',
        path: '/policy-decisions',
        icon: 'scale',
        availability: 'implemented',
        description: 'Advisory non-blocking security decisions (LOG_ALERT) and rationale log'
      }
    ]
  },
  {
    id: 'governance-operations',
    title: 'GOVERNANCE & OPERATIONS',
    items: [
      {
        id: 'audit-history',
        label: 'Audit History',
        path: '/audit-history',
        icon: 'history',
        availability: 'implemented',
        description: 'Chronological timeline of analyst triage events and system incident lifecycle transitions'
      },
      {
        id: 'system-health',
        label: 'System Health',
        path: '/system-health',
        icon: 'cpu',
        availability: 'implemented',
        description: 'Live operational health of Gateway, Redis Stream, Postgres Flyway V3, and Keycloak tiers'
      },
      {
        id: 'settings',
        label: 'Settings',
        path: '/settings',
        icon: 'settings',
        availability: 'implemented',
        description: 'Active platform runtime parameters, Keycloak PKCE client configs, and advisory mode invariant'
      }
    ]
  }
];
