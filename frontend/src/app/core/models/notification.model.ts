export interface SocRealtimeNotification {
  id: string;
  type: 'INCIDENT_ALERT' | 'CAMPAIGN_ESCALATION' | 'POLICY_ADVISORY' | 'BURST_INGESTION' | 'SYSTEM_HEALTH' | string;
  title: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  entityId: string;
  entityType: 'INCIDENT' | 'CAMPAIGN' | 'POLICY' | 'SIMULATION' | 'SYSTEM' | string;
  timestamp: string;
}

export type WebSocketConnectionStatus = 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED';
