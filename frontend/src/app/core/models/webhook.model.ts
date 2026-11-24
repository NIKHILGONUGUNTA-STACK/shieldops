export type WebhookEventType =
  | 'INCIDENT_CREATED'
  | 'INCIDENT_STATUS_CHANGED'
  | 'INCIDENT_CRITICAL'
  | 'CAMPAIGN_ESCALATED'
  | 'POLICY_ADVISORY_TRIGGERED'
  | 'TEST_PING';

export interface WebhookSubscription {
  id: string;
  tenantId: string;
  name: string;
  targetUrl: string;
  secretToken?: string;
  eventTypes: WebhookEventType[];
  enabled: boolean;
  createdAt: string;
  lastTriggeredAt?: string;
  lastStatusCode?: number;
  successCount: number;
  failureCount: number;
}

export interface WebhookSubscriptionCreateRequest {
  tenantId?: string;
  name: string;
  targetUrl: string;
  secretToken?: string;
  eventTypes: WebhookEventType[];
}

export interface WebhookTestDispatchRequest {
  targetUrl: string;
  secretToken?: string;
  message?: string;
}

export interface WebhookDispatchResult {
  subscriptionId: string;
  targetUrl: string;
  statusCode: number;
  success: boolean;
  message: string;
  latencyMs: number;
  timestamp: string;
}
