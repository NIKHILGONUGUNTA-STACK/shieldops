/**
 * ShieldOps Security Operations Models & DTOs
 * Strictly aligned with Phase 5.2 backend response contracts.
 */

export interface SecurityOverview {
  totalEvents24h: number;
  totalAnomalies24h: number;
  activeIncidentsCount: number;
  incidentsBySeverity: Record<string, number>;
  incidentsByCategory: Record<string, number>;
  recentIncidents: IncidentSummary[];
  topRulesTriggered: RuleTriggerStat[];
  eventVolumeTrend: TimeSeriesBucket[];
}

export interface IncidentSummary {
  id: string;
  incidentFingerprint: string;
  ruleId: string;
  threatCategory: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  targetEntityValue: string;
  eventCount: number;
  firstDetectedAt: string;
  lastEventAt: string;
  summary: string;
}

export interface RuleTriggerStat {
  ruleId: string;
  count: number;
}

export interface TimeSeriesBucket {
  bucketTime: string;
  eventCount: number;
}

export type IncidentSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface IncidentResponse {
  id: string;
  incidentFingerprint: string;
  ruleId: string;
  ruleVersion: string;
  threatCategory: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  targetEntityType: string;
  targetEntityValue: string;
  firstDetectedAt: string;
  lastEventAt: string;
  eventCount: number;
  summary: string;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentPageResponse {
  incidents: IncidentResponse[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  first: boolean;
  last: boolean;
}

export interface EvidenceResponse {
  id: string;
  incidentId: string;
  ruleId: string;
  ruleVersion: string;
  evaluatedAt: string;
  confidenceScore: number;
  severity: IncidentSeverity;
  triggerCondition: string;
  distinctResourcesCount: number;
  contributingEventIds: string[];
  mitreTechnique: string;
  createdAt: string;
}

export interface IncidentStatusHistoryResponse {
  id: string;
  incidentId: string;
  previousStatus: IncidentStatus;
  newStatus: IncidentStatus;
  changedBy: string;
  changeReason: string;
  changedAt: string;
}

export interface IncidentStatusUpdateRequest {
  targetStatus: IncidentStatus;
  reason: string;
}

export interface PolicyDecisionResponse {
  id: string;
  incidentId: string;
  targetEntityType: string;
  targetEntityValue: string;
  recommendedAction: string;
  enforcementLevel: string;
  reason: string;
  confidenceScore: number;
  createdAt: string;
}

export interface SecurityEventResponse {
  id: string;
  correlationId: string;
  timestamp: string;
  httpMethod: string;
  requestUri: string;
  routePattern: string;
  statusCode: number;
  durationMs: number;
  customerId: string | null;
  subject: string | null;
  sourceIp: string;
  userAgent: string | null;
  anomalyFlags: string | null;
  resourceType: string | null;
  resourceId: string | null;
  errorCode: string | null;
}

export interface SecurityEventPageResponse {
  events: SecurityEventResponse[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  first: boolean;
  last: boolean;
}

export interface ProblemDetail {
  type?: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  timestamp?: string;
}

export interface IncidentFilterParams {
  page?: number;
  size?: number;
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  threatCategory?: string;
  sortBy?: string;
  sortField?: string;
  sortDirection?: 'asc' | 'desc';
  from?: string;
  to?: string;
}

export interface EventFilterParams {
  page?: number;
  size?: number;
  statusCode?: number;
  httpMethod?: string;
  customerId?: string;
  sourceIp?: string;
  anomalyFlags?: string;
  resourceType?: string;
  correlationId?: string;
  from?: string;
  to?: string;
}
