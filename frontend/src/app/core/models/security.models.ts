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

export interface DiscoveredEndpointResponse {
  id: string;
  httpMethod: string;
  routeTemplate: string;
  serviceName: string;
  firstObservedAt: string;
  lastObservedAt: string;
  totalRequests: number;
  statusDistribution: { [key: string]: number };
  distinctStatusCodes: number[];
  averageLatencyMs: number | null;
}

export interface DiscoveredEndpointPageResponse {
  content: DiscoveredEndpointResponse[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
  totalObservedEndpoints: number;
  totalObservedRequests: number;
  totalMonitoredServices: number;
}

export interface EndpointFilterParams {
  page?: number;
  size?: number;
  method?: string;
  service?: string;
  search?: string;
  sortBy?: string;
  sortDirection?: 'ASC' | 'DESC' | 'asc' | 'desc';
}

export interface DeclaredOperationResponse {
  id: string;
  specificationId: string;
  httpMethod: string;
  pathPattern: string;
  normalizedRoute: string;
  operationId: string | null;
  summary: string | null;
  description: string | null;
  tags: string | null;
  deprecated: boolean;
  serviceBoundary: string;
}

export interface ApiSpecificationResponse {
  id: string;
  name: string;
  description: string | null;
  version: string;
  revisionNumber?: number;
  openapiVersion: string;
  sourceFilename: string;
  contentHash: string;
  format: 'JSON' | 'YAML' | string;
  status: string;
  importedAt: string;
  importedBy: string;
  operationCount: number;
  pathCount: number;
  validationSummary: string;
  operations?: DeclaredOperationResponse[];
}

export interface ApiSpecificationPageResponse {
  content: ApiSpecificationResponse[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
  totalSpecifications: number;
  totalOperations: number;
}

export interface SpecificationFilterParams {
  page?: number;
  size?: number;
  search?: string;
  status?: string;
}

export type ReconciliationCategory =
  | 'MATCHED'
  | 'OBSERVED_UNDOCUMENTED'
  | 'DOCUMENTED_UNOBSERVED'
  | 'METHOD_MISMATCH'
  | 'AMBIGUOUS';

export type ReconciliationPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface ReconciliationItemResponse {
  id: string;
  httpMethod: string;
  normalizedRoute: string;
  pathPattern: string;
  category: ReconciliationCategory;
  specificationId: string | null;
  specificationName: string | null;
  specificationVersion: string | null;
  operationId: string | null;
  serviceBoundary: string;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  totalRequests: number;
  statusDistribution: { [key: string]: number };
  declaredMethodsForRoute: string[];
  observedMethodsForRoute: string[];
  windowStart: string;
  windowEnd: string;
  explanation: string;
  priority: ReconciliationPriority;
  priorityScore: number;
  matchingConfidence: string;
  authFailureCount: number;
  anomalyEventCount: number;
}

export interface PriorityContributingFactor {
  factorId: string;
  factorName: string;
  scoreDelta: number;
  rationale: string;
}

export interface InvestigationSpecMetadata {
  id: string;
  name: string;
  version: string;
  openapiVersion: string;
  format: string;
  sourceFilename: string;
  operationId: string | null;
  summary: string | null;
  description: string | null;
}

export interface InvestigationTelemetryEvidence {
  totalRequests: number;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  statusDistribution: { [key: string]: number };
  authFailureCount: number;
  anomalyEventCount: number;
  distinctStatusCodes: number[];
}

export interface InvestigationLinkedIncident {
  id: string;
  ruleId: string;
  threatCategory: string;
  severity: string;
  status: string;
  summary: string;
  firstDetectedAt: string;
}

export interface ReconciliationInvestigationResponse {
  id: string;
  httpMethod: string;
  normalizedRoute: string;
  pathPattern: string;
  category: ReconciliationCategory;
  priority: ReconciliationPriority;
  priorityScore: number;
  priorityRuleVersion: string;
  contributingFactors: PriorityContributingFactor[];
  matchingConfidence: string;
  confidenceRationale: string;
  confirmedVulnerability: boolean;
  serviceBoundary: string;
  specification: InvestigationSpecMetadata | null;
  telemetryEvidence: InvestigationTelemetryEvidence;
  windowHours: number;
  windowStart: string;
  windowEnd: string;
  declaredMethodsForRoute: string[];
  observedMethodsForRoute: string[];
  linkedIncidents: InvestigationLinkedIncident[];
  explicitLimitations: string[];
  recommendedSteps: string[];
}

export interface ReconciliationSummaryResponse {
  matchedCount: number;
  observedUndocumentedCount: number;
  documentedUnobservedCount: number;
  methodMismatchCount: number;
  ambiguousCount: number;
  totalEvaluated: number;
  coveragePercentage: number;
  windowHours: number;
  windowStart: string;
  windowEnd: string;
  specificationId: string | null;
  specificationName: string | null;
}

export interface ReconciliationPageResponse {
  content: ReconciliationItemResponse[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
  summary: ReconciliationSummaryResponse;
}

export interface ReconciliationFilterParams {
  page?: number;
  size?: number;
  specId?: string;
  service?: string;
  method?: string;
  category?: ReconciliationCategory | string;
  priority?: ReconciliationPriority | string;
  windowHours?: number;
  from?: string;
  to?: string;
  search?: string;
  sortBy?: string;
  sortDirection?: 'asc' | 'desc' | 'ASC' | 'DESC';
}

// ---------------------------------------------------------------------------
// Phase 6.5: API Endpoint Intelligence, Observation History & Spec Evolution
// ---------------------------------------------------------------------------

export interface EndpointSpecMetadata {
  specificationId: string;
  specificationName: string;
  specificationVersion: string;
  specificationRevision: number;
  declaredPath: string;
  declaredMethod: string;
  declaredOperationId: string | null;
  declaredSummary: string | null;
}

export interface EndpointReconciliationStatus {
  status: ReconciliationCategory | string;
  coveragePercent: number;
  matchingSpecification: string | null;
  reconciledAt: string;
}

export interface EndpointPrioritizationDetail {
  priorityScore: number;
  priorityLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confirmedVulnerability: boolean;
  primaryReason: string;
  contributingFactors: Array<{
    factor: string;
    scoreImpact: number;
    explanation: string;
  }>;
  evaluatedAt: string;
}

export interface EndpointLinkedIncident {
  incidentId: string;
  title: string;
  severity: string;
  status: string;
  eventType: string;
  clientIp: string;
  timestamp: string;
}

export interface EndpointIntelligenceResponse {
  endpointId: string;
  httpMethod: string;
  normalizedRoute: string;
  serviceBoundary: string;
  stableHash: string;
  firstObservedAt: string;
  lastObservedAt: string;
  totalRequests: number;
  distinctStatusCodes: number[];
  statusDistribution: Record<string, number>;
  averageLatencyMs: number | null;
  minLatencyMs: number | null;
  maxLatencyMs: number | null;
  specification: EndpointSpecMetadata | null;
  reconciliation: EndpointReconciliationStatus | null;
  discrepancyPrioritization: EndpointPrioritizationDetail | null;
  relatedIncidents: EndpointLinkedIncident[];
  inferredService: boolean;
  confirmedVulnerability: boolean;
  telemetryWindowHours: number;
}

export interface ObservationTimeBucket {
  bucketTimestamp: string;
  requestCount: number;
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status5xx: number;
  avgLatencyMs: number | null;
  minLatencyMs: number | null;
  maxLatencyMs: number | null;
}

export interface EndpointObservationHistoryResponse {
  endpointId: string;
  httpMethod: string;
  normalizedRoute: string;
  serviceBoundary: string;
  windowHours: number;
  bucketIntervalMinutes: number;
  totalRequestsInWindow: number;
  retentionLimitHours: number;
  windowStart: string;
  windowEnd: string;
  buckets: ObservationTimeBucket[];
}

export interface EndpointSecurityEvent {
  eventId: string;
  clientIp: string;
  statusCode: number;
  anomalyScore: number;
  blocked: boolean;
  riskLevel: string;
  failureReason: string | null;
  timestamp: string;
}

export interface EndpointSecurityHistoryResponse {
  endpointId: string;
  httpMethod: string;
  normalizedRoute: string;
  windowHours: number;
  totalAuthFailures: number;
  totalAnomalies: number;
  totalBlocked: number;
  confirmedVulnerability: boolean;
  recentSecurityEvents: EndpointSecurityEvent[];
  linkedIncidents: EndpointLinkedIncident[];
}

export interface OperationChange {
  httpMethod: string;
  pathPattern: string;
  operationId: string | null;
  changeType: 'ADDED' | 'REMOVED' | 'MODIFIED' | 'UNCHANGED';
  fieldChanges: string[];
  baseOperation: any | null;
  targetOperation: any | null;
}

export interface SpecificationDiffResponse {
  baseSpecId: string;
  baseSpecName: string;
  baseSpecVersion: string;
  baseRevisionNumber: number;
  targetSpecId: string;
  targetSpecName: string;
  targetSpecVersion: string;
  targetRevisionNumber: number;
  comparedAt: string;
  addedCount: number;
  removedCount: number;
  modifiedCount: number;
  unchangedCount: number;
  changes: OperationChange[];
}



