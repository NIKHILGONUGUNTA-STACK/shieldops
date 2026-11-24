export type TenantTier = 'STARTER' | 'PROFESSIONAL' | 'ENTERPRISE';
export type TenantStatus = 'ACTIVE' | 'SUSPENDED' | 'PROVISIONING' | 'DECOMMISSIONED';

export interface Tenant {
  id: string;
  name: string;
  tier: TenantTier;
  status: TenantStatus;
  rateLimitRpm: number;
  maxIncidentsRetentionDays: number;
  allowedIpRanges: string[];
  contactEmail?: string;
  webhookUrl?: string;
  createdAt: string;
  updatedAt: string;
}

export interface TenantPageResponse {
  content: Tenant[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

export interface TenantCreateRequest {
  id: string;
  name: string;
  tier?: TenantTier;
  rateLimitRpm: number;
  maxIncidentsRetentionDays: number;
  allowedIpRanges?: string[];
  contactEmail?: string;
  webhookUrl?: string;
}

export interface TenantStatusUpdateRequest {
  status: TenantStatus;
  reason?: string;
}

export interface TenantQuotaUpdateRequest {
  rateLimitRpm: number;
  maxIncidentsRetentionDays: number;
  allowedIpRanges?: string[];
}

export interface TenantUsageResponse {
  tenantId: string;
  tenantName: string;
  rateLimitRpm: number;
  currentWindowRequests: number;
  rateLimitUtilizationPercent: number;
  totalRecordedEvents: number;
  activeIncidentsCount: number;
  activeCampaignsCount: number;
  evaluatedAt: string;
}
