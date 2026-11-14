package com.aegis.gateway.detection.campaign;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Domain entity representing an end-to-end multi-stage API data exfiltration campaign.
 */
public record ExfiltrationCampaign(
    UUID id,
    String campaignId,
    String correlationIdentity,
    String tenantId,
    String clientIp,
    CampaignStage currentStage,
    List<CampaignStage> stagesObserved,
    CampaignStatus status,
    String severity,
    double riskScore,
    String riskCategory,
    String riskRationale,
    CampaignEvidenceCompleteness evidenceCompleteness,
    String missingEvidenceDetails,
    int resourceCount,
    int endpointCount,
    int sensitiveDomainCount,
    Instant firstObservedAt,
    Instant lastObservedAt,
    int eventCount,
    List<UUID> relatedEventIds,
    List<UUID> relatedIncidentIds,
    List<String> relatedRuleIds,
    Instant createdAt,
    Instant updatedAt
) {
    public boolean isOpenOrInvestigating() {
        return status == CampaignStatus.OPEN || status == CampaignStatus.INVESTIGATING || status == CampaignStatus.ESCALATED;
    }
}

