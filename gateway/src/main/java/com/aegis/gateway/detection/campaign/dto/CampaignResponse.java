package com.aegis.gateway.detection.campaign.dto;

import com.aegis.gateway.detection.campaign.CampaignEvidenceCompleteness;
import com.aegis.gateway.detection.campaign.CampaignStage;
import com.aegis.gateway.detection.campaign.CampaignStatus;
import com.aegis.gateway.detection.campaign.ExfiltrationCampaign;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Public DTO representing an Exfiltration Campaign.
 */
public record CampaignResponse(
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
    public static CampaignResponse fromEntity(ExfiltrationCampaign c) {
        return new CampaignResponse(
            c.id(),
            c.campaignId(),
            c.correlationIdentity(),
            c.tenantId(),
            c.clientIp(),
            c.currentStage(),
            c.stagesObserved(),
            c.status(),
            c.severity(),
            c.riskScore(),
            c.riskCategory(),
            c.riskRationale(),
            c.evidenceCompleteness(),
            c.missingEvidenceDetails(),
            c.resourceCount(),
            c.endpointCount(),
            c.sensitiveDomainCount(),
            c.firstObservedAt(),
            c.lastObservedAt(),
            c.eventCount(),
            c.relatedEventIds(),
            c.relatedIncidentIds(),
            c.relatedRuleIds(),
            c.createdAt(),
            c.updatedAt()
        );
    }
}

