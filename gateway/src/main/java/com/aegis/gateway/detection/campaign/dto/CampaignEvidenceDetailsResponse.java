package com.aegis.gateway.detection.campaign.dto;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.SecurityIncident;

import java.util.List;
import java.util.UUID;

/**
 * Detailed forensic evidence and correlated incident references for a campaign.
 */
public record CampaignEvidenceDetailsResponse(
    UUID campaignId,
    String campaignCode,
    List<UUID> relatedEventIds,
    List<UUID> relatedIncidentIds,
    List<String> relatedRuleIds,
    List<DetectionEvidence> evidences,
    List<SecurityIncident> incidents
) {}

