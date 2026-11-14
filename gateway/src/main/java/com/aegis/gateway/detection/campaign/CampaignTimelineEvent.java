package com.aegis.gateway.detection.campaign;

import java.time.Instant;
import java.util.UUID;

/**
 * An individual security event contributing to an exfiltration campaign's attack timeline.
 */
public record CampaignTimelineEvent(
    UUID id,
    UUID campaignId,
    CampaignStage stage,
    UUID eventId,
    String ruleId,
    Instant timestamp,
    String httpMethod,
    String requestPath,
    int statusCode,
    String description,
    Instant createdAt
) {}

