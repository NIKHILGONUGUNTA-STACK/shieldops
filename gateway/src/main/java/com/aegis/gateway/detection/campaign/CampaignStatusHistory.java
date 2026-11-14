package com.aegis.gateway.detection.campaign;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable audit record of a campaign lifecycle status transition.
 */
public record CampaignStatusHistory(
    UUID id,
    UUID campaignId,
    CampaignStatus previousStatus,
    CampaignStatus newStatus,
    String changedBy,
    Instant changedAt,
    String reason
) {}

