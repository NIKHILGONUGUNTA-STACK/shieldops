package com.aegis.gateway.detection.campaign.dto;

import com.aegis.gateway.detection.campaign.CampaignStatus;

/**
 * Request payload for transitioning a campaign's lifecycle state.
 */
public record CampaignStatusUpdateRequest(
    CampaignStatus status,
    String reason
) {}

