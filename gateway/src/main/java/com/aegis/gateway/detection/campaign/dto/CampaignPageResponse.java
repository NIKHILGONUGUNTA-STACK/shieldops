package com.aegis.gateway.detection.campaign.dto;

import java.util.List;

/**
 * Paginated container for Exfiltration Campaigns.
 */
public record CampaignPageResponse(
    List<CampaignResponse> campaigns,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean first,
    boolean last
) {
    public static CampaignPageResponse of(
            List<CampaignResponse> campaigns,
            int page,
            int size,
            long totalElements) {
        int totalPages = size > 0 ? (int) Math.ceil((double) totalElements / size) : 0;
        return new CampaignPageResponse(
            campaigns,
            page,
            size,
            totalElements,
            totalPages,
            page == 0,
            page >= totalPages - 1
        );
    }
}

