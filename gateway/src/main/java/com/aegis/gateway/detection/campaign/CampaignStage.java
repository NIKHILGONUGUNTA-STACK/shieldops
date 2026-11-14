package com.aegis.gateway.detection.campaign;

/**
 * Stages of an API exfiltration campaign in chronological kill-chain progression.
 */
public enum CampaignStage {
    RECONNAISSANCE("Reconnaissance & Endpoint Discovery", 1),
    AUTHORIZATION_PROBING("Authorization & BOLA Probing", 2),
    RESOURCE_DISCOVERY("Resource & Entity Enumeration", 3),
    SENSITIVE_DATA_ACCESS("Sensitive Data Access & Exposure", 4),
    BULK_EXTRACTION("Bulk & Automated Extraction", 5),
    MULTI_DOMAIN_EXTRACTION("Cross-Domain Exfiltration Campaign", 6);

    private final String description;
    private final int rank;

    CampaignStage(String description, int rank) {
        this.description = description;
        this.rank = rank;
    }

    public String getDescription() {
        return description;
    }

    public int getRank() {
        return rank;
    }
}

