package com.aegis.gateway.detection.campaign;

/**
 * Quality and completeness state of forensic evidence supporting an exfiltration campaign.
 */
public enum CampaignEvidenceCompleteness {
    COMPLETE("Full identity, ownership, sensitive schema, and volume telemetry captured"),
    INCOMPLETE("Missing ownership, unclassified endpoint schema, or zero response size"),
    DEGRADED("Provisional schema classification or out-of-order delayed telemetry arriving after timeout");

    private final String description;

    CampaignEvidenceCompleteness(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

