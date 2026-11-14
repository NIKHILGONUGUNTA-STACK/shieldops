package com.aegis.gateway.detection.campaign;

import java.util.Set;

/**
 * Lifecycle states of an Exfiltration Campaign.
 */
public enum CampaignStatus {
    OPEN,
    INVESTIGATING,
    ESCALATED,
    RESOLVED,
    FALSE_POSITIVE;

    public boolean isValidTransition(CampaignStatus nextStatus) {
        if (nextStatus == null || this == nextStatus) {
            return false;
        }

        return switch (this) {
            case OPEN -> Set.of(INVESTIGATING, ESCALATED, RESOLVED, FALSE_POSITIVE).contains(nextStatus);
            case INVESTIGATING -> Set.of(ESCALATED, RESOLVED, FALSE_POSITIVE).contains(nextStatus);
            case ESCALATED -> Set.of(INVESTIGATING, RESOLVED, FALSE_POSITIVE).contains(nextStatus);
            case RESOLVED -> Set.of(OPEN, INVESTIGATING).contains(nextStatus); // Re-open
            case FALSE_POSITIVE -> Set.of(OPEN, INVESTIGATING).contains(nextStatus); // Re-evaluate
        };
    }
}

