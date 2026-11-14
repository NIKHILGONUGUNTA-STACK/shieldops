package com.aegis.gateway.detection.policy;

/**
 * Lifecycle status of an adaptive policy decision recommendation.
 */
public enum PolicyStatus {
    RECOMMENDED,
    UNDER_REVIEW,
    APPROVED,
    REJECTED,
    SUPERSEDED;

    public boolean isValidTransition(PolicyStatus target) {
        if (this == target) {
            return true;
        }
        return switch (this) {
            case RECOMMENDED -> target == UNDER_REVIEW || target == APPROVED || target == REJECTED || target == SUPERSEDED;
            case UNDER_REVIEW -> target == APPROVED || target == REJECTED || target == SUPERSEDED;
            case APPROVED, REJECTED -> target == UNDER_REVIEW || target == SUPERSEDED;
            case SUPERSEDED -> false;
        };
    }
}
