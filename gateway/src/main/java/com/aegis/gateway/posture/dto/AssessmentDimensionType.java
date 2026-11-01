package com.aegis.gateway.posture.dto;

/**
 * Six independent security posture assessment dimensions for discovered API endpoints.
 */
public enum AssessmentDimensionType {
    EXPOSURE("API Exposure & Inventory"),
    AUTHENTICATION("Authentication Posture"),
    AUTHORIZATION("Authorization Posture"),
    DATA_SENSITIVITY("Resource & Data Sensitivity"),
    BEHAVIORAL("Traffic & Behavioral Posture"),
    SPECIFICATION("API Specification Posture");

    private final String displayName;

    AssessmentDimensionType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}

