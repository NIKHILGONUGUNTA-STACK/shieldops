package com.aegis.gateway.detection.model;

public enum IncidentStatus {
    OPEN,
    INVESTIGATING,
    CONTAINED,
    RESOLVED,
    FALSE_POSITIVE;

    public static IncidentStatus fromString(String val) {
        if (val == null) return OPEN;
        try {
            return IncidentStatus.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return OPEN;
        }
    }
}
