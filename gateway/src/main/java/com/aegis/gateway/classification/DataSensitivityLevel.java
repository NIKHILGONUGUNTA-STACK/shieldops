package com.aegis.gateway.classification;

/**
 * Deterministic data sensitivity levels for Aegis sensitive data classification.
 * Ranks determine hierarchy and conflict resolution:
 * RESTRICTED (4) > CONFIDENTIAL (3) > INTERNAL (2) > PUBLIC (1).
 */
public enum DataSensitivityLevel {
    /**
     * Information intentionally available without authentication.
     */
    PUBLIC(1, "Public"),

    /**
     * Internal operational information not intended for unrestricted external access.
     */
    INTERNAL(2, "Internal"),

    /**
     * Customer profiles, account information, transaction details, and personal information.
     */
    CONFIDENTIAL(3, "Confidential"),

    /**
     * Authentication secrets, access tokens, credentials, cryptographic secrets, and highly sensitive financial identifiers.
     */
    RESTRICTED(4, "Restricted");

    private final int rank;
    private final String displayName;

    DataSensitivityLevel(int rank, String displayName) {
        this.rank = rank;
        this.displayName = displayName;
    }

    public int getRank() {
        return rank;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isHigherThan(DataSensitivityLevel other) {
        if (other == null) {
            return true;
        }
        return this.rank > other.rank;
    }

    public static DataSensitivityLevel highest(DataSensitivityLevel a, DataSensitivityLevel b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.rank >= b.rank ? a : b;
    }
}

