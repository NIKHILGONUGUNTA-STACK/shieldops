package com.aegis.gateway.classification;

import java.time.Instant;
import java.util.List;

/**
 * Consolidated sensitive data classification dossier for a single API endpoint.
 */
public record EndpointDataClassification(
    String id,
    String httpMethod,
    String routeTemplate,
    String serviceBoundary,
    DataSensitivityLevel highestSensitivityLevel,
    int totalFields,
    int classifiedFieldsCount,
    int unclassifiedFieldsCount,
    List<FieldClassification> fieldClassifications,
    double coveragePercentage,
    boolean manualReviewRequired,
    Instant evaluatedAt
) {
    public EndpointDataClassification {
        if (fieldClassifications == null) {
            fieldClassifications = List.of();
        }
    }
}

