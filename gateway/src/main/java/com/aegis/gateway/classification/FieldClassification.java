package com.aegis.gateway.classification;

import java.util.Set;

/**
 * Field-level data classification record containing auditability metadata,
 * sensitivity level, approved roles, ownership requirements, and evidence confidence.
 */
public record FieldClassification(
    String serviceBoundary,
    String httpMethod,
    String routeTemplate,
    String fieldPath,
    DataSensitivityLevel dataClassification,
    String classificationRationale,
    Set<String> approvedAccessRoles,
    ResourceOwnershipRequirement resourceOwnershipRequirements,
    String schemaSource,
    ClassificationConfidence confidence,
    String policyVersion,
    boolean manualReviewRequired
) {
    public FieldClassification {
        if (approvedAccessRoles == null) {
            approvedAccessRoles = Set.of();
        }
    }
}

