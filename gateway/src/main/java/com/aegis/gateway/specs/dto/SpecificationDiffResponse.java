package com.aegis.gateway.specs.dto;

import java.util.List;

/**
 * Structural comparison response between two specification revisions.
 */
public record SpecificationDiffResponse(
    ApiSpecificationResponse baseSpecification,
    ApiSpecificationResponse targetSpecification,
    int addedCount,
    int removedCount,
    int modifiedCount,
    int unchangedCount,
    List<OperationChange> changes
) {}
