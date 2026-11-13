package com.aegis.gateway.detection.leakage;

import java.time.Instant;
import java.util.Map;

/**
 * Real-time operational metrics for Advanced Bulk Extraction and Excessive Data Exposure vectors.
 */
public record ExtractionAnalyticsResponse(
    long totalExtractionIncidents,
    long rapidExtractions,
    long lowAndSlowExtractions,
    long distributedExtractions,
    long paginationExtractions,
    long multiResourceExtractions,
    long excessiveExposures,
    long cumulativeRecordsHarvested,
    long cumulativeBytesExposed,
    Map<String, Long> extractionsByTargetEntity,
    Instant generatedAt
) {}
