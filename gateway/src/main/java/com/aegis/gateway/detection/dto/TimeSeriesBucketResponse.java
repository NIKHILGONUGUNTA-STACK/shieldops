package com.aegis.gateway.detection.dto;

public record TimeSeriesBucketResponse(
    String timestampBucket,
    long totalCount,
    long anomalyCount
) {}
