package com.aegis.gateway.detection.dto;

public record RuleTriggerStatResponse(
    String ruleId,
    long triggerCount
) {}
