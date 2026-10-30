package com.aegis.gateway.reconciliation.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * Security incident reliably associated with this API route finding within the observation window.
 */
public record InvestigationLinkedIncident(
    UUID id,
    String ruleId,
    String threatCategory,
    String severity,
    String status,
    String summary,
    Instant firstDetectedAt
) {}
