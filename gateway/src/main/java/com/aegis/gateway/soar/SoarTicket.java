package com.aegis.gateway.soar;

import java.time.Instant;

/**
 * Domain model representing an external SOAR incident response ticket.
 */
public record SoarTicket(
        String id,
        String incidentId,
        String externalSystem,
        String externalTicketId,
        String title,
        String severity,
        String status,
        String assignee,
        Instant createdAt,
        Instant updatedAt
) {
    public SoarTicket withStatus(String newStatus, Instant updateTime) {
        return new SoarTicket(
                id,
                incidentId,
                externalSystem,
                externalTicketId,
                title,
                severity,
                newStatus,
                assignee,
                createdAt,
                updateTime != null ? updateTime : Instant.now()
        );
    }
}
