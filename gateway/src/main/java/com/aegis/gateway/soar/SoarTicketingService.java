package com.aegis.gateway.soar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Service managing bidirectional SOAR incident synchronization (Jira, PagerDuty, Slack, ServiceNow).
 */
@Service
public class SoarTicketingService {
    private static final Logger log = LoggerFactory.getLogger(SoarTicketingService.class);

    private final Map<String, SoarTicket> tickets = new ConcurrentHashMap<>();

    public SoarTicketingService() {
        initDefaultTickets();
    }

    private void initDefaultTickets() {
        Instant now = Instant.now();
        SoarTicket t1 = new SoarTicket(
                "SOAR-TCK-001",
                "INC-1794828844-4280",
                "JIRA",
                "SEC-1049",
                "[CRITICAL] Multi-Stage Exfiltration Campaign Detected on Customer Accounts",
                "CRITICAL",
                "MITIGATION_APPLIED",
                "analyst.security",
                now.minusSeconds(3600),
                now.minusSeconds(1200)
        );
        SoarTicket t2 = new SoarTicket(
                "SOAR-TCK-002",
                "INC-1794828841-1096",
                "PAGERDUTY",
                "PD-98421",
                "[HIGH] Unauthorized Horizontal Resource Traversal (BOLA Probing)",
                "HIGH",
                "INVESTIGATING",
                "oncall.engineer",
                now.minusSeconds(1800),
                now.minusSeconds(300)
        );
        tickets.put(t1.id(), t1);
        tickets.put(t2.id(), t2);
    }

    public SoarTicket createTicket(String incidentId, String externalSystem, String title, String severity, String assignee) {
        String id = "SOAR-TCK-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
        String externalTicketId = switch (externalSystem.toUpperCase()) {
            case "JIRA" -> "SEC-" + (1000 + new Random().nextInt(9000));
            case "PAGERDUTY" -> "PD-" + (10000 + new Random().nextInt(90000));
            case "SERVICENOW" -> "INC" + (100000 + new Random().nextInt(900000));
            default -> "ALERT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        };

        Instant now = Instant.now();
        SoarTicket ticket = new SoarTicket(
                id,
                incidentId != null ? incidentId : "INC-" + UUID.randomUUID().toString().substring(0, 8),
                externalSystem.toUpperCase(),
                externalTicketId,
                title,
                severity != null ? severity.toUpperCase() : "HIGH",
                "OPEN",
                assignee != null ? assignee : "security.queue",
                now,
                now
        );

        tickets.put(id, ticket);
        log.info("SOAR Ticket Dispatched: [{}] {} to {} for incident {}", id, externalTicketId, externalSystem, incidentId);
        return ticket;
    }

    public Optional<SoarTicket> handleCallback(String externalTicketId, String newStatus, String comment) {
        Optional<SoarTicket> existing = tickets.values().stream()
                .filter(t -> t.externalTicketId().equalsIgnoreCase(externalTicketId))
                .findFirst();

        if (existing.isPresent()) {
            SoarTicket current = existing.get();
            SoarTicket updated = current.withStatus(newStatus.toUpperCase(), Instant.now());
            tickets.put(updated.id(), updated);
            log.info("SOAR Webhook Callback Processed: Ticket {} ({}) transitioned to '{}'. Comment: {}",
                    current.id(), externalTicketId, newStatus, comment);
            return Optional.of(updated);
        }

        log.warn("SOAR Webhook Callback Received for unknown external ticket ID: {}", externalTicketId);
        return Optional.empty();
    }

    public List<SoarTicket> getTickets() {
        return tickets.values().stream()
                .sorted(Comparator.comparing(SoarTicket::createdAt).reversed())
                .collect(Collectors.toList());
    }

    public Optional<SoarTicket> getTicket(String id) {
        return Optional.ofNullable(tickets.get(id));
    }
}
