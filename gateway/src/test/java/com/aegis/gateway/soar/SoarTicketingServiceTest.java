package com.aegis.gateway.soar;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SoarTicketingServiceTest {

    private SoarTicketingService service;

    @BeforeEach
    void setUp() {
        service = new SoarTicketingService();
    }

    @Test
    void testCreateTicket() {
        SoarTicket ticket = service.createTicket(
                "INC-TEST-99",
                "JIRA",
                "High Severity Attack Campaign",
                "CRITICAL",
                "soc.lead"
        );

        assertThat(ticket).isNotNull();
        assertThat(ticket.externalSystem()).isEqualTo("JIRA");
        assertThat(ticket.externalTicketId()).startsWith("SEC-");
        assertThat(ticket.status()).isEqualTo("OPEN");

        Optional<SoarTicket> fetched = service.getTicket(ticket.id());
        assertThat(fetched).isPresent();
        assertThat(fetched.get().title()).isEqualTo("High Severity Attack Campaign");
    }

    @Test
    void testHandleCallback() {
        SoarTicket ticket = service.createTicket(
                "INC-TEST-100",
                "PAGERDUTY",
                "BOLA Probing Incident",
                "HIGH",
                "oncall.engineer"
        );

        Optional<SoarTicket> updated = service.handleCallback(
                ticket.externalTicketId(),
                "RESOLVED",
                "Incident mitigated automatically via Aegis WAF ban"
        );

        assertThat(updated).isPresent();
        assertThat(updated.get().status()).isEqualTo("RESOLVED");
    }

    @Test
    void testGetTickets() {
        List<SoarTicket> allTickets = service.getTickets();
        assertThat(allTickets).isNotEmpty();
    }
}
