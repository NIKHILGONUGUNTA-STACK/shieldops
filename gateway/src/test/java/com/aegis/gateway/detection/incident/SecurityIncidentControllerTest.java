package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.IncidentStatusHistory;
import com.aegis.gateway.detection.model.PolicyDecision;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIncidentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IncidentRepository incidentRepository;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcClient.sql("DELETE FROM security_data.policy_decisions").update();
        jdbcClient.sql("DELETE FROM security_data.incident_status_history").update();
        jdbcClient.sql("DELETE FROM security_data.detection_evidence").update();
        jdbcClient.sql("DELETE FROM security_data.incidents").update();
    }

    @Test
    void unauthenticatedRequestToIncidentsReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/incidents"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void customerRoleAccessToIncidentsReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/incidents")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void listIncidentsWithPaginationAndFilters() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();

        SecurityIncident inc1 = new SecurityIncident(
            id1, "fp-1", "RULE-BOLA-01", "1.0.0", "BOLA_CAMPAIGN", "CRITICAL",
            IncidentStatus.OPEN, "CUSTOMER", "10000000-0000-4000-8000-000000000001",
            now.minus(10, ChronoUnit.MINUTES), now.minus(5, ChronoUnit.MINUTES), 10,
            "BOLA campaign detected", now.minus(10, ChronoUnit.MINUTES), now.minus(5, ChronoUnit.MINUTES)
        );

        SecurityIncident inc2 = new SecurityIncident(
            id2, "fp-2", "RULE-RATE-01", "1.0.0", "RATE_ABUSE", "HIGH",
            IncidentStatus.INVESTIGATING, "IP", "192.168.1.100",
            now.minus(20, ChronoUnit.MINUTES), now.minus(1, ChronoUnit.MINUTES), 50,
            "Rate limit violation", now.minus(20, ChronoUnit.MINUTES), now.minus(1, ChronoUnit.MINUTES)
        );

        incidentRepository.saveIncident(inc1);
        incidentRepository.saveIncident(inc2);

        // List all (page 0, size 20)
        mockMvc.perform(get("/api/v1/security/incidents")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(2))
            .andExpect(jsonPath("$.content", hasSize(2)));

        // Filter by status=OPEN
        mockMvc.perform(get("/api/v1/security/incidents?status=OPEN")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(id1.toString()))
            .andExpect(jsonPath("$.content[0].threatCategory").value("BOLA_CAMPAIGN"));

        // Filter by severity=HIGH
        mockMvc.perform(get("/api/v1/security/incidents?severity=HIGH")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(id2.toString()));

        // Filter by targetEntityType=CUSTOMER
        mockMvc.perform(get("/api/v1/security/incidents?targetEntityType=CUSTOMER")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].targetEntityValue").value("10000000-0000-4000-8000-000000000001"));
    }

    @Test
    void getIncidentByIdSuccess() throws Exception {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            id, "fp-single", "RULE-AUTH-01", "1.0.0", "CREDENTIAL_ACCESS", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "cust-99",
            now, now, 5, "Brute force attack", now, now
        );
        incidentRepository.saveIncident(inc);

        mockMvc.perform(get("/api/v1/security/incidents/" + id)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(id.toString()))
            .andExpect(jsonPath("$.ruleId").value("RULE-AUTH-01"))
            .andExpect(jsonPath("$.threatCategory").value("CREDENTIAL_ACCESS"))
            .andExpect(jsonPath("$.status").value("OPEN"));
    }

    @Test
    void getIncidentByIdNotFoundReturns404() throws Exception {
        UUID nonExistentId = UUID.randomUUID();
        mockMvc.perform(get("/api/v1/security/incidents/" + nonExistentId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status").value(404))
            .andExpect(jsonPath("$.title").value("Not Found"));
    }

    @Test
    void getEvidenceForIncident() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-ev", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "c1", now, now, 3, "BOLA", now, now
        );
        incidentRepository.saveIncident(inc);

        UUID evId = UUID.randomUUID();
        DetectionEvidence ev = new DetectionEvidence(
            evId, incId, "RULE-BOLA-01", "1.0.0", now, 0.95, "HIGH",
            "observed >= 3", 3, 300, 3, "{\"test\":\"details\"}",
            List.of(UUID.randomUUID()), now
        );
        incidentRepository.saveEvidence(ev);

        mockMvc.perform(get("/api/v1/security/incidents/" + incId + "/evidence")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(1)))
            .andExpect(jsonPath("$[0].id").value(evId.toString()))
            .andExpect(jsonPath("$[0].incidentId").value(incId.toString()))
            .andExpect(jsonPath("$[0].confidenceScore").value(0.95))
            .andExpect(jsonPath("$[0].ruleId").value("RULE-BOLA-01"));
    }

    @Test
    void getEvidenceForMissingIncidentReturns404() throws Exception {
        UUID missingId = UUID.randomUUID();
        mockMvc.perform(get("/api/v1/security/incidents/" + missingId + "/evidence")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status").value(404));
    }

    @Test
    void getHistoryForIncident() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-hist", "RULE-PROBE-01", "1.0.0", "PROBE", "HIGH",
            IncidentStatus.OPEN, "IP", "10.0.0.1", now, now, 4, "Probe", now, now
        );
        incidentRepository.saveIncident(inc);

        IncidentStatusHistory hist = new IncidentStatusHistory(
            UUID.randomUUID(), incId, "NONE", "OPEN", "RULE-PROBE-01", now, "Initial trigger"
        );
        incidentRepository.saveStatusHistory(hist);

        mockMvc.perform(get("/api/v1/security/incidents/" + incId + "/history")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(1)))
            .andExpect(jsonPath("$[0].incidentId").value(incId.toString()))
            .andExpect(jsonPath("$[0].previousStatus").value("NONE"))
            .andExpect(jsonPath("$[0].newStatus").value("OPEN"))
            .andExpect(jsonPath("$[0].changedBy").value("RULE-PROBE-01"));
    }

    @Test
    void getHistoryForMissingIncidentReturns404() throws Exception {
        UUID missingId = UUID.randomUUID();
        mockMvc.perform(get("/api/v1/security/incidents/" + missingId + "/history")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status").value(404));
    }

    @Test
    void getPolicyDecisionsForIncidentAndGlobal() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-pol", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "c1", now, now, 3, "BOLA", now, now
        );
        incidentRepository.saveIncident(inc);

        PolicyDecision dec = new PolicyDecision(
            UUID.randomUUID(), incId, "RULE_BOLA_POLICY", "LOG_ALERT", "ADVISORY",
            now, null, "Advisory alert per Phase 4 specification", now
        );
        incidentRepository.savePolicyDecision(dec);

        // Incident specific
        mockMvc.perform(get("/api/v1/security/incidents/" + incId + "/policy-decisions")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(1)))
            .andExpect(jsonPath("$[0].policyRule").value("RULE_BOLA_POLICY"))
            .andExpect(jsonPath("$[0].enforcementLevel").value("ADVISORY"));

        // Global recent decisions
        mockMvc.perform(get("/api/v1/security/policy-decisions")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(1)))
            .andExpect(jsonPath("$[0].policyRule").value("RULE_BOLA_POLICY"));
    }
}
