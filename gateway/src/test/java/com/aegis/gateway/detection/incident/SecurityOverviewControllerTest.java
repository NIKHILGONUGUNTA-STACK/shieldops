package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
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
class SecurityOverviewControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApiEventRepository apiEventRepository;

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
        jdbcClient.sql("DELETE FROM security_data.api_events").update();
    }

    @Test
    void unauthenticatedRequestToOverviewReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/overview"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void customerRoleAccessToOverviewReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/overview")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void invalidWindowHoursReturns400BadRequest() throws Exception {
        mockMvc.perform(get("/api/v1/security/overview?windowHours=0")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.title").value("Bad Request"))
            .andExpect(jsonPath("$.detail").value(containsString("between 1 and 168")));

        mockMvc.perform(get("/api/v1/security/overview?windowHours=200")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void overviewReturnsAggregatedMetricsCorrectly() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        // 1. Populate telemetry events: 3 events (2 normal, 1 anomaly)
        ApiEvent e1 = new ApiEvent(
            UUID.randomUUID(), "cid-ov-1", now.minus(2, ChronoUnit.HOURS), "192.168.1.1", "GET",
            "/api/v1/customers", "/customers", 200, 10L, "u1", "ROLE_CUSTOMER",
            "c1", "agent", "hash", "NONE", null, null, null, 0L, 0
        );
        ApiEvent e2 = new ApiEvent(
            UUID.randomUUID(), "cid-ov-2", now.minus(1, ChronoUnit.HOURS), "192.168.1.2", "GET",
            "/api/v1/accounts", "/accounts", 200, 15L, "u2", "ROLE_CUSTOMER",
            "c2", "agent", "hash", "NONE", null, null, null, 0L, 0
        );
        ApiEvent e3 = new ApiEvent(
            UUID.randomUUID(), "cid-ov-3", now.minus(30, ChronoUnit.MINUTES), "192.168.1.3", "POST",
            "/api/v1/transfers", "/transfers", 403, 30L, "u3", "ROLE_CUSTOMER",
            "c3", "agent", "hash", "FORBIDDEN_ATTEMPT", null, null, null, 0L, 0
        );
        apiEventRepository.save(e1);
        apiEventRepository.save(e2);
        apiEventRepository.save(e3);

        // 2. Populate incident: 1 OPEN incident with CRITICAL severity
        UUID incId = UUID.randomUUID();
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-overview", "RULE-BOLA-01", "1.0.0", "BOLA_CAMPAIGN", "CRITICAL",
            IncidentStatus.OPEN, "CUSTOMER", "cust-ov-1", now.minus(1, ChronoUnit.HOURS),
            now.minus(10, ChronoUnit.MINUTES), 5, "Correlated BOLA campaign",
            now.minus(1, ChronoUnit.HOURS), now.minus(10, ChronoUnit.MINUTES)
        );
        incidentRepository.saveIncident(inc);

        // 3. Populate evidence
        DetectionEvidence ev = new DetectionEvidence(
            UUID.randomUUID(), incId, "RULE-BOLA-01", "1.0.0", now.minus(10, ChronoUnit.MINUTES),
            0.95, "CRITICAL", "observed >= 3", 3, 300, 3, "{\"evidence\":\"detail\"}",
            List.of(UUID.randomUUID()), now.minus(10, ChronoUnit.MINUTES)
        );
        incidentRepository.saveEvidence(ev);

        mockMvc.perform(get("/api/v1/security/overview?windowHours=24")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalEvents").value(3))
            .andExpect(jsonPath("$.totalAnomalies").value(1))
            .andExpect(jsonPath("$.openIncidents").value(1))
            .andExpect(jsonPath("$.incidentsBySeverity.CRITICAL").value(1))
            .andExpect(jsonPath("$.incidentsBySeverity.HIGH").value(0))
            .andExpect(jsonPath("$.incidentsByCategory.BOLA_CAMPAIGN").value(1))
            .andExpect(jsonPath("$.recentIncidents", hasSize(1)))
            .andExpect(jsonPath("$.recentIncidents[0].id").value(incId.toString()))
            .andExpect(jsonPath("$.recentIncidents[0].severity").value("CRITICAL"))
            .andExpect(jsonPath("$.topTriggeredRules", hasSize(1)))
            .andExpect(jsonPath("$.topTriggeredRules[0].ruleId").value("RULE-BOLA-01"))
            .andExpect(jsonPath("$.topTriggeredRules[0].triggerCount").value(1))
            .andExpect(jsonPath("$.timeSeriesTrend").isArray());
    }
}
