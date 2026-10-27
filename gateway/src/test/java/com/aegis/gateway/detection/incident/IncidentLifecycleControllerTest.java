package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.IncidentStatusHistory;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IncidentLifecycleControllerTest {

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
    void analystCanTransitionStatusFromOpenToInvestigating() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-1", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "cust-1", now, now, 3, "BOLA probing", now, now
        );
        incidentRepository.saveIncident(inc);

        String body = """
            {
                "status": "INVESTIGATING",
                "reason": "Analyst sarah assigned to review probing logs"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))
                    .jwt(j -> j.claim("preferred_username", "sarah.analyst"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(incId.toString()))
            .andExpect(jsonPath("$.status").value("INVESTIGATING"));

        // Verify status in DB
        SecurityIncident persisted = incidentRepository.findById(incId).orElseThrow();
        assertThat(persisted.status()).isEqualTo(IncidentStatus.INVESTIGATING);

        // Verify status history audit record
        List<IncidentStatusHistory> history = incidentRepository.findStatusHistoryByIncidentId(incId);
        assertThat(history).hasSize(1);
        assertThat(history.getFirst().previousStatus()).isEqualTo("OPEN");
        assertThat(history.getFirst().newStatus()).isEqualTo("INVESTIGATING");
        assertThat(history.getFirst().changedBy()).isEqualTo("sarah.analyst");
        assertThat(history.getFirst().reason()).isEqualTo("Analyst sarah assigned to review probing logs");
    }

    @Test
    void adminCanReopenResolvedTerminalIncidentToInvestigating() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-2", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.RESOLVED, "CUSTOMER", "cust-2", now, now, 5, "Resolved incident", now, now
        );
        incidentRepository.saveIncident(inc);

        String body = """
            {
                "status": "INVESTIGATING",
                "reason": "Reopening incident due to subsequent correlated telemetry wave"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))
                    .jwt(j -> j.claim("preferred_username", "admin.david"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("INVESTIGATING"));

        SecurityIncident persisted = incidentRepository.findById(incId).orElseThrow();
        assertThat(persisted.status()).isEqualTo(IncidentStatus.INVESTIGATING);

        List<IncidentStatusHistory> history = incidentRepository.findStatusHistoryByIncidentId(incId);
        assertThat(history).hasSize(1);
        assertThat(history.getFirst().previousStatus()).isEqualTo("RESOLVED");
        assertThat(history.getFirst().newStatus()).isEqualTo("INVESTIGATING");
        assertThat(history.getFirst().changedBy()).isEqualTo("admin.david");
    }

    @Test
    void analystForbiddenFromReopeningResolvedTerminalIncident() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-3", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.RESOLVED, "CUSTOMER", "cust-3", now, now, 5, "Resolved incident", now, now
        );
        incidentRepository.saveIncident(inc);

        String body = """
            {
                "status": "INVESTIGATING",
                "reason": "Analyst trying to reopen resolved incident"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))
                    .jwt(j -> j.claim("preferred_username", "sam.analyst"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.title").value("Forbidden"))
            .andExpect(jsonPath("$.detail").value(containsString("Only SECURITY_ADMIN can reopen a terminal incident")));
    }

    @Test
    void invalidStatusTransitionReturns409Conflict() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-4", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.CONTAINED, "CUSTOMER", "cust-4", now, now, 5, "Contained incident", now, now
        );
        incidentRepository.saveIncident(inc);

        // Transition from CONTAINED directly back to OPEN is not allowed
        String body = """
            {
                "status": "OPEN",
                "reason": "Attempting invalid direct transition back to open"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))
                    .jwt(j -> j.claim("preferred_username", "sam.analyst"))))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.status").value(409))
            .andExpect(jsonPath("$.title").value("Conflict"));
    }

    @Test
    void transitionToSameStatusReturns409Conflict() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-5", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "cust-5", now, now, 5, "Open incident", now, now
        );
        incidentRepository.saveIncident(inc);

        String body = """
            {
                "status": "OPEN",
                "reason": "Transitioning to identical status"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))
                    .jwt(j -> j.claim("preferred_username", "sam.analyst"))))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    void transitionWithInvalidStatusStringReturns400BadRequest() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-6", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "cust-6", now, now, 5, "Open incident", now, now
        );
        incidentRepository.saveIncident(inc);

        String body = """
            {
                "status": "NON_EXISTENT_STATUS",
                "reason": "Some valid reason with sufficient length"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.title").value("Bad Request"));
    }

    @Test
    void transitionWithTooShortReasonReturns400BadRequest() throws Exception {
        UUID incId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SecurityIncident inc = new SecurityIncident(
            incId, "fp-lifecycle-7", "RULE-BOLA-01", "1.0.0", "BOLA", "HIGH",
            IncidentStatus.OPEN, "CUSTOMER", "cust-7", now, now, 5, "Open incident", now, now
        );
        incidentRepository.saveIncident(inc);

        String body = """
            {
                "status": "INVESTIGATING",
                "reason": "tiny"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + incId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.title").value("Bad Request"))
            .andExpect(jsonPath("$.detail").value(containsString("between 5 and 512 characters")));
    }

    @Test
    void transitionForMissingIncidentReturns404NotFound() throws Exception {
        UUID missingId = UUID.randomUUID();
        String body = """
            {
                "status": "INVESTIGATING",
                "reason": "Valid reason length here"
            }
            """;

        mockMvc.perform(patch("/api/v1/security/incidents/" + missingId + "/status")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status").value(404));
    }
}
