package com.aegis.gateway.telemetry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityEventControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApiEventRepository apiEventRepository;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcClient.sql("DELETE FROM security_data.api_events").update();
    }

    @Test
    void unauthenticatedRequestReturns401Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/security/events"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    void customerRoleDeniedWith403Forbidden() throws Exception {
        mockMvc.perform(get("/api/v1/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
                    .jwt(j -> j.claim("customerId", "10000000-0000-4000-8000-000000000001"))))
            .andExpect(status().isForbidden())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.detail").value("Access is denied"));
    }

    @Test
    void securityAnalystAllowedWith200Ok() throws Exception {
        mockMvc.perform(get("/api/v1/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").value(20))
            .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void securityAdminAllowedWith200Ok() throws Exception {
        mockMvc.perform(get("/api/v1/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Correlation-Id"))
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").value(20));
    }

    @Test
    void actualPersistedEventReturnedWithSanitizedFields() throws Exception {
        UUID eventId = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        ApiEvent event = new ApiEvent(
            eventId,
            "corr-test-1234",
            now,
            "192.168.1.100",
            "POST",
            "/api/v1/transfers",
            "/transfers",
            200,
            42L,
            "alex.morgan",
            "ROLE_CUSTOMER",
            "10000000-0000-4000-8000-000000000001",
            "Mozilla/5.0",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "NONE"
        );
        apiEventRepository.save(event);

        mockMvc.perform(get("/api/v1/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(eventId.toString()))
            .andExpect(jsonPath("$.content[0].correlationId").value("corr-test-1234"))
            .andExpect(jsonPath("$.content[0].httpMethod").value("POST"))
            .andExpect(jsonPath("$.content[0].requestPath").value("/api/v1/transfers"))
            .andExpect(jsonPath("$.content[0].statusCode").value(200))
            .andExpect(jsonPath("$.content[0].latencyMs").value(42))
            .andExpect(jsonPath("$.content[0].authSubject").value("alex.morgan"))
            .andExpect(jsonPath("$.content[0].payloadHash").value("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
            .andExpect(jsonPath("$.content[0].anomalyFlags").value("NONE"));
    }

    @Test
    void emptyResultReturnsZeroElements() throws Exception {
        mockMvc.perform(get("/api/v1/security/events")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.content").isArray())
            .andExpect(jsonPath("$.content", hasSize(0)))
            .andExpect(jsonPath("$.totalElements").value(0))
            .andExpect(jsonPath("$.totalPages").value(0));
    }

    @Test
    void paginationBoundariesAndDeterministicOrdering() throws Exception {
        Instant baseTime = Instant.now().minus(10, ChronoUnit.MINUTES);
        for (int i = 0; i < 5; i++) {
            ApiEvent e = new ApiEvent(
                UUID.randomUUID(),
                "corr-order-" + i,
                baseTime.plus(i, ChronoUnit.MINUTES),
                "10.0.0." + i,
                "POST",
                "/api/v1/customers",
                "/customers",
                200,
                10L + i,
                "user-" + i,
                "ROLE_CUSTOMER",
                "cust-" + i,
                "agent",
                "hash-" + i,
                "NONE"
            );
            apiEventRepository.save(e);
        }

        // Page 0, Size 2 with httpMethod=POST filter: Must return most recent 2 events (corr-order-4, corr-order-3)
        mockMvc.perform(get("/api/v1/security/events?page=0&size=2&httpMethod=POST")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").value(2))
            .andExpect(jsonPath("$.totalElements").value(5))
            .andExpect(jsonPath("$.totalPages").value(3))
            .andExpect(jsonPath("$.hasNext").value(true))
            .andExpect(jsonPath("$.hasPrevious").value(false))
            .andExpect(jsonPath("$.content", hasSize(2)))
            .andExpect(jsonPath("$.content[0].correlationId").value("corr-order-4"))
            .andExpect(jsonPath("$.content[1].correlationId").value("corr-order-3"));

        // Page 1, Size 2 with httpMethod=POST filter: Next 2 events (corr-order-2, corr-order-1)
        mockMvc.perform(get("/api/v1/security/events?page=1&size=2&httpMethod=POST")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.page").value(1))
            .andExpect(jsonPath("$.size").value(2))
            .andExpect(jsonPath("$.hasNext").value(true))
            .andExpect(jsonPath("$.hasPrevious").value(true))
            .andExpect(jsonPath("$.content[0].correlationId").value("corr-order-2"))
            .andExpect(jsonPath("$.content[1].correlationId").value("corr-order-1"));

        // Negative page / excessive size bounded automatically
        mockMvc.perform(get("/api/v1/security/events?page=-5&size=500&httpMethod=POST")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.page").value(0))
            .andExpect(jsonPath("$.size").value(100)); // Capped at max 100
    }

    @Test
    void authorizationBypassAttemptsRejected() throws Exception {
        // Attempt 1: Manipulating query param ?role=SECURITY_ANALYST with Customer token
        mockMvc.perform(get("/api/v1/security/events?role=SECURITY_ANALYST")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403));

        // Attempt 2: Manipulating X-Aegis-User-Roles header with Customer token
        mockMvc.perform(get("/api/v1/security/events")
                .header("X-Aegis-User-Roles", "ROLE_SECURITY_ANALYST")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void gatewayRoutingAndIdentityPropagation() throws Exception {
        // Test alternate path /security/events
        mockMvc.perform(get("/security/events")
                .header("X-Correlation-Id", "cid-routing-check")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(header().string("X-Correlation-Id", "cid-routing-check"));
    }

    @Test
    void failureHandlingWhenTelemetryDatabaseUnavailableReturns503() throws Exception {
        ApiEventRepository mockRepo = mock(ApiEventRepository.class);
        when(mockRepo.findEvents(anyInt(), anyInt(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
            .thenThrow(new DataAccessResourceFailureException("Database connection pool exhausted"));

        SecurityEventController controller = new SecurityEventController(mockRepo);
        MockMvc isolatedMockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        isolatedMockMvc.perform(get("/api/v1/security/events"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.status").value(503))
            .andExpect(jsonPath("$.title").value("Service Unavailable"))
            .andExpect(jsonPath("$.detail").value("Telemetry event store is currently unavailable"));
    }
}
