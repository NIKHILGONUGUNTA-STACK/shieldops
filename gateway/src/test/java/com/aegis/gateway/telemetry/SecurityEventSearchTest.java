package com.aegis.gateway.telemetry;

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
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityEventSearchTest {

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
    void searchByMultipleFiltersReturnsMatchingEvents() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();

        ApiEvent event1 = new ApiEvent(
            id1, "cid-001", now.minus(5, ChronoUnit.MINUTES), "192.168.1.10", "POST",
            "/api/v1/customers", "/customers", 403, 25L, "attacker", "ROLE_CUSTOMER",
            "10000000-0000-4000-8000-000000000001", "Mozilla/5.0", "hash1",
            "FORBIDDEN_ATTEMPT", "CUSTOMER", "10000000-0000-4000-8000-000000000002",
            "BOLA_VIOLATION", 150L, 0
        );

        ApiEvent event2 = new ApiEvent(
            id2, "cid-002", now.minus(2, ChronoUnit.MINUTES), "10.0.0.5", "GET",
            "/api/v1/accounts", "/accounts", 200, 15L, "legit-user", "ROLE_CUSTOMER",
            "10000000-0000-4000-8000-000000000002", "curl/7.68", "hash2",
            "NONE", "ACCOUNT", "20000000-0000-4000-8000-000000000001",
            null, 350L, 2
        );

        apiEventRepository.save(event1);
        apiEventRepository.save(event2);

        // Filter by customerId
        mockMvc.perform(get("/api/v1/security/events?customerId=10000000-0000-4000-8000-000000000001")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(id1.toString()))
            .andExpect(jsonPath("$.content[0].resourceType").value("CUSTOMER"))
            .andExpect(jsonPath("$.content[0].errorCode").value("BOLA_VIOLATION"));

        // Filter by sourceIp
        mockMvc.perform(get("/api/v1/security/events?sourceIp=10.0.0.5")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(id2.toString()));

        // Filter by anomalyFlags
        mockMvc.perform(get("/api/v1/security/events?anomalyFlags=FORBIDDEN")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(id1.toString()));

        // Filter by correlationId
        mockMvc.perform(get("/api/v1/security/events?correlationId=cid-002")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].id").value(id2.toString()));
    }

    @Test
    void searchWithDateRangeFiltering() throws Exception {
        Instant base = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        ApiEvent e1 = new ApiEvent(
            UUID.randomUUID(), "cid-time-1", base.minus(3, ChronoUnit.HOURS), "192.168.1.1", "GET",
            "/api/v1/customers", "/customers", 200, 10L, "u1", "ROLE_CUSTOMER",
            "c1", "agent", "hash", "NONE", null, null, null, 0L, 0
        );
        ApiEvent e2 = new ApiEvent(
            UUID.randomUUID(), "cid-time-2", base.minus(1, ChronoUnit.HOURS), "192.168.1.1", "GET",
            "/api/v1/customers", "/customers", 200, 10L, "u1", "ROLE_CUSTOMER",
            "c1", "agent", "hash", "NONE", null, null, null, 0L, 0
        );
        apiEventRepository.save(e1);
        apiEventRepository.save(e2);

        String from = base.minus(2, ChronoUnit.HOURS).toString();
        String to = base.toString();

        mockMvc.perform(get("/api/v1/security/events?from=" + from + "&to=" + to)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].correlationId").value("cid-time-2"));
    }

    @Test
    void searchWithInvalidDateRangeReturns400BadRequest() throws Exception {
        Instant now = Instant.now();
        String from = now.toString();
        String to = now.minus(1, ChronoUnit.HOURS).toString(); // from is after to

        mockMvc.perform(get("/api/v1/security/events?from=" + from + "&to=" + to)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.title").value("Bad Request"))
            .andExpect(jsonPath("$.detail").value(containsString("must not be after")));
    }

    @Test
    void searchWithMalformedDateReturns400BadRequest() throws Exception {
        mockMvc.perform(get("/api/v1/security/events?from=not-a-timestamp")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.status").value(400))
            .andExpect(jsonPath("$.title").value("Bad Request"));
    }

    @Test
    void getSecurityEventByIdSuccess() throws Exception {
        UUID eventId = UUID.randomUUID();
        ApiEvent event = new ApiEvent(
            eventId, "cid-single-lookup", Instant.now(), "10.0.0.99", "GET",
            "/api/v1/customers/profile", "/customers", 200, 12L, "alex", "ROLE_CUSTOMER",
            "c-alex", "Mozilla/5.0", "hash-single", "NONE", "CUSTOMER", "cust-1", null, 250L, 1
        );
        apiEventRepository.save(event);

        mockMvc.perform(get("/api/v1/security/events/" + eventId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(eventId.toString()))
            .andExpect(jsonPath("$.correlationId").value("cid-single-lookup"))
            .andExpect(jsonPath("$.sourceIp").value("10.0.0.99"))
            .andExpect(jsonPath("$.resourceType").value("CUSTOMER"))
            .andExpect(jsonPath("$.resourceId").value("cust-1"));
    }

    @Test
    void getSecurityEventByIdNotFoundReturns404() throws Exception {
        UUID nonExistentId = UUID.randomUUID();
        mockMvc.perform(get("/api/v1/security/events/" + nonExistentId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status").value(404))
            .andExpect(jsonPath("$.title").value("Not Found"));
    }

    @Test
    void getSecurityEventByInvalidUuidFormatReturns404() throws Exception {
        mockMvc.perform(get("/api/v1/security/events/invalid-uuid-string")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.status").value(404));
    }
}
