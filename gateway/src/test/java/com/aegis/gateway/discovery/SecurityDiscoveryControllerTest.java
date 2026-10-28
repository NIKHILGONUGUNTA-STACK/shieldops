package com.aegis.gateway.discovery;

import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityDiscoveryControllerTest {

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
    @DisplayName("Unauthenticated request returns 401 Unauthorized ProblemDetail")
    void unauthenticatedRequestReturns401() throws Exception {
        mockMvc.perform(get("/api/v1/security/discovery/endpoints"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    @DisplayName("Unauthorized role (ROLE_CUSTOMER) returns 403 Forbidden ProblemDetail")
    void unauthorizedRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/discovery/endpoints")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    @DisplayName("Empty database returns empty list and 0 totals without error")
    void emptyDatabaseReturnsEmptyResponse() throws Exception {
        mockMvc.perform(get("/api/v1/security/discovery/endpoints")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
            .andExpect(jsonPath("$.content", hasSize(0)))
            .andExpect(jsonPath("$.totalElements").value(0))
            .andExpect(jsonPath("$.totalObservedEndpoints").value(0))
            .andExpect(jsonPath("$.totalObservedRequests").value(0))
            .andExpect(jsonPath("$.totalMonitoredServices").value(0));
    }

    @Test
    @DisplayName("Aggregates multiple concrete UUID requests into single normalized endpoint with accurate counts")
    void aggregatesConcreteRequestsIntoSingleNormalizedEndpoint() throws Exception {
        Instant t1 = Instant.now().minus(10, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS);
        Instant t2 = Instant.now().minus(5, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS);
        Instant t3 = Instant.now().minus(1, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS);

        // 3 requests to customer profile with different customer UUIDs
        ApiEvent e1 = new ApiEvent(
            UUID.randomUUID(), "cid-1", t1, "10.0.0.1", "GET",
            "/api/v1/customers/00000000-0000-0000-0000-000000000001/profile",
            "/api/v1/customers/{customerId}/profile",
            200, 30L, "sub1", "ROLE_CUSTOMER", "00000000-0000-0000-0000-000000000001",
            "agent", "hash", "NONE"
        );
        ApiEvent e2 = new ApiEvent(
            UUID.randomUUID(), "cid-2", t2, "10.0.0.2", "GET",
            "/api/v1/customers/00000000-0000-0000-0000-000000000002/profile",
            "/api/v1/customers/{customerId}/profile",
            200, 45L, "sub2", "ROLE_CUSTOMER", "00000000-0000-0000-0000-000000000002",
            "agent", "hash", "NONE"
        );
        ApiEvent e3 = new ApiEvent(
            UUID.randomUUID(), "cid-3", t3, "10.0.0.3", "GET",
            "/api/v1/customers/00000000-0000-0000-0000-000000000003/profile",
            "/api/v1/customers/{customerId}/profile",
            403, 15L, "attacker", "ROLE_CUSTOMER", "00000000-0000-0000-0000-000000000003",
            "curl", "hash", "FORBIDDEN_ATTEMPT"
        );

        apiEventRepository.save(e1);
        apiEventRepository.save(e2);
        apiEventRepository.save(e3);

        mockMvc.perform(get("/api/v1/security/discovery/endpoints")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.totalObservedEndpoints").value(1))
            .andExpect(jsonPath("$.totalObservedRequests").value(3))
            .andExpect(jsonPath("$.totalMonitoredServices").value(1))
            .andExpect(jsonPath("$.content[0].httpMethod").value("GET"))
            .andExpect(jsonPath("$.content[0].routeTemplate").value("/api/v1/customers/{customerId}/profile"))
            .andExpect(jsonPath("$.content[0].serviceName").value("customer-service"))
            .andExpect(jsonPath("$.content[0].totalRequests").value(3))
            .andExpect(jsonPath("$.content[0].statusDistribution['2xx']").value(2))
            .andExpect(jsonPath("$.content[0].statusDistribution['4xx']").value(1))
            .andExpect(jsonPath("$.content[0].statusDistribution['5xx']").value(0))
            .andExpect(jsonPath("$.content[0].firstObservedAt").value(t1.toString()))
            .andExpect(jsonPath("$.content[0].lastObservedAt").value(t3.toString()));
    }

    @Test
    @DisplayName("Distinguishes different HTTP methods on the same route template")
    void distinguishesDifferentHttpMethodsOnSameRoute() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        ApiEvent getBen = new ApiEvent(
            UUID.randomUUID(), "cid-ben-1", now.minus(5, ChronoUnit.MINUTES), "10.0.0.1", "GET",
            "/api/v1/beneficiaries", "/api/v1/beneficiaries", 200, 20L, "user1", "ROLE_CUSTOMER",
            "cust1", "agent", "hash", "NONE"
        );
        ApiEvent postBen = new ApiEvent(
            UUID.randomUUID(), "cid-ben-2", now.minus(2, ChronoUnit.MINUTES), "10.0.0.1", "POST",
            "/api/v1/beneficiaries", "/api/v1/beneficiaries", 201, 55L, "user1", "ROLE_CUSTOMER",
            "cust1", "agent", "hash", "NONE"
        );

        apiEventRepository.save(getBen);
        apiEventRepository.save(postBen);

        // Fetch all endpoints: should find 2 distinct endpoints
        mockMvc.perform(get("/api/v1/security/discovery/endpoints")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(2))
            .andExpect(jsonPath("$.content[*].httpMethod", containsInAnyOrder("GET", "POST")))
            .andExpect(jsonPath("$.content[0].serviceName").value("transaction-service"))
            .andExpect(jsonPath("$.content[1].serviceName").value("transaction-service"));

        // Filter by method=POST
        mockMvc.perform(get("/api/v1/security/discovery/endpoints?method=POST")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].httpMethod").value("POST"))
            .andExpect(jsonPath("$.content[0].routeTemplate").value("/api/v1/beneficiaries"));
    }

    @Test
    @DisplayName("Filters endpoints by service name and search keyword")
    void filtersByServiceAndSearch() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        ApiEvent custEvent = new ApiEvent(
            UUID.randomUUID(), "cid-c", now.minus(3, ChronoUnit.MINUTES), "10.0.0.1", "GET",
            "/api/v1/customers/00000000-0000-0000-0000-000000000001", "/api/v1/customers/{customerId}",
            200, 20L, "u1", "ROLE_CUSTOMER", "c1", "agent", "hash", "NONE"
        );
        ApiEvent acctEvent = new ApiEvent(
            UUID.randomUUID(), "cid-a", now.minus(1, ChronoUnit.MINUTES), "10.0.0.1", "GET",
            "/api/v1/accounts/ACCT-1001/balance", "/api/v1/accounts/{accountId}/balance",
            200, 25L, "u1", "ROLE_CUSTOMER", "c1", "agent", "hash", "NONE"
        );

        apiEventRepository.save(custEvent);
        apiEventRepository.save(acctEvent);

        // Filter service=customer-service
        mockMvc.perform(get("/api/v1/security/discovery/endpoints?service=customer-service")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].serviceName").value("customer-service"));

        // Search query matching "balance"
        mockMvc.perform(get("/api/v1/security/discovery/endpoints?search=balance")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.totalElements").value(1))
            .andExpect(jsonPath("$.content[0].routeTemplate").value("/api/v1/accounts/{accountId}/balance"));
    }

    @Test
    @DisplayName("Validates pagination parameters rejecting invalid bounds")
    void validatesPaginationBounds() throws Exception {
        mockMvc.perform(get("/api/v1/security/discovery/endpoints?page=-1")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Invalid Pagination Parameter"));

        mockMvc.perform(get("/api/v1/security/discovery/endpoints?size=200")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Invalid Pagination Parameter"));
    }

    @Test
    @DisplayName("Retrieves single endpoint by ID successfully or returns 404 when absent")
    void retrievesSingleEndpointById() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        ApiEvent event = new ApiEvent(
            UUID.randomUUID(), "cid-single", now, "10.0.0.1", "POST",
            "/api/v1/transfers", "/api/v1/transfers", 200, 75L, "u1", "ROLE_CUSTOMER",
            "c1", "agent", "hash", "NONE"
        );
        apiEventRepository.save(event);

        String endpointId = RouteNormalizer.generateEndpointId("POST", "/api/v1/transfers");

        mockMvc.perform(get("/api/v1/security/discovery/endpoints/" + endpointId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(endpointId))
            .andExpect(jsonPath("$.httpMethod").value("POST"))
            .andExpect(jsonPath("$.routeTemplate").value("/api/v1/transfers"))
            .andExpect(jsonPath("$.serviceName").value("transaction-service"));

        mockMvc.perform(get("/api/v1/security/discovery/endpoints/ep_nonexistent9999")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.title").value("Endpoint Not Found"));
    }
}
