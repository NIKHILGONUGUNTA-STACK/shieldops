package com.aegis.customer.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class InternalTrustFilterTest {
    private static final String SECRET = "test-secret-key-for-unit-tests-32chars!";
    private InternalTrustFilter filter;

    @BeforeEach
    void setUp() {
        filter = new InternalTrustFilter(SECRET, true, new ObjectMapper());
    }

    @Test
    void rejectsDirectRequestWithoutSignatureHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/customers/10000000-0000-4000-8000-000000000001");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentAsString()).contains("Gateway trust attestation missing or invalid");
    }

    @Test
    void rejectsRequestWithInvalidSignature() throws Exception {
        String correlationId = UUID.randomUUID().toString();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/customers/10000000-0000-4000-8000-000000000001");
        request.addHeader(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);
        request.addHeader(TrustTokenUtils.SIGNATURE_HEADER, "t=1700000000;sig=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentAsString()).contains("Gateway trust attestation missing or invalid");
    }

    @Test
    void allowsRequestWithValidSignature() throws Exception {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-123";
        String path = "/customers/10000000-0000-4000-8000-000000000001";
        String validHeader = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, "10000000-0000-4000-8000-000000000001", "CUSTOMER", "GET", path, SECRET
        );

        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.addHeader(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);
        request.addHeader(TrustTokenUtils.USER_ID_HEADER, userId);
        request.addHeader(TrustTokenUtils.CUSTOMER_ID_HEADER, "10000000-0000-4000-8000-000000000001");
        request.addHeader(TrustTokenUtils.ROLES_HEADER, "CUSTOMER");
        request.addHeader(TrustTokenUtils.SIGNATURE_HEADER, validHeader);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getHeader(TrustTokenUtils.CORRELATION_ID_HEADER)).isEqualTo(correlationId);
    }

    @Test
    void rejectsRequestWhenMethodIsTampered() throws Exception {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-123";
        String path = "/customers/10000000-0000-4000-8000-000000000001";
        // Attestation signed for GET
        String headerSignedForGet = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, "10000000-0000-4000-8000-000000000001", "CUSTOMER", "GET", path, SECRET
        );

        // Attacker attempts POST with the GET attestation
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.addHeader(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);
        request.addHeader(TrustTokenUtils.USER_ID_HEADER, userId);
        request.addHeader(TrustTokenUtils.CUSTOMER_ID_HEADER, "10000000-0000-4000-8000-000000000001");
        request.addHeader(TrustTokenUtils.ROLES_HEADER, "CUSTOMER");
        request.addHeader(TrustTokenUtils.SIGNATURE_HEADER, headerSignedForGet);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentAsString()).contains("Gateway trust attestation missing or invalid");
    }

    @Test
    void rejectsRequestWhenPathIsTampered() throws Exception {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-123";
        // Attestation signed for customer 1
        String headerSignedForCust1 = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, "10000000-0000-4000-8000-000000000001", "CUSTOMER", "GET", "/customers/10000000-0000-4000-8000-000000000001", SECRET
        );

        // Attacker attempts to use on customer 2
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/customers/10000000-0000-4000-8000-000000000002");
        request.addHeader(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);
        request.addHeader(TrustTokenUtils.USER_ID_HEADER, userId);
        request.addHeader(TrustTokenUtils.CUSTOMER_ID_HEADER, "10000000-0000-4000-8000-000000000001");
        request.addHeader(TrustTokenUtils.ROLES_HEADER, "CUSTOMER");
        request.addHeader(TrustTokenUtils.SIGNATURE_HEADER, headerSignedForCust1);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentAsString()).contains("Gateway trust attestation missing or invalid");
    }

    @Test
    void rejectsRequestWhenRolesAreTampered() throws Exception {
        String correlationId = UUID.randomUUID().toString();
        String userId = "user-123";
        String path = "/customers/10000000-0000-4000-8000-000000000001";
        // Signed for CUSTOMER
        String header = TrustTokenUtils.buildAttestationHeader(
            correlationId, userId, "10000000-0000-4000-8000-000000000001", "CUSTOMER", "GET", path, SECRET
        );

        // Attacker claims SECURITY_ADMIN
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.addHeader(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);
        request.addHeader(TrustTokenUtils.USER_ID_HEADER, userId);
        request.addHeader(TrustTokenUtils.CUSTOMER_ID_HEADER, "10000000-0000-4000-8000-000000000001");
        request.addHeader(TrustTokenUtils.ROLES_HEADER, "SECURITY_ADMIN");
        request.addHeader(TrustTokenUtils.SIGNATURE_HEADER, header);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentAsString()).contains("Gateway trust attestation missing or invalid");
    }

    @Test
    void allowsActuatorHealthWithoutSignature() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health/readiness");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }
}
