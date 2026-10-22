package com.aegis.gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CorrelationFilterTest {
    private CorrelationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new CorrelationFilter();
    }

    @Test
    void generatesCorrelationIdWhenMissing() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/customers");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String correlationId = response.getHeader(CorrelationFilter.CORRELATION_ID_HEADER);
        assertThat(correlationId).isNotBlank();
        assertThat(UUID.fromString(correlationId)).isNotNull();
    }

    @Test
    void preservesValidIncomingCorrelationId() throws Exception {
        String existing = "req-custom-trace-12345";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/customers");
        request.addHeader(CorrelationFilter.CORRELATION_ID_HEADER, existing);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getHeader(CorrelationFilter.CORRELATION_ID_HEADER)).isEqualTo(existing);
    }

    @Test
    void replacesInvalidCorrelationIdContainingIllegalCharacters() throws Exception {
        String invalid = "bad<script>alert(1)</script>";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/customers");
        request.addHeader(CorrelationFilter.CORRELATION_ID_HEADER, invalid);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String result = response.getHeader(CorrelationFilter.CORRELATION_ID_HEADER);
        assertThat(result).isNotEqualTo(invalid);
        assertThat(UUID.fromString(result)).isNotNull();
    }
}
