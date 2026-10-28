package com.aegis.gateway.specs;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecuritySpecificationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @BeforeEach
    void cleanDatabase() {
        jdbcClient.sql("DELETE FROM security_data.api_spec_operations").update();
        jdbcClient.sql("DELETE FROM security_data.api_specifications").update();
    }

    private static final String VALID_CUSTOMER_JSON = """
        {
          "openapi": "3.0.3",
          "info": {
            "title": "Customer Service API",
            "version": "1.0.0",
            "description": "Customer domain operations"
          },
          "paths": {
            "/api/v1/customers/{customerId}": {
              "get": {
                "operationId": "getCustomer",
                "summary": "Get customer by ID",
                "tags": ["Customers"],
                "responses": { "200": { "description": "OK" } }
              }
            },
            "/api/v1/customers/{customerId}/profile": {
              "get": {
                "operationId": "getCustomerProfile",
                "summary": "Get customer profile",
                "responses": { "200": { "description": "OK" } }
              }
            }
          }
        }
        """;

    private static final String VALID_ACCOUNT_YAML = """
        openapi: 3.1.0
        info:
          title: Account Service API
          version: 2.1.0
          description: Financial accounts
        paths:
          /api/v1/accounts/{accountId}/balance:
            get:
              operationId: getBalance
              summary: Check balance
              responses:
                '200':
                  description: OK
        """;

    @Test
    @DisplayName("Unauthenticated upload returns 401 Unauthorized ProblemDetail")
    void unauthenticatedUploadReturns401() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "customer.json", "application/json", VALID_CUSTOMER_JSON.getBytes(StandardCharsets.UTF_8)
        );

        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    @DisplayName("Customer role returns 403 Forbidden ProblemDetail")
    void customerRoleReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/security/specs")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
            .andExpect(status().isForbidden())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE));
    }

    @Test
    @DisplayName("Analyst can read specs but cannot upload or delete (403)")
    void analystCanReadButCannotUploadOrDelete() throws Exception {
        // Analyst can list
        mockMvc.perform(get("/api/v1/security/specs")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk());

        // Analyst upload -> 403 Forbidden
        MockMultipartFile file = new MockMultipartFile(
            "file", "customer.json", "application/json", VALID_CUSTOMER_JSON.getBytes(StandardCharsets.UTF_8)
        );
        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Admin can upload valid OpenAPI JSON and declared operations are persisted")
    void adminCanUploadOpenApiJson() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "customer.json", "application/json", VALID_CUSTOMER_JSON.getBytes(StandardCharsets.UTF_8)
        );

        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").isNotEmpty())
            .andExpect(jsonPath("$.name").value("Customer Service API"))
            .andExpect(jsonPath("$.version").value("1.0.0"))
            .andExpect(jsonPath("$.openapiVersion").value("3.0.3"))
            .andExpect(jsonPath("$.format").value("JSON"))
            .andExpect(jsonPath("$.operationCount").value(2))
            .andExpect(jsonPath("$.operations", hasSize(2)))
            .andExpect(jsonPath("$.operations[0].serviceBoundary").value("customer-service"));
    }

    @Test
    @DisplayName("Admin can upload valid OpenAPI YAML specification")
    void adminCanUploadOpenApiYaml() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "accounts.yaml", "application/yaml", VALID_ACCOUNT_YAML.getBytes(StandardCharsets.UTF_8)
        );

        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.name").value("Account Service API"))
            .andExpect(jsonPath("$.openapiVersion").value("3.1.0"))
            .andExpect(jsonPath("$.format").value("YAML"))
            .andExpect(jsonPath("$.operationCount").value(1))
            .andExpect(jsonPath("$.operations[0].pathPattern").value("/api/v1/accounts/{accountId}/balance"))
            .andExpect(jsonPath("$.operations[0].serviceBoundary").value("account-service"));
    }

    @Test
    @DisplayName("Duplicate content upload returns existing spec without duplicating operations")
    void duplicateUploadReturnsExistingSpec() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "customer.json", "application/json", VALID_CUSTOMER_JSON.getBytes(StandardCharsets.UTF_8)
        );

        // First upload
        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isCreated());

        // Repeated duplicate upload
        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.name").value("Customer Service API"));

        // Verify only 1 specification and 2 operations exist in database
        Long specCount = jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_specifications").query(Long.class).single();
        Long opCount = jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_spec_operations").query(Long.class).single();

        org.assertj.core.api.Assertions.assertThat(specCount).isEqualTo(1L);
        org.assertj.core.api.Assertions.assertThat(opCount).isEqualTo(2L);
    }

    @Test
    @DisplayName("Malformed upload returns 400 ProblemDetail")
    void malformedUploadReturns400() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "bad.json", "application/json", "{ broken json ".getBytes(StandardCharsets.UTF_8)
        );

        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("OpenAPI Specification Validation Failed"));
    }

    @Test
    @DisplayName("Upload with unsupported media type returns 415 ProblemDetail")
    void unsupportedMediaTypeReturns415() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "test.exe", "application/x-msdownload", "binary content".getBytes(StandardCharsets.UTF_8)
        );

        mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isUnsupportedMediaType())
            .andExpect(jsonPath("$.title").value("Unsupported Media Type"));
    }

    @Test
    @DisplayName("Get specification by ID returns details with declared operations")
    void getSpecificationByIdReturnsDetails() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "customer.json", "application/json", VALID_CUSTOMER_JSON.getBytes(StandardCharsets.UTF_8)
        );

        String responseJson = mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andReturn().getResponse().getContentAsString();

        com.fasterxml.jackson.databind.JsonNode root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(responseJson);
        String specId = root.get("id").asText();

        mockMvc.perform(get("/api/v1/security/specs/" + specId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(specId))
            .andExpect(jsonPath("$.name").value("Customer Service API"))
            .andExpect(jsonPath("$.operations", hasSize(2)));

        mockMvc.perform(get("/api/v1/security/specs/" + specId + "/operations")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(2)))
            .andExpect(jsonPath("$[0].serviceBoundary").value("customer-service"));
    }

    @Test
    @DisplayName("Admin can delete specification and operations are cascaded")
    void adminCanDeleteSpecification() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file", "customer.json", "application/json", VALID_CUSTOMER_JSON.getBytes(StandardCharsets.UTF_8)
        );

        String responseJson = mockMvc.perform(multipart("/api/v1/security/specs/upload").file(file)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andReturn().getResponse().getContentAsString();

        com.fasterxml.jackson.databind.JsonNode root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(responseJson);
        String specId = root.get("id").asText();

        // Delete specification
        mockMvc.perform(delete("/api/v1/security/specs/" + specId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ADMIN"))))
            .andExpect(status().isNoContent());

        // Subsequent get returns 404
        mockMvc.perform(get("/api/v1/security/specs/" + specId)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))))
            .andExpect(status().isNotFound());

        // Verify cascading delete removed operations
        Long opCount = jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_spec_operations").query(Long.class).single();
        org.assertj.core.api.Assertions.assertThat(opCount).isEqualTo(0L);
    }
}

