package com.aegis.gateway.specs;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OpenApiParserTest {

    private OpenApiParser parser;

    @BeforeEach
    void setUp() {
        parser = new OpenApiParser();
    }

    @Test
    @DisplayName("Successfully parses valid OpenAPI 3.0.3 JSON document")
    void parsesValidOpenApi30Json() {
        String json = """
            {
              "openapi": "3.0.3",
              "info": {
                "title": "Customer Service API",
                "version": "1.2.0",
                "description": "Production customer management endpoints"
              },
              "paths": {
                "/api/v1/customers/{customerId}": {
                  "get": {
                    "operationId": "getCustomerById",
                    "summary": "Get customer by UUID",
                    "tags": ["Customers", "Profiles"],
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

        OpenApiSpecData data = parser.parseAndValidate(json.getBytes(StandardCharsets.UTF_8), "customer-api.json");

        assertThat(data.name()).isEqualTo("Customer Service API");
        assertThat(data.version()).isEqualTo("1.2.0");
        assertThat(data.openapiVersion()).isEqualTo("3.0.3");
        assertThat(data.format()).isEqualTo("JSON");
        assertThat(data.pathCount()).isEqualTo(2);
        assertThat(data.operationCount()).isEqualTo(2);
        assertThat(data.contentHash()).isNotBlank();

        DeclaredOperationData op1 = data.operations().get(0);
        assertThat(op1.httpMethod()).isEqualTo("GET");
        assertThat(op1.pathPattern()).isEqualTo("/api/v1/customers/{customerId}");
        assertThat(op1.normalizedRoute()).isEqualTo("/api/v1/customers/{customerId}");
        assertThat(op1.serviceBoundary()).isEqualTo("customer-service");
        assertThat(op1.tags()).isEqualTo("Customers, Profiles");
    }

    @Test
    @DisplayName("Successfully parses valid OpenAPI 3.1.0 YAML document")
    void parsesValidOpenApi31Yaml() {
        String yaml = """
            openapi: 3.1.0
            info:
              title: Account Service API
              version: 2.0.1
              description: Account and balance management
            paths:
              /api/v1/accounts/{accountId}/balance:
                get:
                  operationId: getAccountBalance
                  summary: Fetch live account balance
                  tags:
                    - Accounts
                  responses:
                    '200':
                      description: Successful balance retrieval
              /api/v1/transfers:
                post:
                  operationId: executeTransfer
                  summary: Execute financial transfer
                  responses:
                    '201':
                      description: Created
            """;

        OpenApiSpecData data = parser.parseAndValidate(yaml.getBytes(StandardCharsets.UTF_8), "account-api.yaml");

        assertThat(data.name()).isEqualTo("Account Service API");
        assertThat(data.version()).isEqualTo("2.0.1");
        assertThat(data.openapiVersion()).isEqualTo("3.1.0");
        assertThat(data.format()).isEqualTo("YAML");
        assertThat(data.operationCount()).isEqualTo(2);

        DeclaredOperationData transferOp = data.operations().stream()
            .filter(o -> o.pathPattern().equals("/api/v1/transfers"))
            .findFirst().orElseThrow();
        assertThat(transferOp.httpMethod()).isEqualTo("POST");
        assertThat(transferOp.serviceBoundary()).isEqualTo("transaction-service");
    }

    @Test
    @DisplayName("Rejects unsupported Swagger 2.0 documents")
    void rejectsSwagger20() {
        String swagger2 = """
            {
              "swagger": "2.0",
              "info": { "title": "Old API", "version": "1.0" },
              "paths": {}
            }
            """;

        assertThatThrownBy(() -> parser.parseAndValidate(swagger2.getBytes(StandardCharsets.UTF_8), "legacy.json"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Unsupported Swagger 2.0");
    }

    @Test
    @DisplayName("Rejects unsupported OpenAPI 4.x versions")
    void rejectsOpenApi4() {
        String openapi4 = """
            {
              "openapi": "4.0.0",
              "info": { "title": "Future API", "version": "1.0" },
              "paths": {}
            }
            """;

        assertThatThrownBy(() -> parser.parseAndValidate(openapi4.getBytes(StandardCharsets.UTF_8), "future.json"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Unsupported OpenAPI version: '4.0.0'");
    }

    @Test
    @DisplayName("Rejects documents with missing required info or paths")
    void rejectsMissingRequiredFields() {
        String missingInfo = """
            {
              "openapi": "3.0.3",
              "paths": {}
            }
            """;
        assertThatThrownBy(() -> parser.parseAndValidate(missingInfo.getBytes(StandardCharsets.UTF_8), "no-info.json"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Missing required 'info' object");

        String missingPaths = """
            {
              "openapi": "3.0.3",
              "info": { "title": "Test", "version": "1.0" }
            }
            """;
        assertThatThrownBy(() -> parser.parseAndValidate(missingPaths.getBytes(StandardCharsets.UTF_8), "no-paths.json"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Missing required 'paths' object");
    }

    @Test
    @DisplayName("Rejects unsafe remote $ref URL references")
    void rejectsRemoteRefUrls() {
        String remoteRef = """
            {
              "openapi": "3.0.3",
              "info": { "title": "Malicious Ref API", "version": "1.0" },
              "paths": {
                "/api/test": {
                  "get": {
                    "responses": {
                      "200": {
                        "$ref": "https://attacker.com/schemas/exploit.json"
                      }
                    }
                  }
                }
              }
            }
            """;

        assertThatThrownBy(() -> parser.parseAndValidate(remoteRef.getBytes(StandardCharsets.UTF_8), "exploit.json"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Unsafe external $ref reference detected");
    }

    @Test
    @DisplayName("Rejects unsafe external file references")
    void rejectsExternalFileRefs() {
        String fileRef = """
            openapi: 3.0.3
            info:
              title: File Traversal API
              version: 1.0
            paths:
              /api/test:
                get:
                  responses:
                    '200':
                      $ref: '../../etc/passwd.yaml'
            """;

        assertThatThrownBy(() -> parser.parseAndValidate(fileRef.getBytes(StandardCharsets.UTF_8), "traversal.yaml"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Unsafe external file reference detected");
    }

    @Test
    @DisplayName("Rejects malformed syntax")
    void rejectsMalformedSyntax() {
        String malformed = "{ openapi: 3.0.0, info: broken json ";
        assertThatThrownBy(() -> parser.parseAndValidate(malformed.getBytes(StandardCharsets.UTF_8), "broken.json"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Malformed");
    }

    @Test
    @DisplayName("Rejects empty or blank specification file")
    void rejectsEmptyContent() {
        assertThatThrownBy(() -> parser.parseAndValidate(new byte[0], "empty.yaml"))
            .isInstanceOf(OpenApiValidationException.class)
            .hasMessageContaining("Empty specification file provided");
    }
}

