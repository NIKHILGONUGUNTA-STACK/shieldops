package com.aegis.gateway.specs;

import com.aegis.gateway.reconciliation.ApiReconciliationService;
import com.aegis.gateway.reconciliation.dto.ReconciliationCategory;
import com.aegis.gateway.reconciliation.dto.ReconciliationPageResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class FintechSpecificationBaselineTest {

    @Autowired
    private OpenApiParser parser;

    @Autowired
    private ApiSpecificationService specService;

    @Autowired
    private ApiReconciliationService reconciliationService;

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

    private byte[] loadSpecBytes(String filename) throws IOException {
        Path[] candidates = new Path[]{
            Paths.get("simulation", "specs", filename),
            Paths.get("..", "simulation", "specs", filename),
            Paths.get("C:", "Users", "nikhi", "aegis", "simulation", "specs", filename)
        };
        for (Path p : candidates) {
            if (Files.exists(p)) {
                return Files.readAllBytes(p);
            }
        }
        throw new IOException("Spec file not found in candidates: " + filename);
    }

    @Test
    @DisplayName("Customer Service OpenAPI specification parses cleanly with 2 operations")
    void testCustomerServiceSpec() throws Exception {
        byte[] bytes = loadSpecBytes("customer-service.yaml");
        OpenApiSpecData specData = parser.parseAndValidate(bytes, "customer-service.yaml");

        assertThat(specData).isNotNull();
        assertThat(specData.name()).isEqualTo("Customer Service API");
        assertThat(specData.version()).isEqualTo("1.0.0");
        assertThat(specData.openapiVersion()).isEqualTo("3.0.3");
        assertThat(specData.format()).isEqualTo("YAML");
        assertThat(specData.operationCount()).isEqualTo(2);

        List<DeclaredOperationData> ops = specData.operations();
        assertThat(ops).extracting(DeclaredOperationData::operationId)
            .containsExactlyInAnyOrder("getCustomer", "getCustomerProfile");
        assertThat(ops).allMatch(op -> "customer-service".equals(op.serviceBoundary()));
        assertThat(ops).extracting(DeclaredOperationData::normalizedRoute)
            .containsExactlyInAnyOrder("/api/v1/customers/{customerId}", "/api/v1/customers/{customerId}/profile");
    }

    @Test
    @DisplayName("Account Service OpenAPI specification parses cleanly with 3 operations")
    void testAccountServiceSpec() throws Exception {
        byte[] bytes = loadSpecBytes("account-service.yaml");
        OpenApiSpecData specData = parser.parseAndValidate(bytes, "account-service.yaml");

        assertThat(specData).isNotNull();
        assertThat(specData.name()).isEqualTo("Account Service API");
        assertThat(specData.version()).isEqualTo("1.0.0");
        assertThat(specData.openapiVersion()).isEqualTo("3.0.3");
        assertThat(specData.format()).isEqualTo("YAML");
        assertThat(specData.operationCount()).isEqualTo(3);

        List<DeclaredOperationData> ops = specData.operations();
        assertThat(ops).extracting(DeclaredOperationData::operationId)
            .containsExactlyInAnyOrder("listAccounts", "getAccount", "getAccountBalance");
        assertThat(ops).allMatch(op -> "account-service".equals(op.serviceBoundary()));
        assertThat(ops).extracting(DeclaredOperationData::normalizedRoute)
            .containsExactlyInAnyOrder("/api/v1/accounts", "/api/v1/accounts/{accountId}", "/api/v1/accounts/{accountId}/balance");
    }

    @Test
    @DisplayName("Transaction Service OpenAPI specification parses cleanly with 7 operations")
    void testTransactionServiceSpec() throws Exception {
        byte[] bytes = loadSpecBytes("transaction-service.yaml");
        OpenApiSpecData specData = parser.parseAndValidate(bytes, "transaction-service.yaml");

        assertThat(specData).isNotNull();
        assertThat(specData.name()).isEqualTo("Transaction Service API");
        assertThat(specData.version()).isEqualTo("1.0.0");
        assertThat(specData.openapiVersion()).isEqualTo("3.0.3");
        assertThat(specData.format()).isEqualTo("YAML");
        assertThat(specData.operationCount()).isEqualTo(7);

        List<DeclaredOperationData> ops = specData.operations();
        assertThat(ops).extracting(DeclaredOperationData::operationId)
            .containsExactlyInAnyOrder(
                "listBeneficiaries", "createBeneficiary", "getBeneficiary", "verifyBeneficiary",
                "listTransactions", "getTransaction", "executeTransfer"
            );
        assertThat(ops).allMatch(op -> "transaction-service".equals(op.serviceBoundary()));
        assertThat(ops).extracting(DeclaredOperationData::normalizedRoute)
            .containsExactlyInAnyOrder(
                "/api/v1/beneficiaries",
                "/api/v1/beneficiaries",
                "/api/v1/beneficiaries/{beneficiaryId}",
                "/api/v1/beneficiaries/{beneficiaryId}/verify",
                "/api/v1/transactions",
                "/api/v1/transactions/{transactionId}",
                "/api/v1/transfers"
            );
    }

    @Test
    @DisplayName("Import all 3 FinTech specifications into ApiSpecificationService and verify baseline reconciliation")
    void testImportAllAndReconcile() throws Exception {
        byte[] custBytes = loadSpecBytes("customer-service.yaml");
        byte[] acctBytes = loadSpecBytes("account-service.yaml");
        byte[] txBytes = loadSpecBytes("transaction-service.yaml");

        var custResp = specService.importSpecification(custBytes, "customer-service.yaml", "fintech-admin");
        var acctResp = specService.importSpecification(acctBytes, "account-service.yaml", "fintech-admin");
        var txResp = specService.importSpecification(txBytes, "transaction-service.yaml", "fintech-admin");

        assertThat(custResp.operationCount()).isEqualTo(2);
        assertThat(acctResp.operationCount()).isEqualTo(3);
        assertThat(txResp.operationCount()).isEqualTo(7);

        // Verify database persistence
        Integer specCount = jdbcClient.sql("SELECT count(*) FROM security_data.api_specifications").query(Integer.class).single();
        Integer opCount = jdbcClient.sql("SELECT count(*) FROM security_data.api_spec_operations").query(Integer.class).single();

        assertThat(specCount).isEqualTo(3);
        assertThat(opCount).isEqualTo(12);

        // Run reconciliation across all imported specs
        ReconciliationPageResponse reconciliation = reconciliationService.reconcile(
            0, 50, null, null, null, null, null, null, null, null, null, "priority", "desc"
        );

        assertThat(reconciliation).isNotNull();
        assertThat(reconciliation.summary().totalEvaluated()).isEqualTo(12);
        // Before traffic simulation, all 12 declared endpoints should be DOCUMENTED_UNOBSERVED
        assertThat(reconciliation.summary().documentedUnobservedCount()).isEqualTo(12);
        assertThat(reconciliation.summary().observedUndocumentedCount()).isEqualTo(0);
        assertThat(reconciliation.summary().matchedCount()).isEqualTo(0);
        assertThat(reconciliation.content()).hasSize(12);
        assertThat(reconciliation.content()).allMatch(item -> item.category() == ReconciliationCategory.DOCUMENTED_UNOBSERVED);
    }
}
