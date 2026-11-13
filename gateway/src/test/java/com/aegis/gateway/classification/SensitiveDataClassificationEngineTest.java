package com.aegis.gateway.classification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SensitiveDataClassificationEngine Unit Tests")
class SensitiveDataClassificationEngineTest {

    private SensitiveDataClassificationEngine engine;

    @BeforeEach
    void setUp() {
        engine = new SensitiveDataClassificationEngine(null);
    }

    @Test
    @DisplayName("Should classify customer profile email as CONFIDENTIAL with confirmed confidence")
    void shouldClassifyCustomerProfileEmailAsConfidential() {
        FieldClassification fc = engine.classifyField(
            "customer-service", "GET", "/api/v1/customers/{customerId}/profile", "email"
        );

        assertThat(fc).isNotNull();
        assertThat(fc.dataClassification()).isEqualTo(DataSensitivityLevel.CONFIDENTIAL);
        assertThat(fc.confidence()).isEqualTo(ClassificationConfidence.CONFIRMED);
        assertThat(fc.resourceOwnershipRequirements()).isEqualTo(ResourceOwnershipRequirement.OWNER_CUSTOMER);
        assertThat(fc.approvedAccessRoles()).contains("CUSTOMER", "SECURITY_ANALYST");
        assertThat(fc.manualReviewRequired()).isFalse();
    }

    @Test
    @DisplayName("Should classify account balance as CONFIDENTIAL with customer ownership requirement")
    void shouldClassifyAccountBalanceAsConfidential() {
        FieldClassification fc = engine.classifyField(
            "account-service", "GET", "/api/v1/accounts/{accountId}/balance", "availableBalance"
        );

        assertThat(fc.dataClassification()).isEqualTo(DataSensitivityLevel.CONFIDENTIAL);
        assertThat(fc.resourceOwnershipRequirements()).isEqualTo(ResourceOwnershipRequirement.OWNER_CUSTOMER);
        assertThat(fc.fieldPath()).isEqualTo("availableBalance");
    }

    @Test
    @DisplayName("Should classify access token as RESTRICTED")
    void shouldClassifyAccessTokenAsRestricted() {
        FieldClassification fc = engine.classifyField(
            "external-gateway", "POST", "/realms/aegis-dev/protocol/openid-connect/token", "access_token"
        );

        assertThat(fc.dataClassification()).isEqualTo(DataSensitivityLevel.RESTRICTED);
        assertThat(fc.confidence()).isEqualTo(ClassificationConfidence.CONFIRMED);
    }

    @Test
    @DisplayName("Should classify unknown field as UNKNOWN with UNKNOWN confidence and manual review flag")
    void shouldClassifyUnknownFieldAsInternalUnknown() {
        FieldClassification fc = engine.classifyField(
            "custom-service", "GET", "/api/v1/unknown/resource", "unregisteredField"
        );

        assertThat(fc.dataClassification()).isEqualTo(DataSensitivityLevel.UNKNOWN);
        assertThat(fc.confidence()).isEqualTo(ClassificationConfidence.UNKNOWN);
        assertThat(fc.manualReviewRequired()).isTrue();
        assertThat(fc.schemaSource()).isEqualTo("UNCLASSIFIED_OBSERVATION");
    }

    @Test
    @DisplayName("Should resolve policy conflicts by prioritizing higher sensitivity level")
    void shouldResolvePolicyConflictsWithHigherPrecedence() {
        String route = "/api/v1/test/conflict";
        String method = "GET";
        String field = "secretScore";

        // Register initial rule as INTERNAL
        engine.registerRule(new FieldClassification(
            "test-service", method, route, field,
            DataSensitivityLevel.INTERNAL, "Initial internal policy",
            Set.of("SECURITY_ANALYST"), ResourceOwnershipRequirement.NONE,
            "TEST_RULE_V1", ClassificationConfidence.PROVISIONAL, "v1.0.0", false
        ));

        FieldClassification check1 = engine.classifyField("test-service", method, route, field);
        assertThat(check1.dataClassification()).isEqualTo(DataSensitivityLevel.INTERNAL);

        // Register competing rule as RESTRICTED -> Should upgrade
        engine.registerRule(new FieldClassification(
            "test-service", method, route, field,
            DataSensitivityLevel.RESTRICTED, "Confidentiality audit finding",
            Set.of("SECURITY_ADMIN"), ResourceOwnershipRequirement.INTERNAL_SERVICE,
            "AUDIT_RULE", ClassificationConfidence.CONFIRMED, "v1.0.1", false
        ));

        FieldClassification check2 = engine.classifyField("test-service", method, route, field);
        assertThat(check2.dataClassification()).isEqualTo(DataSensitivityLevel.RESTRICTED);
        assertThat(check2.confidence()).isEqualTo(ClassificationConfidence.CONFIRMED);

        // Register competing lower rule as PUBLIC -> Should NOT downgrade
        engine.registerRule(new FieldClassification(
            "test-service", method, route, field,
            DataSensitivityLevel.PUBLIC, "Erroneous public policy",
            Set.of(), ResourceOwnershipRequirement.NONE,
            "TEST_RULE_V2", ClassificationConfidence.PROVISIONAL, "v1.0.2", false
        ));

        FieldClassification check3 = engine.classifyField("test-service", method, route, field);
        assertThat(check3.dataClassification()).isEqualTo(DataSensitivityLevel.RESTRICTED);
    }

    @Test
    @DisplayName("Should match nested fields with wildcard pattern")
    void shouldMatchNestedFieldsWithWildcardPattern() {
        FieldClassification fc = engine.classifyField(
            "account-service", "GET", "/api/v1/accounts", "customer.firstName"
        );

        assertThat(fc.dataClassification()).isEqualTo(DataSensitivityLevel.CONFIDENTIAL);
        assertThat(fc.fieldPath()).isEqualTo("customer.firstName");
    }

    @Test
    @DisplayName("Should redact sensitive values according to data sensitivity level")
    void shouldRedactSensitiveValuesAppropriately() {
        // Restricted -> full redaction
        String redRestricted = engine.redactValue("access_token", "eyJhbGciOi...", DataSensitivityLevel.RESTRICTED);
        assertThat(redRestricted).isEqualTo("[REDACTED_RESTRICTED]");

        // Confidential email -> structural masking
        String redEmail = engine.redactValue("email", "alex.morgan@example.test", DataSensitivityLevel.CONFIDENTIAL);
        assertThat(redEmail).startsWith("a***@").endsWith(".test");

        // Confidential account number -> last 4 digits
        String redAcct = engine.redactValue("accountNumber", "ACCT-00010001", DataSensitivityLevel.CONFIDENTIAL);
        assertThat(redAcct).isEqualTo("****0001");

        // Confidential balance -> masked amount
        String redBal = engine.redactValue("balance", "12383.74", DataSensitivityLevel.CONFIDENTIAL);
        assertThat(redBal).isEqualTo("***.**");

        // Public -> unredacted
        String pub = engine.redactValue("status", "UP", DataSensitivityLevel.PUBLIC);
        assertThat(pub).isEqualTo("UP");
    }

    @Test
    @DisplayName("Should calculate accurate platform and service-level coverage metrics")
    void shouldCalculateAccurateCoverageMetrics() {
        SensitiveDataInventorySummary summary = engine.getSummary();

        assertThat(summary).isNotNull();
        assertThat(summary.totalMonitoredEndpoints()).isGreaterThan(0);
        assertThat(summary.totalClassifiedFields()).isGreaterThan(0);
        assertThat(summary.overallCoveragePercentage()).isGreaterThan(50.0);
        assertThat(summary.countsBySensitivity().get(DataSensitivityLevel.CONFIDENTIAL)).isGreaterThan(0);

        assertThat(summary.serviceWiseCoverage()).containsKey("customer-service");
        assertThat(summary.serviceWiseCoverage()).containsKey("account-service");
        assertThat(summary.serviceWiseCoverage()).containsKey("transaction-service");

        ServiceClassificationSummary custSummary = summary.serviceWiseCoverage().get("customer-service");
        assertThat(custSummary.totalEndpoints()).isGreaterThanOrEqualTo(2);
        assertThat(custSummary.coveragePercentage()).isGreaterThan(90.0);
    }

    @Test
    @DisplayName("Should retrieve endpoint classification details by ID")
    void shouldRetrieveEndpointClassificationDetailsById() {
        SensitiveDataInventoryPageResponse page = engine.getInventory(0, 5, "customer-service", null, null, null, null, "asc");
        assertThat(page.content()).isNotEmpty();

        String epId = page.content().get(0).id();
        Optional<EndpointDataClassification> details = engine.getEndpointDetails(epId);

        assertThat(details).isPresent();
        assertThat(details.get().id()).isEqualTo(epId);
        assertThat(details.get().fieldClassifications()).isNotEmpty();
    }
}

