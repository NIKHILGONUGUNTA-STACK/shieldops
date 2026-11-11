package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.classification.DataSensitivityLevel;
import com.aegis.gateway.classification.EndpointDataClassification;
import com.aegis.gateway.classification.SensitiveDataClassificationEngine;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.rules.DetectionRule;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RULE-BOLA-CONFIRMED-01: Confirmed Broken Object Level Authorization (BOLA) Data Leakage.
 * Triggers when a caller receives a successful HTTP 200 response for a resource explicitly owned by
 * another customer, without holding administrative or security analyst privileges.
 */
@Component
public class RuleBolaConfirmed01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleBolaConfirmed01.class);

    public static final String RULE_ID = "RULE-BOLA-CONFIRMED-01";
    public static final String RULE_VERSION = "1.0.0";

    private static final Pattern CUST_PATH_PATTERN = Pattern.compile("^/(api/v1/)?customers/([0-9a-fA-F-]+)(/profile)?");
    private static final Pattern ACCT_PATH_PATTERN = Pattern.compile("^/(api/v1/)?accounts/([0-9a-fA-F-]+|ACCT-[a-zA-Z0-9_-]+)(/balance)?");
    private static final Pattern TX_PATH_PATTERN = Pattern.compile("^/(api/v1/)?(transactions|transfers)/([0-9a-fA-F-]+)");

    private final SensitiveDataClassificationEngine classificationEngine;
    private final boolean enabled;

    @Autowired
    public RuleBolaConfirmed01(
            SensitiveDataClassificationEngine classificationEngine,
            @Value("${aegis.detection.rules.bola-confirmed.enabled:true}") boolean enabled) {
        this.classificationEngine = classificationEngine;
        this.enabled = enabled;
    }

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getRuleVersion() {
        return RULE_VERSION;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public RuleEvaluationResult evaluate(ApiEvent event) {
        if (!enabled || event == null) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 1. Must be a successful response (HTTP 200)
        if (event.statusCode() != 200) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Caller must have an authenticated customer identity
        String callerCustomerId = event.customerId();
        if (callerCustomerId == null || callerCustomerId.isBlank() || "anonymous".equalsIgnoreCase(callerCustomerId)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Exclude privileged security analysts and administrators
        String roles = event.authRoles() != null ? event.authRoles().toUpperCase() : "";
        if (roles.contains("SECURITY_ANALYST") || roles.contains("SECURITY_ADMIN") || roles.contains("INTERNAL_SERVICE")) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 4. Extract target resource ID and check cross-owner condition
        String requestPath = event.requestPath() != null ? event.requestPath() : "";
        String targetResourceId = event.resourceId() != null && !event.resourceId().isBlank()
            ? event.resourceId().trim()
            : extractResourceId(requestPath);

        if (targetResourceId == null || targetResourceId.isBlank()) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        boolean isCrossOwner = isCrossOwnerAccess(callerCustomerId.trim(), targetResourceId, event.resourceType(), requestPath);
        if (!isCrossOwner) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 5. Verify sensitivity classification
        String method = event.httpMethod() != null ? event.httpMethod().toUpperCase() : "GET";
        String routeTemplate = event.routeId() != null && !event.routeId().isBlank() ? event.routeId() : requestPath;
        EndpointDataClassification classification = classificationEngine.classifyEndpoint(method, routeTemplate);

        DataSensitivityLevel sensitivity = classification != null && classification.highestSensitivityLevel() != null
            ? classification.highestSensitivityLevel()
            : DataSensitivityLevel.CONFIDENTIAL;

        // BOLA on PUBLIC or INTERNAL metadata is not customer data leakage
        if (sensitivity == DataSensitivityLevel.PUBLIC || sensitivity == DataSensitivityLevel.INTERNAL) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 6. Generate Detection Evidence
        Instant now = event.timestamp() != null ? event.timestamp() : Instant.now();
        UUID evidenceId = UUID.randomUUID();

        String triggerCondition = String.format(
            "Confirmed BOLA Leakage: Caller customer %s successfully retrieved %s resource %s (%s) with HTTP 200",
            callerCustomerId, sensitivity, targetResourceId, event.resourceType() != null ? event.resourceType() : "RESOURCE"
        );

        String evidenceDetails = String.format(
            "Confirmed BOLA Data Leakage: Caller customerId=%s accessed unauthorized target resourceId=%s on route %s %s. Response status=200, sensitivity=%s, responseSize=%d bytes.",
            callerCustomerId, targetResourceId, method, routeTemplate, sensitivity, event.responseSizeBytes()
        );

        DetectionEvidence evidence = new DetectionEvidence(
            evidenceId,
            null,
            RULE_ID,
            RULE_VERSION,
            now,
            0.98, // High confidence on confirmed 200 cross-owner read
            "CRITICAL",
            triggerCondition,
            1,
            60,
            1,
            evidenceDetails,
            List.of(event.id()),
            now
        );

        String summary = String.format(
            "Confirmed BOLA data leakage: Customer %s obtained unauthorized access to %s resource %s",
            callerCustomerId, sensitivity, targetResourceId
        );

        log.warn("RULE-BOLA-CONFIRMED-01 triggered for caller {} on resource {}: {}",
            callerCustomerId, targetResourceId, triggerCondition);

        return RuleEvaluationResult.triggered(
            RULE_ID,
            RULE_VERSION,
            "CUSTOMER",
            callerCustomerId,
            evidence,
            summary
        );
    }

    private boolean isCrossOwnerAccess(String callerCustomerId, String targetResourceId, String resourceType, String path) {
        if ("CUSTOMER".equalsIgnoreCase(resourceType) || "CUSTOMER_PROFILE".equalsIgnoreCase(resourceType)) {
            return !callerCustomerId.equalsIgnoreCase(targetResourceId);
        }

        // Account / transfer lookup by customer query parameter
        if (path.contains("customerId=") && !path.contains("customerId=" + callerCustomerId)) {
            return true;
        }

        // If target resource is a specific customer UUID in path different from caller
        Matcher custMatcher = CUST_PATH_PATTERN.matcher(path);
        if (custMatcher.find()) {
            String pathCustId = custMatcher.group(2);
            return pathCustId != null && !pathCustId.equalsIgnoreCase(callerCustomerId);
        }

        return false;
    }

    private String extractResourceId(String path) {
        Matcher cust = CUST_PATH_PATTERN.matcher(path);
        if (cust.find()) return cust.group(2);

        Matcher acct = ACCT_PATH_PATTERN.matcher(path);
        if (acct.find()) return acct.group(2);

        Matcher tx = TX_PATH_PATTERN.matcher(path);
        if (tx.find()) return tx.group(3);

        return null;
    }
}

