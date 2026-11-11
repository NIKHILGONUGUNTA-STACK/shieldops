package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.classification.DataSensitivityLevel;
import com.aegis.gateway.classification.EndpointDataClassification;
import com.aegis.gateway.classification.FieldClassification;
import com.aegis.gateway.classification.ResourceOwnershipRequirement;
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
import java.util.*;

/**
 * RULE-DATA-LEAK-01: Sensitive Data Exposure Detection.
 * Detects unexpected exposure of CONFIDENTIAL or RESTRICTED data to unapproved roles,
 * anonymous callers, or callers violating resource ownership requirements.
 */
@Component
public class RuleDataLeak01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleDataLeak01.class);

    public static final String RULE_ID = "RULE-DATA-LEAK-01";
    public static final String RULE_VERSION = "1.0.0";

    private final SensitiveDataClassificationEngine classificationEngine;
    private final boolean enabled;

    @Autowired
    public RuleDataLeak01(
            SensitiveDataClassificationEngine classificationEngine,
            @Value("${aegis.detection.rules.data-leak01.enabled:true}") boolean enabled) {
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

        // 1. Must be a successful response (HTTP 200 or 201)
        if (event.statusCode() != 200 && event.statusCode() != 201) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Resolve endpoint sensitivity classification
        String method = event.httpMethod() != null ? event.httpMethod().toUpperCase() : "GET";
        String route = event.routeId() != null && !event.routeId().isBlank() ? event.routeId() : event.requestPath();
        EndpointDataClassification classification = classificationEngine.classifyEndpoint(method, route);

        if (classification == null) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        DataSensitivityLevel sensitivity = classification.highestSensitivityLevel();
        if (sensitivity != DataSensitivityLevel.CONFIDENTIAL && sensitivity != DataSensitivityLevel.RESTRICTED) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Inspect authorization context
        String authSubject = event.authSubject() != null ? event.authSubject().trim() : "anonymous";
        String customerId = event.customerId() != null ? event.customerId().trim() : "";
        Set<String> callerRoles = parseCallerRoles(event.authRoles());

        // Check A: Anonymous or unauthenticated access to sensitive data
        boolean isAnonymousAccess = "anonymous".equalsIgnoreCase(authSubject) || customerId.isBlank() && callerRoles.isEmpty();

        // Check B: Role mismatch - caller has roles, but none match approved roles for the sensitive fields
        Set<String> approvedRoles = collectApprovedRoles(classification);
        boolean hasApprovedRole = callerRoles.stream().anyMatch(r ->
            approvedRoles.contains(r) ||
            approvedRoles.contains("ROLE_" + r) ||
            r.equals("SECURITY_ADMIN") ||
            r.equals("SECURITY_ANALYST")
        );

        // Check C: Resource ownership violation on customer-owned resource
        boolean ownershipViolated = false;
        if (requiresCustomerOwnership(classification) && !callerRoles.contains("SECURITY_ANALYST") && !callerRoles.contains("SECURITY_ADMIN")) {
            String targetResourceId = event.resourceId() != null ? event.resourceId().trim() : "";
            if (!customerId.isBlank() && !targetResourceId.isBlank() && !customerId.equalsIgnoreCase(targetResourceId) && "CUSTOMER".equalsIgnoreCase(event.resourceType())) {
                ownershipViolated = true;
            }
        }

        // Check D: Restricted credential exposure
        boolean restrictedExposed = sensitivity == DataSensitivityLevel.RESTRICTED &&
            !callerRoles.contains("SECURITY_ADMIN");

        if (!isAnonymousAccess && hasApprovedRole && !ownershipViolated && !restrictedExposed) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 4. Generate structured detection evidence
        Instant now = event.timestamp() != null ? event.timestamp() : Instant.now();
        String targetEntityType = !customerId.isBlank() ? "CUSTOMER" : "IDENTITY";
        String targetEntityValue = !customerId.isBlank() ? customerId : authSubject;

        String severity = sensitivity == DataSensitivityLevel.RESTRICTED ? "CRITICAL" : "HIGH";
        String reason = isAnonymousAccess ? "Unauthenticated access to sensitive endpoint" :
            (ownershipViolated ? "Customer ownership invariant violated on confidential resource" :
            (restrictedExposed ? "Restricted credential/secret exposed in HTTP response" : "Caller roles lack approved access for sensitive schema"));

        String triggerCondition = String.format(
            "Unauthorized sensitive data exposure: Endpoint %s %s (%s) accessed by '%s' [%s]. Reason: %s",
            method, route, sensitivity, targetEntityValue, String.join(",", callerRoles), reason
        );

        String evidenceDetails = String.format(
            "Sensitive Data Exposure: route=%s %s, highestSensitivity=%s, responseSize=%d bytes, recordCount=%d, callerRoles=%s, approvedRoles=%s, ownershipRequirement=%s. Violation: %s.",
            method, route, sensitivity, event.responseSizeBytes(), event.recordCount(),
            callerRoles, approvedRoles, classification.fieldClassifications().isEmpty() ? "NONE" : classification.fieldClassifications().get(0).resourceOwnershipRequirements(),
            reason
        );

        DetectionEvidence evidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            RULE_ID,
            RULE_VERSION,
            now,
            0.92,
            severity,
            triggerCondition,
            1,
            60,
            1,
            evidenceDetails,
            List.of(event.id()),
            now
        );

        String summary = String.format(
            "Sensitive data exposure: %s fields on %s accessed without approved role or valid ownership",
            sensitivity, route
        );

        log.warn("RULE-DATA-LEAK-01 triggered for entity {}: {}", targetEntityValue, triggerCondition);

        return RuleEvaluationResult.triggered(
            RULE_ID,
            RULE_VERSION,
            targetEntityType,
            targetEntityValue,
            evidence,
            summary
        );
    }

    private Set<String> parseCallerRoles(String rolesStr) {
        if (rolesStr == null || rolesStr.isBlank()) return Collections.emptySet();
        Set<String> roles = new HashSet<>();
        for (String r : rolesStr.split(",")) {
            String trimmed = r.trim().toUpperCase();
            if (!trimmed.isBlank()) {
                roles.add(trimmed);
            }
        }
        return roles;
    }

    private Set<String> collectApprovedRoles(EndpointDataClassification classification) {
        Set<String> approved = new HashSet<>();
        for (FieldClassification f : classification.fieldClassifications()) {
            if (f.approvedAccessRoles() != null) {
                approved.addAll(f.approvedAccessRoles());
            }
        }
        return approved;
    }

    private boolean requiresCustomerOwnership(EndpointDataClassification classification) {
        return classification.fieldClassifications().stream()
            .anyMatch(f -> f.resourceOwnershipRequirements() == ResourceOwnershipRequirement.OWNER_CUSTOMER);
    }
}

