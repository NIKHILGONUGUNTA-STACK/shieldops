package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.classification.*;
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
import java.util.stream.Collectors;

/**
 * RULE-EXCESSIVE-EXPOSURE-01: Excessive Sensitive Data Exposure & Field-Level Contract Verification.
 * Evaluates observed response fields against authoritative OpenAPI schemas and sensitivity policies:
 * 1. CONFIDENTIAL fields returned on endpoints with non-confidential contracts.
 * 2. RESTRICTED fields (tokens, credentials, secrets) exposed to unauthorized roles.
 * 3. Sensitive fields returned to unauthenticated or anonymous callers.
 * 4. Unexpected response fields and schema drift involving sensitive fields.
 * 5. Unknown or unclassified response fields requiring SOC review.
 *
 * Invariant: Authorized owner access to legitimate confidential fields is explicitly non-malicious.
 * Invariant: Missing metadata produces an explicit INCOMPLETE or UNKNOWN evidence state.
 */
@Component
public class RuleExcessiveDataExposure01 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleExcessiveDataExposure01.class);

    public static final String RULE_ID = "RULE-EXCESSIVE-EXPOSURE-01";
    public static final String RULE_VERSION = "1.0.0";

    private final SensitiveDataClassificationEngine classificationEngine;
    private final boolean enabled;

    @Autowired
    public RuleExcessiveDataExposure01(
            SensitiveDataClassificationEngine classificationEngine,
            @Value("${aegis.detection.rules.excessive-exposure.enabled:true}") boolean enabled) {
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

        // 1. Must be a successful response
        if (event.statusCode() != 200 && event.statusCode() != 201) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Resolve endpoint identity and classification
        String method = event.httpMethod() != null ? event.httpMethod().toUpperCase() : "GET";
        String rawRoute = event.routeId() != null && !event.routeId().isBlank() ? event.routeId() : event.requestPath();
        String route = com.aegis.gateway.discovery.RouteNormalizer.normalize(rawRoute);
        EndpointDataClassification epClassification = classificationEngine.classifyEndpoint(method, route);

        // 3. Inspect observed fields telemetry
        String observedFieldsStr = event.observedFields();
        if (observedFieldsStr == null || observedFieldsStr.isBlank()) {
            // Missing field-level metadata: evaluate whether unclassified endpoint or incomplete evidence
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        List<String> observedFields = Arrays.stream(observedFieldsStr.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .toList();

        if (observedFields.isEmpty()) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 4. Resolve caller identity, roles, and ownership
        String authSubject = event.authSubject() != null ? event.authSubject().trim() : "anonymous";
        String customerId = event.customerId() != null ? event.customerId().trim() : "";
        Set<String> callerRoles = parseRoles(event.authRoles());
        boolean isAnonymous = "anonymous".equalsIgnoreCase(authSubject) || (customerId.isBlank() && callerRoles.isEmpty());
        boolean isSecurityAdmin = callerRoles.contains("SECURITY_ADMIN");
        boolean isSecurityAnalyst = callerRoles.contains("SECURITY_ANALYST") || isSecurityAdmin;

        // Resource ownership check
        String resourceId = event.resourceId() != null ? event.resourceId().trim() : "";
        boolean isAuthorizedOwner = !customerId.isBlank() && !resourceId.isBlank() && customerId.equalsIgnoreCase(resourceId);

        // 5. Evaluate each observed field against contract
        Map<String, FieldClassification> declaredFields = classificationEngine.getDeclaredFields(method, route);
        boolean hasDeclaredSchema = classificationEngine.hasDeclaredSchema(method, route);
        DataSensitivityLevel endpointLevel = epClassification != null ? epClassification.highestSensitivityLevel() : DataSensitivityLevel.UNKNOWN;

        List<String> restrictedExposed = new ArrayList<>();
        List<String> unauthenticatedSensitive = new ArrayList<>();
        List<String> contractBreachFields = new ArrayList<>();
        List<String> sensitiveSchemaDrift = new ArrayList<>();
        List<String> unknownFields = new ArrayList<>();

        for (String field : observedFields) {
            FieldClassification fc = classificationEngine.classifyField(
                epClassification != null ? epClassification.serviceBoundary() : "unknown",
                method, route, field
            );
            DataSensitivityLevel fieldLevel = fc.dataClassification();
            boolean isDeclared = hasDeclaredSchema && (declaredFields.containsKey(field) || hasMatchingPattern(declaredFields.keySet(), field));

            // Contextual heuristic for unexpected/undeclared fields
            if (fieldLevel == DataSensitivityLevel.UNKNOWN || !isDeclared) {
                String lower = field.toLowerCase();
                if (lower.contains("token") || lower.contains("secret") || lower.contains("password") ||
                    lower.contains("key") || lower.contains("credential") || lower.contains("hash") ||
                    lower.contains("cvv")) {
                    fieldLevel = DataSensitivityLevel.RESTRICTED;
                } else if (lower.contains("email") || lower.contains("account") || lower.contains("balance") ||
                           lower.contains("ssn") || lower.contains("tax") || lower.contains("phone")) {
                    fieldLevel = DataSensitivityLevel.CONFIDENTIAL;
                }
            }

            // Check A: RESTRICTED fields exposed to non-admin
            if (fieldLevel == DataSensitivityLevel.RESTRICTED) {
                if (!isSecurityAdmin) {
                    restrictedExposed.add(field);
                }
            }

            // Check B: Sensitive fields (CONFIDENTIAL or RESTRICTED) returned to unauthenticated callers
            if (isAnonymous && (fieldLevel == DataSensitivityLevel.CONFIDENTIAL || fieldLevel == DataSensitivityLevel.RESTRICTED)) {
                unauthenticatedSensitive.add(field);
            }

            // Check C: CONFIDENTIAL fields returned on an endpoint whose declared contract is strictly PUBLIC or INTERNAL
            if (fieldLevel == DataSensitivityLevel.CONFIDENTIAL) {
                if (hasDeclaredSchema && endpointLevel != DataSensitivityLevel.CONFIDENTIAL && endpointLevel != DataSensitivityLevel.RESTRICTED) {
                    contractBreachFields.add(field);
                }
            }

            // Check D: Schema Drift - undeclared fields appearing on catalogued endpoints
            if (hasDeclaredSchema && !isDeclared) {
                if (fieldLevel == DataSensitivityLevel.CONFIDENTIAL || fieldLevel == DataSensitivityLevel.RESTRICTED) {
                    sensitiveSchemaDrift.add(field);
                } else if (fieldLevel == DataSensitivityLevel.UNKNOWN) {
                    unknownFields.add(field);
                }
            }

            // Check E: Explicit UNKNOWN classification
            if (fieldLevel == DataSensitivityLevel.UNKNOWN) {
                if (!unknownFields.contains(field)) {
                    unknownFields.add(field);
                }
            }
        }

        // Invariant: Legitimate authorized owner accessing their declared confidential fields is benign
        if (isAuthorizedOwner && restrictedExposed.isEmpty() && unauthenticatedSensitive.isEmpty() && contractBreachFields.isEmpty() && sensitiveSchemaDrift.isEmpty()) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 6. Determine if any violation occurred
        boolean hasViolation = !restrictedExposed.isEmpty() ||
                               !unauthenticatedSensitive.isEmpty() ||
                               !contractBreachFields.isEmpty() ||
                               !sensitiveSchemaDrift.isEmpty() ||
                               (!unknownFields.isEmpty() && !hasDeclaredSchema);

        if (!hasViolation) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 7. Calculate Severity and Confidence
        String severity;
        double confidence;
        String violationType;
        String evidenceCompleteness = "COMPLETE";

        if (!restrictedExposed.isEmpty()) {
            severity = "CRITICAL";
            confidence = 0.98;
            violationType = "RESTRICTED_FIELD_EXPOSURE";
        } else if (!unauthenticatedSensitive.isEmpty()) {
            severity = "CRITICAL";
            confidence = 0.95;
            violationType = "UNAUTHENTICATED_SENSITIVE_EXPOSURE";
        } else if (!sensitiveSchemaDrift.isEmpty()) {
            severity = "HIGH";
            confidence = 0.90;
            violationType = "SENSITIVE_SCHEMA_DRIFT";
        } else if (!contractBreachFields.isEmpty()) {
            severity = "HIGH";
            confidence = 0.90;
            violationType = "CONFIDENTIAL_CONTRACT_BREACH";
        } else {
            severity = "MEDIUM";
            confidence = 0.70;
            violationType = "UNKNOWN_FIELD_ANOMALY";
            evidenceCompleteness = "UNKNOWN";
        }

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();
        String targetEntity = !customerId.isBlank() ? customerId : authSubject;

        String triggerCondition = String.format(
            "Excessive Data Exposure [%s] on %s %s: restricted=%s, unauth=%s, contractBreach=%s, drift=%s, unknown=%s",
            violationType, method, route, restrictedExposed, unauthenticatedSensitive, contractBreachFields, sensitiveSchemaDrift, unknownFields
        );

        String evidenceDetails = String.format(
            "Excessive Data Exposure Analysis: Route=%s %s, Caller='%s' (roles=%s, owner=%s). " +
            "EndpointContractLevel=%s, ObservedFieldsCount=%d. " +
            "Violations: [RestrictedExposed=%s, UnauthSensitive=%s, ContractBreach=%s, SensitiveSchemaDrift=%s, UnknownFields=%s]. " +
            "EvidenceCompleteness=%s.",
            method, route, targetEntity, callerRoles, isAuthorizedOwner,
            endpointLevel, observedFields.size(),
            restrictedExposed, unauthenticatedSensitive, contractBreachFields, sensitiveSchemaDrift, unknownFields,
            evidenceCompleteness
        );

        DetectionEvidence evidence = new DetectionEvidence(
            UUID.randomUUID(),
            null,
            RULE_ID,
            RULE_VERSION,
            eventTime,
            confidence,
            severity,
            triggerCondition,
            1,
            60,
            1,
            evidenceDetails,
            List.of(event.id()),
            eventTime
        );

        String summary = String.format(
            "Excessive data exposure on %s: %s detected (%d anomalous fields)",
            route, violationType,
            restrictedExposed.size() + unauthenticatedSensitive.size() + contractBreachFields.size() + sensitiveSchemaDrift.size() + unknownFields.size()
        );

        log.warn("RULE-EXCESSIVE-EXPOSURE-01 triggered for entity {}: {}", targetEntity, triggerCondition);

        return RuleEvaluationResult.triggered(
            RULE_ID,
            RULE_VERSION,
            !customerId.isBlank() ? "CUSTOMER" : "IDENTITY",
            targetEntity,
            evidence,
            summary
        );
    }

    private boolean hasMatchingPattern(Set<String> declaredPatterns, String field) {
        for (String pattern : declaredPatterns) {
            if (pattern.endsWith(".*")) {
                String prefix = pattern.substring(0, pattern.length() - 2);
                if (field.startsWith(prefix + ".")) {
                    return true;
                }
            }
        }
        return false;
    }

    private Set<String> parseRoles(String rolesStr) {
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
}
