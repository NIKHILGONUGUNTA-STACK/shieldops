package com.aegis.gateway.reconciliation;

import com.aegis.gateway.reconciliation.dto.PriorityContributingFactor;
import com.aegis.gateway.reconciliation.dto.ReconciliationCategory;
import com.aegis.gateway.reconciliation.dto.ReconciliationPrioritizationResult;
import com.aegis.gateway.reconciliation.dto.ReconciliationPriority;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Deterministic, explainable prioritization engine for API contract discrepancy findings.
 * Version: v1.0.0
 * 
 * Scores discrepancies from 0 to 100 points across four transparent dimensions:
 * 1. Discrepancy Category Base Points (0 - 35)
 * 2. Service & Operational Criticality (0 - 20)
 * 3. Security Telemetry Signals (Auth Failures & Anomaly Flags) (0 - 40)
 * 4. Exposure Volume & Persistence (0 - 15)
 * 
 * Strict Invariant: Does not treat discrepancies as confirmed vulnerabilities.
 */
@Component
public class ApiDiscrepancyPrioritizer {

    public static final String RULE_VERSION = "v1.0.0";

    private static final Set<String> HIGH_CRITICALITY_SERVICES = Set.of(
        "transaction-service", "account-service"
    );

    private static final List<String> SENSITIVE_PATH_PATTERNS = List.of(
        "/transfer", "/transfers", "/payment", "/payments", "/payout",
        "/auth", "/token", "/credentials", "/admin", "/internal", "/keys"
    );

    /**
     * Evaluates a reconciled API operation and generates a transparent, explainable priority score.
     */
    public ReconciliationPrioritizationResult prioritize(
            ReconciliationCategory category,
            String normalizedRoute,
            String serviceBoundary,
            long totalRequests,
            long authFailureCount,
            long anomalyEventCount,
            Instant firstObservedAt,
            Instant lastObservedAt,
            boolean isAmbiguous) {

        List<PriorityContributingFactor> factors = new ArrayList<>();
        int score = 0;

        // Factor 1: Category Base Score
        int categoryDelta = switch (category) {
            case OBSERVED_UNDOCUMENTED -> 35;
            case METHOD_MISMATCH -> 30;
            case AMBIGUOUS -> 20;
            case DOCUMENTED_UNOBSERVED -> 10;
            case MATCHED -> 0;
        };

        String categoryRationale = switch (category) {
            case OBSERVED_UNDOCUMENTED -> "Observed active wire traffic on an undocumented shadow route (+35 pts)";
            case METHOD_MISMATCH -> "Observed undeclared HTTP method on declared route pattern (+30 pts)";
            case AMBIGUOUS -> "Contradictory route or service mappings detected across specifications (+20 pts)";
            case DOCUMENTED_UNOBSERVED -> "Declared operation received zero traffic in monitoring window (+10 pts)";
            case MATCHED -> "Declared contract matches observed wire traffic (+0 pts)";
        };
        factors.add(new PriorityContributingFactor("FACTOR_CATEGORY", "Finding Category Base", categoryDelta, categoryRationale));
        score += categoryDelta;

        // Factor 2: Service Boundary Criticality & Sensitive Route Patterns
        int criticalityDelta = 0;
        String criticalityRationale;
        String lowerRoute = normalizedRoute != null ? normalizedRoute.toLowerCase() : "";
        String lowerService = serviceBoundary != null ? serviceBoundary.toLowerCase() : "";

        boolean hasSensitivePattern = SENSITIVE_PATH_PATTERNS.stream().anyMatch(lowerRoute::contains);
        boolean isHighCriticalityService = HIGH_CRITICALITY_SERVICES.contains(lowerService);

        if (isHighCriticalityService || hasSensitivePattern) {
            criticalityDelta = 20;
            criticalityRationale = String.format("Route belongs to high-impact financial or sensitive domain (%s) (+20 pts)",
                isHighCriticalityService ? serviceBoundary : "sensitive path keyword");
        } else if (lowerService.contains("customer") || lowerRoute.contains("customer") || lowerRoute.contains("user")) {
            criticalityDelta = 10;
            criticalityRationale = "Route belongs to core customer entity boundary (+10 pts)";
        } else {
            criticalityDelta = 0;
            criticalityRationale = "Standard non-sensitive service boundary (+0 pts)";
        }
        factors.add(new PriorityContributingFactor("FACTOR_CRITICALITY", "Service Criticality & Scope", criticalityDelta, criticalityRationale));
        score += criticalityDelta;

        // Factor 3: Security Telemetry (Authorization Failures & Anomaly Indicators)
        int securityDelta = 0;
        List<String> secReasons = new ArrayList<>();

        if (authFailureCount >= 50) {
            securityDelta += 25;
            secReasons.add(String.format("Elevated authorization failures (401/403): %d events (+25 pts)", authFailureCount));
        } else if (authFailureCount > 0) {
            securityDelta += 15;
            secReasons.add(String.format("Active authorization failures (401/403): %d events (+15 pts)", authFailureCount));
        }

        if (anomalyEventCount > 0) {
            securityDelta += 15;
            secReasons.add(String.format("Gateway telemetry flagged %d threat anomaly events (+15 pts)", anomalyEventCount));
        }

        if (securityDelta == 0) {
            factors.add(new PriorityContributingFactor("FACTOR_SECURITY_SIGNALS", "Security Telemetry Indicators", 0,
                "No authorization failures (401/403) or anomaly flags observed in telemetry (+0 pts)"));
        } else {
            factors.add(new PriorityContributingFactor("FACTOR_SECURITY_SIGNALS", "Security Telemetry Indicators", securityDelta,
                String.join("; ", secReasons)));
            score += securityDelta;
        }

        // Factor 4: Request Volume & Operational Exposure
        int exposureDelta = 0;
        String exposureRationale;
        if (totalRequests >= 1000) {
            exposureDelta = 10;
            exposureRationale = String.format("High operational volume: %d observed requests (+10 pts)", totalRequests);
        } else if (totalRequests >= 50) {
            exposureDelta = 5;
            exposureRationale = String.format("Moderate operational volume: %d observed requests (+5 pts)", totalRequests);
        } else if (totalRequests > 0) {
            exposureDelta = 0;
            exposureRationale = String.format("Low operational volume: %d observed requests (+0 pts)", totalRequests);
        } else {
            exposureDelta = 0;
            exposureRationale = "Zero traffic observed during the monitoring window (+0 pts)";
        }
        factors.add(new PriorityContributingFactor("FACTOR_EXPOSURE", "Operational Exposure", exposureDelta, exposureRationale));
        score += exposureDelta;

        // Factor 5: Persistence Over Time
        if (firstObservedAt != null && lastObservedAt != null) {
            long hoursSpan = Duration.between(firstObservedAt, lastObservedAt).toHours();
            if (hoursSpan >= 12 && totalRequests >= 10) {
                factors.add(new PriorityContributingFactor("FACTOR_PERSISTENCE", "Temporal Persistence", 5,
                    String.format("Traffic persisted across %d hours within monitoring window (+5 pts)", hoursSpan)));
                score += 5;
            }
        }

        // Bounded Score (0 - 100)
        int boundedScore = Math.min(100, Math.max(0, score));

        // Priority Level Mapping
        ReconciliationPriority priority;
        if (boundedScore >= 75) {
            priority = ReconciliationPriority.CRITICAL;
        } else if (boundedScore >= 50) {
            priority = ReconciliationPriority.HIGH;
        } else if (boundedScore >= 25) {
            priority = ReconciliationPriority.MEDIUM;
        } else {
            priority = ReconciliationPriority.LOW;
        }

        // Confidence Evaluation (Conceptually separate from Priority!)
        String matchingConfidence;
        String confidenceRationale;
        if (isAmbiguous) {
            matchingConfidence = "LOW";
            confidenceRationale = "Ambiguous route definition or specification conflict lowers mapping certainty.";
        } else if (category == ReconciliationCategory.OBSERVED_UNDOCUMENTED && !normalizedRoute.contains("{")) {
            matchingConfidence = "HIGH";
            confidenceRationale = "Exact static path observed on wire with no parameter variance.";
        } else if (category == ReconciliationCategory.OBSERVED_UNDOCUMENTED) {
            matchingConfidence = "MEDIUM";
            confidenceRationale = "Normalized parameterized route derived via conservative telemetry clustering.";
        } else {
            matchingConfidence = "HIGH";
            confidenceRationale = "Canonical route template and method unambiguously matched against declared contract.";
        }

        return new ReconciliationPrioritizationResult(
            priority,
            boundedScore,
            RULE_VERSION,
            factors,
            matchingConfidence,
            confidenceRationale
        );
    }
}
