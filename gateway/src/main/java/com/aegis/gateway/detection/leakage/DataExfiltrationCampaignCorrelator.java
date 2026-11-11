package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.detection.correlation.ContextualCorrelator;
import com.aegis.gateway.detection.correlation.CorrelationResult;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Correlates multi-stage data exfiltration campaigns across distinct attack phases:
 * Stage 1: Reconnaissance & Resource Enumeration (RULE-PROBE-01)
 * Stage 2: Broken Object Level Authorization (RULE-BOLA-01, RULE-BOLA-02)
 * Stage 3: Unauthorized Sensitive Data Retrieval & Bulk Extraction (RULE-BOLA-CONFIRMED-01, RULE-DATA-LEAK-01, RULE-BULK-EXTRACT-01, RULE-DATA-01)
 */
@Component
@Order(5)
public class DataExfiltrationCampaignCorrelator implements ContextualCorrelator {
    private static final Logger log = LoggerFactory.getLogger(DataExfiltrationCampaignCorrelator.class);

    private static final Set<String> STAGE_1_RECONNAISSANCE = Set.of(
        RuleProbe01.RULE_ID
    );

    private static final Set<String> STAGE_2_ACCESS_PROBING = Set.of(
        RuleBola01.RULE_ID,
        RuleBola02.RULE_ID
    );

    private static final Set<String> STAGE_3_EXTRACTION = Set.of(
        RuleBolaConfirmed01.RULE_ID,
        RuleDataLeak01.RULE_ID,
        RuleBulkExtract01.RULE_ID,
        RuleData01.RULE_ID
    );

    private static final Set<String> ALL_SUPPORTED_RULES = new HashSet<>();
    static {
        ALL_SUPPORTED_RULES.addAll(STAGE_1_RECONNAISSANCE);
        ALL_SUPPORTED_RULES.addAll(STAGE_2_ACCESS_PROBING);
        ALL_SUPPORTED_RULES.addAll(STAGE_3_EXTRACTION);
        ALL_SUPPORTED_RULES.add("DATA_EXFILTRATION_CAMPAIGN");
        ALL_SUPPORTED_RULES.add("MULTI_VECTOR");
    }

    @Override
    public boolean supports(String ruleId) {
        if (ruleId == null) return false;
        return ALL_SUPPORTED_RULES.contains(ruleId.toUpperCase().trim());
    }

    @Override
    public CorrelationResult evaluateCorrelation(
            RuleEvaluationResult newResult,
            SecurityIncident activeIncident,
            List<DetectionEvidence> pastEvidences) {

        if (!newResult.triggered() || newResult.evidence().isEmpty()) {
            return CorrelationResult.notCorrelated();
        }

        DetectionEvidence newEvidence = newResult.evidence().get();

        // 1. Anti-Affinity Rule: Verify target entity type and value match the active incident
        if (!activeIncident.targetEntityType().equalsIgnoreCase(newResult.targetEntityType()) ||
            !activeIncident.targetEntityValue().equalsIgnoreCase(newResult.targetEntityValue())) {
            log.debug("Anti-affinity triggered: evidence target {}:{} does not match incident {}:{}",
                newResult.targetEntityType(), newResult.targetEntityValue(),
                activeIncident.targetEntityType(), activeIncident.targetEntityValue());
            return CorrelationResult.notCorrelated();
        }

        // 2. Closed Incident Check: Do not absorb into resolved status
        if (activeIncident.status() != null &&
            (activeIncident.status().name().equals("RESOLVED") || activeIncident.status().name().equals("FALSE_POSITIVE"))) {
            return CorrelationResult.notCorrelated();
        }

        // 3. Deduplicate contributing event IDs
        Set<UUID> allEventIds = new LinkedHashSet<>();
        Set<String> rulesSeen = new LinkedHashSet<>();
        Set<String> distinctStages = new TreeSet<>();

        if (pastEvidences != null) {
            for (DetectionEvidence ev : pastEvidences) {
                if (ev.contributingEventIds() != null) {
                    allEventIds.addAll(ev.contributingEventIds());
                }
                rulesSeen.add(ev.ruleId());
                classifyStage(ev.ruleId(), distinctStages);
            }
        }

        List<UUID> newEventIds = newEvidence.contributingEventIds() != null
            ? newEvidence.contributingEventIds()
            : List.of();

        boolean isExactDuplicate = !newEventIds.isEmpty() && allEventIds.containsAll(newEventIds);
        if (isExactDuplicate) {
            return new CorrelationResult(
                true,
                activeIncident.id(),
                activeIncident.incidentFingerprint(),
                activeIncident.threatCategory(),
                activeIncident.severity(),
                newEvidence.confidenceScore(),
                allEventIds.size(),
                newEvidence.distinctResources(),
                rulesSeen,
                new ArrayList<>(allEventIds),
                "Idempotent redelivery of existing detection evidence",
                true,
                activeIncident.summary(),
                "DATA_EXFILTRATION_ADVISORY_POLICY"
            );
        }

        allEventIds.addAll(newEventIds);
        rulesSeen.add(newEvidence.ruleId());
        classifyStage(newEvidence.ruleId(), distinctStages);

        // 4. Determine multi-stage progression
        boolean isMultiStage = distinctStages.size() >= 2;

        String threatCategory = isMultiStage
            ? "DATA_EXFILTRATION_CAMPAIGN"
            : (activeIncident.threatCategory() != null ? activeIncident.threatCategory() : "DATA_LEAKAGE");

        String severity = isMultiStage
            ? "CRITICAL"
            : escalateSeverity(activeIncident.severity(), newEvidence.severity());

        // Bayesian confidence combination
        double pastConfidence = pastEvidences != null && !pastEvidences.isEmpty()
            ? pastEvidences.stream().mapToDouble(DetectionEvidence::confidenceScore).max().orElse(0.8)
            : 0.8;
        double combinedConfidence = 1.0 - (1.0 - pastConfidence) * (1.0 - newEvidence.confidenceScore());
        combinedConfidence = Math.min(0.99, Math.round(combinedConfidence * 100.0) / 100.0);

        int totalDistinctResources = Math.max(activeIncident.eventCount(), newEvidence.distinctResources());

        String timelineDescription = String.format(
            "Multi-stage exfiltration campaign [%s] for %s %s: Observed stages [%s] across rules [%s] with %d contributing events.",
            severity, activeIncident.targetEntityType(), activeIncident.targetEntityValue(),
            String.join(" -> ", distinctStages), String.join(", ", rulesSeen), allEventIds.size()
        );

        String rationale = String.format(
            "Correlated multi-stage attack: Actor progressed through %d distinct phases: %s.",
            distinctStages.size(), String.join(", ", distinctStages)
        );

        log.warn("Correlated multi-stage data exfiltration campaign for {}: stages={}",
            activeIncident.targetEntityValue(), distinctStages);

        return new CorrelationResult(
            true,
            activeIncident.id(),
            activeIncident.incidentFingerprint(),
            threatCategory,
            severity,
            combinedConfidence,
            allEventIds.size(),
            totalDistinctResources,
            rulesSeen,
            new ArrayList<>(allEventIds),
            rationale,
            false,
            timelineDescription,
            "EXFILTRATION_CAMPAIGN_ADVISORY_POLICY"
        );
    }

    private void classifyStage(String ruleId, Set<String> stages) {
        if (ruleId == null) return;
        if (STAGE_1_RECONNAISSANCE.contains(ruleId)) {
            stages.add("1_RECONNAISSANCE");
        } else if (STAGE_2_ACCESS_PROBING.contains(ruleId)) {
            stages.add("2_BOLA_PROBING");
        } else if (STAGE_3_EXTRACTION.contains(ruleId)) {
            stages.add("3_DATA_EXTRACTION");
        }
    }

    private String escalateSeverity(String s1, String s2) {
        int r1 = rank(s1);
        int r2 = rank(s2);
        return r1 >= r2 ? s1 : s2;
    }

    private int rank(String severity) {
        if (severity == null) return 0;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}

