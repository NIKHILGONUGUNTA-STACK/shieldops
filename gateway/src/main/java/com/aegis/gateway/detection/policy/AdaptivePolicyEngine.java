package com.aegis.gateway.detection.policy;

import com.aegis.gateway.detection.campaign.CampaignEvidenceCompleteness;
import com.aegis.gateway.detection.campaign.CampaignStage;
import com.aegis.gateway.detection.campaign.ExfiltrationCampaign;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

/**
 * Adaptive Security Response and Policy Decision Engine.
 * Translates evidence-backed incidents and campaigns into explainable, advisory policy recommendations.
 * Strictly non-enforcing (advisory only).
 */
@Service
public class AdaptivePolicyEngine {

    private static final Logger log = LoggerFactory.getLogger(AdaptivePolicyEngine.class);
    private static final String ENFORCEMENT_LEVEL = "ADVISORY";

    private final PolicyRepository policyRepository;

    public AdaptivePolicyEngine(PolicyRepository policyRepository) {
        this.policyRepository = policyRepository;
    }

    /**
     * Evaluates a security incident and generates an advisory policy decision recommendation.
     */
    @Transactional
    public AdaptivePolicyDecision evaluateIncident(SecurityIncident incident, List<DetectionEvidence> evidenceList) {
        CampaignEvidenceCompleteness completeness = determineEvidenceCompleteness(incident, evidenceList);

        String policyId;
        String riskLevel = incident.severity() != null ? incident.severity() : "MEDIUM";
        String rationale;

        // Rule 1: Incomplete or ambiguous evidence suppression
        if (completeness == CampaignEvidenceCompleteness.INCOMPLETE || completeness == CampaignEvidenceCompleteness.DEGRADED) {
            policyId = "POL-AMBIGUOUS-EVIDENCE-01";
            riskLevel = "MEDIUM";
            rationale = String.format(
                "Incident %s exhibits %s evidence. Severe response suppressed; requesting forensic telemetry enrichment.",
                incident.id(), completeness
            );
        } else {
            String ruleId = incident.ruleId() != null ? incident.ruleId() : "";
            switch (ruleId) {
                case "RULE-BOLA-CONFIRMED-01" -> {
                    policyId = "POL-BOLA-CONFIRMED-01";
                    riskLevel = "CRITICAL";
                    rationale = "Confirmed cross-owner resource exfiltration detected. Immediate incident escalation recommended.";
                }
                case "RULE-EXCESSIVE-EXPOSURE-01", "RULE-DATA-LEAK-01" -> {
                    policyId = "POL-DATA-EXPOSURE-01";
                    riskLevel = "HIGH";
                    rationale = "Response payload exposed sensitive or undeclared fields outside contract. Contract review recommended.";
                }
                case "RULE-ADV-EXTRACT-01", "RULE-BULK-EXTRACT-01" -> {
                    if (incident.summary() != null && incident.summary().toLowerCase().contains("low-and-slow")) {
                        policyId = "POL-LOW-SLOW-01";
                        riskLevel = "HIGH";
                        rationale = "Sub-threshold creeping extraction detected across extended temporal window. Correlation analysis recommended.";
                    } else if (incident.summary() != null && incident.summary().toLowerCase().contains("multi-domain")) {
                        policyId = "POL-MULTI-DOMAIN-01";
                        riskLevel = "HIGH";
                        rationale = "Extraction observed spanning multiple microservice entity boundaries. Enterprise threat review recommended.";
                    } else {
                        policyId = "POL-BULK-EXTRACT-01";
                        riskLevel = "HIGH";
                        rationale = "Rapid bulk extraction pattern detected exceeding volume thresholds. Analyst triage recommended.";
                    }
                }
                case "RULE-BOLA-01", "RULE-BOLA-02" -> {
                    policyId = "POL-BOLA-PROBE-01";
                    riskLevel = "MEDIUM";
                    rationale = "Cross-owner authorization denial observed. Token and permission audit recommended.";
                }
                case "RULE-PROBE-01" -> {
                    policyId = "POL-RECON-01";
                    riskLevel = "LOW";
                    rationale = "Undocumented endpoint or perimeter scanning detected without privilege bypass. Passive monitoring recommended.";
                }
                default -> {
                    policyId = "POL-AMBIGUOUS-EVIDENCE-01";
                    rationale = "Security anomaly detected without specific policy pattern. Forensic inspection recommended.";
                }
            }
        }

        return createDecision(
            incident.id(),
            null,
            policyId,
            riskLevel,
            rationale,
            extractIncidentSupportingEvidence(incident, evidenceList),
            incident.targetEntityValue(),
            "tenant-default",
            completeness,
            buildIncidentEvidenceSnapshot(incident, evidenceList)
        );
    }

    /**
     * Evaluates an exfiltration campaign and generates a high-level campaign response recommendation.
     */
    @Transactional
    public AdaptivePolicyDecision evaluateCampaign(
        ExfiltrationCampaign campaign,
        List<String> evidenceUris,
        String missingEvidenceReasons
    ) {
        CampaignEvidenceCompleteness completeness = campaign.evidenceCompleteness() != null
            ? campaign.evidenceCompleteness()
            : CampaignEvidenceCompleteness.COMPLETE;

        String policyId;
        String riskLevel = campaign.riskCategory() != null ? campaign.riskCategory() : "MEDIUM";
        String rationale;

        // Incomplete / Degraded evidence gate
        if (completeness == CampaignEvidenceCompleteness.INCOMPLETE || completeness == CampaignEvidenceCompleteness.DEGRADED) {
            policyId = "POL-AMBIGUOUS-EVIDENCE-01";
            riskLevel = "MEDIUM";
            rationale = String.format(
                "Campaign %s has %s telemetry (%s). Prioritization suppressed until missing telemetry is collected.",
                campaign.id(), completeness, missingEvidenceReasons != null ? missingEvidenceReasons : "incomplete"
            );
        } else if (campaign.stagesObserved().contains(CampaignStage.BULK_EXTRACTION)
            || campaign.stagesObserved().contains(CampaignStage.MULTI_DOMAIN_EXTRACTION)
            || campaign.riskScore() >= 85.0) {
            policyId = "POL-CAMPAIGN-01";
            riskLevel = "CRITICAL";
            rationale = String.format(
                "Confirmed multi-stage exfiltration campaign (Score: %.1f, Stages: %s). Immediate incident commander prioritization recommended.",
                campaign.riskScore(), campaign.stagesObserved()
            );
        } else if (campaign.stagesObserved().contains(CampaignStage.AUTHORIZATION_PROBING)) {
            policyId = "POL-BOLA-PROBE-01";
            riskLevel = "HIGH";
            rationale = "Active authorization probing campaign observed targeting customer resources. Access token review recommended.";
        } else {
            policyId = "POL-RECON-01";
            riskLevel = "LOW";
            rationale = "Early-stage reconnaissance scans observed within campaign boundary. Passive monitoring recommended.";
        }

        List<String> supportingEvidence = new ArrayList<>();
        supportingEvidence.add("Campaign:" + campaign.id());
        supportingEvidence.add("Stages:" + campaign.stagesObserved());
        supportingEvidence.add("RiskScore:" + campaign.riskScore());
        if (evidenceUris != null) {
            supportingEvidence.addAll(evidenceUris);
        }

        return createDecision(
            null,
            campaign.id(),
            policyId,
            riskLevel,
            rationale,
            supportingEvidence,
            campaign.correlationIdentity(),
            campaign.tenantId(),
            completeness,
            buildCampaignEvidenceSnapshot(campaign, evidenceUris)
        );
    }

    private AdaptivePolicyDecision createDecision(
        UUID incidentId,
        UUID campaignId,
        String policyId,
        String riskLevel,
        String rationale,
        List<String> supportingEvidence,
        String identityContext,
        String tenantId,
        CampaignEvidenceCompleteness completeness,
        String snapshot
    ) {
        SecurityPolicy policy = policyRepository.findPolicyById(policyId).orElse(null);

        // If policy is disabled, fall back to safe default
        PolicyAction action;
        String policyVersion;
        PolicyCategory category;

        if (policy != null && policy.enabled()) {
            action = policy.recommendedAction();
            policyVersion = policy.version();
            category = policy.category();
        } else if (policy != null && !policy.enabled()) {
            action = PolicyAction.MONITOR_ACTIVITY;
            policyVersion = policy.version();
            category = policy.category();
            rationale = String.format("[POLICY %s DISABLED] %s", policy.id(), rationale);
        } else {
            action = PolicyAction.INVESTIGATE_ACTIVITY;
            policyVersion = "1.0.0";
            category = PolicyCategory.GENERAL;
        }

        Instant now = Instant.now();
        AdaptivePolicyDecision decision = new AdaptivePolicyDecision(
            UUID.randomUUID(),
            incidentId,
            campaignId,
            policyId,
            policyVersion,
            category,
            riskLevel,
            action,
            ENFORCEMENT_LEVEL,
            rationale,
            supportingEvidence,
            identityContext,
            tenantId,
            completeness,
            snapshot,
            PolicyStatus.RECOMMENDED,
            null,
            null,
            null,
            null,
            now,
            now.plusSeconds(86400 * 7), // 7 days advisory validity
            now
        );

        policyRepository.savePolicyDecision(decision);
        log.info(
            "Adaptive policy decision generated [id={}, policy={}, action={}, advisory=true, incident={}, campaign={}]",
            decision.id(), decision.policyId(), decision.recommendedAction(), incidentId, campaignId
        );
        return decision;
    }

    private CampaignEvidenceCompleteness determineEvidenceCompleteness(
        SecurityIncident incident, List<DetectionEvidence> evidenceList
    ) {
        if (incident.targetEntityValue() == null || incident.targetEntityValue().isBlank()
            || "UNKNOWN".equalsIgnoreCase(incident.targetEntityValue())) {
            return CampaignEvidenceCompleteness.INCOMPLETE;
        }
        if (evidenceList == null || evidenceList.isEmpty()) {
            return CampaignEvidenceCompleteness.DEGRADED;
        }
        return CampaignEvidenceCompleteness.COMPLETE;
    }

    private List<String> extractIncidentSupportingEvidence(
        SecurityIncident incident, List<DetectionEvidence> evidenceList
    ) {
        List<String> evidence = new ArrayList<>();
        evidence.add("Incident:" + incident.id());
        evidence.add("Rule:" + incident.ruleId());
        if (evidenceList != null) {
            for (DetectionEvidence e : evidenceList) {
                evidence.add("Trigger:" + e.triggerCondition());
                if (e.contributingEventIds() != null) {
                    evidence.addAll(e.contributingEventIds().stream().map(UUID::toString).toList());
                }
            }
        }
        return evidence;
    }

    private String buildIncidentEvidenceSnapshot(SecurityIncident incident, List<DetectionEvidence> evidenceList) {
        return String.format(
            "{\"incidentId\":\"%s\",\"ruleId\":\"%s\",\"severity\":\"%s\",\"target\":\"%s\",\"evidenceCount\":%d}",
            incident.id(), incident.ruleId(), incident.severity(), incident.targetEntityValue(),
            evidenceList != null ? evidenceList.size() : 0
        );
    }

    private String buildCampaignEvidenceSnapshot(ExfiltrationCampaign campaign, List<String> evidenceUris) {
        return String.format(
            "{\"campaignId\":\"%s\",\"riskScore\":%.2f,\"stages\":\"%s\",\"events\":%d,\"urisCount\":%d}",
            campaign.id(), campaign.riskScore(), campaign.stagesObserved(), campaign.eventCount(),
            evidenceUris != null ? evidenceUris.size() : 0
        );
    }
}
