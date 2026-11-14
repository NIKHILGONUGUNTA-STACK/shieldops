package com.aegis.gateway.detection.engine;

import com.aegis.gateway.detection.campaign.ExfiltrationCampaignCorrelator;
import com.aegis.gateway.detection.incident.IncidentService;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.DetectionRule;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ThreatDetectionEngine {
    private static final Logger log = LoggerFactory.getLogger(ThreatDetectionEngine.class);

    private final List<DetectionRule> rules;
    private final IncidentService incidentService;
    private final ExfiltrationCampaignCorrelator campaignCorrelator;

    @Autowired
    public ThreatDetectionEngine(
            List<DetectionRule> rules,
            IncidentService incidentService,
            @Autowired(required = false) ExfiltrationCampaignCorrelator campaignCorrelator) {
        this.rules = rules != null ? rules : List.of();
        this.incidentService = incidentService;
        this.campaignCorrelator = campaignCorrelator;
        log.info("Initialized ThreatDetectionEngine with {} active rules and campaign correlator {}",
            this.rules.size(), campaignCorrelator != null ? "ENABLED" : "DISABLED");
    }

    public ThreatDetectionEngine(List<DetectionRule> rules, IncidentService incidentService) {
        this(rules, incidentService, null);
    }

    public List<SecurityIncident> processEvent(ApiEvent event) {
        if (event == null) {
            return List.of();
        }

        List<SecurityIncident> incidents = new ArrayList<>();
        boolean anyRuleTriggered = false;

        for (DetectionRule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }

            try {
                RuleEvaluationResult result = rule.evaluate(event);
                if (result.triggered()) {
                    anyRuleTriggered = true;
                    SecurityIncident inc = incidentService.processRuleResult(result);
                    if (inc != null) {
                        incidents.add(inc);
                    }
                    if (campaignCorrelator != null) {
                        campaignCorrelator.correlateEvent(event, result, inc);
                    }
                }
            } catch (Exception e) {
                log.error("Rule {} evaluation failed for event {}: {}", rule.getRuleId(), event.id(), e.getMessage(), e);
            }
        }

        // If no isolated rule triggered, check if event contributes to resource discovery / pagination stage
        if (!anyRuleTriggered && campaignCorrelator != null) {
            try {
                campaignCorrelator.correlateEvent(event, null, null);
            } catch (Exception e) {
                log.debug("Campaign stage correlation skipped for non-rule event {}: {}", event.id(), e.getMessage());
            }
        }

        return incidents;
    }
}
