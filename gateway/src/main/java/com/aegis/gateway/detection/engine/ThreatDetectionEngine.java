package com.aegis.gateway.detection.engine;

import com.aegis.gateway.detection.incident.IncidentService;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.detection.rules.DetectionRule;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ThreatDetectionEngine {
    private static final Logger log = LoggerFactory.getLogger(ThreatDetectionEngine.class);

    private final List<DetectionRule> rules;
    private final IncidentService incidentService;

    public ThreatDetectionEngine(List<DetectionRule> rules, IncidentService incidentService) {
        this.rules = rules != null ? rules : List.of();
        this.incidentService = incidentService;
        log.info("Initialized ThreatDetectionEngine with {} active rules", this.rules.size());
    }

    public List<SecurityIncident> processEvent(ApiEvent event) {
        if (event == null) {
            return List.of();
        }

        List<SecurityIncident> incidents = new ArrayList<>();
        for (DetectionRule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }

            try {
                RuleEvaluationResult result = rule.evaluate(event);
                if (result.triggered()) {
                    SecurityIncident inc = incidentService.processRuleResult(result);
                    if (inc != null) {
                        incidents.add(inc);
                    }
                }
            } catch (Exception e) {
                log.error("Rule {} evaluation failed for event {}: {}", rule.getRuleId(), event.id(), e.getMessage(), e);
            }
        }
        return incidents;
    }
}
