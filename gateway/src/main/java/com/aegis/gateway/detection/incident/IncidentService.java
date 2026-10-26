package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.correlation.BolaCampaignCorrelator;
import com.aegis.gateway.detection.correlation.ContextualCorrelationEngine;
import com.aegis.gateway.detection.correlation.MultiVectorCampaignCorrelator;
import com.aegis.gateway.detection.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class IncidentService {
    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final IncidentRepository repository;
    private final ContextualCorrelationEngine correlationEngine;

    @Autowired
    public IncidentService(IncidentRepository repository, ContextualCorrelationEngine correlationEngine) {
        this.repository = repository;
        this.correlationEngine = correlationEngine;
    }

    public IncidentService(IncidentRepository repository) {
        this(repository, new ContextualCorrelationEngine(List.of(new BolaCampaignCorrelator(), new MultiVectorCampaignCorrelator()), repository, null));
    }

    @Transactional
    public SecurityIncident processRuleResult(RuleEvaluationResult result) {
        return correlationEngine.correlateAndProcess(result);
    }

    @Transactional
    public SecurityIncident transitionStatus(UUID incidentId, IncidentStatus newStatus, String changedBy, String reason) {
        List<SecurityIncident> all = repository.findAllIncidents();
        SecurityIncident target = all.stream().filter(i -> i.id().equals(incidentId)).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Incident not found: " + incidentId));

        IncidentStatus oldStatus = target.status();
        if (oldStatus == newStatus) {
            return target;
        }

        SecurityIncident updated = new SecurityIncident(
            target.id(),
            target.incidentFingerprint(),
            target.ruleId(),
            target.ruleVersion(),
            target.threatCategory(),
            target.severity(),
            newStatus,
            target.targetEntityType(),
            target.targetEntityValue(),
            target.firstDetectedAt(),
            target.lastEventAt(),
            target.eventCount(),
            target.summary(),
            target.createdAt(),
            Instant.now()
        );
        repository.updateIncident(updated);

        IncidentStatusHistory history = new IncidentStatusHistory(
            UUID.randomUUID(),
            incidentId,
            oldStatus.name(),
            newStatus.name(),
            changedBy,
            Instant.now(),
            reason
        );
        repository.saveStatusHistory(history);

        log.info("Transitioned incident {} status from {} to {} by {}", incidentId, oldStatus, newStatus, changedBy);
        return updated;
    }
}
