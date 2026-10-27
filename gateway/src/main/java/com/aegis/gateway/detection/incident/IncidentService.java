package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.correlation.BolaCampaignCorrelator;
import com.aegis.gateway.detection.correlation.ContextualCorrelationEngine;
import com.aegis.gateway.detection.correlation.MultiVectorCampaignCorrelator;
import com.aegis.gateway.detection.model.*;
import com.aegis.gateway.security.InvalidStatusTransitionException;
import com.aegis.gateway.security.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
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
    public SecurityIncident updateIncidentStatus(UUID incidentId, IncidentStatus newStatus, String reason, String changedBy, boolean isAdmin) {
        if (newStatus == null) {
            throw new IllegalArgumentException("Target status is required");
        }
        if (reason == null || reason.trim().length() < 5 || reason.trim().length() > 512) {
            throw new IllegalArgumentException("Reason must be between 5 and 512 characters");
        }

        SecurityIncident target = repository.findById(incidentId)
            .orElseGet(() -> repository.findAllIncidents().stream().filter(i -> i.id().equals(incidentId)).findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + incidentId)));

        IncidentStatus currentStatus = target.status();
        if (currentStatus == newStatus) {
            throw new InvalidStatusTransitionException("Incident is already in status: " + newStatus);
        }

        validateStatusTransition(currentStatus, newStatus, isAdmin);

        Instant now = Instant.now();
        repository.updateIncidentStatus(incidentId, newStatus, now);

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
            now
        );

        IncidentStatusHistory history = new IncidentStatusHistory(
            UUID.randomUUID(),
            incidentId,
            currentStatus.name(),
            newStatus.name(),
            changedBy != null && !changedBy.isBlank() ? changedBy : "system",
            now,
            reason.trim()
        );
        repository.saveStatusHistory(history);

        log.info("Transitioned incident {} status from {} to {} by {}", incidentId, currentStatus, newStatus, changedBy);
        return updated;
    }

    @Transactional
    public SecurityIncident transitionStatus(UUID incidentId, IncidentStatus newStatus, String changedBy, String reason) {
        return updateIncidentStatus(incidentId, newStatus, reason, changedBy, true);
    }

    private void validateStatusTransition(IncidentStatus current, IncidentStatus target, boolean isAdmin) {
        if (current == IncidentStatus.RESOLVED || current == IncidentStatus.FALSE_POSITIVE) {
            if (target != IncidentStatus.INVESTIGATING) {
                throw new InvalidStatusTransitionException("Terminal incidents in " + current + " status can only be transitioned to INVESTIGATING");
            }
            if (!isAdmin) {
                throw new AccessDeniedException("Only SECURITY_ADMIN can reopen a terminal incident in " + current + " status");
            }
            return;
        }

        switch (current) {
            case OPEN -> {
                if (target != IncidentStatus.INVESTIGATING && target != IncidentStatus.CONTAINED
                        && target != IncidentStatus.RESOLVED && target != IncidentStatus.FALSE_POSITIVE) {
                    throw new InvalidStatusTransitionException("Invalid transition from OPEN to " + target);
                }
            }
            case INVESTIGATING -> {
                if (target != IncidentStatus.OPEN && target != IncidentStatus.CONTAINED
                        && target != IncidentStatus.RESOLVED && target != IncidentStatus.FALSE_POSITIVE) {
                    throw new InvalidStatusTransitionException("Invalid transition from INVESTIGATING to " + target);
                }
            }
            case CONTAINED -> {
                if (target == IncidentStatus.OPEN) {
                    throw new InvalidStatusTransitionException("Cannot transition incident directly from CONTAINED to OPEN. Must transition to INVESTIGATING first.");
                }
                if (target != IncidentStatus.INVESTIGATING && target != IncidentStatus.RESOLVED && target != IncidentStatus.FALSE_POSITIVE) {
                    throw new InvalidStatusTransitionException("Invalid transition from CONTAINED to " + target);
                }
            }
            default -> throw new InvalidStatusTransitionException("Unknown current status: " + current);
        }
    }
}
