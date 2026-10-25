package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class IncidentService {
    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final IncidentRepository repository;

    public IncidentService(IncidentRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public SecurityIncident processRuleResult(RuleEvaluationResult result) {
        if (!result.triggered() || result.evidence().isEmpty()) {
            return null;
        }

        DetectionEvidence rawEvidence = result.evidence().get();
        Instant now = Instant.now();

        // 1. Calculate deterministic deduplication fingerprint
        // Fingerprint partitions by rule, target entity, and window bucket (e.g. 5-min slot)
        long windowBucket = now.getEpochSecond() / Math.max(60, rawEvidence.windowSeconds());
        String fingerprint = computeFingerprint(
            result.ruleId(),
            result.targetEntityType(),
            result.targetEntityValue(),
            windowBucket
        );

        Optional<SecurityIncident> existingOpt = repository.findActiveByFingerprint(fingerprint);

        SecurityIncident incident;
        if (existingOpt.isPresent()) {
            SecurityIncident existing = existingOpt.get();
            incident = existing.withUpdatedEvents(now, rawEvidence.observedCount(), rawEvidence.severity());
            repository.updateIncident(incident);
            log.info("Appended evidence to existing incident {} for target {}:{}",
                incident.id(), result.targetEntityType(), result.targetEntityValue());
        } else {
            UUID incidentId = UUID.randomUUID();
            incident = new SecurityIncident(
                incidentId,
                fingerprint,
                result.ruleId(),
                result.ruleVersion(),
                "BOLA_ATTEMPT",
                rawEvidence.severity(),
                IncidentStatus.OPEN,
                result.targetEntityType(),
                result.targetEntityValue(),
                now,
                now,
                rawEvidence.observedCount(),
                result.summary(),
                now,
                now
            );
            repository.saveIncident(incident);

            // Record initial lifecycle transition
            IncidentStatusHistory initialHistory = new IncidentStatusHistory(
                UUID.randomUUID(),
                incidentId,
                "NONE",
                IncidentStatus.OPEN.name(),
                result.ruleId(),
                now,
                "Initial detection trigger: " + rawEvidence.triggerCondition()
            );
            repository.saveStatusHistory(initialHistory);

            // Record advisory policy decision
            PolicyDecision decision = new PolicyDecision(
                UUID.randomUUID(),
                incidentId,
                "DEFAULT_BOLA_ADVISORY_POLICY",
                "LOG_ALERT",
                "ADVISORY",
                now,
                now.plusSeconds(3600), // 1 hour advisory window
                "Repeated BOLA cross-customer access probing detected. Action remains advisory per Phase 4 specification.",
                now
            );
            repository.savePolicyDecision(decision);

            log.warn("Created NEW Security Incident {} [{}]: {}", incidentId, rawEvidence.severity(), result.summary());
        }

        // Attach incident ID to evidence and persist
        DetectionEvidence linkedEvidence = new DetectionEvidence(
            rawEvidence.id(),
            incident.id(),
            rawEvidence.ruleId(),
            rawEvidence.ruleVersion(),
            rawEvidence.evaluatedAt(),
            rawEvidence.confidenceScore(),
            rawEvidence.severity(),
            rawEvidence.triggerCondition(),
            rawEvidence.observedCount(),
            rawEvidence.windowSeconds(),
            rawEvidence.distinctResources(),
            rawEvidence.evidenceDetails(),
            rawEvidence.contributingEventIds(),
            now
        );
        repository.saveEvidence(linkedEvidence);

        return incident;
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

    private String computeFingerprint(String ruleId, String entityType, String entityValue, long windowBucket) {
        String raw = ruleId + ":" + entityType + ":" + entityValue + ":" + windowBucket;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            return UUID.nameUUIDFromBytes(raw.getBytes(StandardCharsets.UTF_8)).toString();
        }
    }
}
