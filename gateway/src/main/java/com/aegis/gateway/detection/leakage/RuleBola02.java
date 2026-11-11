package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.detection.model.BolaAttemptRecord;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.ProbeRecord;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.rules.DetectionRule;
import com.aegis.gateway.detection.state.DetectionStateStore;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

/**
 * RULE-BOLA-02: BOLA Probing Campaign Detection.
 * Identifies systematic reconnaissance following an authorization denial (HTTP 403 on cross-owner resource),
 * where the caller iteratively probes adjacent or sequential resource identifiers (HTTP 403 or 404).
 */
@Component
public class RuleBola02 implements DetectionRule {
    private static final Logger log = LoggerFactory.getLogger(RuleBola02.class);

    public static final String RULE_ID = "RULE-BOLA-02";
    public static final String RULE_VERSION = "1.0.0";

    private final DetectionStateStore stateStore;
    private final boolean enabled;
    private final int minProbeCount;
    private final int minDistinctResources;
    private final int windowSeconds;

    @Autowired
    public RuleBola02(
            DetectionStateStore stateStore,
            @Value("${aegis.detection.rules.bola02.enabled:true}") boolean enabled,
            @Value("${aegis.detection.rules.bola02.min-probe-count:2}") int minProbeCount,
            @Value("${aegis.detection.rules.bola02.min-distinct-resources:2}") int minDistinctResources,
            @Value("${aegis.detection.rules.bola02.window-seconds:180}") int windowSeconds) {
        this.stateStore = stateStore;
        this.enabled = enabled;
        this.minProbeCount = minProbeCount;
        this.minDistinctResources = minDistinctResources;
        this.windowSeconds = windowSeconds;
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

        // 1. Must be a 403 Forbidden or 404 Not Found outcome
        if (event.statusCode() != 403 && event.statusCode() != 404) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 2. Caller must have an identified customer identity
        String customerId = event.customerId();
        if (customerId == null || customerId.isBlank() || "anonymous".equalsIgnoreCase(customerId)) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 3. Must target resource path
        String targetResourceId = event.resourceId() != null && !event.resourceId().isBlank()
            ? event.resourceId().trim()
            : event.requestPath();

        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();

        // 4. Record probe in state store
        stateStore.recordBolaProbe(customerId, event.id(), targetResourceId, event.statusCode(), eventTime);

        // 5. Query sliding window for both BOLA denials (403) and subsequent probes (403/404)
        Instant windowStart = eventTime.minusSeconds(windowSeconds);
        List<BolaAttemptRecord> previousBolaAttempts = stateStore.getRecentBolaAttempts(customerId, windowStart);
        List<ProbeRecord> recentProbes = stateStore.getRecentBolaProbes(customerId, windowStart);

        // Must have at least one previous BOLA denial (403)
        if (previousBolaAttempts.isEmpty() && event.statusCode() != 403) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        Set<UUID> allEventIds = new LinkedHashSet<>();
        Set<String> distinctResources = new HashSet<>();

        for (BolaAttemptRecord b : previousBolaAttempts) {
            allEventIds.add(b.eventId());
            distinctResources.add(b.resourceId());
        }
        for (ProbeRecord p : recentProbes) {
            allEventIds.add(p.eventId());
            distinctResources.add(p.path());
        }

        // 6. Check threshold
        if (recentProbes.size() < minProbeCount || distinctResources.size() < minDistinctResources) {
            return RuleEvaluationResult.notTriggered(RULE_ID, RULE_VERSION);
        }

        // 7. Generate Detection Evidence
        UUID evidenceId = UUID.randomUUID();
        String triggerCondition = String.format(
            "BOLA probing campaign by %s: %d authorization denials and probes across %d distinct resources in %ds",
            customerId, recentProbes.size(), distinctResources.size(), windowSeconds
        );

        String evidenceDetails = String.format(
            "BOLA Probing Campaign: Caller customerId=%s executed %d probing requests across %d distinct resources (%s) following authorization denials. Event IDs=%s in %ds window.",
            customerId, recentProbes.size(), distinctResources.size(), distinctResources, allEventIds, windowSeconds
        );

        DetectionEvidence evidence = new DetectionEvidence(
            evidenceId,
            null,
            RULE_ID,
            RULE_VERSION,
            eventTime,
            0.90,
            "HIGH",
            triggerCondition,
            allEventIds.size(),
            windowSeconds,
            distinctResources.size(),
            evidenceDetails,
            new ArrayList<>(allEventIds),
            eventTime
        );

        String summary = String.format(
            "BOLA probing campaign: %s probed %d adjacent resources following initial access denial",
            customerId, distinctResources.size()
        );

        log.warn("RULE-BOLA-02 triggered for entity {}: {}", customerId, triggerCondition);

        return RuleEvaluationResult.triggered(
            RULE_ID,
            RULE_VERSION,
            "CUSTOMER",
            customerId,
            evidence,
            summary
        );
    }
}

