package com.aegis.gateway.detection.campaign;

import com.aegis.gateway.classification.DataSensitivityLevel;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.RuleEvaluationResult;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.telemetry.ApiEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Deterministic, explainable multi-stage API data exfiltration campaign
 * correlation engine.
 * Correlates independently observed security telemetry across kill-chain
 * stages:
 * 1. Reconnaissance
 * 2. Authorization Probing
 * 3. Resource Discovery
 * 4. Sensitive Data Access & Exposure
 * 5. Bulk & Low-and-Slow Extraction
 * 6. Multi-Domain Extraction
 */
@Service
public class ExfiltrationCampaignCorrelator {
    private static final Logger log = LoggerFactory.getLogger(ExfiltrationCampaignCorrelator.class);

    // Temporal campaign correlation window (15 minutes = 900 seconds)
    private static final Duration CAMPAIGN_WINDOW = Duration.ofSeconds(900);

    private final CampaignRepository campaignRepository;

    // Ephemeral state cache tracking recent sequence stages per correlation
    // identity to handle out-of-order events
    private final Map<String, Deque<StageObservation>> recentObservations = new ConcurrentHashMap<>();

    public ExfiltrationCampaignCorrelator(CampaignRepository campaignRepository) {
        this.campaignRepository = campaignRepository;
    }

    public record StageObservation(
            UUID eventId,
            CampaignStage stage,
            String ruleId,
            String endpoint,
            String domain,
            String resourceId,
            Instant timestamp,
            int statusCode,
            long responseSizeBytes,
            boolean hasRestrictedField,
            boolean hasUnauthorizedAccess) {
    }

    /**
     * Correlates an API event and optional rule evaluation result into multi-stage
     * exfiltration campaigns.
     */
    @Transactional
    public Optional<ExfiltrationCampaign> correlateEvent(
            ApiEvent event,
            RuleEvaluationResult ruleResult,
            SecurityIncident linkedIncident) {

        if (event == null) {
            return Optional.empty();
        }

        // 1. Resolve reliable correlation identity:
        // Priority: customerId -> authSubject -> (never merge distinct users sharing
        // IP)
        String identity = resolveCorrelationIdentity(event);
        String tenantId = "DEFAULT_TENANT";
        Instant eventTime = event.timestamp() != null ? event.timestamp() : Instant.now();

        // 2. Identify kill-chain stage of the incoming event
        CampaignStage stage = classifyStage(event, ruleResult);
        if (stage == null) {
            return Optional.empty();
        }

        String domain = extractDomain(event.requestPath());
        String resourceId = event.resourceId() != null ? event.resourceId() : extractResourceId(event.requestPath());

        boolean hasRestricted = (ruleResult != null && ruleResult.ruleId() != null
                && ruleResult.ruleId().contains("RESTRICTED")) ||
                (event.observedFields() != null && (event.observedFields().contains("auth_token_hash")
                        || event.observedFields().contains("secret")));
        boolean hasUnauthorized = (event.statusCode() == 200 && ruleResult != null && ruleResult.ruleId() != null &&
                (ruleResult.ruleId().contains("BOLA-CONFIRMED") || ruleResult.ruleId().contains("DATA-LEAK")));

        StageObservation obs = new StageObservation(
                event.id(),
                stage,
                ruleResult != null ? ruleResult.ruleId() : "TELEMETRY-OBSERVATION",
                event.requestPath(),
                domain,
                resourceId,
                eventTime,
                event.statusCode(),
                event.responseSizeBytes(),
                hasRestricted,
                hasUnauthorized);

        // 3. Track observation in sliding memory for this identity
        Deque<StageObservation> observations = recentObservations.computeIfAbsent(identity, k -> new ArrayDeque<>());
        synchronized (observations) {
            // Deduplication check: ignore if exact eventId already processed
            boolean isDuplicate = observations.stream().anyMatch(o -> o.eventId().equals(obs.eventId()));
            if (isDuplicate) {
                log.debug("Duplicate event delivery ignored for identity {}: {}", identity, obs.eventId());
                return campaignRepository.findActiveByIdentity(identity, tenantId);
            }

            // Evict records outside sliding window relative to incoming event
            Instant cutoff = eventTime.minus(CAMPAIGN_WINDOW);
            observations.removeIf(o -> o.timestamp().isBefore(cutoff));
            observations.addLast(obs);
        }

        // 4. Analyze aggregated stages across window
        Set<CampaignStage> distinctStages = new TreeSet<>(Comparator.comparingInt(CampaignStage::getRank));
        Set<String> distinctDomains = new HashSet<>();
        Set<String> distinctResources = new HashSet<>();
        Set<UUID> allEventIds = new LinkedHashSet<>();
        Set<String> allRuleIds = new LinkedHashSet<>();
        boolean observedUnauthorized = false;
        boolean observedRestricted = false;
        long totalBytes = 0;
        boolean missingSize = false;
        boolean missingOwnership = (event.customerId() == null && event.authSubject() == null);

        synchronized (observations) {
            for (StageObservation o : observations) {
                distinctStages.add(o.stage());
                if (o.domain() != null)
                    distinctDomains.add(o.domain());
                if (o.resourceId() != null)
                    distinctResources.add(o.resourceId());
                allEventIds.add(o.eventId());
                if (o.ruleId() != null && !o.ruleId().isBlank())
                    allRuleIds.add(o.ruleId());
                if (o.hasUnauthorizedAccess())
                    observedUnauthorized = true;
                if (o.hasRestrictedField())
                    observedRestricted = true;
                totalBytes += o.responseSizeBytes();
                if (o.responseSizeBytes() <= 0)
                    missingSize = true;
            }
        }

        // 5. Invariant check: Single standalone anomaly does NOT become a campaign!
        // Campaign requires:
        // - >= 2 distinct kill-chain stages, OR
        // - Multi-domain extraction (>= 2 domains), OR
        // - Excessive volume extraction (>= 50,000 bytes) with at least Stage 3+
        boolean qualifiesAsCampaign = (distinctStages.size() >= 2) ||
                (distinctDomains.size() >= 2 && distinctStages.contains(CampaignStage.MULTI_DOMAIN_EXTRACTION)) ||
                (distinctStages.contains(CampaignStage.BULK_EXTRACTION) && distinctResources.size() >= 3);

        if (!qualifiesAsCampaign) {
            log.debug(
                    "Event for identity {} classified as stage {} but does not meet multi-stage campaign criteria (stages={})",
                    identity, stage, distinctStages.size());
            return Optional.empty();
        }

        // 6. Evidence completeness evaluation
        CampaignEvidenceCompleteness completeness = CampaignEvidenceCompleteness.COMPLETE;
        String missingDetails = null;
        if (missingOwnership && missingSize) {
            completeness = CampaignEvidenceCompleteness.INCOMPLETE;
            missingDetails = "Missing verified caller ownership and zero response wire volume telemetry";
        } else if (missingOwnership) {
            completeness = CampaignEvidenceCompleteness.INCOMPLETE;
            missingDetails = "Caller lacks customerId or verified ownership binding";
        } else if (missingSize) {
            completeness = CampaignEvidenceCompleteness.DEGRADED;
            missingDetails = "Response size header missing or reported as 0 bytes";
        }

        // 7. Calculate deterministic risk score
        String highestSeverity = determineSeverity(distinctStages, observedUnauthorized, observedRestricted,
                totalBytes);
        CampaignRiskAssessment assessment = CampaignRiskAssessment.calculate(
                distinctStages.size(),
                highestSeverity,
                distinctResources.size(),
                distinctDomains.size(),
                completeness,
                observedUnauthorized,
                observedRestricted);

        // 8. Find or create ExfiltrationCampaign
        Optional<ExfiltrationCampaign> activeOpt = campaignRepository.findActiveByIdentity(identity, tenantId);
        ExfiltrationCampaign campaign;

        if (activeOpt.isPresent()) {
            ExfiltrationCampaign existing = activeOpt.get();

            List<UUID> mergedEvents = new ArrayList<>(existing.relatedEventIds());
            if (!mergedEvents.contains(event.id()))
                mergedEvents.add(event.id());

            List<UUID> mergedIncidents = new ArrayList<>(existing.relatedIncidentIds());
            if (linkedIncident != null && !mergedIncidents.contains(linkedIncident.id())) {
                mergedIncidents.add(linkedIncident.id());
            }

            List<String> mergedRules = new ArrayList<>(existing.relatedRuleIds());
            allRuleIds.forEach(r -> {
                if (!mergedRules.contains(r))
                    mergedRules.add(r);
            });

            List<CampaignStage> mergedStages = new ArrayList<>(existing.stagesObserved());
            distinctStages.forEach(s -> {
                if (!mergedStages.contains(s))
                    mergedStages.add(s);
            });

            campaign = new ExfiltrationCampaign(
                    existing.id(),
                    existing.campaignId(),
                    existing.correlationIdentity(),
                    existing.tenantId(),
                    event.sourceIp(),
                    stage.getRank() >= existing.currentStage().getRank() ? stage : existing.currentStage(),
                    mergedStages,
                    existing.status(),
                    highestSeverity,
                    assessment.overallScore(),
                    assessment.riskCategory(),
                    assessment.rationale(),
                    completeness,
                    missingDetails,
                    Math.max(existing.resourceCount(), distinctResources.size()),
                    Math.max(existing.endpointCount(), distinctDomains.size()),
                    Math.max(existing.sensitiveDomainCount(), distinctDomains.size()),
                    existing.firstObservedAt().isBefore(eventTime) ? existing.firstObservedAt() : eventTime,
                    eventTime.isAfter(existing.lastObservedAt()) ? eventTime : existing.lastObservedAt(),
                    mergedEvents.size(),
                    mergedEvents,
                    mergedIncidents,
                    mergedRules,
                    existing.createdAt(),
                    Instant.now());
            campaignRepository.updateCampaign(campaign);
            log.info("Updated existing exfiltration campaign {} for identity {}: stage={}, score={}",
                    campaign.campaignId(), identity, campaign.currentStage(), campaign.riskScore());
        } else {
            UUID newId = UUID.randomUUID();
            String campId = generateCampaignId(eventTime);

            List<UUID> incIds = linkedIncident != null ? List.of(linkedIncident.id()) : List.of();

            campaign = new ExfiltrationCampaign(
                    newId,
                    campId,
                    identity,
                    tenantId,
                    event.sourceIp(),
                    stage,
                    new ArrayList<>(distinctStages),
                    CampaignStatus.OPEN,
                    highestSeverity,
                    assessment.overallScore(),
                    assessment.riskCategory(),
                    assessment.rationale(),
                    completeness,
                    missingDetails,
                    distinctResources.size(),
                    distinctDomains.size(),
                    distinctDomains.size(),
                    eventTime,
                    eventTime,
                    new ArrayList<>(allEventIds).size(),
                    new ArrayList<>(allEventIds),
                    incIds,
                    new ArrayList<>(allRuleIds),
                    Instant.now(),
                    Instant.now());
            campaignRepository.saveCampaign(campaign);

            // Record initial lifecycle transition
            campaignRepository.saveStatusHistory(new CampaignStatusHistory(
                    UUID.randomUUID(),
                    newId,
                    CampaignStatus.OPEN,
                    CampaignStatus.OPEN,
                    "CORRELATION_ENGINE",
                    Instant.now(),
                    "Initial multi-stage campaign escalation: " + assessment.rationale()));

            log.warn("Created NEW exfiltration campaign {} for identity {}: stage={}, score={}",
                    campId, identity, stage, assessment.overallScore());
        }

        // 9. Record timeline event
        String desc = String.format("Stage [%s] detected via %s on %s %s (HTTP %d)",
                stage.name(), ruleResult != null ? ruleResult.ruleId() : "TELEMETRY",
                event.httpMethod(), event.requestPath(), event.statusCode());

        campaignRepository.saveTimelineEvent(new CampaignTimelineEvent(
                UUID.randomUUID(),
                campaign.id(),
                stage,
                event.id(),
                ruleResult != null ? ruleResult.ruleId() : "TELEMETRY",
                eventTime,
                event.httpMethod(),
                event.requestPath(),
                event.statusCode(),
                desc,
                Instant.now()));

        return Optional.of(campaign);
    }

    private CampaignStage classifyStage(ApiEvent event, RuleEvaluationResult ruleResult) {
        String ruleId = ruleResult != null ? ruleResult.ruleId() : "";
        String path = event.requestPath() != null ? event.requestPath().toLowerCase() : "";
        int status = event.statusCode();

        // 1. Reconnaissance
        if (ruleId.contains("PROBE") || path.contains("/actuator") || path.contains("/swagger")
                || path.contains("/admin")) {
            return CampaignStage.RECONNAISSANCE;
        }

        // 2. Authorization Probing (403 on sensitive path)
        if (ruleId.contains("BOLA-01") || ruleId.contains("BOLA-02")
                || (status == 403 && (path.contains("/customers") || path.contains("/accounts")))) {
            return CampaignStage.AUTHORIZATION_PROBING;
        }

        // 3. Multi-Domain Extraction
        if (ruleId.contains("MULTI_RESOURCE") || ruleId.contains("MULTI-RESOURCE")) {
            return CampaignStage.MULTI_DOMAIN_EXTRACTION;
        }

        // 4. Bulk Extraction / Pagination Crawling
        if (ruleId.contains("BULK-EXTRACT") || ruleId.contains("PAGINATION")
                || (event.pageNumber() != null && event.pageNumber() >= 2)) {
            return CampaignStage.BULK_EXTRACTION;
        }

        // 5. Sensitive Data Access & Exposure
        if (ruleId.contains("BOLA-CONFIRMED") || ruleId.contains("DATA-LEAK") || ruleId.contains("EXCESSIVE-EXPOSURE")
                ||
                (status == 200 && path.contains("/profile") && event.observedFields() != null
                        && event.observedFields().contains("auth_token_hash"))) {
            return CampaignStage.SENSITIVE_DATA_ACCESS;
        }

        // 6. Resource Discovery (Repeated queries on account/transaction collections)
        if (status == 200
                && (path.endsWith("/accounts") || path.endsWith("/transactions") || path.endsWith("/beneficiaries"))) {
            return CampaignStage.RESOURCE_DISCOVERY;
        }

        return null;
    }

    private String determineSeverity(Set<CampaignStage> stages, boolean unauthorized, boolean restricted,
            long totalBytes) {
        if (unauthorized || restricted || stages.size() >= 3) {
            return "CRITICAL";
        }
        if (stages.contains(CampaignStage.BULK_EXTRACTION) || stages.contains(CampaignStage.MULTI_DOMAIN_EXTRACTION)
                || totalBytes >= 50000) {
            return "HIGH";
        }
        return "MEDIUM";
    }

    private String resolveCorrelationIdentity(ApiEvent event) {
        if (event.customerId() != null && !event.customerId().isBlank()) {
            return event.customerId().trim();
        }
        if (event.authSubject() != null && !event.authSubject().isBlank()) {
            return event.authSubject().trim();
        }
        return "ANON_" + event.sourceIp();
    }

    private String extractDomain(String path) {
        if (path == null)
            return "UNKNOWN";
        String clean = path.replace("/api/v1/", "").replace("/api/", "");
        int slash = clean.indexOf('/');
        return slash > 0 ? clean.substring(0, slash) : clean;
    }

    private String extractResourceId(String path) {
        if (path == null)
            return null;
        String[] parts = path.split("/");
        for (int i = parts.length - 1; i >= 0; i--) {
            String p = parts[i];
            if (p.length() > 8 || p.matches(".*\\d+.*")) {
                return p;
            }
        }
        return null;
    }

    private String generateCampaignId(Instant ts) {
        long epoch = ts.toEpochMilli() % 1000000;
        return String.format("CAMP-%d-%04d", ts.getEpochSecond(), epoch % 10000);
    }
}
