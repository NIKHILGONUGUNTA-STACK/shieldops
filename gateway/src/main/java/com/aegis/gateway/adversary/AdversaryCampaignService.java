package com.aegis.gateway.adversary;

import com.aegis.gateway.workflow.WorkflowCheckResult;
import com.aegis.gateway.workflow.WorkflowStateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service managing automated Red Team adversary probing campaigns.
 * Synthesizes adversarial API sequence mutations to stress-test runtime edge policies and identify gaps.
 */
@Service
public class AdversaryCampaignService {
    private static final Logger log = LoggerFactory.getLogger(AdversaryCampaignService.class);

    private final WorkflowStateService workflowStateService;
    private final Map<String, AdversaryCampaign> campaigns = new ConcurrentHashMap<>();

    @Autowired
    public AdversaryCampaignService(WorkflowStateService workflowStateService) {
        this.workflowStateService = workflowStateService;
        initSeedCampaigns();
    }

    private void initSeedCampaigns() {
        Instant now = Instant.now();

        // Seed 1: Transfer Step Skipping Probing
        AdversaryCampaign c1 = new AdversaryCampaign(
            "ADV-CAMP-001",
            "Payment Transfer Step-Skipping Reconnaissance",
            "POST /api/v1/transfers",
            AdversaryMutationStrategy.STEP_SKIPPING,
            20,
            20,
            0,
            0.0,
            "COMPLETED",
            now.minusSeconds(7200),
            now.minusSeconds(7150),
            List.of()
        );

        // Seed 2: Beneficiary Registration Gap Probing (Evasion detected)
        AdversaryProbeResult ev1 = new AdversaryProbeResult(
            "PRB-9901",
            "POST",
            "/api/v1/beneficiaries",
            "sess-adv-99",
            AdversaryMutationStrategy.OUT_OF_ORDER_TRAVERSAL,
            false,
            200,
            null,
            "Target endpoint '/api/v1/beneficiaries' lacks predecessor enforcement for prior account verification."
        );
        AdversaryProbeResult ev2 = new AdversaryProbeResult(
            "PRB-9902",
            "POST",
            "/api/v1/beneficiaries",
            "sess-adv-100",
            AdversaryMutationStrategy.STEP_SKIPPING,
            false,
            200,
            null,
            "Direct beneficiary creation allowed without preceding GET /api/v1/accounts check."
        );

        AdversaryCampaign c2 = new AdversaryCampaign(
            "ADV-CAMP-002",
            "Beneficiary Creation Out-of-Order Exploitation",
            "POST /api/v1/beneficiaries",
            AdversaryMutationStrategy.OUT_OF_ORDER_TRAVERSAL,
            15,
            5,
            10,
            0.667,
            "COMPLETED",
            now.minusSeconds(3600),
            now.minusSeconds(3550),
            List.of(ev1, ev2)
        );

        campaigns.put(c1.id(), c1);
        campaigns.put(c2.id(), c2);
    }

    public List<AdversaryCampaign> getCampaigns() {
        return campaigns.values().stream()
            .sorted(Comparator.comparing(AdversaryCampaign::startedAt).reversed())
            .toList();
    }

    public Optional<AdversaryCampaign> getCampaign(String id) {
        return Optional.ofNullable(campaigns.get(id));
    }

    public AdversaryCampaign runCampaign(String name, String targetEndpoint, AdversaryMutationStrategy strategy, int probeCount) {
        int count = Math.max(1, Math.min(probeCount, 100));
        String id = "ADV-CAMP-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase();
        Instant startedAt = Instant.now();

        String method = "POST";
        String path = targetEndpoint;
        if (targetEndpoint.contains(" ")) {
            String[] parts = targetEndpoint.split(" ", 2);
            method = parts[0].toUpperCase();
            path = parts[1];
        }

        int blocked = 0;
        int evaded = 0;
        List<AdversaryProbeResult> traces = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            String probeId = "PRB-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
            String sessionId = "sess-probe-" + UUID.randomUUID().toString().substring(0, 8);

            // Execute probe evaluation against Gateway workflow engine
            WorkflowCheckResult result = workflowStateService.checkCompliance(
                sessionId,
                method,
                path,
                List.of("ROLE_CUSTOMER")
            );

            if (!result.allowed()) {
                blocked++;
            } else {
                evaded++;
                if (traces.size() < 5) {
                    traces.add(new AdversaryProbeResult(
                        probeId,
                        method,
                        path,
                        sessionId,
                        strategy,
                        false,
                        200,
                        null,
                        String.format("Adversarial probe with strategy %s bypassed edge policies for %s %s", strategy, method, path)
                    ));
                }
            }
        }

        Instant completedAt = Instant.now();
        double evasionRate = count > 0 ? (double) evaded / count : 0.0;

        AdversaryCampaign campaign = new AdversaryCampaign(
            id,
            name != null ? name : "Automated " + strategy + " Campaign",
            method + " " + path,
            strategy,
            count,
            blocked,
            evaded,
            evasionRate,
            "COMPLETED",
            startedAt,
            completedAt,
            traces
        );

        campaigns.put(id, campaign);
        log.warn("Adversary Campaign Executed: [{}] '{}' target: {} {} - Probes: {}, Blocked: {}, Evaded: {} ({:.1f}%)",
            id, campaign.name(), method, path, count, blocked, evaded, evasionRate * 100);

        return campaign;
    }
}
