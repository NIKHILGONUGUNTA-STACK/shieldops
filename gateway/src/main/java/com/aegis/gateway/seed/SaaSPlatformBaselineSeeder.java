package com.aegis.gateway.seed;

import com.aegis.gateway.detection.campaign.*;
import com.aegis.gateway.detection.model.*;
import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.evaluation.dto.AblationResponse;
import com.aegis.gateway.evaluation.dto.ExperimentImportRequest;
import com.aegis.gateway.evaluation.dto.RobustnessFindingDto;
import com.aegis.gateway.evaluation.service.ResearchEvaluationService;
import com.aegis.gateway.specs.ApiSpecificationService;
import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Enterprise SaaS Platform Baseline Seeder.
 * Runs idempotently on application startup to ensure all 15 SOC dashboard views
 * have rich, real database-backed entities out of the box:
 * 1. Registered OpenAPI contracts (Customer, Account, Transaction services)
 * 2. Multi-tenant API telemetry across banking and retail tenants
 * 3. Triageable security incidents with forensic evidence and status transition histories
 * 4. Advisory policy decisions logged under the out-of-band architecture
 * 5. Correlated multi-stage attack campaigns with timeline events
 * 6. Canonical research benchmark baseline (DS-AEGIS-RESEARCH-V1.1)
 */
@Component
public class SaaSPlatformBaselineSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SaaSPlatformBaselineSeeder.class);

    private final ApiSpecificationService apiSpecificationService;
    private final ApiEventRepository apiEventRepository;
    private final IncidentRepository incidentRepository;
    private final CampaignRepository campaignRepository;
    private final Optional<ResearchEvaluationService> evaluationService;
    private final ResourceLoader resourceLoader;
    private final ObjectMapper objectMapper;
    private final boolean seedEnabled;

    public SaaSPlatformBaselineSeeder(
        ApiSpecificationService apiSpecificationService,
        ApiEventRepository apiEventRepository,
        IncidentRepository incidentRepository,
        CampaignRepository campaignRepository,
        Optional<ResearchEvaluationService> evaluationService,
        ResourceLoader resourceLoader,
        ObjectMapper objectMapper,
        @Value("${aegis.seed.baseline.enabled:true}") boolean seedEnabled
    ) {
        this.apiSpecificationService = apiSpecificationService;
        this.apiEventRepository = apiEventRepository;
        this.incidentRepository = incidentRepository;
        this.campaignRepository = campaignRepository;
        this.evaluationService = evaluationService;
        this.resourceLoader = resourceLoader;
        this.objectMapper = objectMapper;
        this.seedEnabled = seedEnabled;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!seedEnabled) {
            log.info("SaaS baseline seeding is disabled by configuration (aegis.seed.baseline.enabled=false).");
            return;
        }

        try {
            seedOpenApiSpecifications();
            seedResearchBenchmark();

            UUID inc1Id = UUID.fromString("b01a0000-0000-4000-8000-000000000001");
            UUID campaignId = UUID.fromString("c01a0000-0000-4000-8000-000000000001");
            boolean hasBaselineEvents = apiEventRepository.findEvents(0, 1, null, null, null, null, null, null, null, null, "corr-benign-alex-0").totalElements() > 0;
            boolean hasBaselineIncidents = incidentRepository.findById(inc1Id).isPresent();
            boolean hasBaselineCampaigns = campaignRepository.findById(campaignId).isPresent();

            if (!hasBaselineEvents || !hasBaselineIncidents || !hasBaselineCampaigns) {
                log.info("Seeding realistic SaaS multi-tenant API telemetry, active incidents, and campaigns (events missing: {}, incidents missing: {}, campaigns missing: {})...",
                    !hasBaselineEvents, !hasBaselineIncidents, !hasBaselineCampaigns);
                seedTelemetryIncidentsAndCampaigns(hasBaselineEvents, hasBaselineIncidents, hasBaselineCampaigns);
                log.info("Successfully completed SaaS baseline platform seeding.");
            } else {
                log.info("Baseline telemetry, incidents, and campaigns already present. Skipping duplicate seeding.");
            }
        } catch (Exception e) {
            log.error("Error during SaaS baseline seeding: {}", e.getMessage(), e);
        }
    }

    public void seedOpenApiSpecifications() {
        String[] specFiles = new String[] {
            "customer-service.yaml",
            "account-service.yaml",
            "transaction-service.yaml"
        };

        for (String filename : specFiles) {
            try {
                Resource resource = resourceLoader.getResource("classpath:specs/" + filename);
                if (resource.exists() && resource.isReadable()) {
                    try (InputStream is = resource.getInputStream()) {
                        byte[] bytes = is.readAllBytes();
                        apiSpecificationService.importSpecification(bytes, filename, "saas-baseline-bootstrap");
                        log.info("Loaded OpenAPI contract: {}", filename);
                    }
                } else {
                    log.debug("Spec resource not found at classpath:specs/{}", filename);
                }
            } catch (Exception e) {
                log.warn("Failed to load specification {}: {}", filename, e.getMessage());
            }
        }
    }

    public void seedResearchBenchmark() {
        if (evaluationService.isEmpty()) {
            return;
        }
        try {
            var latest = evaluationService.get().getLatestBenchmark();
            if (latest != null && "DS-AEGIS-RESEARCH-V1.1".equals(latest.datasetId())) {
                return; // already present
            }
        } catch (Exception ignored) {
        }

        try {
            ExperimentImportRequest fallbackReq = new ExperimentImportRequest(
                "DS-AEGIS-RESEARCH-V1.1",
                "1.1.0",
                "83e67d66853de0ca17ad4e94617470df5ea50f62409d7fc857577090138d9f78",
                200, 80, 70, 30, 20,
                "EXP-V11-CANONICAL",
                "Neutral Corpus v1.1 Comparative Evaluation",
                Map.of("coverageRatio", "0.75", "primaryBinaryEvaluated", "150"),
                List.of(
                    new AblationResponse("FULL_CONTEXTUAL", 1.0, 1.0, 1.0, 0.0, 0.0),
                    new AblationResponse("NO_IDENTITY", 1.0, 1.0, 1.0, 0.0, 0.0),
                    new AblationResponse("NO_TENANT", 1.0, 1.0, 1.0, 0.0, 0.0),
                    new AblationResponse("NO_OWNERSHIP", 1.0, 0.8571, 0.9231, 0.0, -0.0769),
                    new AblationResponse("NO_SENSITIVITY", 1.0, 0.8571, 0.9231, 0.0, -0.0769),
                    new AblationResponse("NO_AUTH_OUTCOME", 1.0, 1.0, 1.0, 0.0, 0.0),
                    new AblationResponse("NO_TEMPORAL", 1.0, 0.8571, 0.9231, 0.0, -0.0769),
                    new AblationResponse("NO_CAMPAIGN", 1.0, 1.0, 1.0, 0.0, 0.0)
                ),
                List.of(
                    new RobustnessFindingDto("Shared-IP NAT Disambiguation", "Identity & Network", "Partitioned", "Zero false positive alarm", true, "Anti-Affinity"),
                    new RobustnessFindingDto("Cross-Owner Account Detail Probe", "Resource Ownership", "Mismatched ID", "BOLA alert produced", true, "Ownership"),
                    new RobustnessFindingDto("Restricted Secret Exposure", "Sensitivity Classification", "Leaking secret", "CRITICAL alert produced", true, "Classification"),
                    new RobustnessFindingDto("Sliding-Window Temporal Eviction", "Temporal Behavior", "Beyond 120s window", "Evicted safely", true, "Deque Eviction"),
                    new RobustnessFindingDto("Automated Pagination Scraping", "API Behavior", "Harvesting >= 3 pages", "Flagged with high confidence", true, "Pagination"),
                    new RobustnessFindingDto("Missing Resource Ownership Uncertainty", "Uncertainty", "Missing ownership", "Flagged UNCERTAIN for triage", true, "Uncertainty"),
                    new RobustnessFindingDto("Multi-Stage Kill-Chain Progression", "Campaign Correlation", "Recon+Probe+Extract", "DATA_EXFILTRATION_CAMPAIGN materialized", true, "Campaign")
                )
            );
            evaluationService.get().importExperiment(fallbackReq);
            log.info("Initialized canonical DS-AEGIS-RESEARCH-V1.1 benchmark baseline.");
        } catch (Exception ex) {
            log.warn("Could not import benchmark baseline: {}", ex.getMessage());
        }
    }

    public void seedTelemetryIncidentsAndCampaigns() {
        seedTelemetryIncidentsAndCampaigns(false, false, false);
    }

    public void seedTelemetryIncidentsAndCampaigns(boolean hasBaselineEvents, boolean hasBaselineIncidents, boolean hasBaselineCampaigns) {
        Instant now = Instant.now();
        List<ApiEvent> events = new ArrayList<>();

        // Tenant IDs
        String tenantUS = "tenant-fintech-us";
        String tenantEU = "tenant-retail-eu";
        String tenantAPAC = "tenant-apac-banking";

        // IDs
        String custAlex = "10000000-0000-4000-8000-000000000001";
        String acctAlex = "20000000-0000-4000-8000-000000000001";

        String custSam = "10000000-0000-4000-8000-000000000002";
        String acctSam = "20000000-0000-4000-8000-000000000002";

        String custAttacker = "10000000-0000-4000-8000-000000000099";

        // 1. Benign FinTech Baseline Events (100 events across last 24h)
        for (int i = 0; i < 40; i++) {
            Instant ts = now.minus(24 * 60 - i * 35, ChronoUnit.MINUTES);
            events.add(new ApiEvent(
                UUID.randomUUID(),
                "corr-benign-alex-" + i,
                ts,
                "192.168.1.100",
                "GET",
                "/customers/" + custAlex,
                "customer_service",
                200,
                18 + (i % 15),
                "usr-alex-01",
                "ROLE_CUSTOMER",
                custAlex,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "hash-alex-" + i,
                "NONE",
                "CUSTOMER",
                custAlex,
                null,
                580,
                1,
                "id,firstName,lastName,email,phone,taxId,address",
                null,
                null,
                null, null, null, null,
                tenantUS,
                "customer-service"
            ));

            events.add(new ApiEvent(
                UUID.randomUUID(),
                "corr-benign-acct-" + i,
                ts.plusSeconds(2),
                "192.168.1.100",
                "GET",
                "/accounts/" + acctAlex,
                "account_service",
                200,
                22 + (i % 10),
                "usr-alex-01",
                "ROLE_CUSTOMER",
                custAlex,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "hash-acct-" + i,
                "NONE",
                "ACCOUNT",
                acctAlex,
                null,
                420,
                1,
                "id,accountNumber,balance,currency,status,customerId",
                null,
                null,
                null, null, null, null,
                tenantUS,
                "account-service"
            ));
        }

        // EU Retail Tenant benign activity
        for (int i = 0; i < 20; i++) {
            Instant ts = now.minus(20 * 60 - i * 50, ChronoUnit.MINUTES);
            events.add(new ApiEvent(
                UUID.randomUUID(),
                "corr-eu-sam-" + i,
                ts,
                "192.168.1.105",
                "GET",
                "/accounts/" + acctSam + "/balance",
                "account_service",
                200,
                15 + (i % 8),
                "usr-sam-02",
                "ROLE_CUSTOMER",
                custSam,
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
                "hash-sam-" + i,
                "NONE",
                "ACCOUNT",
                acctSam,
                null,
                280,
                1,
                "id,balance,currency",
                null,
                null,
                null, null, null, null,
                tenantEU,
                "account-service"
            ));
        }

        // 2. Reconnaissance Scan Events (15 events)
        List<UUID> reconEventIds = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            Instant ts = now.minus(18 * 60 - i * 5, ChronoUnit.MINUTES);
            String targetPath = (i % 3 == 0) ? "/actuator/env" : ((i % 3 == 1) ? "/swagger-ui.html" : "/admin/metrics");
            UUID eid = UUID.randomUUID();
            reconEventIds.add(eid);
            events.add(new ApiEvent(
                eid,
                "corr-recon-" + i,
                ts,
                "198.51.100.42",
                "GET",
                targetPath,
                "gateway_direct",
                404,
                12,
                "anonymous",
                "NONE",
                null,
                "curl/7.88.1 (Security Scanner)",
                "hash-recon-" + i,
                "RECON_SCAN",
                "PERIMETER",
                targetPath,
                "NOT_FOUND",
                145,
                0,
                null,
                null,
                null,
                null, null, null, null,
                tenantUS,
                "perimeter"
            ));
        }

        // 3. BOLA Probing and Confirmed Leakage Events (20 events)
        List<UUID> bolaEventIds = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            Instant ts = now.minus(10 * 60 - i * 15, ChronoUnit.MINUTES);
            UUID eid = UUID.randomUUID();
            bolaEventIds.add(eid);
            boolean isLeak = (i >= 10); // last 5 were successful leaks
            events.add(new ApiEvent(
                eid,
                "corr-bola-" + i,
                ts,
                "203.0.113.15",
                "GET",
                "/accounts/" + acctSam,
                "account_service",
                isLeak ? 200 : 403,
                isLeak ? 38 : 14,
                "usr-attacker-99",
                "ROLE_CUSTOMER",
                custAttacker,
                "Python-requests/2.31.0",
                "hash-bola-" + i,
                isLeak ? "BOLA_CONFIRMED_LEAK" : "BOLA_ATTEMPT",
                "ACCOUNT",
                acctSam,
                isLeak ? null : "FORBIDDEN",
                isLeak ? 1280 : 120,
                1,
                "id,accountNumber,balance,currency,status,customerId",
                null,
                null,
                null, null, null, null,
                tenantUS,
                "account-service"
            ));
        }

        // 4. Sensitive Secret Exposure Events (10 events)
        List<UUID> exposureEventIds = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Instant ts = now.minus(8 * 60 - i * 20, ChronoUnit.MINUTES);
            UUID eid = UUID.randomUUID();
            exposureEventIds.add(eid);
            events.add(new ApiEvent(
                eid,
                "corr-exposure-" + i,
                ts,
                "192.168.1.100",
                "POST",
                "/customers",
                "customer_service",
                200,
                42,
                "usr-alex-01",
                "ROLE_CUSTOMER",
                custAlex,
                "PostmanRuntime/7.36.0",
                "hash-exposure-" + i,
                "SENSITIVE_DATA_EXPOSURE",
                "CUSTOMER",
                custAlex,
                null,
                2450,
                1,
                "id,firstName,lastName,email,taxId,auth_token_hash,apiKeySecret",
                null,
                null,
                null, null, null, null,
                tenantUS,
                "customer-service"
            ));
        }

        // 5. Excessive Bulk Data Extraction / Deep Pagination Events (10 events)
        List<UUID> bulkEventIds = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Instant ts = now.minus(4 * 60 - i * 10, ChronoUnit.MINUTES);
            UUID eid = UUID.randomUUID();
            bulkEventIds.add(eid);
            events.add(new ApiEvent(
                eid,
                "corr-bulk-" + i,
                ts,
                "10.0.1.50",
                "GET",
                "/transactions?page=" + (100 + i) + "&size=1000",
                "transaction_service",
                200,
                185,
                "usr-batch-scrape",
                "ROLE_BATCH_SERVICE",
                null,
                "Scrapy/2.11.0",
                "hash-bulk-" + i,
                "EXCESSIVE_DATA_EXTRACTION",
                "TRANSACTION",
                "BULK-TX-SET",
                null,
                245000,
                1000,
                "id,accountId,amount,currency,timestamp,reference,recipientNote",
                100 + i,
                1000,
                null, null, null, null,
                tenantUS,
                "transaction-service"
            ));
        }

        // 6. SQL Injection Attempt Events (5 events)
        List<UUID> sqliEventIds = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Instant ts = now.minus(2 * 60 - i * 15, ChronoUnit.MINUTES);
            UUID eid = UUID.randomUUID();
            sqliEventIds.add(eid);
            events.add(new ApiEvent(
                eid,
                "corr-sqli-" + i,
                ts,
                "198.51.100.42",
                "GET",
                "/customers?search=' UNION SELECT 1,username,password FROM users--",
                "customer_service",
                400,
                25,
                "anonymous",
                "NONE",
                null,
                "sqlmap/1.7.11#stable",
                "hash-sqli-" + i,
                "INJECTION_ATTEMPT",
                "ENDPOINT",
                "/customers",
                "BAD_REQUEST",
                210,
                0,
                null,
                null,
                null,
                null, null, null, null,
                tenantUS,
                "customer-service"
            ));
        }

        // Save all events to database if not already present
        if (!hasBaselineEvents) {
            apiEventRepository.saveAll(events);
            log.info("Persisted {} multi-tenant API events to security_data.api_events", events.size());
        } else {
            log.info("Baseline API events already present. Skipping event batch insert.");
        }

        // -------------------------------------------------------------
        // Seed 6 Active/Investigating/Resolved Security Incidents
        // -------------------------------------------------------------
        UUID inc1Id = UUID.fromString("b01a0000-0000-4000-8000-000000000001");
        UUID inc1bId = UUID.fromString("b01a0000-0000-4000-8000-00000000001b");
        UUID inc2Id = UUID.fromString("b01a0000-0000-4000-8000-000000000002");
        UUID inc3Id = UUID.fromString("b01a0000-0000-4000-8000-000000000003");
        UUID inc4Id = UUID.fromString("b01a0000-0000-4000-8000-000000000004");
        UUID inc5Id = UUID.fromString("b01a0000-0000-4000-8000-000000000005");

        if (!hasBaselineIncidents) {
            SecurityIncident inc1 = new SecurityIncident(
                inc1Id,
                "FP-BOLA-200000000002-USR99",
                "RULE-BOLA-01",
                "1.0.0",
                "BOLA",
                "CRITICAL",
                IncidentStatus.OPEN,
                "ACCOUNT",
                acctSam,
                now.minus(10, ChronoUnit.HOURS),
                now.minus(2, ChronoUnit.HOURS),
                15,
                "Confirmed BOLA unauthorized data leakage: Attacker usr-attacker-99 accessed account resource 20000000-0000-4000-8000-000000000002 belonging to Sam Taylor",
                now.minus(10, ChronoUnit.HOURS),
                now.minus(2, ChronoUnit.HOURS)
            );
            incidentRepository.saveIncident(inc1);
            incidentRepository.saveEvidence(new DetectionEvidence(
                UUID.randomUUID(),
                inc1Id,
                "RULE-BOLA-01",
                "1.0.0",
                now.minus(2, ChronoUnit.HOURS),
                0.98,
                "CRITICAL",
                "Cross-subject resource owner mismatch with HTTP 200 and sensitive financial schema fields",
                15,
                7200,
                2,
                "Observed 5 successful HTTP 200 leakages containing native financial balances after initial 403 rejections.",
                bolaEventIds,
                now.minus(2, ChronoUnit.HOURS)
            ));
            incidentRepository.savePolicyDecision(new PolicyDecision(
                UUID.randomUUID(),
                inc1Id,
                "POL-BOLA-DEFENSE-01",
                "TERMINATE_SESSION",
                "ADVISORY",
                now.minus(2, ChronoUnit.HOURS),
                now.plus(24, ChronoUnit.HOURS),
                "Confirmed exfiltration of sensitive account balance and ownership records across tenant boundaries.",
                now.minus(2, ChronoUnit.HOURS)
            ));
            incidentRepository.saveStatusHistory(new IncidentStatusHistory(
                UUID.randomUUID(),
                inc1Id,
                "NONE",
                "OPEN",
                "system-correlator",
                now.minus(10, ChronoUnit.HOURS),
                "Initial automated correlation from RULE-BOLA-01 alert stream"
            ));

            // Incident 1b: Investigating BOLA Access Attempt
            SecurityIncident inc1b = new SecurityIncident(
                inc1bId,
                "FP-BOLA-200000000001-USR98",
                "RULE-BOLA-01",
                "1.0.0",
                "BOLA",
                "HIGH",
                IncidentStatus.INVESTIGATING,
                "ACCOUNT",
                acctAlex,
                now.minus(6, ChronoUnit.HOURS),
                now.minus(1, ChronoUnit.HOURS),
                8,
                "Cross-Tenant Object Level Authorization Probe: External caller usr-attacker-98 attempted IDOR access to account resource 20000000-0000-4000-8000-000000000001",
                now.minus(6, ChronoUnit.HOURS),
                now.minus(1, ChronoUnit.HOURS)
            );
            incidentRepository.saveIncident(inc1b);
            incidentRepository.saveEvidence(new DetectionEvidence(
                UUID.randomUUID(),
                inc1bId,
                "RULE-BOLA-01",
                "1.0.0",
                now.minus(1, ChronoUnit.HOURS),
                0.91,
                "HIGH",
                "Sliding-window threshold exceeded: 3 unauthorized attempts across distinct account resources",
                8,
                300,
                2,
                "Observed multiple 403 Forbidden responses attempting access to accounts owned by other customer identities.",
                bolaEventIds.isEmpty() ? List.of(UUID.randomUUID()) : bolaEventIds.subList(0, Math.min(3, bolaEventIds.size())),
                now.minus(1, ChronoUnit.HOURS)
            ));
            incidentRepository.savePolicyDecision(new PolicyDecision(
                UUID.randomUUID(),
                inc1bId,
                "POL-BOLA-DEFENSE-01",
                "INVESTIGATE_ACTIVITY",
                "ADVISORY",
                now.minus(5, ChronoUnit.HOURS),
                now.plus(12, ChronoUnit.HOURS),
                "Repeated 403 Forbidden responses against foreign object identifiers recorded for forensic review.",
                now.minus(5, ChronoUnit.HOURS)
            ));
            incidentRepository.saveStatusHistory(new IncidentStatusHistory(
                UUID.randomUUID(),
                inc1bId,
                "OPEN",
                "INVESTIGATING",
                "analyst-sarah",
                now.minus(30, ChronoUnit.MINUTES),
                "Investigating whether probe was automated scanner or targeted penetration test."
            ));

            // Incident 2: Reconnaissance
            SecurityIncident inc2 = new SecurityIncident(
            inc2Id,
            "FP-RECON-1985110042",
            "RULE-RECON-01",
            "1.0.0",
            "CREDENTIAL_ACCESS",
            "HIGH",
            IncidentStatus.INVESTIGATING,
            "PERIMETER",
            "198.51.100.42",
            now.minus(18, ChronoUnit.HOURS),
            now.minus(16, ChronoUnit.HOURS),
            15,
            "Perimeter route enumeration: Repeated 404 probes against non-declared administrative endpoints (/actuator/env, /swagger-ui.html)",
            now.minus(18, ChronoUnit.HOURS),
            now.minus(16, ChronoUnit.HOURS)
        );
        incidentRepository.saveIncident(inc2);
        incidentRepository.saveEvidence(new DetectionEvidence(
            UUID.randomUUID(),
            inc2Id,
            "RULE-RECON-01",
            "1.0.0",
            now.minus(16, ChronoUnit.HOURS),
            0.92,
            "HIGH",
            "Rapid discovery burst against non-inventoried administrative routes",
            15,
            1800,
            3,
            "Source IP scanned 3 distinct undeclared admin paths in under 15 minutes.",
            reconEventIds,
            now.minus(16, ChronoUnit.HOURS)
        ));
        incidentRepository.savePolicyDecision(new PolicyDecision(
            UUID.randomUUID(),
            inc2Id,
            "POL-RATE-LIMIT-ADVISORY",
            "RATE_LIMIT_IP",
            "ADVISORY",
            now.minus(16, ChronoUnit.HOURS),
            now.plus(12, ChronoUnit.HOURS),
            "Sustained scanning behavior exceeding 10 probes/minute from unauthenticated external IP.",
            now.minus(16, ChronoUnit.HOURS)
        ));
        incidentRepository.saveStatusHistory(new IncidentStatusHistory(
            UUID.randomUUID(),
            inc2Id,
            "NONE",
            "OPEN",
            "system-correlator",
            now.minus(18, ChronoUnit.HOURS),
            "Initial automated correlation from RULE-RECON-01"
        ));
        incidentRepository.saveStatusHistory(new IncidentStatusHistory(
            UUID.randomUUID(),
            inc2Id,
            "OPEN",
            "INVESTIGATING",
            "analyst-sarah",
            now.minus(17, ChronoUnit.HOURS),
            "Assigned to Tier-2 SOC Analyst for perimeter IP reputation triage"
        ));

            // Incident 3: Sensitive Secret Exposure
            SecurityIncident inc3 = new SecurityIncident(
            inc3Id,
            "FP-EXPOSURE-CUSTOMER-HASH",
            "RULE-SENSITIVE-DATA-01",
            "1.0.0",
            "SENSITIVE_DATA_EXPOSURE",
            "CRITICAL",
            IncidentStatus.OPEN,
            "SERVICE",
            "customer-service",
            now.minus(8, ChronoUnit.HOURS),
            now.minus(4, ChronoUnit.HOURS),
            10,
            "Sensitive Credential Exposure: Internal auth token hash and raw tax ID detected in outbound JSON body",
            now.minus(8, ChronoUnit.HOURS),
            now.minus(4, ChronoUnit.HOURS)
        );
        incidentRepository.saveIncident(inc3);
        incidentRepository.saveEvidence(new DetectionEvidence(
            UUID.randomUUID(),
            inc3Id,
            "RULE-SENSITIVE-DATA-01",
            "1.0.0",
            now.minus(4, ChronoUnit.HOURS),
            0.99,
            "CRITICAL",
            "Field classification matches RESTRICTED pattern: auth_token_hash, tax_id",
            10,
            3600,
            1,
            "Response payloads from /customers contained unmasked API keys and credential digests.",
            exposureEventIds,
            now.minus(4, ChronoUnit.HOURS)
        ));
        incidentRepository.savePolicyDecision(new PolicyDecision(
            UUID.randomUUID(),
            inc3Id,
            "POL-MASKING-INVARIANT",
            "FLAG_SENSITIVE_FIELD",
            "ADVISORY",
            now.minus(4, ChronoUnit.HOURS),
            now.plus(48, ChronoUnit.HOURS),
            "Response field contains unmasked authorization secrets violating Zero-Trust field classification policy.",
            now.minus(4, ChronoUnit.HOURS)
        ));

            // Incident 4: Bulk Deep Pagination Scraping
            SecurityIncident inc4 = new SecurityIncident(
            inc4Id,
            "FP-EXTRACTION-BATCH-SCRAPE",
            "RULE-EXTRACTION-01",
            "1.0.0",
            "EXCESSIVE_DATA_EXTRACTION",
            "HIGH",
            IncidentStatus.CONTAINED,
            "CUSTOMER",
            "usr-batch-scrape",
            now.minus(4, ChronoUnit.HOURS),
            now.minus(1, ChronoUnit.HOURS),
            10,
            "Bulk Data Extraction: Automated pagination harvesting 10,000+ financial transaction records within 2 minutes",
            now.minus(4, ChronoUnit.HOURS),
            now.minus(1, ChronoUnit.HOURS)
        );
        incidentRepository.saveIncident(inc4);
        incidentRepository.saveEvidence(new DetectionEvidence(
            UUID.randomUUID(),
            inc4Id,
            "RULE-EXTRACTION-01",
            "1.0.0",
            now.minus(1, ChronoUnit.HOURS),
            0.89,
            "HIGH",
            "Total transferred payload exceeded 2.45MB across sequential page queries",
            10,
            120,
            1,
            "10 consecutive queries with pageSize=1000 retrieved comprehensive historical transaction ledger.",
            bulkEventIds,
            now.minus(1, ChronoUnit.HOURS)
        ));
        incidentRepository.saveStatusHistory(new IncidentStatusHistory(
            UUID.randomUUID(),
            inc4Id,
            "INVESTIGATING",
            "CONTAINED",
            "analyst-sarah",
            now.minus(30, ChronoUnit.MINUTES),
            "Client confirmed non-interactive scraper. Throttling advisory active."
        ));

            // Incident 5: SQL Injection Attempt (Resolved)
            SecurityIncident inc5 = new SecurityIncident(
            inc5Id,
            "FP-SQLI-CUSTOMER-QUERY",
            "RULE-SQLI-01",
            "1.0.0",
            "INJECTION_ATTEMPT",
            "MEDIUM",
            IncidentStatus.RESOLVED,
            "ENDPOINT",
            "/customers",
            now.minus(2, ChronoUnit.HOURS),
            now.minus(1, ChronoUnit.HOURS),
            5,
            "SQL Injection Probe: UNION SELECT syntax fragment in customer search parameter",
            now.minus(2, ChronoUnit.HOURS),
            now.minus(1, ChronoUnit.HOURS)
        );
        incidentRepository.saveIncident(inc5);
        incidentRepository.saveStatusHistory(new IncidentStatusHistory(
            UUID.randomUUID(),
            inc5Id,
            "OPEN",
            "RESOLVED",
            "lead-analyst-dave",
            now.minus(45, ChronoUnit.MINUTES),
            "Confirmed sanitized by JPA repository. No data compromise."
        ));

            log.info("Persisted 6 security incidents with forensic evidence, policy decisions, and status histories.");
        } else {
            log.info("Security incidents already present. Skipping incident seeding.");
        }

        // -------------------------------------------------------------
        // Seed Multi-Stage Exfiltration Campaigns
        // -------------------------------------------------------------
        UUID campaignId = UUID.fromString("c01a0000-0000-4000-8000-000000000001");
        UUID campaign2Id = UUID.fromString("c01a0000-0000-4000-8000-000000000002");

        if (!hasBaselineCampaigns) {
            ExfiltrationCampaign campaign = new ExfiltrationCampaign(
                campaignId,
                "EXFIL-CAMPAIGN-001",
                "attacker-ip-198.51.100.42",
                tenantUS,
                "198.51.100.42",
                CampaignStage.BULK_EXTRACTION,
                List.of(CampaignStage.RECONNAISSANCE, CampaignStage.AUTHORIZATION_PROBING, CampaignStage.BULK_EXTRACTION),
                CampaignStatus.OPEN,
                "CRITICAL",
                94.5,
                "CRITICAL",
                "Temporal kill-chain correlation: Adversary progressed from perimeter discovery (/actuator/env) to BOLA authorization probing and bulk data extraction of customer financial accounts.",
                CampaignEvidenceCompleteness.COMPLETE,
                "None. All kill chain stages confirmed via wire telemetry.",
                5,
                3,
                2,
                now.minus(18, ChronoUnit.HOURS),
                now.minus(2, ChronoUnit.HOURS),
                35,
                List.of(reconEventIds.get(0), bolaEventIds.get(0), bolaEventIds.get(bolaEventIds.size() - 1)),
                List.of(inc1Id, inc2Id),
                List.of("RULE-RECON-01", "RULE-BOLA-01", "RULE-EXTRACTION-01"),
                now.minus(18, ChronoUnit.HOURS),
                now.minus(2, ChronoUnit.HOURS)
            );
            campaignRepository.saveCampaign(campaign);

            // Timeline events for the campaign
            campaignRepository.saveTimelineEvent(new CampaignTimelineEvent(
                UUID.randomUUID(),
                campaignId,
                CampaignStage.RECONNAISSANCE,
                reconEventIds.get(0),
                "RULE-RECON-01",
                now.minus(18, ChronoUnit.HOURS),
                "GET",
                "/actuator/env",
                404,
                "Perimeter enumeration against non-inventoried administrative endpoint",
                now.minus(18, ChronoUnit.HOURS)
            ));
            campaignRepository.saveTimelineEvent(new CampaignTimelineEvent(
                UUID.randomUUID(),
                campaignId,
                CampaignStage.AUTHORIZATION_PROBING,
                bolaEventIds.get(0),
                "RULE-BOLA-01",
                now.minus(10, ChronoUnit.HOURS),
                "GET",
                "/accounts/" + acctSam,
                403,
                "Cross-tenant IDOR access probe against victim account",
                now.minus(10, ChronoUnit.HOURS)
            ));
            campaignRepository.saveTimelineEvent(new CampaignTimelineEvent(
                UUID.randomUUID(),
                campaignId,
                CampaignStage.BULK_EXTRACTION,
                bolaEventIds.get(bolaEventIds.size() - 1),
                "RULE-BOLA-01",
                now.minus(2, ChronoUnit.HOURS),
                "GET",
                "/accounts/" + acctSam,
                200,
                "Successful unauthorized financial exfiltration containing account balance and PII",
                now.minus(2, ChronoUnit.HOURS)
            ));

            campaignRepository.saveStatusHistory(new CampaignStatusHistory(
                UUID.randomUUID(),
                campaignId,
                CampaignStatus.OPEN,
                CampaignStatus.INVESTIGATING,
                "security-engine",
                now.minus(10, ChronoUnit.HOURS),
                "Automated multi-vector campaign promotion upon observing stage escalation"
            ));

            // Seed Campaign 2: Investigating BOLA / Credential Enumeration
            ExfiltrationCampaign campaign2 = new ExfiltrationCampaign(
                campaign2Id,
                "EXFIL-CAMPAIGN-002",
                "attacker-ip-203.0.113.88",
                tenantEU,
                "203.0.113.88",
                CampaignStage.AUTHORIZATION_PROBING,
                List.of(CampaignStage.RECONNAISSANCE, CampaignStage.AUTHORIZATION_PROBING),
                CampaignStatus.INVESTIGATING,
                "HIGH",
                82.0,
                "HIGH",
                "Multi-resource IDOR & BOLA credential enumeration campaign across European retail tenant accounts.",
                CampaignEvidenceCompleteness.COMPLETE,
                "Full correlation across 12 API probe requests.",
                3,
                2,
                1,
                now.minus(8, ChronoUnit.HOURS),
                now.minus(4, ChronoUnit.HOURS),
                18,
                reconEventIds.isEmpty() ? List.of(UUID.randomUUID()) : List.of(reconEventIds.get(0)),
                List.of(inc1Id),
                List.of("RULE-RECON-01", "RULE-BOLA-01"),
                now.minus(8, ChronoUnit.HOURS),
                now.minus(4, ChronoUnit.HOURS)
            );
            campaignRepository.saveCampaign(campaign2);
            campaignRepository.saveTimelineEvent(new CampaignTimelineEvent(
                UUID.randomUUID(),
                campaign2Id,
                CampaignStage.RECONNAISSANCE,
                UUID.randomUUID(),
                "RULE-RECON-01",
                now.minus(8, ChronoUnit.HOURS),
                "GET",
                "/api/v1/customers",
                401,
                "Anonymous enumeration of customer listing endpoint",
                now.minus(8, ChronoUnit.HOURS)
            ));
            campaignRepository.saveTimelineEvent(new CampaignTimelineEvent(
                UUID.randomUUID(),
                campaign2Id,
                CampaignStage.AUTHORIZATION_PROBING,
                UUID.randomUUID(),
                "RULE-BOLA-01",
                now.minus(2, ChronoUnit.HOURS),
                "GET",
                "/accounts/20000000-0000-4000-8000-000000000001",
                403,
                "Cross-tenant IDOR probing against retail account",
                now.minus(2, ChronoUnit.HOURS)
            ));
            campaignRepository.saveStatusHistory(new CampaignStatusHistory(
                UUID.randomUUID(),
                campaign2Id,
                CampaignStatus.OPEN,
                CampaignStatus.INVESTIGATING,
                "analyst-sarah",
                now.minus(4, ChronoUnit.HOURS),
                "Analyst escalated to investigating after observing cross-tenant resource probe sequence"
            ));

            log.info("Persisted multi-stage exfiltration campaigns EXFIL-CAMPAIGN-001 and EXFIL-CAMPAIGN-002 with timeline events.");
        } else {
            log.info("Exfiltration campaigns already present. Skipping campaign seeding.");
        }
    }
}
