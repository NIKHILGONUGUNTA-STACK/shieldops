package com.aegis.gateway.simulation.service;

import com.aegis.gateway.simulation.model.SimulationCampaignStage;
import com.aegis.gateway.simulation.model.SimulationCampaignTemplate;
import com.aegis.gateway.simulation.model.SimulationScenarioDto;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class SimulationCatalogService {

    private final Map<String, SimulationScenarioDto> scenarios = new LinkedHashMap<>();
    private final Map<String, SimulationCampaignTemplate> templates = new LinkedHashMap<>();

    public SimulationCatalogService() {
        initScenarios();
        initTemplates();
    }

    public List<SimulationScenarioDto> getAllScenarios() {
        return new ArrayList<>(scenarios.values());
    }

    public Optional<SimulationScenarioDto> getScenario(String id) {
        return Optional.ofNullable(scenarios.get(id));
    }

    public List<SimulationCampaignTemplate> getAllTemplates() {
        return new ArrayList<>(templates.values());
    }

    public Optional<SimulationCampaignTemplate> getTemplate(String id) {
        return Optional.ofNullable(templates.get(id));
    }

    private void registerScenario(SimulationScenarioDto dto) {
        scenarios.put(dto.id(), dto);
    }

    private void registerTemplate(SimulationCampaignTemplate template) {
        templates.put(template.id(), template);
    }

    private void initScenarios() {
        // Benign Scenarios
        registerScenario(new SimulationScenarioDto(
            "SCEN-BENIGN-01", "Normal Customer Workflow",
            "Simulates authentic customer interactions: account summary, transaction listing.",
            "BENIGN", "INFO", true,
            List.of("baseline", "benign", "customer"),
            List.of("/customers/{id}", "/accounts/{id}", "/transactions"),
            List.of("HTTP 200", "No alerts")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-BENIGN-PAGINATION", "Legitimate Deep Pagination",
            "Customer walks through pages with bounded page size under reasonable intervals.",
            "BENIGN", "INFO", true,
            List.of("pagination", "benign"),
            List.of("/transactions?page={p}&size=20"),
            List.of("HTTP 200", "No extraction alert")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-BENIGN-LARGE-RESP", "Legitimate Bulk Export",
            "Authorized customer fetches approved monthly export under reasonable thresholds.",
            "BENIGN", "INFO", true,
            List.of("volume", "benign"),
            List.of("/accounts/{id}/export"),
            List.of("HTTP 200", "No leakage alert")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-BENIGN-BENEFICIARY", "Beneficiary Creation & Verification",
            "Legitimate creation and verification of transaction beneficiaries.",
            "BENIGN", "INFO", true,
            List.of("beneficiary", "benign"),
            List.of("/beneficiaries", "/beneficiaries/verify"),
            List.of("HTTP 201", "HTTP 200")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-BENIGN-LOOKALIKE", "Benign Lookalike Traffic",
            "Burst traffic from legitimate batch dashboard operations resembling probing.",
            "BENIGN", "LOW", true,
            List.of("lookalike", "benign", "resilience"),
            List.of("/customers/{id}", "/accounts/{id}"),
            List.of("HTTP 200", "Suppressed alert")
        ));

        // BOLA / Authorization Scenarios
        registerScenario(new SimulationScenarioDto(
            "SCEN-BOLA-01", "Classic Cross-Tenant BOLA Access",
            "Attacker attempts unauthorized access to another tenant's account.",
            "BOLA", "HIGH", true,
            List.of("bola", "idor", "cross-tenant"),
            List.of("/accounts/{victim_id}"),
            List.of("HTTP 403/404", "RULE-BOLA-01 alert")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-BOLA-02", "Sequential BOLA ID Harvest",
            "Attacker enumerates sequential customer and account identifiers.",
            "BOLA", "HIGH", true,
            List.of("bola", "enumeration"),
            List.of("/customers/{seq_id}", "/accounts/{seq_id}"),
            List.of("RULE-BOLA-02 alert", "INCIDENT_CREATED")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-BOLA-CONFIRMED", "Confirmed BOLA Data Exposure",
            "Unauthorized access succeeds and returns payload containing victim confidential data.",
            "BOLA", "CRITICAL", true,
            List.of("bola", "confirmed", "leakage"),
            List.of("/accounts/{victim_id}"),
            List.of("RULE-BOLA-CONFIRMED-01 alert", "High severity incident")
        ));

        // Data Leakage & Exposure Scenarios
        registerScenario(new SimulationScenarioDto(
            "SCEN-DATA-LEAK-01", "Sensitive Data Leakage via Contract Drift",
            "Endpoint returns unclassified confidential fields outside contract.",
            "LEAKAGE", "HIGH", true,
            List.of("leakage", "classification", "schema-drift"),
            List.of("/customers/{id}"),
            List.of("RULE-DATA-LEAK-01 alert")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-DATA-RESTRICTED", "Restricted Field Exposure",
            "Endpoint leaks restricted financial data (e.g. tax identifier, full PAN).",
            "LEAKAGE", "CRITICAL", true,
            List.of("restricted", "leakage", "compliance"),
            List.of("/accounts/{id}/compliance"),
            List.of("Critical Data Leak incident")
        ));

        // Extraction & Exfiltration Scenarios
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXTRACT-PAGINATION", "Scraping via Unbounded Pagination",
            "Attacker requests large page sizes in tight succession to dump database.",
            "EXFILTRATION", "HIGH", true,
            List.of("extraction", "pagination", "bulk"),
            List.of("/transactions?page={p}&size=500"),
            List.of("RULE-BULK-EXTRACT-01 alert")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXTRACT-CUMULATIVE", "Cumulative Volume Exfiltration",
            "Slow extraction exceeding cumulative byte limits across multiple calls.",
            "EXFILTRATION", "HIGH", true,
            List.of("extraction", "cumulative", "volume"),
            List.of("/transactions", "/accounts"),
            List.of("RULE-BULK-EXTRACT-01 alert")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXTRACT-MULTI-RESOURCE", "Multi-Domain Data Extraction",
            "Coordinated extraction accessing customers, accounts, and transactions across domains.",
            "EXFILTRATION", "CRITICAL", true,
            List.of("extraction", "multi-domain", "campaign"),
            List.of("/customers", "/accounts", "/transactions"),
            List.of("Multi-Domain Extraction Campaign")
        ));

        // Multi-Stage Campaigns
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXFIL-RECON-PROBE", "Reconnaissance followed by Authorization Probing",
            "Attacker scans OpenAPI endpoints then sequentially tests parameter boundaries.",
            "EXFILTRATION", "HIGH", true,
            List.of("campaign", "recon", "probe"),
            List.of("/openapi.json", "/customers/{id}"),
            List.of("Exfiltration Campaign Stage: PROBING")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXFIL-PROBE-EXTRACT", "Probing followed by Unauthorized Extraction",
            "Attacker establishes valid target boundaries and dumps unauthorized records.",
            "EXFILTRATION", "CRITICAL", true,
            List.of("campaign", "probe", "extract"),
            List.of("/accounts/{id}", "/transactions"),
            List.of("Exfiltration Campaign Stage: EXTRACTION")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXFIL-EXPOSE-BULK", "Exposure followed by Bulk Extraction",
            "Attacker identifies contract discrepancy and exploits it for bulk dump.",
            "EXFILTRATION", "CRITICAL", true,
            List.of("campaign", "exposure", "bulk"),
            List.of("/customers/{id}", "/transactions"),
            List.of("Exfiltration Campaign Stage: BULK")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EXFIL-LOW-SLOW-MULTI", "Low-and-Slow Multi-Tenant Extraction",
            "Stealth extraction throttled over extended periods across distinct tenants.",
            "EXFILTRATION", "HIGH", true,
            List.of("campaign", "low-and-slow", "stealth"),
            List.of("/accounts/{id}"),
            List.of("Exfiltration Campaign Stage: LOW_AND_SLOW")
        ));

        // Probing & Security Abuse
        registerScenario(new SimulationScenarioDto(
            "SCEN-SEC-AUTH-ABUSE", "Authentication Abuse & Token Tampering",
            "Attempts using forged claims, expired tokens, and mismatched signatures.",
            "PROBING", "HIGH", true,
            List.of("auth", "tampering", "probing"),
            List.of("/customers/me", "/accounts"),
            List.of("HTTP 401/403", "Auth Anomaly")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-SEC-INJECTION-PROBE", "Injection & Fuzzing Probes",
            "Security fuzzing with SQL, NoSQL, and path traversal strings in query parameters.",
            "PROBING", "MEDIUM", true,
            List.of("fuzzing", "injection", "probing"),
            List.of("/customers?query={payload}"),
            List.of("HTTP 400", "Input Validation Trigger")
        ));

        // Mixed & Edge Workloads
        registerScenario(new SimulationScenarioDto(
            "SCEN-MIXED-CONCURRENT", "Concurrent Benign & Malicious Traffic",
            "Interleaved legitimate customer requests and concurrent BOLA probes.",
            "MIXED", "HIGH", true,
            List.of("mixed", "concurrent", "telemetry"),
            List.of("/customers/{id}", "/accounts/{id}"),
            List.of("Isolated Detection without Benign False Positives")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-MIXED-MULTI-TENANT", "Multi-Tenant Boundary Cross-Probing",
            "Cross-tenant testing verifying strict identity and data isolation.",
            "MIXED", "HIGH", true,
            List.of("multi-tenant", "isolation"),
            List.of("/accounts/{id}"),
            List.of("Boundary Isolation Maintained")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EDGE-WINDOW-BOUNDARY", "Temporal Window Boundary Tests",
            "Events dispatched right around sliding aggregation time limits.",
            "MIXED", "MEDIUM", true,
            List.of("edge", "temporal", "window"),
            List.of("/transactions"),
            List.of("Proper Time Bounding")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EDGE-INCOMPLETE-SEQUENCE", "Incomplete Attack Sequence",
            "Attacker aborts campaign mid-sequence; verifies state transitions.",
            "MIXED", "MEDIUM", true,
            List.of("edge", "incomplete", "state"),
            List.of("/customers", "/accounts"),
            List.of("State Handled Correctly")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-EDGE-NO-RESP-SIZE", "Missing Response Size Telemetry",
            "Responses without Content-Length; evaluates fallback estimators.",
            "MIXED", "LOW", true,
            List.of("edge", "telemetry", "fallback"),
            List.of("/accounts"),
            List.of("Graceful Metric Estimation")
        ));

        // Infrastructure Resilience
        registerScenario(new SimulationScenarioDto(
            "SCEN-INFRA-BACKLOG", "Redis Stream Telemetry Backlog Resilience",
            "Injects heavy telemetry backlog; verifies zero event loss and deduplication.",
            "INFRASTRUCTURE", "MEDIUM", true,
            List.of("infra", "backlog", "resilience"),
            List.of("/events/stream"),
            List.of("Stream Consumer Catch-up without Loss")
        ));
        registerScenario(new SimulationScenarioDto(
            "SCEN-INFRA-UNAVAILABLE", "Downstream Service Transient Outage",
            "Simulates downstream dependency circuit-breaker and fallback responses.",
            "INFRASTRUCTURE", "MEDIUM", true,
            List.of("infra", "outage", "circuit-breaker"),
            List.of("/customers/{id}"),
            List.of("HTTP 503 Gateway Fallback Handling")
        ));
    }

    private void initTemplates() {
        // 1. TPL-BENIGN-WORKDAY
        registerTemplate(new SimulationCampaignTemplate(
            "TPL-BENIGN-WORKDAY",
            "Standard Benign Business Workday",
            "Comprehensive benign workload simulating normal customer banking operations.",
            List.of(
                new SimulationCampaignStage(1, "Customer Logins & Profile Fetch", "SCEN-BENIGN-01", 5, 200, List.of(), 0, 0, List.of(), 30),
                new SimulationCampaignStage(2, "Transaction History Inspection", "SCEN-BENIGN-PAGINATION", 4, 300, List.of(), 0, 0, List.of(), 30),
                new SimulationCampaignStage(3, "Beneficiary Creation & Verification", "SCEN-BENIGN-BENEFICIARY", 3, 250, List.of(), 0, 0, List.of(), 30)
            ),
            "SEQUENTIAL", 5.0, 2, 60,
            List.of("benign", "baseline", "workday")
        ));

        // 2. TPL-BOLA-EXFIL-CAMPAIGN
        registerTemplate(new SimulationCampaignTemplate(
            "TPL-BOLA-EXFIL-CAMPAIGN",
            "Full Multi-Stage BOLA Exfiltration Campaign",
            "Multi-stage attack transitioning from recon to BOLA exploitation and bulk exfiltration.",
            List.of(
                new SimulationCampaignStage(1, "Endpoint Reconnaissance & Probing", "SCEN-EXFIL-RECON-PROBE", 5, 200, List.of("RULE-PROBING-01"), 0, 0, List.of(), 30),
                new SimulationCampaignStage(2, "Cross-Tenant BOLA Exploitation", "SCEN-BOLA-01", 6, 250, List.of("RULE-BOLA-01"), 1, 0, List.of("ENFORCE_CHALLENGE"), 30),
                new SimulationCampaignStage(3, "Confirmed Sensitive Data Leakage", "SCEN-BOLA-CONFIRMED", 4, 300, List.of("RULE-BOLA-CONFIRMED-01"), 1, 1, List.of("QUARANTINE_IDENTITY"), 30),
                new SimulationCampaignStage(4, "Coordinated Bulk Extraction", "SCEN-EXTRACT-PAGINATION", 8, 150, List.of("RULE-BULK-EXTRACT-01"), 1, 1, List.of("RATE_LIMIT_IDENTITY"), 30)
            ),
            "SEQUENTIAL", 8.0, 3, 90,
            List.of("bola", "campaign", "exfiltration", "critical")
        ));

        // 3. TPL-LOW-SLOW-STEALTH
        registerTemplate(new SimulationCampaignTemplate(
            "TPL-LOW-SLOW-STEALTH",
            "Low-and-Slow Stealth Exfiltration Campaign",
            "Sub-threshold distributed data harvesting designed to test temporal sliding correlation.",
            List.of(
                new SimulationCampaignStage(1, "Intermittent Account Inquiries", "SCEN-EXFIL-LOW-SLOW-MULTI", 6, 800, List.of(), 0, 0, List.of(), 45),
                new SimulationCampaignStage(2, "Cumulative Multi-Tenant Harvesting", "SCEN-EXTRACT-CUMULATIVE", 6, 900, List.of("RULE-BULK-EXTRACT-01"), 1, 1, List.of("THROTTLE_API_ACCESS"), 45)
            ),
            "SEQUENTIAL", 2.0, 1, 120,
            List.of("stealth", "low-and-slow", "correlation")
        ));

        // 4. TPL-FULL-MIXED-WORKLOAD
        registerTemplate(new SimulationCampaignTemplate(
            "TPL-FULL-MIXED-WORKLOAD",
            "Mixed Production Traffic & High-Volume Attacks",
            "Concurrent benign customer sessions executing alongside coordinated attack vectors.",
            List.of(
                new SimulationCampaignStage(1, "Concurrent Mixed Workload", "SCEN-MIXED-CONCURRENT", 10, 150, List.of("RULE-BOLA-01"), 1, 0, List.of(), 40),
                new SimulationCampaignStage(2, "Multi-Tenant Probing with Auth Tampering", "SCEN-SEC-AUTH-ABUSE", 8, 200, List.of("RULE-BOLA-02"), 1, 1, List.of("REVOKE_SESSION"), 40),
                new SimulationCampaignStage(3, "High-Volume Extraction with Legitimate Traffic", "SCEN-EXTRACT-MULTI-RESOURCE", 8, 150, List.of("RULE-BULK-EXTRACT-01"), 1, 1, List.of("BLOCK_IDENTITY"), 40)
            ),
            "MIXED", 10.0, 4, 120,
            List.of("mixed", "concurrent", "production-stress")
        ));

        // 5. TPL-INFRA-RESILIENCE
        registerTemplate(new SimulationCampaignTemplate(
            "TPL-INFRA-RESILIENCE",
            "Telemetry Pipeline & Infrastructure Resilience",
            "Tests detection pipeline resilience under stream backlogs and transient outages.",
            List.of(
                new SimulationCampaignStage(1, "Telemetry Stream Backlog Injection", "SCEN-INFRA-BACKLOG", 15, 100, List.of(), 0, 0, List.of(), 30),
                new SimulationCampaignStage(2, "Transient Upstream Outage Recovery", "SCEN-INFRA-UNAVAILABLE", 5, 250, List.of(), 0, 0, List.of(), 30)
            ),
            "SEQUENTIAL", 12.0, 3, 60,
            List.of("resilience", "infra", "backlog")
        ));
    }
}

