package com.aegis.gateway.posture;

import com.aegis.gateway.discovery.dto.EndpointIntelligenceResponse;
import com.aegis.gateway.discovery.dto.EndpointLinkedIncident;
import com.aegis.gateway.discovery.dto.EndpointPrioritizationDetail;
import com.aegis.gateway.discovery.dto.EndpointReconciliationStatus;
import com.aegis.gateway.discovery.dto.EndpointSpecMetadata;
import com.aegis.gateway.posture.dto.*;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;

/**
 * Pure, deterministic API Security Posture Assessment Engine (Rule Version v1.0.0).
 *
 * Evaluates discovered endpoints across 6 independent dimensions:
 * 1. API Exposure & Inventory Posture
 * 2. Authentication Posture
 * 3. Authorization Posture
 * 4. Resource & Data Sensitivity Posture
 * 5. Traffic & Behavioral Posture
 * 6. API Specification Posture
 *
 * STRICT INVARIANTS:
 * - confirmedVulnerability is guaranteed FALSE.
 * - Missing evidence is represented as UNKNOWN; missing data is NEVER treated as safe or unsafe.
 * - 401 is NOT proof every request is authenticated; missing OpenAPI security is NOT proof route is unauthenticated.
 * - 403 is NOT proof authorization is correct; 200 is NOT proof of unauthorized access.
 * - Data sensitivity is UNKNOWN unless explicitly configured; PII inference from route terms is strictly prohibited.
 * - High request volume alone is NOT automatically malicious.
 */
@Component
public class ApiPostureAssessmentEngine {

    public static final String ASSESSMENT_RULE_VERSION = "v1.0.0";

    /**
     * Evaluates security posture for an endpoint using its unified intelligence dossier.
     */
    public EndpointPostureResponse assess(EndpointIntelligenceResponse intel) {
        if (intel == null) {
            throw new IllegalArgumentException("Endpoint intelligence dossier cannot be null");
        }

        Instant assessmentTime = Instant.now();
        Map<String, DimensionAssessment> dimensions = new LinkedHashMap<>();

        // 1. Exposure Dimension
        DimensionAssessment exposure = evaluateExposure(intel, assessmentTime);
        dimensions.put(AssessmentDimensionType.EXPOSURE.name(), exposure);

        // 2. Authentication Dimension
        DimensionAssessment auth = evaluateAuthentication(intel, assessmentTime);
        dimensions.put(AssessmentDimensionType.AUTHENTICATION.name(), auth);

        // 3. Authorization Dimension
        DimensionAssessment authz = evaluateAuthorization(intel, assessmentTime);
        dimensions.put(AssessmentDimensionType.AUTHORIZATION.name(), authz);

        // 4. Data Sensitivity Dimension
        DimensionAssessment sensitivity = evaluateDataSensitivity(intel, assessmentTime);
        dimensions.put(AssessmentDimensionType.DATA_SENSITIVITY.name(), sensitivity);

        // 5. Behavioral Dimension
        DimensionAssessment behavioral = evaluateBehavioral(intel, assessmentTime);
        dimensions.put(AssessmentDimensionType.BEHAVIORAL.name(), behavioral);

        // 6. Specification Dimension
        DimensionAssessment spec = evaluateSpecification(intel, assessmentTime);
        dimensions.put(AssessmentDimensionType.SPECIFICATION.name(), spec);

        // Aggregation & Invariants
        int findingCount = 0;
        int unknownCount = 0;
        int verifiedCount = 0;

        List<String> consolidatedSteps = new ArrayList<>();

        for (DimensionAssessment da : dimensions.values()) {
            if (da.status() == DimensionStatus.FINDING) {
                findingCount++;
                if (da.recommendedActions() != null) {
                    consolidatedSteps.addAll(da.recommendedActions());
                }
            } else if (da.status() == DimensionStatus.UNKNOWN) {
                unknownCount++;
            } else if (da.status() == DimensionStatus.VERIFIED) {
                verifiedCount++;
            }
        }

        // Categorical Overall Posture
        OverallPosture overallPosture;
        String overallExplanation;

        if (findingCount > 0) {
            overallPosture = OverallPosture.ATTENTION_REQUIRED;
            overallExplanation = String.format(
                "Endpoint requires analyst attention: %d finding%s identified across evaluated dimensions.",
                findingCount, findingCount == 1 ? "" : "s"
            );
        } else if (unknownCount >= 3) {
            overallPosture = OverallPosture.INSUFFICIENT_EVIDENCE;
            overallExplanation = String.format(
                "Insufficient empirical evidence: %d of 6 security dimensions could not be definitively verified. Missing evidence is not treated as safe.",
                unknownCount
            );
        } else {
            overallPosture = OverallPosture.ADEQUATE;
            overallExplanation = String.format(
                "Adequate security posture: %d dimensions verified by concrete evidence with zero security findings.",
                verifiedCount
            );
        }

        double evidenceCoverage = ((double) (6 - unknownCount) / 6.0) * 100.0;

        return new EndpointPostureResponse(
            intel.id(),
            intel.httpMethod(),
            intel.routeTemplate(),
            intel.serviceBoundary(),
            assessmentTime,
            ASSESSMENT_RULE_VERSION,
            overallPosture,
            Math.round(evidenceCoverage * 10.0) / 10.0,
            dimensions,
            findingCount,
            false, // confirmedVulnerability is guaranteed FALSE
            overallExplanation,
            consolidatedSteps,
            intel.lastObservedAt(),
            intel.firstObservedAt(),
            intel.totalRequests()
        );
    }

    // -----------------------------------------------------------------------
    // Dimension 1: API Exposure & Inventory Posture
    // -----------------------------------------------------------------------
    private DimensionAssessment evaluateExposure(EndpointIntelligenceResponse intel, Instant now) {
        List<PostureEvidenceItem> evidence = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        evidence.add(new PostureEvidenceItem(
            EvidenceSourceType.WIRE_TELEMETRY,
            "Observed in wire telemetry",
            intel.totalRequests() + " requests recorded",
            intel.lastObservedAt()
        ));

        EndpointReconciliationStatus recon = intel.reconciliation();
        String categoryStr = recon != null ? recon.category() : null;

        DimensionStatus status;
        String summary;

        if (intel.totalRequests() <= 0) {
            status = DimensionStatus.UNKNOWN;
            summary = "Insufficient wire observations: endpoint has recorded 0 telemetry requests in current window.";
            actions.add("Verify whether traffic is being routed to the gateway perimeter for this route.");
        } else if ("MATCHED".equalsIgnoreCase(categoryStr)) {
            status = DimensionStatus.VERIFIED;
            summary = "Endpoint is observed in wire traffic and fully documented in an active OpenAPI specification.";
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.RECONCILIATION_ENGINE,
                "Reconciliation category: MATCHED",
                "Contract coverage verified",
                now
            ));
        } else if ("OBSERVED_UNDOCUMENTED".equalsIgnoreCase(categoryStr) || intel.specification() == null) {
            status = DimensionStatus.FINDING;
            summary = "Shadow API Exposure: Endpoint is actively receiving wire traffic but is completely undocumented in declared specifications.";
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.RECONCILIATION_ENGINE,
                "Reconciliation category: OBSERVED_UNDOCUMENTED",
                "0% contract coverage",
                now
            ));
            actions.add("Catalog endpoint in authoritative OpenAPI specification or decommission unapproved endpoint.");
        } else {
            status = DimensionStatus.FINDING;
            summary = "Contract Discrepancy: Endpoint exhibits documentation divergence (" + categoryStr + ").";
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.RECONCILIATION_ENGINE,
                "Reconciliation divergence: " + categoryStr,
                "Discrepancy identified",
                now
            ));
            actions.add("Reconcile route parameter templates between runtime telemetry and OpenAPI contract.");
        }

        String limitations = "Observation is bounded by perimeter gateway telemetry retention limit (720h).";

        return new DimensionAssessment(
            AssessmentDimensionType.EXPOSURE,
            status,
            summary,
            evidence,
            limitations,
            actions
        );
    }

    // -----------------------------------------------------------------------
    // Dimension 2: Authentication Posture
    // -----------------------------------------------------------------------
    private DimensionAssessment evaluateAuthentication(EndpointIntelligenceResponse intel, Instant now) {
        List<PostureEvidenceItem> evidence = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        String route = intel.routeTemplate() != null ? intel.routeTemplate().toLowerCase() : "";
        boolean isPublicActuator = route.startsWith("/actuator");
        boolean isProtectedConfigRoute = isGatewayProtected(route);

        DimensionStatus status;
        String summary;

        if (isPublicActuator) {
            status = DimensionStatus.VERIFIED;
            summary = "Public endpoint by design: Gateway Spring Security configuration explicitly permits unauthenticated access (permitAll).";
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.GATEWAY_CONFIG,
                "Spring Security permitAll matcher: /actuator/**",
                "Unauthenticated by design",
                now
            ));
        } else if (intel.authFailureCount() > 0 && (intel.authFailureCount() >= 5 || (double) intel.authFailureCount() / Math.max(1, intel.totalRequests()) > 0.1)) {
            status = DimensionStatus.FINDING;
            summary = String.format("Elevated authentication failures: %d HTTP 401 Unauthorized responses observed in window.", intel.authFailureCount());
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.WIRE_TELEMETRY,
                "Elevated 401 Unauthorized count",
                intel.authFailureCount() + " failures",
                intel.lastObservedAt()
            ));
            actions.add("Inspect client credentials and tokens for expired or unauthorized access probing.");
        } else if (isProtectedConfigRoute) {
            status = DimensionStatus.VERIFIED;
            summary = "Perimeter authentication enforced: Route is bound to mandatory OAuth2 JWT bearer authentication in gateway policy.";
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.GATEWAY_CONFIG,
                "Gateway SecurityConfig: Mandatory OAuth2 JWT validation required",
                "Role authorization enforced",
                now
            ));
            if (intel.authFailureCount() > 0) {
                evidence.add(new PostureEvidenceItem(
                    EvidenceSourceType.WIRE_TELEMETRY,
                    "Enforcement telemetry: 401 Unauthorized observed on invalid requests",
                    intel.authFailureCount() + " rejected requests",
                    intel.lastObservedAt()
                ));
            }
        } else {
            status = DimensionStatus.UNKNOWN;
            summary = "Authentication enforcement cannot be definitively verified from available telemetry and configuration mappings alone.";
            actions.add("Verify gateway perimeter security rule mapping for this route pattern.");
        }

        String limitations = "Gateway validates OAuth2 JWT tokens at perimeter; internal microservice mTLS and downstream propagation cannot be directly inspected.";

        return new DimensionAssessment(
            AssessmentDimensionType.AUTHENTICATION,
            status,
            summary,
            evidence,
            limitations,
            actions
        );
    }

    // -----------------------------------------------------------------------
    // Dimension 3: Authorization Posture
    // -----------------------------------------------------------------------
    private DimensionAssessment evaluateAuthorization(EndpointIntelligenceResponse intel, Instant now) {
        List<PostureEvidenceItem> evidence = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        List<EndpointLinkedIncident> incidents = intel.linkedIncidents();
        boolean hasBolaIncident = incidents != null && incidents.stream()
            .anyMatch(i -> (i.ruleId() != null && i.ruleId().toUpperCase().contains("BOLA"))
                        || (i.threatCategory() != null && i.threatCategory().toUpperCase().contains("BOLA"))
                        || (i.summary() != null && i.summary().toUpperCase().contains("BOLA")));

        long status403Count = intel.statusDistribution() != null ? intel.statusDistribution().getOrDefault("4xx", 0L) : 0L;

        DimensionStatus status;
        String summary;

        if (hasBolaIncident) {
            status = DimensionStatus.FINDING;
            summary = "Broken Object Level Authorization (BOLA) concern: Correlated security incident indicates unauthorized cross-resource access.";
            for (EndpointLinkedIncident inc : incidents) {
                if ((inc.ruleId() != null && inc.ruleId().toUpperCase().contains("BOLA"))
                    || (inc.threatCategory() != null && inc.threatCategory().toUpperCase().contains("BOLA"))
                    || (inc.summary() != null && inc.summary().toUpperCase().contains("BOLA"))) {
                    evidence.add(new PostureEvidenceItem(
                        EvidenceSourceType.SECURITY_INCIDENT,
                        "Incident: " + inc.ruleId() + " (" + inc.severity() + ")",
                        "Incident ID: " + inc.id(),
                        inc.firstDetectedAt()
                    ));
                }
            }
            actions.add("Audit backend controller for object-level ownership checks (e.g., matching JWT sub against resource ID).");
        } else {
            // Strict Invariant: 403 is not proof authorization is correct; 200 is not proof of unauthorized access.
            // Gateway telemetry alone cannot prove fine-grained object-level ownership policies without backend policy verification.
            status = DimensionStatus.UNKNOWN;
            summary = "Object-level authorization policies cannot be independently verified from gateway wire telemetry alone. Requires backend microservice resource ownership verification.";
            if (status403Count > 0) {
                evidence.add(new PostureEvidenceItem(
                    EvidenceSourceType.WIRE_TELEMETRY,
                    "Client 4xx responses observed (including potential 403 Forbidden)",
                    status403Count + " responses",
                    intel.lastObservedAt()
                ));
            }
            actions.add("Review microservice authorization logic to ensure tenants cannot access peer object identifiers.");
        }

        String limitations = "Passive wire telemetry records HTTP status codes but cannot verify application-layer data ownership validation on successful 200 responses.";

        return new DimensionAssessment(
            AssessmentDimensionType.AUTHORIZATION,
            status,
            summary,
            evidence,
            limitations,
            actions
        );
    }

    // -----------------------------------------------------------------------
    // Dimension 4: Resource & Data Sensitivity Posture
    // -----------------------------------------------------------------------
    private DimensionAssessment evaluateDataSensitivity(EndpointIntelligenceResponse intel, Instant now) {
        List<PostureEvidenceItem> evidence = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        // STRICT INVARIANT: Do NOT infer that an endpoint exposes PII merely because its route contains terms such as customer, account or profile.
        // Return UNKNOWN when no explicit sensitivity classification exists.
        DimensionStatus status = DimensionStatus.UNKNOWN;
        String summary = "No explicit data sensitivity or PII classification metadata is configured for this endpoint.";
        String limitations = "Automatic keyword inference (e.g. matching 'customer' or 'account') is strictly disabled to prevent speculative data classification.";

        actions.add("Assign an explicit data classification label (e.g. PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED) in the service governance catalog.");

        return new DimensionAssessment(
            AssessmentDimensionType.DATA_SENSITIVITY,
            status,
            summary,
            evidence,
            limitations,
            actions
        );
    }

    // -----------------------------------------------------------------------
    // Dimension 5: Traffic & Behavioral Posture
    // -----------------------------------------------------------------------
    private DimensionAssessment evaluateBehavioral(EndpointIntelligenceResponse intel, Instant now) {
        List<PostureEvidenceItem> evidence = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        long requests = intel.totalRequests();
        long anomalies = intel.anomalyEventCount();
        List<EndpointLinkedIncident> incidents = intel.linkedIncidents();
        boolean hasIncidents = incidents != null && !incidents.isEmpty();

        long status5xx = 0;
        if (intel.statusDistribution() != null) {
            status5xx = intel.statusDistribution().getOrDefault("5xx", 0L);
        }

        DimensionStatus status;
        String summary;

        if (hasIncidents) {
            status = DimensionStatus.FINDING;
            summary = String.format("Behavioral anomaly: %d correlated security incident%s detected for this endpoint.", incidents.size(), incidents.size() == 1 ? "" : "s");
            for (EndpointLinkedIncident inc : incidents) {
                evidence.add(new PostureEvidenceItem(
                    EvidenceSourceType.SECURITY_INCIDENT,
                    inc.ruleId() + " [" + inc.severity() + "]",
                    "Status: " + inc.status() + " - " + inc.summary(),
                    inc.firstDetectedAt()
                ));
            }
            actions.add("Inspect correlated security incidents and review attacker client IP behavior.");
        } else if (anomalies > 0) {
            status = DimensionStatus.FINDING;
            summary = String.format("Elevated anomaly indicators: %d anomaly event%s flagged by detection telemetry.", anomalies, anomalies == 1 ? "" : "s");
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.WIRE_TELEMETRY,
                "Anomaly event count",
                anomalies + " events",
                intel.lastObservedAt()
            ));
            actions.add("Inspect anomalous request parameters and client IP access distribution in API Event Explorer.");
        } else if (requests >= 10 && ((double) status5xx / requests) > 0.15) {
            status = DimensionStatus.FINDING;
            summary = String.format("Elevated server error rate: %d 5xx response%s observed (%.1f%% of traffic).", status5xx, status5xx == 1 ? "" : "s", ((double) status5xx / requests) * 100.0);
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.WIRE_TELEMETRY,
                "High 5xx server error rate",
                status5xx + " / " + requests + " requests",
                intel.lastObservedAt()
            ));
            actions.add("Check backend microservice logs for unhandled exceptions or service failure.");
        } else if (requests >= 5) {
            // STRICT INVARIANT: High request count by itself must NOT automatically indicate malicious activity.
            status = DimensionStatus.VERIFIED;
            summary = String.format("Normal behavioral profile: %d observed requests with stable response distribution and zero security anomalies.", requests);
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.WIRE_TELEMETRY,
                "Stable traffic distribution",
                requests + " requests, avg latency " + (intel.averageLatencyMs() != null ? Math.round(intel.averageLatencyMs()) + "ms" : "N/A"),
                intel.lastObservedAt()
            ));
        } else {
            status = DimensionStatus.UNKNOWN;
            summary = "Insufficient traffic volume: endpoint has recorded fewer than 5 requests in current window to establish a behavioral baseline.";
            actions.add("Expand the observation window or allow traffic baseline to accumulate.");
        }

        String limitations = "Traffic profile reflects wire telemetry within observation window (up to 720h); long-term seasonal traffic baselines require extended monitoring.";

        return new DimensionAssessment(
            AssessmentDimensionType.BEHAVIORAL,
            status,
            summary,
            evidence,
            limitations,
            actions
        );
    }

    // -----------------------------------------------------------------------
    // Dimension 6: API Specification Posture
    // -----------------------------------------------------------------------
    private DimensionAssessment evaluateSpecification(EndpointIntelligenceResponse intel, Instant now) {
        List<PostureEvidenceItem> evidence = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        EndpointSpecMetadata spec = intel.specification();
        EndpointReconciliationStatus recon = intel.reconciliation();
        EndpointPrioritizationDetail prio = intel.prioritization();

        DimensionStatus status;
        String summary;

        if (spec != null && recon != null && "MATCHED".equalsIgnoreCase(recon.category())) {
            if (prio != null && ("CRITICAL".equalsIgnoreCase(prio.priority()) || "HIGH".equalsIgnoreCase(prio.priority()))) {
                status = DimensionStatus.FINDING;
                summary = "Specification discrepancy: finding flagged with " + prio.priority() + " priority (Score " + prio.priorityScore() + ").";
                evidence.add(new PostureEvidenceItem(
                    EvidenceSourceType.RECONCILIATION_ENGINE,
                    "Discrepancy priority: " + prio.priority() + " (Score " + prio.priorityScore() + ")",
                    "Rule version: " + prio.ruleVersion(),
                    now
                ));
                actions.add("Investigate specification discrepancy in API Reconciliation workspace.");
            } else {
                status = DimensionStatus.VERIFIED;
                summary = String.format("Specification contract verified: Endpoint matches declared OpenAPI contract '%s' (v%s, rev %d).",
                    spec.specificationName(), spec.specificationVersion(), spec.revisionNumber());
                evidence.add(new PostureEvidenceItem(
                    EvidenceSourceType.OPENAPI_SPEC,
                    "Declared operation in " + spec.specificationName(),
                    spec.operationId() != null ? "operationId: " + spec.operationId() : "Matched operation",
                    now
                ));
            }
        } else if (spec == null) {
            status = DimensionStatus.FINDING;
            summary = "Missing OpenAPI specification contract: Endpoint is uncataloged in any declared specification.";
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.OPENAPI_SPEC,
                "No declared specification matched",
                "Observed undocumented",
                now
            ));
            actions.add("Import OpenAPI specification for the service in API Specifications module.");
        } else {
            status = DimensionStatus.FINDING;
            summary = "Specification mismatch: " + (recon != null ? recon.category() : "Unreconciled contract");
            evidence.add(new PostureEvidenceItem(
                EvidenceSourceType.RECONCILIATION_ENGINE,
                "Reconciliation category: " + (recon != null ? recon.category() : "UNKNOWN"),
                "Contract divergence",
                now
            ));
            actions.add("Reconcile route contracts in API Reconciliation module.");
        }

        String limitations = "Specification analysis verifies path pattern, HTTP method, and operation contract; payload schemas are verified at runtime boundary.";

        return new DimensionAssessment(
            AssessmentDimensionType.SPECIFICATION,
            status,
            summary,
            evidence,
            limitations,
            actions
        );
    }

    private boolean isGatewayProtected(String route) {
        if (route == null) return false;
        return route.startsWith("/customers") || route.startsWith("/api/v1/customers")
            || route.startsWith("/accounts") || route.startsWith("/api/v1/accounts")
            || route.startsWith("/transfers") || route.startsWith("/api/v1/transfers")
            || route.startsWith("/beneficiaries") || route.startsWith("/api/v1/beneficiaries")
            || route.startsWith("/transactions") || route.startsWith("/api/v1/transactions")
            || route.startsWith("/security") || route.startsWith("/api/v1/security");
    }
}
