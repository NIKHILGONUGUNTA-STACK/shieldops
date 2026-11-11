package com.aegis.gateway.detection.leakage;

import com.aegis.gateway.detection.dto.IncidentPageResponse;
import com.aegis.gateway.detection.dto.IncidentResponse;
import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * REST controller for Data Leakage and BOLA detection telemetry, evidence, and analytics.
 */
@RestController
@RequestMapping("/api/v1/security/leakage")
public class DataLeakageController {
    private static final Logger log = LoggerFactory.getLogger(DataLeakageController.class);

    private static final Set<String> LEAKAGE_CATEGORIES = Set.of(
        "BOLA_CONFIRMED_LEAK",
        "BOLA_ATTEMPT",
        "BOLA",
        "BOLA_PROBE_CAMPAIGN",
        "SENSITIVE_DATA_EXPOSURE",
        "EXCESSIVE_DATA_EXTRACTION",
        "DATA_EXFILTRATION_CAMPAIGN",
        "DATA_ACCESS"
    );

    private final IncidentRepository repository;

    public DataLeakageController(IncidentRepository repository) {
        this.repository = repository;
    }

    @GetMapping(value = "/summary", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<DataLeakageSummaryResponse> getSummary() {
        List<SecurityIncident> all = repository.findAllIncidents();

        List<SecurityIncident> leakageIncidents = all.stream()
            .filter(i -> isLeakageCategory(i.threatCategory(), i.ruleId()))
            .sorted(Comparator.comparing(SecurityIncident::lastEventAt).reversed())
            .toList();

        long total = leakageIncidents.size();
        long confirmedBola = leakageIncidents.stream().filter(i -> "BOLA_CONFIRMED_LEAK".equalsIgnoreCase(i.threatCategory())).count();
        long deniedBola = leakageIncidents.stream().filter(i -> "BOLA_ATTEMPT".equalsIgnoreCase(i.threatCategory()) || "BOLA".equalsIgnoreCase(i.threatCategory())).count();
        long sensitiveExposure = leakageIncidents.stream().filter(i -> "SENSITIVE_DATA_EXPOSURE".equalsIgnoreCase(i.threatCategory())).count();
        long bulkExtract = leakageIncidents.stream().filter(i -> "EXCESSIVE_DATA_EXTRACTION".equalsIgnoreCase(i.threatCategory()) || "DATA_ACCESS".equalsIgnoreCase(i.threatCategory())).count();
        long multiStage = leakageIncidents.stream().filter(i -> "DATA_EXFILTRATION_CAMPAIGN".equalsIgnoreCase(i.threatCategory())).count();

        Map<String, Long> bySeverity = leakageIncidents.stream()
            .collect(Collectors.groupingBy(SecurityIncident::severity, Collectors.counting()));

        Map<String, Long> byStatus = leakageIncidents.stream()
            .collect(Collectors.groupingBy(i -> i.status() != null ? i.status().name() : "OPEN", Collectors.counting()));

        List<IncidentResponse> recent = leakageIncidents.stream()
            .limit(10)
            .map(this::mapToResponse)
            .toList();

        return ResponseEntity.ok(new DataLeakageSummaryResponse(
            total,
            confirmedBola,
            deniedBola,
            sensitiveExposure,
            bulkExtract,
            multiStage,
            bySeverity,
            byStatus,
            recent,
            Instant.now()
        ));
    }

    @GetMapping(value = "/incidents", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<IncidentPageResponse> getLeakageIncidents(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "category", required = false) String category,
            @RequestParam(name = "severity", required = false) String severity,
            @RequestParam(name = "status", required = false) String statusStr,
            @RequestParam(name = "search", required = false) String search) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.max(1, Math.min(100, size));

        List<SecurityIncident> all = repository.findAllIncidents().stream()
            .filter(i -> isLeakageCategory(i.threatCategory(), i.ruleId()))
            .filter(i -> category == null || category.isBlank() || category.equalsIgnoreCase(i.threatCategory()))
            .filter(i -> severity == null || severity.isBlank() || severity.equalsIgnoreCase(i.severity()))
            .filter(i -> statusStr == null || statusStr.isBlank() || (i.status() != null && statusStr.equalsIgnoreCase(i.status().name())))
            .filter(i -> {
                if (search == null || search.isBlank()) return true;
                String q = search.toLowerCase().trim();
                return i.targetEntityValue().toLowerCase().contains(q) ||
                       i.summary().toLowerCase().contains(q) ||
                       i.ruleId().toLowerCase().contains(q);
            })
            .sorted(Comparator.comparing(SecurityIncident::lastEventAt).reversed())
            .toList();

        int total = all.size();
        int totalPages = (int) Math.ceil((double) total / boundedSize);
        int offset = boundedPage * boundedSize;

        List<IncidentResponse> paged;
        if (offset >= total) {
            paged = Collections.emptyList();
        } else {
            paged = all.subList(offset, Math.min(offset + boundedSize, total)).stream()
                .map(this::mapToResponse)
                .toList();
        }

        return ResponseEntity.ok(new IncidentPageResponse(
            paged,
            boundedPage,
            boundedSize,
            total,
            totalPages,
            boundedPage == 0,
            boundedPage >= totalPages - 1
        ));
    }

    @GetMapping(value = "/incidents/{id}/evidence", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<DetectionEvidence>> getIncidentEvidence(@PathVariable("id") UUID id) {
        List<DetectionEvidence> evidences = repository.findEvidenceByIncidentId(id);
        return ResponseEntity.ok(evidences);
    }

    @GetMapping(value = "/rules", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<DataLeakageRuleInfoResponse>> getRules() {
        List<DataLeakageRuleInfoResponse> rules = List.of(
            new DataLeakageRuleInfoResponse(
                RuleBolaConfirmed01.RULE_ID,
                RuleBolaConfirmed01.RULE_VERSION,
                "Confirmed BOLA Data Leakage",
                "Detects successful HTTP 200 responses for cross-owner customer resources without administrative authorization.",
                "BOLA_CONFIRMED_LEAK",
                "CRITICAL",
                true,
                "HTTP 200 on cross-owner customer resource by unprivileged caller"
            ),
            new DataLeakageRuleInfoResponse(
                RuleDataLeak01.RULE_ID,
                RuleDataLeak01.RULE_VERSION,
                "Sensitive Data Exposure",
                "Detects unauthorized exposure of CONFIDENTIAL or RESTRICTED schema fields to unapproved roles or unauthenticated callers.",
                "SENSITIVE_DATA_EXPOSURE",
                "HIGH",
                true,
                "HTTP 200 on confidential/restricted route accessed without approved role or customer ownership"
            ),
            new DataLeakageRuleInfoResponse(
                RuleBulkExtract01.RULE_ID,
                RuleBulkExtract01.RULE_VERSION,
                "Excessive Data Extraction",
                "Detects bulk scraping or harvesting across >= 3 distinct customer/account resources within a 120s sliding window.",
                "EXCESSIVE_DATA_EXTRACTION",
                "HIGH",
                true,
                "Distinct sensitive resources >= 3 or record volume threshold breached in 120s"
            ),
            new DataLeakageRuleInfoResponse(
                RuleBola02.RULE_ID,
                RuleBola02.RULE_VERSION,
                "BOLA Probing Campaign",
                "Detects systematic resource ID enumeration following an initial 403 Forbidden BOLA denial.",
                "BOLA_PROBE_CAMPAIGN",
                "HIGH",
                true,
                "Initial 403 BOLA denial followed by >= 2 probing requests across distinct targets in 180s"
            ),
            new DataLeakageRuleInfoResponse(
                "DATA_EXFILTRATION_CAMPAIGN",
                "1.0.0",
                "Multi-Stage Exfiltration Correlator",
                "Correlates multi-stage attack progressions (Reconnaissance -> BOLA Probing -> Data Extraction) into a single campaign.",
                "DATA_EXFILTRATION_CAMPAIGN",
                "CRITICAL",
                true,
                "Same actor observes events across >= 2 attack stages"
            )
        );
        return ResponseEntity.ok(rules);
    }

    private boolean isLeakageCategory(String threatCategory, String ruleId) {
        if (threatCategory != null) {
            String cat = threatCategory.toUpperCase().trim();
            if (LEAKAGE_CATEGORIES.contains(cat)) return true;
        }
        if (ruleId != null) {
            String r = ruleId.toUpperCase().trim();
            return r.contains("BOLA") || r.contains("DATA") || r.contains("LEAK") || r.contains("EXTRACT");
        }
        return false;
    }

    private IncidentResponse mapToResponse(SecurityIncident inc) {
        return new IncidentResponse(
            inc.id(),
            inc.incidentFingerprint(),
            inc.ruleId(),
            inc.ruleVersion(),
            inc.threatCategory(),
            inc.severity(),
            inc.status() != null ? inc.status().name() : "OPEN",
            inc.targetEntityType(),
            inc.targetEntityValue(),
            inc.firstDetectedAt(),
            inc.lastEventAt(),
            inc.eventCount(),
            inc.summary(),
            inc.createdAt(),
            inc.updatedAt()
        );
    }
}

