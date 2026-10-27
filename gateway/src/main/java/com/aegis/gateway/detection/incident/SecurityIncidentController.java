package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.dto.*;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.SecurityIncident;
import com.aegis.gateway.security.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.UUID;

@RestController
public class SecurityIncidentController {
    private static final Logger log = LoggerFactory.getLogger(SecurityIncidentController.class);

    private final IncidentRepository incidentRepository;
    private final IncidentService incidentService;

    public SecurityIncidentController(IncidentRepository incidentRepository, IncidentService incidentService) {
        this.incidentRepository = incidentRepository;
        this.incidentService = incidentService;
    }

    @GetMapping(value = {"/api/v1/security/incidents", "/security/incidents"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<IncidentPageResponse> getIncidents(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "status", required = false) String statusStr,
            @RequestParam(name = "severity", required = false) String severity,
            @RequestParam(name = "threatCategory", required = false) String threatCategory,
            @RequestParam(name = "targetEntityType", required = false) String targetEntityType,
            @RequestParam(name = "targetEntityValue", required = false) String targetEntityValue,
            @RequestParam(name = "from", required = false) String fromStr,
            @RequestParam(name = "to", required = false) String toStr,
            @RequestParam(name = "sortBy", defaultValue = "lastEventAt") String sortBy,
            @RequestParam(name = "sortDirection", defaultValue = "DESC") String sortDirection) {

        IncidentStatus status = null;
        if (statusStr != null && !statusStr.isBlank()) {
            try {
                status = IncidentStatus.valueOf(statusStr.trim().toUpperCase());
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid incident status filter: " + statusStr);
            }
        }

        Instant from = null;
        if (fromStr != null && !fromStr.isBlank()) {
            try {
                from = Instant.parse(fromStr.trim());
            } catch (DateTimeParseException ex) {
                throw new IllegalArgumentException("Invalid 'from' timestamp: must be valid ISO-8601 UTC format (e.g. 2026-10-26T17:00:00Z)");
            }
        }

        Instant to = null;
        if (toStr != null && !toStr.isBlank()) {
            try {
                to = Instant.parse(toStr.trim());
            } catch (DateTimeParseException ex) {
                throw new IllegalArgumentException("Invalid 'to' timestamp: must be valid ISO-8601 UTC format (e.g. 2026-10-26T17:00:00Z)");
            }
        }

        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("Invalid time range: 'from' timestamp must not be after 'to' timestamp");
        }

        IncidentPageResponse response = incidentRepository.findIncidents(
            page, size, status, severity, threatCategory, targetEntityType, targetEntityValue, from, to, sortBy, sortDirection
        );
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = {"/api/v1/security/incidents/{id}", "/security/incidents/{id}"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<IncidentResponse> getIncidentById(@PathVariable("id") String idStr) {
        UUID incidentId = parseUuid(idStr, "Incident");
        SecurityIncident incident = incidentRepository.findById(incidentId)
            .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + incidentId));
        return ResponseEntity.ok(IncidentResponse.from(incident));
    }

    @GetMapping(value = {"/api/v1/security/incidents/{id}/evidence", "/security/incidents/{id}/evidence"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<EvidenceResponse>> getIncidentEvidence(@PathVariable("id") String idStr) {
        UUID incidentId = parseUuid(idStr, "Incident");
        incidentRepository.findById(incidentId)
            .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + incidentId));

        List<EvidenceResponse> evidence = incidentRepository.findEvidenceByIncidentId(incidentId)
            .stream().map(EvidenceResponse::from).toList();
        return ResponseEntity.ok(evidence);
    }

    @GetMapping(value = {"/api/v1/security/incidents/{id}/history", "/security/incidents/{id}/history"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<IncidentStatusHistoryResponse>> getIncidentHistory(@PathVariable("id") String idStr) {
        UUID incidentId = parseUuid(idStr, "Incident");
        incidentRepository.findById(incidentId)
            .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + incidentId));

        List<IncidentStatusHistoryResponse> history = incidentRepository.findStatusHistoryByIncidentId(incidentId)
            .stream().map(IncidentStatusHistoryResponse::from).toList();
        return ResponseEntity.ok(history);
    }

    @GetMapping(value = {"/api/v1/security/incidents/{id}/policy-decisions", "/security/incidents/{id}/policy-decisions"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<PolicyDecisionResponse>> getIncidentPolicyDecisions(@PathVariable("id") String idStr) {
        UUID incidentId = parseUuid(idStr, "Incident");
        incidentRepository.findById(incidentId)
            .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + incidentId));

        List<PolicyDecisionResponse> decisions = incidentRepository.findPolicyDecisionsByIncidentId(incidentId)
            .stream().map(PolicyDecisionResponse::from).toList();
        return ResponseEntity.ok(decisions);
    }

    @PatchMapping(value = {"/api/v1/security/incidents/{id}/status", "/security/incidents/{id}/status"}, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<IncidentResponse> updateIncidentStatus(
            @PathVariable("id") String idStr,
            @RequestBody IncidentStatusUpdateRequest request,
            Authentication authentication) {

        UUID incidentId = parseUuid(idStr, "Incident");
        if (request == null || request.status() == null || request.status().isBlank()) {
            throw new IllegalArgumentException("Target status is required");
        }

        IncidentStatus newStatus;
        try {
            newStatus = IncidentStatus.valueOf(request.status().trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid incident status: " + request.status());
        }

        String actor = extractActor(authentication);
        boolean isAdmin = hasAdminRole(authentication);

        SecurityIncident updated = incidentService.updateIncidentStatus(
            incidentId, newStatus, request.reason(), actor, isAdmin
        );
        return ResponseEntity.ok(IncidentResponse.from(updated));
    }

    @GetMapping(value = {"/api/v1/security/policy-decisions", "/security/policy-decisions"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<PolicyDecisionResponse>> getRecentPolicyDecisions(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size) {
        List<PolicyDecisionResponse> decisions = incidentRepository.findRecentPolicyDecisions(page, size)
            .stream().map(PolicyDecisionResponse::from).toList();
        return ResponseEntity.ok(decisions);
    }

    private UUID parseUuid(String idStr, String resourceName) {
        try {
            return UUID.fromString(idStr.trim());
        } catch (Exception ex) {
            throw new ResourceNotFoundException(resourceName + " not found with ID: " + idStr);
        }
    }

    private String extractActor(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String preferredUsername = jwt.getClaimAsString("preferred_username");
            if (preferredUsername != null && !preferredUsername.isBlank()) {
                return preferredUsername;
            }
            return jwt.getSubject() != null ? jwt.getSubject() : "unknown-analyst";
        }
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        return "unknown-analyst";
    }

    private boolean hasAdminRole(Authentication auth) {
        if (auth == null) return false;
        return auth.getAuthorities().stream()
            .anyMatch(a -> "ROLE_SECURITY_ADMIN".equals(a.getAuthority()) || "SECURITY_ADMIN".equals(a.getAuthority()));
    }
}
