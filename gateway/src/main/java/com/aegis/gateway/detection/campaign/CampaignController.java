package com.aegis.gateway.detection.campaign;

import com.aegis.gateway.detection.campaign.dto.*;
import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.SecurityIncident;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.*;

/**
 * REST controller for Multi-Stage Exfiltration Campaign management, timeline inspection,
 * forensic evidence correlation, and analyst lifecycle updates.
 */
@RestController
@RequestMapping("/api/v1/security/campaigns")
@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
public class CampaignController {
    private static final Logger log = LoggerFactory.getLogger(CampaignController.class);

    private final CampaignRepository campaignRepository;
    private final IncidentRepository incidentRepository;

    public CampaignController(CampaignRepository campaignRepository, IncidentRepository incidentRepository) {
        this.campaignRepository = campaignRepository;
        this.incidentRepository = incidentRepository;
    }

    /**
     * GET /api/v1/security/campaigns
     * Lists paginated exfiltration campaigns with optional filtering.
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CampaignPageResponse> getCampaigns(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) CampaignStatus status,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) CampaignStage stage,
            @RequestParam(required = false) String search) {

        CampaignPageResponse response = campaignRepository.findCampaigns(
            page, size, status, severity, stage, search
        );
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/v1/security/campaigns/{id}
     * Retrieves detail for a specific campaign by internal UUID or campaign ID code.
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CampaignResponse> getCampaignById(@PathVariable String id) {
        ExfiltrationCampaign campaign = resolveCampaign(id);
        return ResponseEntity.ok(CampaignResponse.fromEntity(campaign));
    }

    /**
     * GET /api/v1/security/campaigns/{id}/timeline
     * Retrieves the chronological attack kill-chain timeline events for a campaign.
     */
    @GetMapping(value = "/{id}/timeline", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<CampaignTimelineEvent>> getCampaignTimeline(@PathVariable String id) {
        ExfiltrationCampaign campaign = resolveCampaign(id);
        List<CampaignTimelineEvent> events = campaignRepository.findTimelineByCampaignId(campaign.id());
        return ResponseEntity.ok(events);
    }

    /**
     * GET /api/v1/security/campaigns/{id}/evidence
     * Retrieves all forensic detection evidence and correlated incidents contributing to this campaign.
     */
    @GetMapping(value = "/{id}/evidence", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CampaignEvidenceDetailsResponse> getCampaignEvidence(@PathVariable String id) {
        ExfiltrationCampaign campaign = resolveCampaign(id);

        List<SecurityIncident> linkedIncidents = new ArrayList<>();
        List<DetectionEvidence> linkedEvidences = new ArrayList<>();

        if (campaign.relatedIncidentIds() != null) {
            for (UUID incId : campaign.relatedIncidentIds()) {
                incidentRepository.findById(incId).ifPresent(linkedIncidents::add);
                linkedEvidences.addAll(incidentRepository.findEvidenceByIncidentId(incId));
            }
        }

        CampaignEvidenceDetailsResponse response = new CampaignEvidenceDetailsResponse(
            campaign.id(),
            campaign.campaignId(),
            campaign.relatedEventIds(),
            campaign.relatedIncidentIds(),
            campaign.relatedRuleIds(),
            linkedEvidences,
            linkedIncidents
        );
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/v1/security/campaigns/{id}/history
     * Retrieves the complete lifecycle audit history for a campaign.
     */
    @GetMapping(value = "/{id}/history", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<CampaignStatusHistory>> getCampaignHistory(@PathVariable String id) {
        ExfiltrationCampaign campaign = resolveCampaign(id);
        List<CampaignStatusHistory> history = campaignRepository.findStatusHistoryByCampaignId(campaign.id());
        return ResponseEntity.ok(history);
    }

    /**
     * GET /api/v1/security/campaigns/{id}/risk
     * Retrieves the deterministic risk assessment and scoring rationale.
     */
    @GetMapping(value = "/{id}/risk", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CampaignRiskAssessment> getCampaignRisk(@PathVariable String id) {
        ExfiltrationCampaign campaign = resolveCampaign(id);

        boolean hasUnauthorized = campaign.stagesObserved().contains(CampaignStage.SENSITIVE_DATA_ACCESS) ||
            campaign.severity().equalsIgnoreCase("CRITICAL");
        boolean hasRestricted = campaign.riskRationale() != null &&
            campaign.riskRationale().toLowerCase().contains("restricted");

        CampaignRiskAssessment assessment = CampaignRiskAssessment.calculate(
            campaign.stagesObserved().size(),
            campaign.severity(),
            campaign.resourceCount(),
            campaign.sensitiveDomainCount(),
            campaign.evidenceCompleteness(),
            hasUnauthorized,
            hasRestricted
        );
        return ResponseEntity.ok(assessment);
    }

    /**
     * PATCH /api/v1/security/campaigns/{id}/status
     * Transitions a campaign's lifecycle state with explicit validation and audit trail.
     */
    @PatchMapping(value = "/{id}/status", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CampaignResponse> updateCampaignStatus(
            @PathVariable String id,
            @RequestBody CampaignStatusUpdateRequest request) {

        if (request == null || request.status() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Target status is required");
        }

        ExfiltrationCampaign campaign = resolveCampaign(id);
        CampaignStatus currentStatus = campaign.status();
        CampaignStatus targetStatus = request.status();

        if (!currentStatus.isValidTransition(targetStatus)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                String.format("Invalid lifecycle transition from %s to %s", currentStatus, targetStatus)
            );
        }

        String changedBy = resolveCurrentUser();
        String reason = (request.reason() != null && !request.reason().isBlank())
            ? request.reason().trim()
            : String.format("Status transitioned from %s to %s", currentStatus, targetStatus);

        ExfiltrationCampaign updated = new ExfiltrationCampaign(
            campaign.id(),
            campaign.campaignId(),
            campaign.correlationIdentity(),
            campaign.tenantId(),
            campaign.clientIp(),
            campaign.currentStage(),
            campaign.stagesObserved(),
            targetStatus,
            campaign.severity(),
            campaign.riskScore(),
            campaign.riskCategory(),
            campaign.riskRationale(),
            campaign.evidenceCompleteness(),
            campaign.missingEvidenceDetails(),
            campaign.resourceCount(),
            campaign.endpointCount(),
            campaign.sensitiveDomainCount(),
            campaign.firstObservedAt(),
            campaign.lastObservedAt(),
            campaign.eventCount(),
            campaign.relatedEventIds(),
            campaign.relatedIncidentIds(),
            campaign.relatedRuleIds(),
            campaign.createdAt(),
            Instant.now()
        );

        campaignRepository.updateCampaign(updated);

        // Record immutable audit history
        campaignRepository.saveStatusHistory(new CampaignStatusHistory(
            UUID.randomUUID(),
            campaign.id(),
            currentStatus,
            targetStatus,
            changedBy,
            Instant.now(),
            reason
        ));

        log.info("Campaign {} status updated from {} to {} by {}",
            campaign.campaignId(), currentStatus, targetStatus, changedBy);

        return ResponseEntity.ok(CampaignResponse.fromEntity(updated));
    }

    private ExfiltrationCampaign resolveCampaign(String idOrCode) {
        Optional<ExfiltrationCampaign> opt;
        try {
            UUID uuid = UUID.fromString(idOrCode);
            opt = campaignRepository.findById(uuid);
        } catch (IllegalArgumentException e) {
            opt = campaignRepository.findByCampaignId(idOrCode);
        }

        return opt.orElseThrow(() -> new ResponseStatusException(
            HttpStatus.NOT_FOUND, "Exfiltration campaign not found: " + idOrCode
        ));
    }

    private String resolveCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null && !auth.getName().isBlank()) {
            return auth.getName();
        }
        return "SECURITY_ANALYST";
    }
}

