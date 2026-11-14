package com.aegis.gateway.detection.campaign;

import com.aegis.gateway.detection.campaign.dto.CampaignPageResponse;
import com.aegis.gateway.detection.campaign.dto.CampaignResponse;
import com.aegis.gateway.detection.campaign.dto.CampaignStatusUpdateRequest;
import com.aegis.gateway.detection.incident.IncidentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CampaignControllerTest {

    private CampaignRepository campaignRepository;
    private IncidentRepository incidentRepository;
    private CampaignController controller;

    private final UUID campaignId = UUID.randomUUID();
    private ExfiltrationCampaign sampleCampaign;

    @BeforeEach
    void setUp() {
        campaignRepository = mock(CampaignRepository.class);
        incidentRepository = mock(IncidentRepository.class);
        controller = new CampaignController(campaignRepository, incidentRepository);

        sampleCampaign = new ExfiltrationCampaign(
            campaignId,
            "CAMP-202611-0001",
            "attacker-subject-01",
            "DEFAULT_TENANT",
            "198.51.100.25",
            CampaignStage.AUTHORIZATION_PROBING,
            List.of(CampaignStage.RECONNAISSANCE, CampaignStage.AUTHORIZATION_PROBING),
            CampaignStatus.OPEN,
            "HIGH",
            65.0,
            "HIGH",
            "Reconnaissance followed by authorization probing",
            CampaignEvidenceCompleteness.COMPLETE,
            null,
            2,
            2,
            1,
            Instant.now().minusSeconds(60),
            Instant.now(),
            3,
            List.of(UUID.randomUUID()),
            List.of(UUID.randomUUID()),
            List.of("RULE-PROBE-01", "RULE-BOLA-01"),
            Instant.now().minusSeconds(60),
            Instant.now()
        );
    }

    @Test
    @DisplayName("GET /api/v1/security/campaigns returns paginated campaigns")
    void testGetCampaigns() {
        CampaignResponse resp = CampaignResponse.fromEntity(sampleCampaign);
        CampaignPageResponse pageResp = CampaignPageResponse.of(List.of(resp), 0, 20, 1L);

        when(campaignRepository.findCampaigns(0, 20, null, null, null, null)).thenReturn(pageResp);

        ResponseEntity<CampaignPageResponse> result = controller.getCampaigns(0, 20, null, null, null, null);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().campaigns()).hasSize(1);
        assertThat(result.getBody().campaigns().get(0).campaignId()).isEqualTo("CAMP-202611-0001");
    }

    @Test
    @DisplayName("GET /api/v1/security/campaigns/{id} returns campaign detail")
    void testGetCampaignById() {
        when(campaignRepository.findById(campaignId)).thenReturn(Optional.of(sampleCampaign));

        ResponseEntity<CampaignResponse> result = controller.getCampaignById(campaignId.toString());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().id()).isEqualTo(campaignId);
        assertThat(result.getBody().riskScore()).isEqualTo(65.0);
    }

    @Test
    @DisplayName("GET /api/v1/security/campaigns/{id} throws 404 when not found")
    void testGetCampaignNotFound() {
        UUID unknownId = UUID.randomUUID();
        when(campaignRepository.findById(unknownId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.getCampaignById(unknownId.toString()))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("404 NOT_FOUND");
    }

    @Test
    @DisplayName("PATCH /api/v1/security/campaigns/{id}/status succeeds on valid transition")
    void testUpdateCampaignStatusValid() {
        when(campaignRepository.findById(campaignId)).thenReturn(Optional.of(sampleCampaign));

        CampaignStatusUpdateRequest req = new CampaignStatusUpdateRequest(CampaignStatus.INVESTIGATING, "Analyst assigned");

        ResponseEntity<CampaignResponse> result = controller.updateCampaignStatus(campaignId.toString(), req);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().status()).isEqualTo(CampaignStatus.INVESTIGATING);

        verify(campaignRepository, times(1)).updateCampaign(any(ExfiltrationCampaign.class));
        verify(campaignRepository, times(1)).saveStatusHistory(any(CampaignStatusHistory.class));
    }

    @Test
    @DisplayName("PATCH /api/v1/security/campaigns/{id}/status rejects invalid transition with 400 Bad Request")
    void testUpdateCampaignStatusInvalid() {
        // Setup campaign already RESOLVED
        ExfiltrationCampaign resolvedCamp = new ExfiltrationCampaign(
            campaignId,
            "CAMP-202611-0001",
            "attacker-subject-01",
            "DEFAULT_TENANT",
            "198.51.100.25",
            CampaignStage.AUTHORIZATION_PROBING,
            List.of(CampaignStage.RECONNAISSANCE),
            CampaignStatus.RESOLVED,
            "MEDIUM",
            40.0,
            "MEDIUM",
            "Resolved",
            CampaignEvidenceCompleteness.COMPLETE,
            null,
            1,
            1,
            1,
            Instant.now(),
            Instant.now(),
            1,
            List.of(),
            List.of(),
            List.of(),
            Instant.now(),
            Instant.now()
        );
        when(campaignRepository.findById(campaignId)).thenReturn(Optional.of(resolvedCamp));

        // Invalid: RESOLVED -> ESCALATED
        CampaignStatusUpdateRequest req = new CampaignStatusUpdateRequest(CampaignStatus.ESCALATED, "Invalid move");

        assertThatThrownBy(() -> controller.updateCampaignStatus(campaignId.toString(), req))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("400 BAD_REQUEST");
    }

    @Test
    @DisplayName("GET /api/v1/security/campaigns/{id}/risk returns calibrated assessment")
    void testGetCampaignRisk() {
        when(campaignRepository.findById(campaignId)).thenReturn(Optional.of(sampleCampaign));

        ResponseEntity<CampaignRiskAssessment> result = controller.getCampaignRisk(campaignId.toString());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().overallScore()).isGreaterThan(0.0);
        assertThat(result.getBody().keyRiskIndicators()).isNotEmpty();
    }
}

