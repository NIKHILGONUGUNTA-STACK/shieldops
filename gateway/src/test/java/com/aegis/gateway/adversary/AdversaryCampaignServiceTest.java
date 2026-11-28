package com.aegis.gateway.adversary;

import com.aegis.gateway.workflow.WorkflowStateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AdversaryCampaignServiceTest {

    private WorkflowStateService workflowStateService;
    private AdversaryCampaignService service;

    @BeforeEach
    void setUp() {
        workflowStateService = new WorkflowStateService(null);
        service = new AdversaryCampaignService(workflowStateService);
    }

    @Test
    @DisplayName("Should load seeded adversary campaigns")
    void testSeedCampaigns() {
        List<AdversaryCampaign> campaigns = service.getCampaigns();
        assertThat(campaigns).hasSizeGreaterThanOrEqualTo(2);

        Optional<AdversaryCampaign> c1 = service.getCampaign("ADV-CAMP-001");
        assertThat(c1).isPresent();
        assertThat(c1.get().evasionRate()).isEqualTo(0.0);

        Optional<AdversaryCampaign> c2 = service.getCampaign("ADV-CAMP-002");
        assertThat(c2).isPresent();
        assertThat(c2.get().evadedProbes()).isGreaterThan(0);
        assertThat(c2.get().evasionTraces()).isNotEmpty();
    }

    @Test
    @DisplayName("Run adversary campaign against existing protected endpoint blocks all probes")
    void testRunCampaignAgainstProtectedEndpoint() {
        // POST /api/v1/transfers is guarded by RULE-WF-TRANSFER-01
        AdversaryCampaign campaign = service.runCampaign(
            "Transfer Probing Test",
            "POST /api/v1/transfers",
            AdversaryMutationStrategy.STEP_SKIPPING,
            10
        );

        assertThat(campaign).isNotNull();
        assertThat(campaign.totalProbes()).isEqualTo(10);
        assertThat(campaign.blockedProbes()).isEqualTo(10);
        assertThat(campaign.evadedProbes()).isEqualTo(0);
        assertThat(campaign.evasionRate()).isEqualTo(0.0);
        assertThat(campaign.status()).isEqualTo("COMPLETED");
    }

    @Test
    @DisplayName("Run adversary campaign against unconstrained endpoint detects evasion")
    void testRunCampaignAgainstUnconstrainedEndpoint() {
        // POST /api/v1/unprotected-action has no workflow rule yet
        AdversaryCampaign campaign = service.runCampaign(
            "Unconstrained Action Evasion Test",
            "POST /api/v1/unprotected-action",
            AdversaryMutationStrategy.OUT_OF_ORDER_TRAVERSAL,
            8
        );

        assertThat(campaign).isNotNull();
        assertThat(campaign.totalProbes()).isEqualTo(8);
        assertThat(campaign.evadedProbes()).isEqualTo(8);
        assertThat(campaign.evasionRate()).isEqualTo(1.0);
        assertThat(campaign.evasionTraces()).isNotEmpty();
    }
}
