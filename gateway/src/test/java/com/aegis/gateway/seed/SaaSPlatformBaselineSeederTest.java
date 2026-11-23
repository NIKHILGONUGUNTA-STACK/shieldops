package com.aegis.gateway.seed;

import com.aegis.gateway.detection.campaign.CampaignRepository;
import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.evaluation.repository.EvaluationRepository;
import com.aegis.gateway.specs.ApiSpecificationRepository;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "aegis.seed.baseline.enabled=true")
@ActiveProfiles("test")
@DisplayName("SaaS Platform Baseline Seeder Tests")
class SaaSPlatformBaselineSeederTest {

    @Autowired
    private SaaSPlatformBaselineSeeder seeder;

    @Autowired
    private ApiEventRepository apiEventRepository;

    @Autowired
    private IncidentRepository incidentRepository;

    @Autowired
    private CampaignRepository campaignRepository;

    @Autowired
    private ApiSpecificationRepository specRepository;

    @Autowired
    private EvaluationRepository evaluationRepository;

    @Test
    @DisplayName("Explicit seeder invocation populates OpenAPI specs, multi-tenant telemetry, incidents, and campaigns")
    void testSeederExecutionAndIdempotency() {
        // Run baseline seeder
        seeder.run(new DefaultApplicationArguments());

        // Verify API specifications seeded
        var specs = specRepository.findSpecifications(0, 10, null, null);
        assertThat(specs.content()).isNotEmpty();

        // Verify telemetry events seeded
        long eventCount = apiEventRepository.count();
        assertThat(eventCount).isGreaterThanOrEqualTo(100);

        // Verify incidents seeded
        long openIncidents = incidentRepository.countOpenIncidents();
        assertThat(openIncidents).isGreaterThanOrEqualTo(2);
        assertThat(incidentRepository.findAllIncidents()).hasSizeGreaterThanOrEqualTo(5);

        // Verify campaigns seeded
        var campaigns = campaignRepository.findCampaigns(0, 10, null, null, null, null);
        assertThat(campaigns.campaigns()).isNotEmpty();
        assertThat(campaigns.campaigns().get(0).campaignId()).isEqualTo("EXFIL-CAMPAIGN-001");

        // Verify evaluation benchmark presence
        var experiment = evaluationRepository.findLatestExperiment();
        assertThat(experiment).isPresent();
        assertThat(experiment.get().datasetId()).isEqualTo("DS-AEGIS-RESEARCH-V1.1");

        // Test Idempotency: Running a second time should not fail or duplicate telemetry
        seeder.run(new DefaultApplicationArguments());
        assertThat(apiEventRepository.count()).isEqualTo(eventCount);
    }
}
