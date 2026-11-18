package com.aegis.gateway.db;

import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.aegis.gateway.telemetry.SecurityEventResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class FlywayMigrationV10Test {

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private ApiEventRepository apiEventRepository;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private StringRedisTemplate redisTemplate;

    @Test
    @DisplayName("V10 migration: api_events accepts nullable attribution, stage, and tenant")
    void testApiEventsAttributionColumns() {
        UUID eventId = UUID.randomUUID();
        ApiEvent event = new ApiEvent(
            eventId,
            "corr-v10-test-01",
            Instant.now(),
            "192.168.1.100",
            "GET",
            "/api/v1/customers/1001",
            "/api/v1/customers/{id}",
            200,
            25L,
            "user-v10",
            "CUSTOMER",
            "1001",
            "Mozilla/5.0",
            null,
            "NONE",
            "CUSTOMER",
            "1001",
            null,
            128L,
            1,
            "id,name",
            0,
            20,
            "SIM-RUN-2026-001",
            "TPL-BENIGN-WORKDAY",
            "SCEN-BENIGN-01",
            "stage-1",
            "tenant-alpha",
            "customer-service"
        );

        apiEventRepository.save(event);

        Optional<SecurityEventResponse> found = apiEventRepository.findById(eventId);
        assertThat(found).isPresent();
        SecurityEventResponse res = found.get();
        assertThat(res.simulationRunId()).isEqualTo("SIM-RUN-2026-001");
        assertThat(res.simulationCampaignId()).isEqualTo("TPL-BENIGN-WORKDAY");
        assertThat(res.simulationScenarioId()).isEqualTo("SCEN-BENIGN-01");
        assertThat(res.simulationStage()).isEqualTo("stage-1");
        assertThat(res.tenantId()).isEqualTo("tenant-alpha");
        assertThat(res.serviceName()).isEqualTo("customer-service");
    }

    @Test
    @DisplayName("V10 migration: api_events accepts NULL attribution and tenant without defaulting")
    void testApiEventsNullAttribution() {
        UUID eventId = UUID.randomUUID();
        ApiEvent event = new ApiEvent(
            eventId,
            "corr-v10-null-test",
            Instant.now(),
            "10.0.0.1",
            "POST",
            "/api/v1/transfers",
            "/api/v1/transfers",
            201,
            40L,
            "anonymous",
            "",
            "",
            "curl/8.0",
            null,
            "NONE",
            "TRANSFER",
            null,
            null,
            0L,
            0,
            null,
            null,
            null,
            null, // simulationRunId
            null, // simulationCampaignId
            null, // simulationScenarioId
            null, // simulationStage
            null, // tenantId (explicitly null, no default)
            null  // serviceName
        );

        apiEventRepository.save(event);

        Optional<SecurityEventResponse> found = apiEventRepository.findById(eventId);
        assertThat(found).isPresent();
        SecurityEventResponse res = found.get();
        assertThat(res.simulationRunId()).isNull();
        assertThat(res.simulationCampaignId()).isNull();
        assertThat(res.simulationScenarioId()).isNull();
        assertThat(res.simulationStage()).isNull();
        assertThat(res.tenantId()).isNull();
        assertThat(res.serviceName()).isNull();
    }

    @Test
    @DisplayName("V10 migration: simulation_runs and stages lifecycle and constraints")
    void testSimulationRunsAndStagesConstraints() {
        String runId = "SIM-RUN-" + UUID.randomUUID();

        // 1. Insert valid simulation run
        int insertedRun = jdbcClient.sql("""
            INSERT INTO security_data.simulation_runs (
                run_id, campaign_id, template_id, status, requested_by, start_time, duration_seconds
            ) VALUES (
                :runId, 'CAMP-V10', 'TPL-BOLA-EXFIL-CAMPAIGN', 'RUNNING', 'analyst@shieldops.dev', CURRENT_TIMESTAMP, 90
            )
            """)
            .param("runId", runId)
            .update();
        assertThat(insertedRun).isEqualTo(1);

        // 2. Insert valid stage
        UUID stageId = UUID.randomUUID();
        int insertedStage = jdbcClient.sql("""
            INSERT INTO security_data.simulation_run_stages (
                id, run_id, stage_id, stage_name, scenario_id, status, total_requests
            ) VALUES (
                :id, :runId, 'stage-1', 'Recon Stage', 'SCEN-EXFIL-RECON-PROBE', 'SUCCESS', 10
            )
            """)
            .param("id", stageId)
            .param("runId", runId)
            .update();
        assertThat(insertedStage).isEqualTo(1);

        // 3. Verify uniqueness constraint (run_id, stage_id, scenario_id)
        assertThatThrownBy(() -> {
            jdbcClient.sql("""
                INSERT INTO security_data.simulation_run_stages (
                    id, run_id, stage_id, stage_name, scenario_id, status
                ) VALUES (
                    :id, :runId, 'stage-1', 'Duplicate Stage', 'SCEN-EXFIL-RECON-PROBE', 'RUNNING'
                )
                """)
                .param("id", UUID.randomUUID())
                .param("runId", runId)
                .update();
        }).isInstanceOf(DataIntegrityViolationException.class);

        // 4. Verify cascade delete
        jdbcClient.sql("DELETE FROM security_data.simulation_runs WHERE run_id = :runId")
            .param("runId", runId)
            .update();

        Long stageCount = jdbcClient.sql("SELECT COUNT(*) FROM security_data.simulation_run_stages WHERE id = :id")
            .param("id", stageId)
            .query(Long.class)
            .single();
        assertThat(stageCount).isZero();
    }
}
