package com.aegis.gateway.simulation;

import com.aegis.gateway.simulation.model.*;
import com.aegis.gateway.simulation.repository.SimulationRunRepository;
import com.aegis.gateway.simulation.service.SimulationExecutionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
public class SimulationRunPersistenceTest {

    @Autowired
    private SimulationRunRepository repository;

    @Autowired
    private SimulationExecutionService executionService;

    @Test
    @DisplayName("Verify simulation run and stage persistence, retrieval and heartbeat")
    void testSimulationRunAndStagePersistence() {
        String runId = "SIM-TEST-" + UUID.randomUUID().toString().substring(0, 8);
        String campaignId = "CAMP-TEST-" + UUID.randomUUID().toString().substring(0, 8);

        SimulationRunConfig config = new SimulationRunConfig(
            "TPL-BENIGN-WORKDAY",
            List.of("SCN-BENIGN-01"),
            30,
            5.0,
            2,
            "SEQUENTIAL",
            42L,
            List.of("tenant-alpha"),
            List.of("/api/v1/customers"),
            true
        );

        SimulationStageResult stage = new SimulationStageResult(
            1,
            "Reconnaissance Probe",
            "SCN-BENIGN-01",
            "PASSED",
            10,
            10,
            0,
            Instant.now().minusSeconds(10),
            Instant.now(),
            1000L,
            List.of(new ExpectedVsActualAssertion("STATUS_CHECK", "2xx Response", 10, 10, true, "10 expected and 10 actual")),
            null
        );

        SimulationRunResponse run = new SimulationRunResponse(
            runId,
            campaignId,
            "TPL-BENIGN-WORKDAY",
            SimulationRunStatus.RUNNING,
            Instant.now().minusSeconds(30),
            null,
            config,
            List.of(stage),
            10,
            10,
            0,
            0,
            true,
            Map.of("environment", "testbed", "seed", 42L),
            "soc-analyst-1",
            Instant.now(),
            null,
            null
        );

        // 1. Save Run
        repository.saveRun(run);

        // 2. Retrieve Run
        Optional<SimulationRunResponse> fetched = repository.findRunById(runId);
        assertThat(fetched).isPresent();
        SimulationRunResponse loaded = fetched.get();
        assertThat(loaded.runId()).isEqualTo(runId);
        assertThat(loaded.campaignId()).isEqualTo(campaignId);
        assertThat(loaded.status()).isEqualTo(SimulationRunStatus.RUNNING);
        assertThat(loaded.totalRequests()).isEqualTo(10);
        assertThat(loaded.requests2xx()).isEqualTo(10);
        assertThat(loaded.requestedBy()).isEqualTo("soc-analyst-1");
        assertThat(loaded.stages()).hasSize(1);
        assertThat(loaded.stages().get(0).stageName()).isEqualTo("Reconnaissance Probe");
        assertThat(loaded.stages().get(0).status()).isEqualTo("PASSED");

        // 3. Heartbeat Update
        repository.updateHeartbeat(runId);
        Optional<SimulationRunResponse> afterHeartbeat = repository.findRunById(runId);
        assertThat(afterHeartbeat).isPresent();
        assertThat(afterHeartbeat.get().lastHeartbeatAt()).isNotNull();

        // 4. Status Update to COMPLETED
        repository.updateRunStatus(runId, SimulationRunStatus.COMPLETED, null, null);
        Optional<SimulationRunResponse> completed = repository.findRunById(runId);
        assertThat(completed).isPresent();
        assertThat(completed.get().status()).isEqualTo(SimulationRunStatus.COMPLETED);
        assertThat(completed.get().endTime()).isNotNull();
    }

    @Test
    @DisplayName("Verify crash recovery transitions uncompleted runs with stale heartbeats to INTERRUPTED")
    void testCrashRecoveryReconcilesStaleRuns() {
        String staleRunId = "SIM-CRASH-" + UUID.randomUUID().toString().substring(0, 8);

        SimulationRunConfig config = new SimulationRunConfig(
            "TPL-BOLA-EXFIL-CAMPAIGN",
            List.of(),
            60,
            10.0,
            1,
            "SEQUENTIAL",
            99L,
            List.of("tenant-beta"),
            List.of("/api/v1/customers"),
            true
        );

        SimulationRunResponse staleRun = new SimulationRunResponse(
            staleRunId,
            "CAMP-CRASH",
            "TPL-BOLA-EXFIL-CAMPAIGN",
            SimulationRunStatus.RUNNING,
            Instant.now().minusSeconds(600),
            null,
            config,
            List.of(),
            5,
            3,
            2,
            0,
            false,
            Map.of("environment", "testbed"),
            "soc-admin",
            Instant.now().minusSeconds(500), // Heartbeat was 500 seconds ago
            null,
            null
        );

        repository.saveRun(staleRun);

        // Verify initial state is RUNNING
        Optional<SimulationRunResponse> preReconcile = repository.findRunById(staleRunId);
        assertThat(preReconcile).isPresent();
        assertThat(preReconcile.get().status()).isEqualTo(SimulationRunStatus.RUNNING);

        // Run recovery with 120s cutoff
        int reconciledCount = repository.reconcileInterruptedRuns(Instant.now().minusSeconds(120));
        assertThat(reconciledCount).isGreaterThanOrEqualTo(1);

        // Verify state is now INTERRUPTED with stop reason
        Optional<SimulationRunResponse> postReconcile = repository.findRunById(staleRunId);
        assertThat(postReconcile).isPresent();
        assertThat(postReconcile.get().status()).isEqualTo(SimulationRunStatus.INTERRUPTED);
        assertThat(postReconcile.get().stopReason()).contains("Gateway restart / ungraceful termination detected");
        assertThat(postReconcile.get().endTime()).isNotNull();
    }

    @Test
    @DisplayName("Verify SimulationExecutionService startRun persists to database and recovers via getRun and listRuns")
    void testExecutionServiceDurableRuns() {
        SimulationRunConfig request = new SimulationRunConfig(
            "TPL-BENIGN-WORKDAY",
            List.of(),
            10,
            2.0,
            1,
            "SEQUENTIAL",
            123L,
            List.of("tenant-gamma"),
            List.of("/api/v1/customers"),
            true // dry run so no live HTTP calls needed in test
        );

        SimulationRunResponse started = executionService.startRun(request);
        assertThat(started).isNotNull();
        String runId = started.runId();

        // Check that repository finds it
        Optional<SimulationRunResponse> persisted = repository.findRunById(runId);
        assertThat(persisted).isPresent();
        assertThat(persisted.get().templateId()).isEqualTo("TPL-BENIGN-WORKDAY");

        // Check that listRuns includes it
        List<SimulationRunResponse> allRuns = executionService.listRuns();
        assertThat(allRuns).anyMatch(r -> r.runId().equals(runId));
    }
}
