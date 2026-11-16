package com.aegis.gateway.simulation;

import com.aegis.gateway.simulation.controller.SimulationController;
import com.aegis.gateway.simulation.model.*;
import com.aegis.gateway.simulation.service.DefaultSimulationHttpDispatcher;
import com.aegis.gateway.simulation.service.SimulationCatalogService;
import com.aegis.gateway.simulation.service.SimulationExecutionService;
import com.aegis.gateway.simulation.service.SimulationHttpDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class SimulationControllerTest {

    private SimulationCatalogService catalogService;
    private SimulationExecutionService executionService;
    private SimulationHttpDispatcher mockDispatcher;
    private SimulationController controller;

    @BeforeEach
    void setUp() {
        catalogService = new SimulationCatalogService();
        mockDispatcher = mock(SimulationHttpDispatcher.class);
        when(mockDispatcher.dispatch(any(), any(), any(), any(), anyInt()))
            .thenReturn(new SimulationHttpDispatcher.DispatchResult(200, 15, 256, Map.of(), null));

        executionService = new SimulationExecutionService(catalogService, mockDispatcher, null, null);
        controller = new SimulationController(catalogService, executionService);
    }

    @Test
    @DisplayName("Catalog lists all scenarios across benign, bola, leakage, exfiltration, mixed, and infra categories")
    void testCatalogListsScenarios() {
        ResponseEntity<List<SimulationScenarioDto>> response = controller.getScenarios();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotEmpty();
        assertThat(response.getBody().stream().anyMatch(s -> s.id().equals("SCEN-BOLA-01"))).isTrue();
        assertThat(response.getBody().stream().anyMatch(s -> s.id().equals("SCEN-BENIGN-01"))).isTrue();
        assertThat(response.getBody().stream().anyMatch(s -> s.id().equals("SCEN-INFRA-BACKLOG"))).isTrue();
    }

    @Test
    @DisplayName("Catalog finds scenario by ID and throws 404 for unknown scenario")
    void testGetScenarioById() {
        ResponseEntity<SimulationScenarioDto> ok = controller.getScenarioById("SCEN-BOLA-01");
        assertThat(ok.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ok.getBody().name()).isEqualTo("Classic Cross-Tenant BOLA Access");

        assertThatThrownBy(() -> controller.getScenarioById("UNKNOWN-SCEN"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Scenario not found");
    }

    @Test
    @DisplayName("Catalog lists templates and gets template by ID")
    void testCatalogTemplates() {
        ResponseEntity<List<SimulationCampaignTemplate>> response = controller.getTemplates();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotEmpty();
        assertThat(response.getBody().stream().anyMatch(t -> t.id().equals("TPL-BOLA-EXFIL-CAMPAIGN"))).isTrue();

        ResponseEntity<SimulationCampaignTemplate> single = controller.getTemplateById("TPL-BENIGN-WORKDAY");
        assertThat(single.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(single.getBody().stages()).isNotEmpty();
    }

    @Test
    @DisplayName("Starts simulation run and retrieves status, controls, and report")
    void testSimulationRunLifecycle() {
        SimulationRunConfig config = new SimulationRunConfig(
            "TPL-BENIGN-WORKDAY",
            List.of(),
            10,
            2.0,
            1,
            "SEQUENTIAL",
            123L,
            List.of("tenant-01"),
            List.of("/api/v1/customers"),
            true // dryRun
        );

        ResponseEntity<SimulationRunResponse> startResp = controller.startRun(config);
        assertThat(startResp.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        SimulationRunResponse created = startResp.getBody();
        assertThat(created).isNotNull();
        assertThat(created.runId()).startsWith("SIM-RUN-");
        assertThat(created.status()).isIn(SimulationRunStatus.RUNNING, SimulationRunStatus.PENDING, SimulationRunStatus.COMPLETED);

        // Pause
        ResponseEntity<SimulationRunResponse> pauseResp = controller.pauseRun(created.runId());
        assertThat(pauseResp.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Resume
        ResponseEntity<SimulationRunResponse> resumeResp = controller.resumeRun(created.runId());
        assertThat(resumeResp.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Stop
        ResponseEntity<SimulationRunResponse> stopResp = controller.stopRun(created.runId());
        assertThat(stopResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(stopResp.getBody().status()).isEqualTo(SimulationRunStatus.STOPPED);

        // Get Run
        ResponseEntity<SimulationRunResponse> getResp = controller.getRun(created.runId());
        assertThat(getResp.getStatusCode()).isEqualTo(HttpStatus.OK);

        // List Runs
        ResponseEntity<List<SimulationRunResponse>> listResp = controller.listRuns();
        assertThat(listResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(listResp.getBody()).isNotEmpty();

        // Get Report
        ResponseEntity<SimulationReport> reportResp = controller.getReport(created.runId());
        assertThat(reportResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(reportResp.getBody().markdownReport()).contains("ShieldOps Simulation Execution & Verification Report");
    }

    @Test
    @DisplayName("DefaultSimulationHttpDispatcher rejects non-localhost destinations for safety")
    void testDispatcherSafetyInvariant() {
        DefaultSimulationHttpDispatcher dispatcher = new DefaultSimulationHttpDispatcher();
        SimulationHttpDispatcher.DispatchResult result = dispatcher.dispatch(
            "GET", "https://external-malicious-site.com/exploit", Map.of(), null, 1000
        );
        assertThat(result.statusCode()).isEqualTo(400);
        assertThat(result.error()).contains("Target host must be localhost");
    }

    @Test
    @DisplayName("DefaultSimulationHttpDispatcher rejects invalid scheme and arbitrary ports")
    void testDispatcherSchemeAndPortRestrictions() {
        DefaultSimulationHttpDispatcher dispatcher = new DefaultSimulationHttpDispatcher();

        // Invalid scheme
        SimulationHttpDispatcher.DispatchResult ftpResult = dispatcher.dispatch(
            "GET", "ftp://localhost:8000/files", Map.of(), null, 1000
        );
        assertThat(ftpResult.statusCode()).isEqualTo(400);
        assertThat(ftpResult.error()).contains("Target scheme must be http or https");

        // Arbitrary port (e.g. Postgres port 5433 or Redis 6379 or SSH 22)
        SimulationHttpDispatcher.DispatchResult pgResult = dispatcher.dispatch(
            "GET", "http://localhost:5433/admin", Map.of(), null, 1000
        );
        assertThat(pgResult.statusCode()).isEqualTo(400);
        assertThat(pgResult.error()).contains("Target port must be 8000");

        SimulationHttpDispatcher.DispatchResult redisResult = dispatcher.dispatch(
            "GET", "http://localhost:6379/data", Map.of(), null, 1000
        );
        assertThat(redisResult.statusCode()).isEqualTo(400);
        assertThat(redisResult.error()).contains("Target port must be 8000");
    }
}

