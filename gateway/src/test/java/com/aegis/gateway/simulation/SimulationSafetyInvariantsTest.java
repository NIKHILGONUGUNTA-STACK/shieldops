package com.aegis.gateway.simulation;

import com.aegis.gateway.simulation.model.SimulationRunConfig;
import com.aegis.gateway.simulation.model.SimulationRunResponse;
import com.aegis.gateway.simulation.service.DefaultSimulationHttpDispatcher;
import com.aegis.gateway.simulation.service.SimulationCatalogService;
import com.aegis.gateway.simulation.service.SimulationExecutionService;
import com.aegis.gateway.simulation.service.SimulationHttpDispatcher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SimulationSafetyInvariantsTest {

    private final DefaultSimulationHttpDispatcher dispatcher = new DefaultSimulationHttpDispatcher();

    @Test
    @DisplayName("Should reject non-http schemes (e.g. ftp, ssh)")
    void testRejectNonHttpScheme() {
        SimulationHttpDispatcher.DispatchResult result = dispatcher.dispatch(
            "GET", "ftp://localhost:8000/api/v1/customers", Map.of(), null, 1000
        );
        assertThat(result.statusCode()).isEqualTo(400);
        assertThat(result.error()).contains("Target scheme must be http or https");
    }

    @Test
    @DisplayName("Should reject external hosts and enforce localhost-only execution")
    void testRejectExternalHosts() {
        SimulationHttpDispatcher.DispatchResult result = dispatcher.dispatch(
            "GET", "http://external-api.evil.com:8000/api/v1/customers", Map.of(), null, 1000
        );
        assertThat(result.statusCode()).isEqualTo(400);
        assertThat(result.error()).contains("Target host must be localhost");
    }

    @Test
    @DisplayName("Should reject non-8000 ports (e.g. Postgres 5432, Redis 6379, Keycloak 8080, SSH 22, Port 80)")
    void testRejectNon8000Ports() {
        // Test database port
        SimulationHttpDispatcher.DispatchResult dbResult = dispatcher.dispatch(
            "GET", "http://localhost:5432/api/v1/customers", Map.of(), null, 1000
        );
        assertThat(dbResult.statusCode()).isEqualTo(400);
        assertThat(dbResult.error()).contains("Target port must be 8000");

        // Test Redis port
        SimulationHttpDispatcher.DispatchResult redisResult = dispatcher.dispatch(
            "GET", "http://localhost:6379/api/v1/customers", Map.of(), null, 1000
        );
        assertThat(redisResult.statusCode()).isEqualTo(400);
        assertThat(redisResult.error()).contains("Target port must be 8000");

        // Test missing port (-1 defaults to 80)
        SimulationHttpDispatcher.DispatchResult missingPortResult = dispatcher.dispatch(
            "GET", "http://localhost/api/v1/customers", Map.of(), null, 1000
        );
        assertThat(missingPortResult.statusCode()).isEqualTo(400);
        assertThat(missingPortResult.error()).contains("Target port must be 8000");
    }

    @Test
    @DisplayName("Should enforce minimum positive bounds on simulation configuration")
    void testEnforceConfigBounds() {
        SimulationCatalogService catalog = mock(SimulationCatalogService.class);
        SimulationHttpDispatcher mockDispatcher = mock(SimulationHttpDispatcher.class);
        SimulationExecutionService service = new SimulationExecutionService(catalog, mockDispatcher);

        // Supply negative and zero values
        SimulationRunConfig badConfig = new SimulationRunConfig(
            "TPL-BENIGN-WORKDAY",
            List.of(),
            -10,    // negative duration
            -5.0,   // negative rate
            0,      // zero concurrency
            "SEQUENTIAL",
            42L,
            List.of("tenant-01"),
            List.of("/api/v1/customers"),
            true
        );

        SimulationRunResponse response = service.startRun(badConfig);

        // Verifies lower bounds are strictly enforced
        assertThat(response.config().durationSeconds()).isGreaterThanOrEqualTo(1);
        assertThat(response.config().requestRate()).isGreaterThanOrEqualTo(0.1);
        assertThat(response.config().concurrency()).isGreaterThanOrEqualTo(1);

        service.stopRun(response.runId());
    }
}
