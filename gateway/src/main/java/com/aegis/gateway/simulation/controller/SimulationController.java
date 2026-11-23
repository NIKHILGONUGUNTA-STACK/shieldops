package com.aegis.gateway.simulation.controller;

import com.aegis.gateway.simulation.model.*;
import com.aegis.gateway.simulation.service.SimulationCatalogService;
import com.aegis.gateway.simulation.service.SimulationExecutionService;
import com.aegis.gateway.telemetry.ApiEvent;
import com.aegis.gateway.telemetry.ApiEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping({"/api/v1/simulation", "/api/v1/security/simulation"})
@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
public class SimulationController {

    private final SimulationCatalogService catalogService;
    private final SimulationExecutionService executionService;
    private final Optional<ApiEventRepository> apiEventRepository;

    public SimulationController(
        SimulationCatalogService catalogService,
        SimulationExecutionService executionService
    ) {
        this(catalogService, executionService, null);
    }

    @Autowired
    public SimulationController(
        SimulationCatalogService catalogService,
        SimulationExecutionService executionService,
        @Autowired(required = false) ApiEventRepository apiEventRepository
    ) {
        this.catalogService = catalogService;
        this.executionService = executionService;
        this.apiEventRepository = Optional.ofNullable(apiEventRepository);
    }

    @GetMapping("/scenarios")
    public ResponseEntity<List<SimulationScenarioDto>> getScenarios() {
        return ResponseEntity.ok(catalogService.getAllScenarios());
    }

    @GetMapping("/scenarios/{id}")
    public ResponseEntity<SimulationScenarioDto> getScenarioById(@PathVariable("id") String id) {
        return catalogService.getScenario(id)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scenario not found: " + id));
    }

    @GetMapping("/templates")
    public ResponseEntity<List<SimulationCampaignTemplate>> getTemplates() {
        return ResponseEntity.ok(catalogService.getAllTemplates());
    }

    @GetMapping("/templates/{id}")
    public ResponseEntity<SimulationCampaignTemplate> getTemplateById(@PathVariable("id") String id) {
        return catalogService.getTemplate(id)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Template not found: " + id));
    }

    @PostMapping("/runs")
    public ResponseEntity<SimulationRunResponse> startRun(@RequestBody(required = false) SimulationRunConfig config) {
        SimulationRunResponse response = executionService.startRun(config);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/runs/{runId}/pause")
    public ResponseEntity<SimulationRunResponse> pauseRun(@PathVariable("runId") String runId) {
        return executionService.pauseRun(runId)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run not found: " + runId));
    }

    @PostMapping("/runs/{runId}/resume")
    public ResponseEntity<SimulationRunResponse> resumeRun(@PathVariable("runId") String runId) {
        return executionService.resumeRun(runId)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run not found: " + runId));
    }

    @PostMapping("/runs/{runId}/stop")
    public ResponseEntity<SimulationRunResponse> stopRun(@PathVariable("runId") String runId) {
        return executionService.stopRun(runId)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run not found: " + runId));
    }

    @GetMapping("/runs/{runId}")
    public ResponseEntity<SimulationRunResponse> getRun(@PathVariable("runId") String runId) {
        return executionService.getRun(runId)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run not found: " + runId));
    }

    @GetMapping("/runs")
    public ResponseEntity<List<SimulationRunResponse>> listRuns() {
        return ResponseEntity.ok(executionService.listRuns());
    }

    @GetMapping("/runs/{runId}/report")
    public ResponseEntity<SimulationReport> getReport(@PathVariable("runId") String runId) {
        return executionService.generateReport(runId)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run not found: " + runId));
    }

    @PostMapping("/traffic/generate")
    public ResponseEntity<Map<String, Object>> generateTrafficBurst(@RequestParam(name = "count", defaultValue = "10") int count) {
        int bounded = Math.min(Math.max(1, count), 100);
        if (apiEventRepository.isEmpty()) {
            return ResponseEntity.ok(Map.of("generated", 0, "status", "REPOSITORY_UNAVAILABLE"));
        }

        Instant now = Instant.now();
        List<ApiEvent> burst = new ArrayList<>(bounded);
        String[] paths = new String[] {
            "/customers/10000000-0000-4000-8000-000000000001",
            "/accounts/20000000-0000-4000-8000-000000000001",
            "/accounts/20000000-0000-4000-8000-000000000001/balance",
            "/transactions",
            "/transfers",
            "/actuator/env"
        };
        String[] services = new String[] {
            "customer-service", "account-service", "account-service", "transaction-service", "transaction-service", "perimeter"
        };

        for (int i = 0; i < bounded; i++) {
            int idx = i % paths.length;
            boolean isRecon = paths[idx].contains("actuator");
            burst.add(new ApiEvent(
                UUID.randomUUID(),
                "burst-corr-" + System.currentTimeMillis() + "-" + i,
                now.minusSeconds(bounded - i),
                isRecon ? "198.51.100.42" : "192.168.1.100",
                isRecon ? "GET" : (paths[idx].equals("/transfers") ? "POST" : "GET"),
                paths[idx],
                services[idx].replace("-", "_"),
                isRecon ? 404 : 200,
                15 + (i * 3L),
                isRecon ? "anonymous" : "usr-alex-01",
                isRecon ? "NONE" : "ROLE_CUSTOMER",
                isRecon ? null : "10000000-0000-4000-8000-000000000001",
                "Aegis-Traffic-Generator/1.0",
                "hash-burst-" + i,
                isRecon ? "RECON_SCAN" : "NONE",
                isRecon ? "PERIMETER" : "FINTECH",
                paths[idx],
                isRecon ? "NOT_FOUND" : null,
                isRecon ? 150 : 540,
                1,
                isRecon ? null : "id,balance,currency,timestamp",
                null, null,
                null, null, null, null,
                "tenant-fintech-us",
                services[idx]
            ));
        }

        apiEventRepository.get().saveAll(burst);
        return ResponseEntity.ok(Map.of(
            "generated", burst.size(),
            "status", "GENERATED",
            "timestamp", now.toString()
        ));
    }
}

