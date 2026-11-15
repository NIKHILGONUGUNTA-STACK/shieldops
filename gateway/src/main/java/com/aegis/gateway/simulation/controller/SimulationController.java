package com.aegis.gateway.simulation.controller;

import com.aegis.gateway.simulation.model.*;
import com.aegis.gateway.simulation.service.SimulationCatalogService;
import com.aegis.gateway.simulation.service.SimulationExecutionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping({"/api/v1/simulation", "/api/v1/security/simulation"})
@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
public class SimulationController {

    private final SimulationCatalogService catalogService;
    private final SimulationExecutionService executionService;

    public SimulationController(
        SimulationCatalogService catalogService,
        SimulationExecutionService executionService
    ) {
        this.catalogService = catalogService;
        this.executionService = executionService;
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
}

