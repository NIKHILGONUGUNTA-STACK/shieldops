package com.aegis.gateway.evaluation.controller;

import com.aegis.gateway.evaluation.dto.EvaluationBenchmarkResponse;
import com.aegis.gateway.evaluation.dto.ExperimentImportRequest;
import com.aegis.gateway.evaluation.model.EvaluationExperiment;
import com.aegis.gateway.evaluation.service.ResearchEvaluationService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/security/evaluation")
public class ResearchEvaluationController {

    private final ResearchEvaluationService service;

    public ResearchEvaluationController(ResearchEvaluationService service) {
        this.service = service;
    }

    @GetMapping(value = "/benchmark", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<EvaluationBenchmarkResponse> getBenchmark() {
        return ResponseEntity.ok(service.getLatestBenchmark());
    }

    @GetMapping(value = "/experiments", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<List<EvaluationExperiment>> getExperiments() {
        return ResponseEntity.ok(service.getExperiments());
    }

    @PostMapping(value = "/import", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN')")
    public ResponseEntity<Map<String, Object>> importExperiment(@RequestBody ExperimentImportRequest request) {
        service.importExperiment(request);
        return ResponseEntity.ok(Map.of(
            "status", "IMPORTED",
            "experimentId", request.experimentId(),
            "datasetId", request.datasetId()
        ));
    }
}
