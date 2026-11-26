package com.aegis.gateway.workflow;

import com.aegis.gateway.telemetry.StreamingAnomalyScorer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * REST API for inspecting and managing deterministic business workflow rules and session state.
 */
@RestController
@RequestMapping("/api/v1/security/workflow")
public class WorkflowController {

    private final WorkflowStateService workflowStateService;
    private final StreamingAnomalyScorer streamingAnomalyScorer;

    @Autowired
    public WorkflowController(
            WorkflowStateService workflowStateService,
            @Autowired(required = false) StreamingAnomalyScorer streamingAnomalyScorer) {
        this.workflowStateService = workflowStateService;
        this.streamingAnomalyScorer = streamingAnomalyScorer;
    }

    @GetMapping("/outliers/stats")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<Map<String, Map<String, Object>>> getOutlierStats() {
        return ResponseEntity.ok(streamingAnomalyScorer != null ? streamingAnomalyScorer.getEndpointStats() : Collections.emptyMap());
    }

    @GetMapping("/rules")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<WorkflowRule>> getRules() {
        return ResponseEntity.ok(workflowStateService.getRules());
    }

    @PostMapping("/rules")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<WorkflowRule> addRule(@RequestBody WorkflowRule rule) {
        workflowStateService.addRule(rule);
        return ResponseEntity.ok(rule);
    }

    @GetMapping("/sessions/{sessionId}")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<Set<String>> getSessionSteps(@PathVariable String sessionId) {
        return ResponseEntity.ok(workflowStateService.getCompletedSteps(sessionId));
    }

    @PostMapping("/sessions/{sessionId}/clear")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<Void> clearSession(@PathVariable String sessionId) {
        workflowStateService.clearSession(sessionId);
        return ResponseEntity.noContent().build();
    }

    public record VerifyRequest(String sessionId, String method, String path, List<String> roles) {}

    @PostMapping("/verify")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<WorkflowCheckResult> verifyStep(@RequestBody VerifyRequest request) {
        Collection<String> roles = request.roles() != null ? request.roles() : Collections.emptyList();
        WorkflowCheckResult result = workflowStateService.checkCompliance(
            request.sessionId(),
            request.method(),
            request.path(),
            roles
        );
        return ResponseEntity.ok(result);
    }
}
