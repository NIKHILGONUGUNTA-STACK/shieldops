package com.aegis.gateway.reconciliation;

import com.aegis.gateway.reconciliation.dto.ReconciliationPageResponse;
import com.aegis.gateway.reconciliation.dto.ReconciliationSummaryResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Controller for documented vs. observed API contract reconciliation and discrepancy analysis.
 * Role-based access: Requires ROLE_SECURITY_ANALYST or ROLE_SECURITY_ADMIN.
 */
@RestController
@RequestMapping("/api/v1/security/reconciliation")
public class SecurityReconciliationController {

    private static final Logger log = LoggerFactory.getLogger(SecurityReconciliationController.class);
    private final ApiReconciliationService reconciliationService;

    public SecurityReconciliationController(ApiReconciliationService reconciliationService) {
        this.reconciliationService = reconciliationService;
    }

    /**
     * Paginated reconciliation report comparing declared contracts against wire telemetry.
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<ReconciliationPageResponse> getReconciliation(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) UUID specId,
            @RequestParam(required = false) String service,
            @RequestParam(required = false) String method,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Integer windowHours,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "category") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDirection) {

        log.debug("Reconciliation request: page={}, size={}, specId={}, category={}, windowHours={}",
            page, size, specId, category, windowHours);

        ReconciliationPageResponse response = reconciliationService.reconcile(
            page,
            size,
            specId,
            service,
            method,
            category,
            windowHours,
            from,
            to,
            search,
            sortBy,
            sortDirection
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Quick summary metrics of reconciliation coverage across a specified observation window.
     */
    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<ReconciliationSummaryResponse> getSummary(
            @RequestParam(required = false) UUID specId,
            @RequestParam(required = false) Integer windowHours,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {

        ReconciliationSummaryResponse summary = reconciliationService.getSummary(specId, windowHours, from, to);
        return ResponseEntity.ok(summary);
    }
}

