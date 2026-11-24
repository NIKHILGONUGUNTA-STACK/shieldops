package com.aegis.gateway.tenant.controller;

import com.aegis.gateway.tenant.dto.*;
import com.aegis.gateway.tenant.model.Tenant;
import com.aegis.gateway.tenant.service.TenantService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

/**
 * REST controller for multi-tenant SaaS administration and quota management.
 */
@RestController
@RequestMapping("/api/v1/admin/tenants")
public class TenantAdminController {

    private static final Logger log = LoggerFactory.getLogger(TenantAdminController.class);

    private final TenantService tenantService;

    public TenantAdminController(TenantService tenantService) {
        this.tenantService = tenantService;
    }

    /**
     * GET /api/v1/admin/tenants
     * List all registered tenants with filtering and pagination.
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<TenantPageResponse> getTenants(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "tier", required = false) String tier,
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "search", required = false) String search) {

        log.debug("Get tenants request: page={}, size={}, tier={}, status={}, search={}", page, size, tier, status, search);
        TenantPageResponse response = tenantService.getTenants(page, size, tier, status, search);
        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/v1/admin/tenants/{id}
     * Get specific tenant details.
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<?> getTenant(@PathVariable("id") String id) {
        return tenantService.getTenantById(id)
            .<ResponseEntity<?>>map(ResponseEntity::ok)
            .orElseGet(() -> {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.NOT_FOUND, "Tenant with identifier '" + id + "' was not found"
                );
                problem.setTitle("Tenant Not Found");
                problem.setType(URI.create("https://aegis.dev/errors/tenant-not-found"));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
            });
    }

    /**
     * POST /api/v1/admin/tenants
     * Provision a new tenant.
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<?> createTenant(@Valid @RequestBody TenantCreateRequest request) {
        try {
            Tenant created = tenantService.createTenant(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException iae) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, iae.getMessage());
            problem.setTitle("Tenant Conflict");
            problem.setType(URI.create("https://aegis.dev/errors/tenant-conflict"));
            return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
        }
    }

    /**
     * PATCH /api/v1/admin/tenants/{id}/status
     * Activate, suspend or modify tenant lifecycle status.
     */
    @PatchMapping(value = "/{id}/status", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<?> updateTenantStatus(
            @PathVariable("id") String id,
            @Valid @RequestBody TenantStatusUpdateRequest request) {

        return tenantService.updateStatus(id, request)
            .<ResponseEntity<?>>map(ResponseEntity::ok)
            .orElseGet(() -> {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.NOT_FOUND, "Tenant with identifier '" + id + "' was not found"
                );
                problem.setTitle("Tenant Not Found");
                problem.setType(URI.create("https://aegis.dev/errors/tenant-not-found"));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
            });
    }

    /**
     * PUT /api/v1/admin/tenants/{id}/quotas
     * Update rate limits and retention policies for a tenant.
     */
    @PutMapping(value = "/{id}/quotas", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<?> updateTenantQuotas(
            @PathVariable("id") String id,
            @Valid @RequestBody TenantQuotaUpdateRequest request) {

        return tenantService.updateQuotas(id, request)
            .<ResponseEntity<?>>map(ResponseEntity::ok)
            .orElseGet(() -> {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.NOT_FOUND, "Tenant with identifier '" + id + "' was not found"
                );
                problem.setTitle("Tenant Not Found");
                problem.setType(URI.create("https://aegis.dev/errors/tenant-not-found"));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
            });
    }

    /**
     * GET /api/v1/admin/tenants/{id}/usage
     * Get live telemetry and quota utilization metrics for a tenant.
     */
    @GetMapping(value = "/{id}/usage", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<?> getTenantUsage(@PathVariable("id") String id) {
        return tenantService.getTenantUsage(id)
            .<ResponseEntity<?>>map(ResponseEntity::ok)
            .orElseGet(() -> {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.NOT_FOUND, "Tenant with identifier '" + id + "' was not found"
                );
                problem.setTitle("Tenant Not Found");
                problem.setType(URI.create("https://aegis.dev/errors/tenant-not-found"));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
            });
    }
}
