package com.aegis.gateway.discovery;

import com.aegis.gateway.discovery.dto.DiscoveredEndpointPageResponse;
import com.aegis.gateway.discovery.dto.DiscoveredEndpointResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

/**
 * Controller exposing read-only API inventory and discovery endpoints derived from actual gateway telemetry.
 */
@RestController
public class SecurityDiscoveryController {

    private static final Logger log = LoggerFactory.getLogger(SecurityDiscoveryController.class);
    private final ApiDiscoveryService discoveryService;

    public SecurityDiscoveryController(ApiDiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
    }

    /**
     * GET /api/v1/security/discovery/endpoints
     * Discovers observed API endpoints aggregated from gateway telemetry.
     */
    @GetMapping(
        value = {"/api/v1/security/discovery/endpoints", "/security/discovery/endpoints"},
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getDiscoveredEndpoints(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "method", required = false) String method,
            @RequestParam(name = "service", required = false) String service,
            @RequestParam(name = "search", required = false) String search,
            @RequestParam(name = "sortBy", defaultValue = "lastObserved") String sortBy,
            @RequestParam(name = "sortDirection", defaultValue = "DESC") String sortDirection) {

        if (page < 0) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST,
                "Page index must not be negative: " + page
            );
            problem.setTitle("Invalid Pagination Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        if (size < 1 || size > 100) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST,
                "Page size must be between 1 and 100: " + size
            );
            problem.setTitle("Invalid Pagination Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            DiscoveredEndpointPageResponse response = discoveryService.getDiscoveredEndpoints(
                page, size, method, service, search, sortBy, sortDirection
            );
            return ResponseEntity.ok(response);
        } catch (DataAccessException dae) {
            log.error("Database error aggregating API inventory: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                "API discovery telemetry store is currently unavailable"
            );
            problem.setTitle("Telemetry Store Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    /**
     * GET /api/v1/security/discovery/endpoints/{id}
     * Retrieves single observed API endpoint record.
     */
    @GetMapping(
        value = {"/api/v1/security/discovery/endpoints/{id}", "/security/discovery/endpoints/{id}"},
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getDiscoveredEndpointById(@PathVariable("id") String id) {
        try {
            return discoveryService.getEndpointById(id)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> {
                    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                        HttpStatus.NOT_FOUND,
                        "Discovered endpoint not found with identifier: " + id
                    );
                    problem.setTitle("Endpoint Not Found");
                    problem.setType(URI.create("https://aegis.dev/errors/not-found"));
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
                });
        } catch (DataAccessException dae) {
            log.error("Database error retrieving API endpoint {}: {}", id, dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                "API discovery telemetry store is currently unavailable"
            );
            problem.setTitle("Telemetry Store Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }
}
