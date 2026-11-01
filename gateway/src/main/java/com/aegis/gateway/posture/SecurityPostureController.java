package com.aegis.gateway.posture;

import com.aegis.gateway.posture.dto.*;
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
 * REST controller exposing evidence-driven API Security Posture assessments.
 * Role-based access: Requires ROLE_SECURITY_ANALYST or ROLE_SECURITY_ADMIN.
 */
@RestController
@RequestMapping("/api/v1/security/posture")
public class SecurityPostureController {

    private static final Logger log = LoggerFactory.getLogger(SecurityPostureController.class);

    private final ApiPostureService postureService;

    public SecurityPostureController(ApiPostureService postureService) {
        this.postureService = postureService;
    }

    /**
     * GET /api/v1/security/posture
     * Paginated security posture assessments across discovered endpoints with dimensional filtering.
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getPosturePage(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "service", required = false) String service,
            @RequestParam(name = "posture", required = false) String posture,
            @RequestParam(name = "dimension", required = false) String dimension,
            @RequestParam(name = "dimensionStatus", required = false) String dimensionStatus,
            @RequestParam(name = "search", required = false) String search,
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours) {

        log.debug("Posture page request: page={}, size={}, service={}, posture={}, windowHours={}",
            page, size, service, posture, windowHours);

        if (windowHours < 1 || windowHours > 720) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "windowHours must be between 1 and 720: " + windowHours
            );
            problem.setTitle("Invalid Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        if (posture != null && !posture.isBlank()) {
            try {
                OverallPosture.valueOf(posture.toUpperCase().trim());
            } catch (IllegalArgumentException iae) {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.BAD_REQUEST, "Invalid posture category filter: " + posture
                );
                problem.setTitle("Invalid Parameter");
                problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
            }
        }

        if (dimension != null && !dimension.isBlank()) {
            try {
                AssessmentDimensionType.valueOf(dimension.toUpperCase().trim());
            } catch (IllegalArgumentException iae) {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.BAD_REQUEST, "Invalid dimension filter: " + dimension
                );
                problem.setTitle("Invalid Parameter");
                problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
            }
        }

        if (dimensionStatus != null && !dimensionStatus.isBlank()) {
            try {
                DimensionStatus.valueOf(dimensionStatus.toUpperCase().trim());
            } catch (IllegalArgumentException iae) {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.BAD_REQUEST, "Invalid dimensionStatus filter: " + dimensionStatus
                );
                problem.setTitle("Invalid Parameter");
                problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
            }
        }

        try {
            PosturePageResponse response = postureService.getPosturePage(
                page, size, service, posture, dimension, dimensionStatus, search, windowHours
            );
            return ResponseEntity.ok(response);
        } catch (DataAccessException dae) {
            log.error("Database error retrieving security posture page: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Security posture telemetry store is currently unavailable"
            );
            problem.setTitle("Telemetry Store Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    /**
     * GET /api/v1/security/posture/summary
     * High-level aggregated posture summary metrics.
     */
    @GetMapping(value = "/summary", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getPostureSummary(
            @RequestParam(name = "service", required = false) String service,
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours) {

        if (windowHours < 1 || windowHours > 720) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "windowHours must be between 1 and 720: " + windowHours
            );
            problem.setTitle("Invalid Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            PostureSummaryResponse summary = postureService.getPostureSummary(service, windowHours);
            return ResponseEntity.ok(summary);
        } catch (DataAccessException dae) {
            log.error("Database error retrieving security posture summary: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Security posture telemetry store is currently unavailable"
            );
            problem.setTitle("Telemetry Store Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    /**
     * GET /api/v1/security/posture/{id}
     * Detailed posture assessment for an individual endpoint.
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getEndpointPosture(
            @PathVariable("id") String id,
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours) {

        if (windowHours < 1 || windowHours > 720) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "windowHours must be between 1 and 720: " + windowHours
            );
            problem.setTitle("Invalid Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            return postureService.getEndpointPosture(id, windowHours)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> {
                    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                        HttpStatus.NOT_FOUND, "Discovered endpoint not found for posture assessment: " + id
                    );
                    problem.setTitle("Endpoint Not Found");
                    problem.setType(URI.create("https://aegis.dev/errors/not-found"));
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
                });
        } catch (DataAccessException dae) {
            log.error("Database error retrieving endpoint posture for {}: {}", id, dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Security posture telemetry store is currently unavailable"
            );
            problem.setTitle("Telemetry Store Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }
}

