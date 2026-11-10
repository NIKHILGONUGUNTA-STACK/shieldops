package com.aegis.gateway.classification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Optional;

/**
 * REST controller exposing deterministic sensitive data classification inventory,
 * endpoint dossiers, and platform-level coverage summaries.
 * Role-based access: Requires ROLE_SECURITY_ANALYST or ROLE_SECURITY_ADMIN.
 */
@RestController
@RequestMapping("/api/v1/security/classification")
public class SensitiveDataClassificationController {

    private static final Logger log = LoggerFactory.getLogger(SensitiveDataClassificationController.class);

    private final SensitiveDataClassificationEngine classificationEngine;

    public SensitiveDataClassificationController(SensitiveDataClassificationEngine classificationEngine) {
        this.classificationEngine = classificationEngine;
    }

    /**
     * GET /api/v1/security/classification/inventory
     * Paginated endpoint classification records with filtering by service, sensitivity, review flag, and search.
     */
    @GetMapping(value = "/inventory", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<SensitiveDataInventoryPageResponse> getInventory(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "service", required = false) String service,
            @RequestParam(name = "sensitivity", required = false) String sensitivity,
            @RequestParam(name = "manualReviewRequired", required = false) Boolean manualReviewRequired,
            @RequestParam(name = "search", required = false) String search,
            @RequestParam(name = "sortBy", defaultValue = "routeTemplate") String sortBy,
            @RequestParam(name = "sortDirection", defaultValue = "asc") String sortDirection) {

        log.debug("Classification inventory request: page={}, size={}, service={}, sensitivity={}, manualReview={}",
            page, size, service, sensitivity, manualReviewRequired);

        SensitiveDataInventoryPageResponse response = classificationEngine.getInventory(
            page, size, service, sensitivity, manualReviewRequired, search, sortBy, sortDirection
        );

        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/v1/security/classification/summary
     * Top-level summary metrics of sensitive data classification and service coverage.
     */
    @GetMapping(value = "/summary", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<SensitiveDataInventorySummary> getSummary() {
        log.debug("Classification summary metrics requested");
        SensitiveDataInventorySummary summary = classificationEngine.getSummary();
        return ResponseEntity.ok(summary);
    }

    /**
     * GET /api/v1/security/classification/endpoints/{id}
     * Detailed field-level breakdown and metadata for a specific endpoint.
     */
    @GetMapping(value = "/endpoints/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getEndpointDetails(@PathVariable("id") String id) {
        log.debug("Endpoint classification details requested for id={}", id);

        Optional<EndpointDataClassification> details = classificationEngine.getEndpointDetails(id);
        if (details.isEmpty()) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.NOT_FOUND, "Endpoint classification record not found with ID: " + id
            );
            problem.setTitle("Endpoint Classification Not Found");
            problem.setType(URI.create("https://aegis.dev/errors/classification-not-found"));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
        }

        return ResponseEntity.ok(details.get());
    }
}

