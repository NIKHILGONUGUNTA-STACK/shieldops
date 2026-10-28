package com.aegis.gateway.specs;

import com.aegis.gateway.specs.dto.ApiSpecificationPageResponse;
import com.aegis.gateway.specs.dto.ApiSpecificationResponse;
import com.aegis.gateway.specs.dto.DeclaredOperationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Controller exposing authenticated, secure OpenAPI specification management APIs.
 */
@RestController
public class SecuritySpecificationController {

    private static final Logger log = LoggerFactory.getLogger(SecuritySpecificationController.class);

    private static final Set<String> ACCEPTED_MEDIA_TYPES = Set.of(
        "application/json",
        "application/yaml",
        "application/x-yaml",
        "text/yaml",
        "text/x-yaml",
        "text/plain",
        "application/octet-stream"
    );

    private final ApiSpecificationService specificationService;

    public SecuritySpecificationController(ApiSpecificationService specificationService) {
        this.specificationService = specificationService;
    }

    /**
     * POST /api/v1/security/specs/upload
     * Uploads and validates an OpenAPI 3.0.x or 3.1.x specification file.
     * Requires SECURITY_ADMIN role.
     */
    @PostMapping(
        value = {"/api/v1/security/specs/upload", "/security/specs/upload", "/api/v1/security/specs", "/security/specs"},
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<?> uploadSpecification(
            @RequestParam("file") MultipartFile file,
            Authentication authentication) {

        if (file == null || file.isEmpty()) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Specification file must not be empty"
            );
            problem.setTitle("Empty File");
            problem.setType(URI.create("https://aegis.dev/errors/empty-file"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        if (file.getSize() > OpenApiParser.MAX_FILE_SIZE_BYTES) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.PAYLOAD_TOO_LARGE,
                "Uploaded file size (" + file.getSize() + " bytes) exceeds maximum limit of " + OpenApiParser.MAX_FILE_SIZE_BYTES + " bytes"
            );
            problem.setTitle("Payload Too Large");
            problem.setType(URI.create("https://aegis.dev/errors/payload-too-large"));
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(problem);
        }

        String originalFilename = file.getOriginalFilename();
        String contentType = file.getContentType();

        boolean validExtension = false;
        if (originalFilename != null) {
            String lower = originalFilename.toLowerCase();
            validExtension = lower.endsWith(".json") || lower.endsWith(".yaml") || lower.endsWith(".yml");
        }

        boolean validContentType = contentType != null && ACCEPTED_MEDIA_TYPES.contains(contentType.toLowerCase().split(";")[0].trim());

        if (!validExtension && !validContentType) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                "Unsupported file type. Expected OpenAPI document in JSON (.json) or YAML (.yaml, .yml) format"
            );
            problem.setTitle("Unsupported Media Type");
            problem.setType(URI.create("https://aegis.dev/errors/unsupported-media-type"));
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(problem);
        }

        try {
            byte[] bytes = file.getBytes();
            String importedBy = authentication != null ? authentication.getName() : "security-admin";
            ApiSpecificationResponse created = specificationService.importSpecification(bytes, originalFilename, importedBy);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (OpenApiValidationException ove) {
            throw ove; // Handled by SecurityApiExceptionHandler -> 400 ProblemDetail
        } catch (DataAccessException dae) {
            log.error("Database error persisting specification: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Specification persistence store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        } catch (Exception ex) {
            log.error("Failed to read specification file: {}", ex.getMessage(), ex);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Failed to read uploaded file: " + ex.getMessage()
            );
            problem.setTitle("Read Error");
            problem.setType(URI.create("https://aegis.dev/errors/bad-request"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }
    }

    /**
     * GET /api/v1/security/specs
     * Lists imported OpenAPI specifications with pagination, search, and filtering.
     */
    @GetMapping(
        value = {"/api/v1/security/specs", "/security/specs"},
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getSpecifications(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "search", required = false) String search,
            @RequestParam(name = "status", required = false) String status) {

        if (page < 0) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Page index must not be negative: " + page
            );
            problem.setTitle("Invalid Pagination Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        if (size < 1 || size > 100) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Page size must be between 1 and 100: " + size
            );
            problem.setTitle("Invalid Pagination Parameter");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            ApiSpecificationPageResponse response = specificationService.getSpecifications(page, size, search, status);
            return ResponseEntity.ok(response);
        } catch (DataAccessException dae) {
            log.error("Database error retrieving specifications: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Specification store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    /**
     * GET /api/v1/security/specs/{id}
     * Retrieves single OpenAPI specification metadata and its declared operations.
     */
    @GetMapping(
        value = {"/api/v1/security/specs/{id}", "/security/specs/{id}"},
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getSpecificationById(@PathVariable("id") String idStr) {
        UUID id = parseUuidOrNull(idStr);
        if (id == null) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Invalid UUID format: " + idStr
            );
            problem.setTitle("Invalid Identifier");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            return specificationService.getSpecificationById(id)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> {
                    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                        HttpStatus.NOT_FOUND, "Specification not found with ID: " + id
                    );
                    problem.setTitle("Not Found");
                    problem.setType(URI.create("https://aegis.dev/errors/not-found"));
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
                });
        } catch (DataAccessException dae) {
            log.error("Database error retrieving specification {}: {}", id, dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Specification store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    /**
     * GET /api/v1/security/specs/{id}/operations
     * Retrieves declared operations of a specific OpenAPI specification.
     */
    @GetMapping(
        value = {"/api/v1/security/specs/{id}/operations", "/security/specs/{id}/operations"},
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getSpecificationOperations(@PathVariable("id") String idStr) {
        UUID id = parseUuidOrNull(idStr);
        if (id == null) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Invalid UUID format: " + idStr
            );
            problem.setTitle("Invalid Identifier");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            List<DeclaredOperationResponse> ops = specificationService.getOperationsBySpecificationId(id);
            return ResponseEntity.ok(ops);
        } catch (DataAccessException dae) {
            log.error("Database error retrieving operations for spec {}: {}", id, dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Specification store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    /**
     * DELETE /api/v1/security/specs/{id}
     * Deletes an imported OpenAPI specification and its cascaded declared operations.
     * Requires SECURITY_ADMIN role.
     */
    @DeleteMapping(
        value = {"/api/v1/security/specs/{id}", "/security/specs/{id}"},
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<?> deleteSpecification(@PathVariable("id") String idStr) {
        UUID id = parseUuidOrNull(idStr);
        if (id == null) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Invalid UUID format: " + idStr
            );
            problem.setTitle("Invalid Identifier");
            problem.setType(URI.create("https://aegis.dev/errors/invalid-parameter"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
        }

        try {
            boolean deleted = specificationService.deleteSpecification(id);
            if (!deleted) {
                ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                    HttpStatus.NOT_FOUND, "Specification not found with ID: " + id
                );
                problem.setTitle("Not Found");
                problem.setType(URI.create("https://aegis.dev/errors/not-found"));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
            }
            return ResponseEntity.noContent().build();
        } catch (DataAccessException dae) {
            log.error("Database error deleting specification {}: {}", id, dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE, "Specification store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    private UUID parseUuidOrNull(String str) {
        if (str == null || str.isBlank()) return null;
        try {
            return UUID.fromString(str.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

