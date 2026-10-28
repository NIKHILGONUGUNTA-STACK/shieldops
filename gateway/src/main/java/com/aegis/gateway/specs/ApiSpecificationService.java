package com.aegis.gateway.specs;

import com.aegis.gateway.specs.dto.ApiSpecificationPageResponse;
import com.aegis.gateway.specs.dto.ApiSpecificationResponse;
import com.aegis.gateway.specs.dto.DeclaredOperationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service orchestrating OpenAPI specification validation, persistence, and querying.
 */
@Service
public class ApiSpecificationService {

    private static final Logger log = LoggerFactory.getLogger(ApiSpecificationService.class);

    private final OpenApiParser parser;
    private final ApiSpecificationRepository repository;

    public ApiSpecificationService(OpenApiParser parser, ApiSpecificationRepository repository) {
        this.parser = parser;
        this.repository = repository;
    }

    /**
     * Ingests, parses, validates, and persists an OpenAPI specification document.
     */
    @Transactional
    public ApiSpecificationResponse importSpecification(byte[] content, String filename, String importedBy) {
        String cleanFilename = sanitizeFilename(filename);

        // Parse and validate structural compliance
        OpenApiSpecData specData = parser.parseAndValidate(content, cleanFilename);

        // Check if an identical specification is already imported
        Optional<ApiSpecificationResponse> existing = repository.findByContentHash(specData.contentHash());
        if (existing.isPresent()) {
            log.info("Specification with content hash {} already exists. Returning existing record.", specData.contentHash());
            UUID existingId = existing.get().id();
            List<DeclaredOperationResponse> ops = repository.findOperationsBySpecId(existingId);
            return existing.get().withOperations(ops);
        }

        UUID id = UUID.randomUUID();
        String safeActor = (importedBy != null && !importedBy.isBlank()) ? importedBy : "system-analyst";

        ApiSpecificationResponse newSpec = new ApiSpecificationResponse(
            id,
            specData.name(),
            specData.description(),
            specData.version(),
            specData.openapiVersion(),
            cleanFilename,
            specData.contentHash(),
            specData.format(),
            "ACTIVE",
            Instant.now(),
            safeActor,
            specData.operationCount(),
            specData.pathCount(),
            specData.validationSummary(),
            List.of()
        );

        String rawContentString = new String(content, StandardCharsets.UTF_8);
        repository.save(newSpec, specData.operations(), rawContentString);

        log.info("Successfully imported OpenAPI spec '{}' (v{}) with {} operations (ID: {})",
            newSpec.name(), newSpec.version(), newSpec.operationCount(), id);

        List<DeclaredOperationResponse> persistedOps = repository.findOperationsBySpecId(id);
        return newSpec.withOperations(persistedOps);
    }

    public ApiSpecificationPageResponse getSpecifications(int page, int size, String search, String status) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        return repository.findSpecifications(boundedPage, boundedSize, search, status);
    }

    public Optional<ApiSpecificationResponse> getSpecificationById(UUID id) {
        return repository.findById(id).map(spec -> {
            List<DeclaredOperationResponse> ops = repository.findOperationsBySpecId(id);
            return spec.withOperations(ops);
        });
    }

    public List<DeclaredOperationResponse> getOperationsBySpecificationId(UUID id) {
        return repository.findOperationsBySpecId(id);
    }

    @Transactional
    public boolean deleteSpecification(UUID id) {
        return repository.deleteById(id);
    }

    private String sanitizeFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            return "openapi-spec.yaml";
        }
        // Strip path traversal sequences and keep only basename
        String basename = filename.replaceAll("[/\\\\]+", "/");
        if (basename.contains("/")) {
            basename = basename.substring(basename.lastIndexOf('/') + 1);
        }
        basename = basename.replaceAll("[^a-zA-Z0-9._-]", "_");
        return basename.length() > 255 ? basename.substring(0, 255) : basename;
    }
}

