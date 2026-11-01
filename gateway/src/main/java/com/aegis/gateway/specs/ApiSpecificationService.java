package com.aegis.gateway.specs;

import com.aegis.gateway.security.ResourceNotFoundException;
import com.aegis.gateway.specs.dto.ApiSpecificationPageResponse;
import com.aegis.gateway.specs.dto.ApiSpecificationResponse;
import com.aegis.gateway.specs.dto.DeclaredOperationResponse;
import com.aegis.gateway.specs.dto.OperationChange;
import com.aegis.gateway.specs.dto.SpecificationDiffResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * Service orchestrating OpenAPI specification validation, persistence, revisioning, and structural diffing.
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
     * Computes the next sequential revision number for specs sharing the same title/name.
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
        int nextRevision = repository.findNextRevisionNumberByName(specData.name());

        ApiSpecificationResponse newSpec = new ApiSpecificationResponse(
            id,
            specData.name(),
            specData.description(),
            specData.version(),
            nextRevision,
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

        log.info("Successfully imported OpenAPI spec '{}' (v{}, rev {}) with {} operations (ID: {})",
            newSpec.name(), newSpec.version(), newSpec.revisionNumber(), newSpec.operationCount(), id);

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

    /**
     * Lists all historical revisions for a specification family identified by specId.
     */
    public List<ApiSpecificationResponse> getSpecificationRevisions(UUID specId) {
        ApiSpecificationResponse spec = repository.findById(specId)
            .orElseThrow(() -> new ResourceNotFoundException("Specification not found with ID: " + specId));
        return repository.findRevisionsByName(spec.name());
    }

    /**
     * Performs a deterministic structural diff between two specification revisions.
     */
    public SpecificationDiffResponse compareSpecifications(UUID baseId, UUID targetId) {
        ApiSpecificationResponse baseSpec = repository.findById(baseId)
            .orElseThrow(() -> new ResourceNotFoundException("Base specification not found with ID: " + baseId));
        ApiSpecificationResponse targetSpec = repository.findById(targetId)
            .orElseThrow(() -> new ResourceNotFoundException("Target specification not found with ID: " + targetId));

        List<DeclaredOperationResponse> baseOps = repository.findOperationsBySpecId(baseId);
        List<DeclaredOperationResponse> targetOps = repository.findOperationsBySpecId(targetId);

        Map<String, DeclaredOperationResponse> baseMap = new LinkedHashMap<>();
        for (var op : baseOps) {
            String key = op.httpMethod().toUpperCase() + ":" + op.normalizedRoute();
            baseMap.put(key, op);
        }

        Map<String, DeclaredOperationResponse> targetMap = new LinkedHashMap<>();
        for (var op : targetOps) {
            String key = op.httpMethod().toUpperCase() + ":" + op.normalizedRoute();
            targetMap.put(key, op);
        }

        List<OperationChange> changes = new ArrayList<>();
        int addedCount = 0;
        int removedCount = 0;
        int modifiedCount = 0;
        int unchangedCount = 0;

        // 1. Identify added and modified/unchanged operations from target perspective
        for (var entry : targetMap.entrySet()) {
            String key = entry.getKey();
            DeclaredOperationResponse targetOp = entry.getValue();

            if (!baseMap.containsKey(key)) {
                addedCount++;
                changes.add(new OperationChange(
                    "ADDED",
                    targetOp.httpMethod(),
                    targetOp.pathPattern(),
                    targetOp.normalizedRoute(),
                    targetOp.operationId(),
                    targetOp.summary(),
                    targetOp.description(),
                    targetOp.tags(),
                    targetOp.deprecated(),
                    List.of("Operation newly declared in target revision")
                ));
            } else {
                DeclaredOperationResponse baseOp = baseMap.get(key);
                List<String> diffs = computeOperationDiffs(baseOp, targetOp);
                if (diffs.isEmpty()) {
                    unchangedCount++;
                    changes.add(new OperationChange(
                        "UNCHANGED",
                        targetOp.httpMethod(),
                        targetOp.pathPattern(),
                        targetOp.normalizedRoute(),
                        targetOp.operationId(),
                        targetOp.summary(),
                        targetOp.description(),
                        targetOp.tags(),
                        targetOp.deprecated(),
                        List.of()
                    ));
                } else {
                    modifiedCount++;
                    changes.add(new OperationChange(
                        "MODIFIED",
                        targetOp.httpMethod(),
                        targetOp.pathPattern(),
                        targetOp.normalizedRoute(),
                        targetOp.operationId(),
                        targetOp.summary(),
                        targetOp.description(),
                        targetOp.tags(),
                        targetOp.deprecated(),
                        diffs
                    ));
                }
            }
        }

        // 2. Identify removed operations (present in base, absent in target)
        for (var entry : baseMap.entrySet()) {
            String key = entry.getKey();
            if (!targetMap.containsKey(key)) {
                removedCount++;
                DeclaredOperationResponse baseOp = entry.getValue();
                changes.add(new OperationChange(
                    "REMOVED",
                    baseOp.httpMethod(),
                    baseOp.pathPattern(),
                    baseOp.normalizedRoute(),
                    baseOp.operationId(),
                    baseOp.summary(),
                    baseOp.description(),
                    baseOp.tags(),
                    baseOp.deprecated(),
                    List.of("Operation removed from specification in target revision")
                ));
            }
        }

        // Sort changes: ADDED -> MODIFIED -> REMOVED -> UNCHANGED
        changes.sort(Comparator.comparingInt(c -> switch (c.changeType()) {
            case "ADDED" -> 1;
            case "MODIFIED" -> 2;
            case "REMOVED" -> 3;
            case "UNCHANGED" -> 4;
            default -> 5;
        }));

        return new SpecificationDiffResponse(
            baseSpec,
            targetSpec,
            addedCount,
            removedCount,
            modifiedCount,
            unchangedCount,
            changes
        );
    }

    private List<String> computeOperationDiffs(DeclaredOperationResponse baseOp, DeclaredOperationResponse targetOp) {
        List<String> diffs = new ArrayList<>();

        if (!Objects.equals(baseOp.pathPattern(), targetOp.pathPattern())) {
            diffs.add(String.format("Path pattern changed: '%s' -> '%s'", baseOp.pathPattern(), targetOp.pathPattern()));
        }
        if (!Objects.equals(baseOp.operationId(), targetOp.operationId())) {
            diffs.add(String.format("Operation ID changed: '%s' -> '%s'",
                baseOp.operationId() != null ? baseOp.operationId() : "<none>",
                targetOp.operationId() != null ? targetOp.operationId() : "<none>"));
        }
        if (!Objects.equals(baseOp.summary(), targetOp.summary())) {
            diffs.add("Operation summary updated");
        }
        if (!Objects.equals(baseOp.description(), targetOp.description())) {
            diffs.add("Operation description updated");
        }
        if (!Objects.equals(baseOp.tags(), targetOp.tags())) {
            diffs.add(String.format("Tags changed: '%s' -> '%s'",
                baseOp.tags() != null ? baseOp.tags() : "<none>",
                targetOp.tags() != null ? targetOp.tags() : "<none>"));
        }
        if (baseOp.deprecated() != targetOp.deprecated()) {
            diffs.add(String.format("Deprecated status changed: %s -> %s", baseOp.deprecated(), targetOp.deprecated()));
        }

        return diffs;
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
