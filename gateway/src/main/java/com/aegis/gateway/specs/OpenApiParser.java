package com.aegis.gateway.specs;

import com.aegis.gateway.discovery.RouteNormalizer;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Secure, offline OpenAPI 3.0.x and 3.1.x parser and structural validator.
 * Enforces file size, structural complexity, local reference safety, and
 * prevents arbitrary outbound network requests or remote $ref resolution.
 */
@Component
public class OpenApiParser {

    private static final Logger log = LoggerFactory.getLogger(OpenApiParser.class);

    public static final long MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
    public static final int MAX_NODE_COUNT = 50_000;
    public static final int MAX_DEPTH = 30;
    public static final int MAX_OPERATIONS = 1_000;

    private static final Pattern OPENAPI_VERSION_PATTERN = Pattern.compile("^3\\.[01](\\.\\d+.*)?$");
    private static final Set<String> SUPPORTED_HTTP_METHODS = Set.of(
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"
    );

    private final ObjectMapper jsonMapper;
    private final YAMLMapper yamlMapper;

    public OpenApiParser() {
        this.jsonMapper = new ObjectMapper();
        this.jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        this.yamlMapper = new YAMLMapper();
    }

    /**
     * Parses and validates raw OpenAPI specification bytes in JSON or YAML format.
     */
    public OpenApiSpecData parseAndValidate(byte[] content, String originalFilename) {
        if (content == null || content.length == 0) {
            throw new OpenApiValidationException("Empty specification file provided");
        }

        if (content.length > MAX_FILE_SIZE_BYTES) {
            throw new OpenApiValidationException(
                "Specification file size (" + content.length + " bytes) exceeds maximum permitted limit (" + MAX_FILE_SIZE_BYTES + " bytes)"
            );
        }

        String contentHash = computeSha256(content);
        String detectedFormat = detectFormat(content, originalFilename);

        JsonNode rootNode;
        try {
            if ("JSON".equalsIgnoreCase(detectedFormat)) {
                rootNode = jsonMapper.readTree(content);
            } else {
                rootNode = yamlMapper.readTree(content);
            }
        } catch (Exception e) {
            log.warn("Failed to parse OpenAPI document syntax: {}", e.getMessage());
            throw new OpenApiValidationException("Malformed " + detectedFormat + " syntax: " + e.getMessage());
        }

        if (rootNode == null || !rootNode.isObject()) {
            throw new OpenApiValidationException("OpenAPI specification root must be a valid JSON/YAML object");
        }

        // Validate tree complexity and safety
        ComplexityTracker tracker = new ComplexityTracker();
        Set<String> visitedPointers = new HashSet<>();
        validateNodeSafety(rootNode, 0, tracker, visitedPointers);

        // Validate OpenAPI version
        JsonNode openapiNode = rootNode.get("openapi");
        if (openapiNode == null || !openapiNode.isTextual() || openapiNode.asText().isBlank()) {
            JsonNode swaggerNode = rootNode.get("swagger");
            if (swaggerNode != null) {
                throw new OpenApiValidationException(
                    "Unsupported Swagger 2.0 specification. Only OpenAPI 3.0.x and 3.1.x specifications are supported."
                );
            }
            throw new OpenApiValidationException(
                "Missing required 'openapi' version attribute. Expected OpenAPI 3.0.x or 3.1.x."
            );
        }

        String openapiVersion = openapiNode.asText().trim();
        if (!OPENAPI_VERSION_PATTERN.matcher(openapiVersion).matches()) {
            throw new OpenApiValidationException(
                "Unsupported OpenAPI version: '" + openapiVersion + "'. Supported versions: 3.0.x and 3.1.x."
            );
        }

        // Validate Info object
        JsonNode infoNode = rootNode.get("info");
        if (infoNode == null || !infoNode.isObject()) {
            throw new OpenApiValidationException("Missing required 'info' object in specification");
        }

        JsonNode titleNode = infoNode.get("title");
        if (titleNode == null || !titleNode.isTextual() || titleNode.asText().isBlank()) {
            throw new OpenApiValidationException("Missing or blank required 'info.title' in specification");
        }
        String title = titleNode.asText().trim();

        JsonNode versionNode = infoNode.get("version");
        if (versionNode == null || !versionNode.isTextual() || versionNode.asText().isBlank()) {
            throw new OpenApiValidationException("Missing or blank required 'info.version' in specification");
        }
        String version = versionNode.asText().trim();

        String description = infoNode.has("description") ? infoNode.get("description").asText("") : "";

        // Validate Paths object
        JsonNode pathsNode = rootNode.get("paths");
        if (pathsNode == null || !pathsNode.isObject()) {
            throw new OpenApiValidationException("Missing required 'paths' object in specification");
        }

        List<DeclaredOperationData> operations = new ArrayList<>();
        int pathCount = 0;

        Iterator<Map.Entry<String, JsonNode>> pathFields = pathsNode.fields();
        while (pathFields.hasNext()) {
            Map.Entry<String, JsonNode> pathEntry = pathFields.next();
            String pathKey = pathEntry.getKey();
            JsonNode pathItem = pathEntry.getValue();

            if (!pathKey.startsWith("/")) {
                throw new OpenApiValidationException("Invalid path key: '" + pathKey + "'. Path must start with a forward slash ('/').");
            }

            pathCount++;
            if (!pathItem.isObject()) {
                continue;
            }

            Iterator<Map.Entry<String, JsonNode>> opFields = pathItem.fields();
            while (opFields.hasNext()) {
                Map.Entry<String, JsonNode> opEntry = opFields.next();
                String methodCandidate = opEntry.getKey().toUpperCase().trim();

                if (!SUPPORTED_HTTP_METHODS.contains(methodCandidate)) {
                    continue; // Skip non-operation keys like parameters, summary, description, $ref
                }

                JsonNode opNode = opEntry.getValue();
                if (!opNode.isObject()) {
                    continue;
                }

                String operationId = opNode.has("operationId") && opNode.get("operationId").isTextual()
                    ? opNode.get("operationId").asText().trim() : null;

                String summary = opNode.has("summary") && opNode.get("summary").isTextual()
                    ? opNode.get("summary").asText().trim() : null;
                if (summary != null && summary.length() > 512) {
                    summary = summary.substring(0, 512);
                }

                String opDesc = opNode.has("description") && opNode.get("description").isTextual()
                    ? opNode.get("description").asText().trim() : null;

                String tags = null;
                if (opNode.has("tags") && opNode.get("tags").isArray()) {
                    List<String> tagList = new ArrayList<>();
                    opNode.get("tags").forEach(t -> {
                        if (t.isTextual() && !t.asText().isBlank()) {
                            tagList.add(t.asText().trim());
                        }
                    });
                    if (!tagList.isEmpty()) {
                        tags = String.join(", ", tagList);
                        if (tags.length() > 256) tags = tags.substring(0, 256);
                    }
                }

                boolean deprecated = opNode.has("deprecated") && opNode.get("deprecated").asBoolean(false);

                String normalizedRoute = RouteNormalizer.normalize(pathKey);
                String serviceBoundary = RouteNormalizer.resolveService(normalizedRoute);

                operations.add(new DeclaredOperationData(
                    methodCandidate,
                    pathKey,
                    normalizedRoute,
                    operationId,
                    summary,
                    opDesc,
                    tags,
                    deprecated,
                    serviceBoundary
                ));

                if (operations.size() > MAX_OPERATIONS) {
                    throw new OpenApiValidationException(
                        "Specification exceeds maximum permitted operations limit (" + MAX_OPERATIONS + ")"
                    );
                }
            }
        }

        String validationSummary = String.format(
            "Validated OpenAPI %s document with %d declared operations across %d paths.",
            openapiVersion, operations.size(), pathCount
        );

        return new OpenApiSpecData(
            title,
            description,
            version,
            openapiVersion,
            detectedFormat,
            contentHash,
            operations.size(),
            pathCount,
            validationSummary,
            operations
        );
    }

    private void validateNodeSafety(JsonNode node, int depth, ComplexityTracker tracker, Set<String> visitedPointers) {
        if (node == null) return;

        tracker.nodeCount++;
        if (tracker.nodeCount > MAX_NODE_COUNT) {
            throw new OpenApiValidationException(
                "Specification exceeds structural node count limit (" + MAX_NODE_COUNT + " nodes)"
            );
        }

        if (depth > MAX_DEPTH) {
            throw new OpenApiValidationException(
                "Specification exceeds maximum nesting depth limit (" + MAX_DEPTH + " levels)"
            );
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if ("$ref".equals(key) && value.isTextual()) {
                    validateRefString(value.asText(), visitedPointers);
                }

                validateNodeSafety(value, depth + 1, tracker, visitedPointers);
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                validateNodeSafety(child, depth + 1, tracker, visitedPointers);
            }
        }
    }

    private void validateRefString(String ref, Set<String> visitedPointers) {
        if (ref == null || ref.isBlank()) {
            return;
        }

        String trimmed = ref.trim();
        String lower = trimmed.toLowerCase();

        // Reject remote protocols
        if (lower.startsWith("http://") || lower.startsWith("https://")
                || lower.startsWith("ftp://") || lower.startsWith("file://")
                || lower.startsWith("//")) {
            throw new OpenApiValidationException(
                "Unsafe external $ref reference detected: '" + trimmed + "'. Remote outbound requests are strictly prohibited."
            );
        }

        // Reject external file paths or parent directory traversals
        if (trimmed.contains("../") || trimmed.contains("..\\")
                || (!trimmed.startsWith("#") && (lower.endsWith(".json") || lower.endsWith(".yaml") || lower.endsWith(".yml")))) {
            throw new OpenApiValidationException(
                "Unsafe external file reference detected: '" + trimmed + "'. Only local document references (#/...) are allowed."
            );
        }

        // Local reference cycle check
        if (trimmed.startsWith("#")) {
            if (visitedPointers.contains(trimmed)) {
                // If it is an immediate self-reference or direct cycle
                if (visitedPointers.size() > 50) {
                    throw new OpenApiValidationException(
                        "Potential circular reference loop detected at: '" + trimmed + "'"
                    );
                }
            }
            visitedPointers.add(trimmed);
        }
    }

    private String detectFormat(byte[] content, String filename) {
        if (filename != null) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".json")) return "JSON";
            if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "YAML";
        }

        // Inspect first non-whitespace character
        for (byte b : content) {
            if (!Character.isWhitespace(b)) {
                if (b == '{' || b == '[') {
                    return "JSON";
                }
                break;
            }
        }
        return "YAML";
    }

    private String computeSha256(byte[] content) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(content);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm must be available", e);
        }
    }

    private static class ComplexityTracker {
        int nodeCount = 0;
    }
}

