package com.aegis.gateway.specs;

import com.aegis.gateway.specs.dto.ApiSpecificationPageResponse;
import com.aegis.gateway.specs.dto.ApiSpecificationResponse;
import com.aegis.gateway.specs.dto.DeclaredOperationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

/**
 * Data access repository for OpenAPI specifications and their declared operations.
 * Interacts with security_data.api_specifications and security_data.api_spec_operations.
 */
@Repository
public class ApiSpecificationRepository {

    private static final Logger log = LoggerFactory.getLogger(ApiSpecificationRepository.class);
    private final JdbcClient jdbcClient;

    public ApiSpecificationRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public boolean existsByContentHash(String contentHash) {
        Long count = jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_specifications WHERE content_hash = :hash")
            .param("hash", contentHash)
            .query(Long.class)
            .single();
        return count != null && count > 0;
    }

    public Optional<ApiSpecificationResponse> findByContentHash(String contentHash) {
        String sql = """
            SELECT id, name, description, version, openapi_version, source_filename,
                   content_hash, format, status, imported_at, imported_by,
                   operation_count, path_count, validation_summary
            FROM security_data.api_specifications
            WHERE content_hash = :hash
            LIMIT 1
            """;

        return jdbcClient.sql(sql)
            .param("hash", contentHash)
            .query((rs, rowNum) -> mapRowToSpecResponse(rs))
            .optional();
    }

    @Transactional
    public void save(ApiSpecificationResponse spec, List<DeclaredOperationData> operations, String rawContent) {
        String insertSpecSql = """
            INSERT INTO security_data.api_specifications (
                id, name, description, version, openapi_version, source_filename,
                content_hash, format, status, imported_at, imported_by,
                operation_count, path_count, validation_summary, raw_content
            ) VALUES (
                :id, :name, :description, :version, :openapiVersion, :sourceFilename,
                :contentHash, :format, :status, :importedAt, :importedBy,
                :operationCount, :pathCount, :validationSummary, :rawContent
            )
            """;

        jdbcClient.sql(insertSpecSql)
            .param("id", spec.id())
            .param("name", spec.name())
            .param("description", spec.description())
            .param("version", spec.version())
            .param("openapiVersion", spec.openapiVersion())
            .param("sourceFilename", spec.sourceFilename())
            .param("contentHash", spec.contentHash())
            .param("format", spec.format())
            .param("status", spec.status())
            .param("importedAt", Timestamp.from(spec.importedAt()))
            .param("importedBy", spec.importedBy())
            .param("operationCount", spec.operationCount())
            .param("pathCount", spec.pathCount())
            .param("validationSummary", spec.validationSummary())
            .param("rawContent", rawContent)
            .update();

        String insertOpSql = """
            INSERT INTO security_data.api_spec_operations (
                id, specification_id, http_method, path_pattern, normalized_route,
                operation_id, summary, description, tags, deprecated, service_boundary
            ) VALUES (
                :id, :specId, :method, :path, :normalizedRoute,
                :opId, :summary, :desc, :tags, :deprecated, :service
            )
            """;

        for (DeclaredOperationData op : operations) {
            jdbcClient.sql(insertOpSql)
                .param("id", UUID.randomUUID())
                .param("specId", spec.id())
                .param("method", op.httpMethod())
                .param("path", op.pathPattern())
                .param("normalizedRoute", op.normalizedRoute())
                .param("opId", op.operationId())
                .param("summary", op.summary())
                .param("desc", op.description())
                .param("tags", op.tags())
                .param("deprecated", op.deprecated())
                .param("service", op.serviceBoundary())
                .update();
        }
    }

    public Optional<ApiSpecificationResponse> findById(UUID id) {
        String sql = """
            SELECT id, name, description, version, openapi_version, source_filename,
                   content_hash, format, status, imported_at, imported_by,
                   operation_count, path_count, validation_summary
            FROM security_data.api_specifications
            WHERE id = :id
            """;

        return jdbcClient.sql(sql)
            .param("id", id)
            .query((rs, rowNum) -> mapRowToSpecResponse(rs))
            .optional();
    }

    public List<DeclaredOperationResponse> findOperationsBySpecId(UUID specId) {
        String sql = """
            SELECT id, specification_id, http_method, path_pattern, normalized_route,
                   operation_id, summary, description, tags, deprecated, service_boundary
            FROM security_data.api_spec_operations
            WHERE specification_id = :specId
            ORDER BY path_pattern ASC, http_method ASC
            """;

        return jdbcClient.sql(sql)
            .param("specId", specId)
            .query((rs, rowNum) -> new DeclaredOperationResponse(
                (UUID) rs.getObject("id"),
                (UUID) rs.getObject("specification_id"),
                rs.getString("http_method"),
                rs.getString("path_pattern"),
                rs.getString("normalized_route"),
                rs.getString("operation_id"),
                rs.getString("summary"),
                rs.getString("description"),
                rs.getString("tags"),
                rs.getBoolean("deprecated"),
                rs.getString("service_boundary")
            ))
            .list();
    }

    public ApiSpecificationPageResponse findSpecifications(int page, int size, String search, String status) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        StringBuilder whereClause = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new HashMap<>();

        if (status != null && !status.isBlank()) {
            whereClause.append(" AND status = :status");
            params.put("status", status.toUpperCase().trim());
        }

        if (search != null && !search.isBlank()) {
            whereClause.append(" AND (LOWER(name) LIKE :search OR LOWER(source_filename) LIKE :search OR LOWER(version) LIKE :search)");
            params.put("search", "%" + search.toLowerCase().trim() + "%");
        }

        String countSql = "SELECT COUNT(*) FROM security_data.api_specifications" + whereClause;
        var countSpec = jdbcClient.sql(countSql);
        for (var entry : params.entrySet()) {
            countSpec = countSpec.param(entry.getKey(), entry.getValue());
        }
        Long total = countSpec.query(Long.class).single();
        long totalElements = total != null ? total : 0L;
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);

        String querySql = """
            SELECT id, name, description, version, openapi_version, source_filename,
                   content_hash, format, status, imported_at, imported_by,
                   operation_count, path_count, validation_summary
            FROM security_data.api_specifications
            """ + whereClause + " ORDER BY imported_at DESC LIMIT :limit OFFSET :offset";

        var querySpec = jdbcClient.sql(querySql);
        for (var entry : params.entrySet()) {
            querySpec = querySpec.param(entry.getKey(), entry.getValue());
        }
        querySpec = querySpec.param("limit", boundedSize).param("offset", offset);

        List<ApiSpecificationResponse> content = querySpec.query((rs, rowNum) -> mapRowToSpecResponse(rs)).list();

        Long totalSpecs = jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_specifications").query(Long.class).single();
        Long totalOps = jdbcClient.sql("SELECT COUNT(*) FROM security_data.api_spec_operations").query(Long.class).single();

        return new ApiSpecificationPageResponse(
            content,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            boundedPage < (totalPages - 1),
            boundedPage > 0,
            totalSpecs != null ? totalSpecs : 0L,
            totalOps != null ? totalOps : 0L
        );
    }

    @Transactional
    public boolean deleteById(UUID id) {
        int updated = jdbcClient.sql("DELETE FROM security_data.api_specifications WHERE id = :id")
            .param("id", id)
            .update();
        return updated > 0;
    }

    private ApiSpecificationResponse mapRowToSpecResponse(ResultSet rs) throws SQLException {
        Object idObj = rs.getObject("id");
        UUID id = (idObj instanceof UUID u) ? u : UUID.fromString(idObj.toString());
        Timestamp ts = rs.getTimestamp("imported_at");
        Instant importedAt = ts != null ? ts.toInstant() : Instant.EPOCH;

        return new ApiSpecificationResponse(
            id,
            rs.getString("name"),
            rs.getString("description"),
            rs.getString("version"),
            rs.getString("openapi_version"),
            rs.getString("source_filename"),
            rs.getString("content_hash"),
            rs.getString("format"),
            rs.getString("status"),
            importedAt,
            rs.getString("imported_by"),
            rs.getInt("operation_count"),
            rs.getInt("path_count"),
            rs.getString("validation_summary"),
            Collections.emptyList()
        );
    }
}

