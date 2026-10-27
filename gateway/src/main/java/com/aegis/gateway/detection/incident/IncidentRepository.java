package com.aegis.gateway.detection.incident;

import com.aegis.gateway.detection.dto.IncidentPageResponse;
import com.aegis.gateway.detection.dto.IncidentResponse;
import com.aegis.gateway.detection.dto.IncidentSummaryResponse;
import com.aegis.gateway.detection.dto.RuleTriggerStatResponse;
import com.aegis.gateway.detection.model.DetectionEvidence;
import com.aegis.gateway.detection.model.IncidentStatus;
import com.aegis.gateway.detection.model.IncidentStatusHistory;
import com.aegis.gateway.detection.model.PolicyDecision;
import com.aegis.gateway.detection.model.SecurityIncident;
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
import java.util.stream.Collectors;

@Repository
public class IncidentRepository {
    private static final Logger log = LoggerFactory.getLogger(IncidentRepository.class);
    private final JdbcClient jdbcClient;

    public IncidentRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<SecurityIncident> findById(UUID id) {
        String sql = """
            SELECT id, incident_fingerprint, rule_id, rule_version, threat_category,
                   severity, status, target_entity_type, target_entity_value,
                   first_detected_at, last_event_at, event_count, summary,
                   created_at, updated_at
            FROM security_data.incidents
            WHERE id = :id
            """;
        return jdbcClient.sql(sql)
            .param("id", id)
            .query((rs, rowNum) -> mapRowToIncident(rs))
            .optional();
    }

    public Optional<SecurityIncident> findActiveByFingerprint(String fingerprint) {
        String sql = """
            SELECT id, incident_fingerprint, rule_id, rule_version, threat_category,
                   severity, status, target_entity_type, target_entity_value,
                   first_detected_at, last_event_at, event_count, summary,
                   created_at, updated_at
            FROM security_data.incidents
            WHERE incident_fingerprint = :fingerprint
              AND status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')
            LIMIT 1
            """;
        return jdbcClient.sql(sql)
            .param("fingerprint", fingerprint)
            .query((rs, rowNum) -> mapRowToIncident(rs)).optional();
    }

    public Optional<SecurityIncident> findActiveByTarget(String entityType, String entityValue) {
        String sql = """
            SELECT id, incident_fingerprint, rule_id, rule_version, threat_category,
                   severity, status, target_entity_type, target_entity_value,
                   first_detected_at, last_event_at, event_count, summary,
                   created_at, updated_at
            FROM security_data.incidents
            WHERE target_entity_type = :entityType
              AND target_entity_value = :entityValue
              AND status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')
            ORDER BY created_at DESC
            LIMIT 1
            """;
        return jdbcClient.sql(sql)
            .param("entityType", entityType)
            .param("entityValue", entityValue)
            .query((rs, rowNum) -> mapRowToIncident(rs)).optional();
    }

    public IncidentPageResponse findIncidents(
            int page,
            int size,
            IncidentStatus status,
            String severity,
            String threatCategory,
            String targetEntityType,
            String targetEntityValue,
            Instant from,
            Instant to,
            String sortBy,
            String sortDirection) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        StringBuilder whereClause = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new HashMap<>();

        if (status != null) {
            whereClause.append(" AND status = :status");
            params.put("status", status.name());
        }
        if (severity != null && !severity.isBlank()) {
            whereClause.append(" AND severity = :severity");
            params.put("severity", severity.toUpperCase().trim());
        }
        if (threatCategory != null && !threatCategory.isBlank()) {
            whereClause.append(" AND threat_category = :threatCategory");
            params.put("threatCategory", threatCategory.toUpperCase().trim());
        }
        if (targetEntityType != null && !targetEntityType.isBlank()) {
            whereClause.append(" AND target_entity_type = :targetEntityType");
            params.put("targetEntityType", targetEntityType.toUpperCase().trim());
        }
        if (targetEntityValue != null && !targetEntityValue.isBlank()) {
            whereClause.append(" AND target_entity_value = :targetEntityValue");
            params.put("targetEntityValue", targetEntityValue.trim());
        }
        if (from != null) {
            whereClause.append(" AND last_event_at >= :fromTimestamp");
            params.put("fromTimestamp", Timestamp.from(from));
        }
        if (to != null) {
            whereClause.append(" AND last_event_at <= :toTimestamp");
            params.put("toTimestamp", Timestamp.from(to));
        }

        String sortColumn = switch (sortBy != null ? sortBy.toLowerCase().trim() : "") {
            case "createdat", "created_at" -> "created_at";
            case "severity" -> "severity";
            case "eventcount", "event_count" -> "event_count";
            default -> "last_event_at";
        };

        String direction = "asc".equalsIgnoreCase(sortDirection) ? "ASC" : "DESC";

        String countSql = "SELECT COUNT(*) FROM security_data.incidents" + whereClause;
        var countSpec = jdbcClient.sql(countSql);
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            countSpec = countSpec.param(entry.getKey(), entry.getValue());
        }
        Long total = countSpec.query(Long.class).single();
        long totalElements = (total != null) ? total : 0L;
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);

        String querySql = "SELECT id, incident_fingerprint, rule_id, rule_version, threat_category, " +
                          "severity, status, target_entity_type, target_entity_value, " +
                          "first_detected_at, last_event_at, event_count, summary, " +
                          "created_at, updated_at " +
                          "FROM security_data.incidents" + whereClause +
                          " ORDER BY " + sortColumn + " " + direction + ", id DESC LIMIT :limit OFFSET :offset";

        var querySpec = jdbcClient.sql(querySql);
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            querySpec = querySpec.param(entry.getKey(), entry.getValue());
        }
        querySpec = querySpec.param("limit", boundedSize).param("offset", offset);

        List<IncidentResponse> content = querySpec.query((rs, rowNum) -> {
            SecurityIncident inc = mapRowToIncident(rs);
            return IncidentResponse.from(inc);
        }).list();

        return new IncidentPageResponse(
            content,
            boundedPage,
            boundedSize,
            totalElements,
            totalPages,
            boundedPage < (totalPages - 1),
            boundedPage > 0
        );
    }

    @Transactional
    public void saveIncident(SecurityIncident inc) {
        String sql = """
            INSERT INTO security_data.incidents (
                id, incident_fingerprint, rule_id, rule_version, threat_category,
                severity, status, target_entity_type, target_entity_value,
                first_detected_at, last_event_at, event_count, summary,
                created_at, updated_at
            ) VALUES (
                :id, :fingerprint, :ruleId, :ruleVersion, :threatCategory,
                :severity, :status, :targetEntityType, :targetEntityValue,
                :firstDetectedAt, :lastEventAt, :eventCount, :summary,
                :createdAt, :updatedAt
            )
            """;
        jdbcClient.sql(sql)
            .param("id", inc.id())
            .param("fingerprint", inc.incidentFingerprint())
            .param("ruleId", inc.ruleId())
            .param("ruleVersion", inc.ruleVersion())
            .param("threatCategory", inc.threatCategory())
            .param("severity", inc.severity())
            .param("status", inc.status().name())
            .param("targetEntityType", inc.targetEntityType())
            .param("targetEntityValue", inc.targetEntityValue())
            .param("firstDetectedAt", Timestamp.from(inc.firstDetectedAt()))
            .param("lastEventAt", Timestamp.from(inc.lastEventAt()))
            .param("eventCount", inc.eventCount())
            .param("summary", inc.summary())
            .param("createdAt", Timestamp.from(inc.createdAt()))
            .param("updatedAt", Timestamp.from(inc.updatedAt()))
            .update();
    }

    @Transactional
    public void updateIncident(SecurityIncident inc) {
        String sql = """
            UPDATE security_data.incidents
            SET threat_category = :threatCategory,
                severity = :severity,
                status = :status,
                last_event_at = :lastEventAt,
                event_count = :eventCount,
                summary = :summary,
                updated_at = :updatedAt
            WHERE id = :id
            """;
        jdbcClient.sql(sql)
            .param("id", inc.id())
            .param("threatCategory", inc.threatCategory())
            .param("severity", inc.severity())
            .param("status", inc.status().name())
            .param("lastEventAt", Timestamp.from(inc.lastEventAt()))
            .param("eventCount", inc.eventCount())
            .param("summary", inc.summary())
            .param("updatedAt", Timestamp.from(inc.updatedAt()))
            .update();
    }

    @Transactional
    public void updateIncidentStatus(UUID id, IncidentStatus status, Instant updatedAt) {
        String sql = """
            UPDATE security_data.incidents
            SET status = :status,
                updated_at = :updatedAt
            WHERE id = :id
            """;
        jdbcClient.sql(sql)
            .param("id", id)
            .param("status", status.name())
            .param("updatedAt", Timestamp.from(updatedAt))
            .update();
    }

    @Transactional
    public void saveEvidence(DetectionEvidence ev) {
        String eventIdsStr = ev.contributingEventIds() != null
            ? ev.contributingEventIds().stream().map(UUID::toString).collect(Collectors.joining(","))
            : "";

        String sql = """
            INSERT INTO security_data.detection_evidence (
                id, incident_id, rule_id, rule_version, evaluated_at,
                confidence_score, severity, trigger_condition, observed_count,
                window_seconds, distinct_resources, evidence_details,
                contributing_event_ids, created_at
            ) VALUES (
                :id, :incidentId, :ruleId, :ruleVersion, :evaluatedAt,
                :confidenceScore, :severity, :triggerCondition, :observedCount,
                :windowSeconds, :distinctResources, :evidenceDetails,
                :contributingEventIds, :createdAt
            )
            """;
        jdbcClient.sql(sql)
            .param("id", ev.id())
            .param("incidentId", ev.incidentId())
            .param("ruleId", ev.ruleId())
            .param("ruleVersion", ev.ruleVersion())
            .param("evaluatedAt", Timestamp.from(ev.evaluatedAt()))
            .param("confidenceScore", ev.confidenceScore())
            .param("severity", ev.severity())
            .param("triggerCondition", ev.triggerCondition())
            .param("observedCount", ev.observedCount())
            .param("windowSeconds", ev.windowSeconds())
            .param("distinctResources", ev.distinctResources())
            .param("evidenceDetails", ev.evidenceDetails())
            .param("contributingEventIds", eventIdsStr)
            .param("createdAt", Timestamp.from(ev.createdAt()))
            .update();
    }

    @Transactional
    public void saveStatusHistory(IncidentStatusHistory hist) {
        String sql = """
            INSERT INTO security_data.incident_status_history (
                id, incident_id, previous_status, new_status, changed_by,
                changed_at, reason
            ) VALUES (
                :id, :incidentId, :previousStatus, :newStatus, :changedBy,
                :changedAt, :reason
            )
            """;
        jdbcClient.sql(sql)
            .param("id", hist.id())
            .param("incidentId", hist.incidentId())
            .param("previousStatus", hist.previousStatus())
            .param("newStatus", hist.newStatus())
            .param("changedBy", hist.changedBy())
            .param("changedAt", Timestamp.from(hist.changedAt()))
            .param("reason", hist.reason())
            .update();
    }

    public List<IncidentStatusHistory> findStatusHistoryByIncidentId(UUID incidentId) {
        String sql = """
            SELECT id, incident_id, previous_status, new_status, changed_by, changed_at, reason
            FROM security_data.incident_status_history
            WHERE incident_id = :incidentId
            ORDER BY changed_at ASC, id ASC
            """;
        return jdbcClient.sql(sql)
            .param("incidentId", incidentId)
            .query((rs, rowNum) -> new IncidentStatusHistory(
                (UUID) rs.getObject("id"),
                (UUID) rs.getObject("incident_id"),
                rs.getString("previous_status"),
                rs.getString("new_status"),
                rs.getString("changed_by"),
                rs.getTimestamp("changed_at").toInstant(),
                rs.getString("reason")
            )).list();
    }

    @Transactional
    public void savePolicyDecision(PolicyDecision dec) {
        String sql = """
            INSERT INTO security_data.policy_decisions (
                id, incident_id, policy_rule, recommended_action,
                enforcement_level, decided_at, expires_at, rationale, created_at
            ) VALUES (
                :id, :incidentId, :policyRule, :recommendedAction,
                :enforcementLevel, :decidedAt, :expiresAt, :rationale, :createdAt
            )
            """;
        jdbcClient.sql(sql)
            .param("id", dec.id())
            .param("incidentId", dec.incidentId())
            .param("policyRule", dec.policyRule())
            .param("recommendedAction", dec.recommendedAction())
            .param("enforcementLevel", dec.enforcementLevel())
            .param("decidedAt", Timestamp.from(dec.decidedAt()))
            .param("expiresAt", dec.expiresAt() != null ? Timestamp.from(dec.expiresAt()) : null)
            .param("rationale", dec.rationale())
            .param("createdAt", Timestamp.from(dec.createdAt()))
            .update();
    }

    public List<PolicyDecision> findPolicyDecisionsByIncidentId(UUID incidentId) {
        String sql = """
            SELECT id, incident_id, policy_rule, recommended_action,
                   enforcement_level, decided_at, expires_at, rationale, created_at
            FROM security_data.policy_decisions
            WHERE incident_id = :incidentId
            ORDER BY created_at DESC, id DESC
            """;
        return jdbcClient.sql(sql)
            .param("incidentId", incidentId)
            .query((rs, rowNum) -> mapRowToPolicyDecision(rs)).list();
    }

    public List<PolicyDecision> findRecentPolicyDecisions(int page, int size) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        String sql = """
            SELECT id, incident_id, policy_rule, recommended_action,
                   enforcement_level, decided_at, expires_at, rationale, created_at
            FROM security_data.policy_decisions
            ORDER BY created_at DESC, id DESC
            LIMIT :limit OFFSET :offset
            """;
        return jdbcClient.sql(sql)
            .param("limit", boundedSize)
            .param("offset", offset)
            .query((rs, rowNum) -> mapRowToPolicyDecision(rs)).list();
    }

    public long countIncidents() {
        return jdbcClient.sql("SELECT COUNT(*) FROM security_data.incidents")
            .query(Long.class).single();
    }

    public long countOpenIncidents() {
        String sql = "SELECT COUNT(*) FROM security_data.incidents WHERE status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')";
        return jdbcClient.sql(sql).query(Long.class).single();
    }

    public Map<String, Long> countIncidentsBySeverity(Instant cutoff) {
        String sql = """
            SELECT severity, COUNT(*) AS cnt
            FROM security_data.incidents
            WHERE created_at >= :cutoff OR status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')
            GROUP BY severity
            """;
        Map<String, Long> result = new LinkedHashMap<>();
        result.put("CRITICAL", 0L);
        result.put("HIGH", 0L);
        result.put("MEDIUM", 0L);
        result.put("LOW", 0L);

        jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .query((rs, rowNum) -> {
                String sev = rs.getString("severity");
                long cnt = rs.getLong("cnt");
                if (sev != null) {
                    result.put(sev.toUpperCase(), cnt);
                }
                return null;
            }).list();
        return result;
    }

    public Map<String, Long> countIncidentsByCategory(Instant cutoff) {
        String sql = """
            SELECT threat_category, COUNT(*) AS cnt
            FROM security_data.incidents
            WHERE created_at >= :cutoff OR status IN ('OPEN', 'INVESTIGATING', 'CONTAINED')
            GROUP BY threat_category
            """;
        Map<String, Long> result = new LinkedHashMap<>();
        jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .query((rs, rowNum) -> {
                String cat = rs.getString("threat_category");
                long cnt = rs.getLong("cnt");
                if (cat != null) {
                    result.put(cat, cnt);
                }
                return null;
            }).list();
        return result;
    }

    public List<IncidentSummaryResponse> findRecentIncidents(int limit) {
        String sql = """
            SELECT id, threat_category, severity, status, target_entity_value, summary, last_event_at
            FROM security_data.incidents
            ORDER BY last_event_at DESC, id DESC
            LIMIT :limit
            """;
        return jdbcClient.sql(sql)
            .param("limit", Math.max(1, limit))
            .query((rs, rowNum) -> new IncidentSummaryResponse(
                (UUID) rs.getObject("id"),
                rs.getString("threat_category"),
                rs.getString("severity"),
                rs.getString("status"),
                rs.getString("target_entity_value"),
                rs.getString("summary"),
                rs.getTimestamp("last_event_at").toInstant()
            )).list();
    }

    public List<RuleTriggerStatResponse> findTopTriggeredRules(Instant cutoff, int limit) {
        String sql = """
            SELECT rule_id, COUNT(*) AS trigger_count
            FROM security_data.detection_evidence
            WHERE created_at >= :cutoff
            GROUP BY rule_id
            ORDER BY trigger_count DESC, rule_id ASC
            LIMIT :limit
            """;
        return jdbcClient.sql(sql)
            .param("cutoff", Timestamp.from(cutoff))
            .param("limit", Math.max(1, limit))
            .query((rs, rowNum) -> new RuleTriggerStatResponse(
                rs.getString("rule_id"),
                rs.getLong("trigger_count")
            )).list();
    }

    public long countEvidence() {
        return jdbcClient.sql("SELECT COUNT(*) FROM security_data.detection_evidence")
            .query(Long.class).single();
    }

    public List<SecurityIncident> findAllIncidents() {
        return jdbcClient.sql("SELECT * FROM security_data.incidents ORDER BY created_at DESC")
            .query((rs, rowNum) -> mapRowToIncident(rs)).list();
    }

    public List<DetectionEvidence> findEvidenceByIncidentId(UUID incidentId) {
        String sql = """
            SELECT id, incident_id, rule_id, rule_version, evaluated_at,
                   confidence_score, severity, trigger_condition, observed_count,
                   window_seconds, distinct_resources, evidence_details,
                   contributing_event_ids, created_at
            FROM security_data.detection_evidence
            WHERE incident_id = :incidentId
            ORDER BY evaluated_at ASC
            """;
        return jdbcClient.sql(sql)
            .param("incidentId", incidentId)
            .query((rs, rowNum) -> mapRowToEvidence(rs)).list();
    }

    private SecurityIncident mapRowToIncident(ResultSet rs) throws SQLException {
        return new SecurityIncident(
            (UUID) rs.getObject("id"),
            rs.getString("incident_fingerprint"),
            rs.getString("rule_id"),
            rs.getString("rule_version"),
            rs.getString("threat_category"),
            rs.getString("severity"),
            IncidentStatus.fromString(rs.getString("status")),
            rs.getString("target_entity_type"),
            rs.getString("target_entity_value"),
            rs.getTimestamp("first_detected_at").toInstant(),
            rs.getTimestamp("last_event_at").toInstant(),
            rs.getInt("event_count"),
            rs.getString("summary"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant()
        );
    }

    private DetectionEvidence mapRowToEvidence(ResultSet rs) throws SQLException {
        String eventIdsRaw = rs.getString("contributing_event_ids");
        List<UUID> eventIds = new ArrayList<>();
        if (eventIdsRaw != null && !eventIdsRaw.isBlank()) {
            for (String s : eventIdsRaw.split(",")) {
                String trimmed = s.trim();
                if (!trimmed.isEmpty()) {
                    try {
                        eventIds.add(UUID.fromString(trimmed));
                    } catch (IllegalArgumentException ignored) {}
                }
            }
        }

        return new DetectionEvidence(
            (UUID) rs.getObject("id"),
            (UUID) rs.getObject("incident_id"),
            rs.getString("rule_id"),
            rs.getString("rule_version"),
            rs.getTimestamp("evaluated_at").toInstant(),
            rs.getDouble("confidence_score"),
            rs.getString("severity"),
            rs.getString("trigger_condition"),
            rs.getInt("observed_count"),
            rs.getInt("window_seconds"),
            rs.getInt("distinct_resources"),
            rs.getString("evidence_details"),
            eventIds,
            rs.getTimestamp("created_at").toInstant()
        );
    }

    private PolicyDecision mapRowToPolicyDecision(ResultSet rs) throws SQLException {
        Timestamp expiresTs = rs.getTimestamp("expires_at");
        return new PolicyDecision(
            (UUID) rs.getObject("id"),
            (UUID) rs.getObject("incident_id"),
            rs.getString("policy_rule"),
            rs.getString("recommended_action"),
            rs.getString("enforcement_level"),
            rs.getTimestamp("decided_at").toInstant(),
            expiresTs != null ? expiresTs.toInstant() : null,
            rs.getString("rationale"),
            rs.getTimestamp("created_at").toInstant()
        );
    }
}
