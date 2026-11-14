package com.aegis.gateway.detection.campaign;

import com.aegis.gateway.detection.campaign.dto.CampaignPageResponse;
import com.aegis.gateway.detection.campaign.dto.CampaignResponse;
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
public class CampaignRepository {
    private static final Logger log = LoggerFactory.getLogger(CampaignRepository.class);
    private final JdbcClient jdbcClient;

    public CampaignRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<ExfiltrationCampaign> findById(UUID id) {
        String sql = """
            SELECT id, campaign_id, correlation_identity, tenant_id, client_ip,
                   current_stage, stages_observed, status, severity, risk_score,
                   risk_category, risk_rationale, evidence_completeness, missing_evidence_details,
                   resource_count, endpoint_count, sensitive_domain_count,
                   first_observed_at, last_observed_at, event_count,
                   related_event_ids, related_incident_ids, related_rule_ids,
                   created_at, updated_at
            FROM security_data.exfiltration_campaigns
            WHERE id = :id
            """;
        return jdbcClient.sql(sql)
            .param("id", id)
            .query((rs, rowNum) -> mapRowToCampaign(rs))
            .optional();
    }

    public Optional<ExfiltrationCampaign> findByCampaignId(String campaignId) {
        String sql = """
            SELECT id, campaign_id, correlation_identity, tenant_id, client_ip,
                   current_stage, stages_observed, status, severity, risk_score,
                   risk_category, risk_rationale, evidence_completeness, missing_evidence_details,
                   resource_count, endpoint_count, sensitive_domain_count,
                   first_observed_at, last_observed_at, event_count,
                   related_event_ids, related_incident_ids, related_rule_ids,
                   created_at, updated_at
            FROM security_data.exfiltration_campaigns
            WHERE campaign_id = :campaignId
            """;
        return jdbcClient.sql(sql)
            .param("campaignId", campaignId)
            .query((rs, rowNum) -> mapRowToCampaign(rs))
            .optional();
    }

    public Optional<ExfiltrationCampaign> findActiveByIdentity(String correlationIdentity, String tenantId) {
        String sql = """
            SELECT id, campaign_id, correlation_identity, tenant_id, client_ip,
                   current_stage, stages_observed, status, severity, risk_score,
                   risk_category, risk_rationale, evidence_completeness, missing_evidence_details,
                   resource_count, endpoint_count, sensitive_domain_count,
                   first_observed_at, last_observed_at, event_count,
                   related_event_ids, related_incident_ids, related_rule_ids,
                   created_at, updated_at
            FROM security_data.exfiltration_campaigns
            WHERE correlation_identity = :identity
              AND tenant_id = :tenantId
              AND status IN ('OPEN', 'INVESTIGATING', 'ESCALATED')
            ORDER BY last_observed_at DESC
            LIMIT 1
            """;
        return jdbcClient.sql(sql)
            .param("identity", correlationIdentity)
            .param("tenantId", tenantId != null ? tenantId : "DEFAULT_TENANT")
            .query((rs, rowNum) -> mapRowToCampaign(rs))
            .optional();
    }

    @Transactional
    public void saveCampaign(ExfiltrationCampaign c) {
        String sql = """
            INSERT INTO security_data.exfiltration_campaigns (
                id, campaign_id, correlation_identity, tenant_id, client_ip,
                current_stage, stages_observed, status, severity, risk_score,
                risk_category, risk_rationale, evidence_completeness, missing_evidence_details,
                resource_count, endpoint_count, sensitive_domain_count,
                first_observed_at, last_observed_at, event_count,
                related_event_ids, related_incident_ids, related_rule_ids,
                created_at, updated_at
            ) VALUES (
                :id, :campaignId, :correlationIdentity, :tenantId, :clientIp,
                :currentStage, :stagesObserved, :status, :severity, :riskScore,
                :riskCategory, :riskRationale, :evidenceCompleteness, :missingEvidenceDetails,
                :resourceCount, :endpointCount, :sensitiveDomainCount,
                :firstObservedAt, :lastObservedAt, :eventCount,
                :relatedEventIds, :relatedIncidentIds, :relatedRuleIds,
                :createdAt, :updatedAt
            )
            """;

        jdbcClient.sql(sql)
            .param("id", c.id())
            .param("campaignId", c.campaignId())
            .param("correlationIdentity", c.correlationIdentity())
            .param("tenantId", c.tenantId())
            .param("clientIp", c.clientIp())
            .param("currentStage", c.currentStage().name())
            .param("stagesObserved", serializeStages(c.stagesObserved()))
            .param("status", c.status().name())
            .param("severity", c.severity())
            .param("riskScore", c.riskScore())
            .param("riskCategory", c.riskCategory())
            .param("riskRationale", c.riskRationale())
            .param("evidenceCompleteness", c.evidenceCompleteness().name())
            .param("missingEvidenceDetails", c.missingEvidenceDetails())
            .param("resourceCount", c.resourceCount())
            .param("endpointCount", c.endpointCount())
            .param("sensitiveDomainCount", c.sensitiveDomainCount())
            .param("firstObservedAt", Timestamp.from(c.firstObservedAt()))
            .param("lastObservedAt", Timestamp.from(c.lastObservedAt()))
            .param("eventCount", c.eventCount())
            .param("relatedEventIds", serializeUuids(c.relatedEventIds()))
            .param("relatedIncidentIds", serializeUuids(c.relatedIncidentIds()))
            .param("relatedRuleIds", String.join(",", c.relatedRuleIds()))
            .param("createdAt", Timestamp.from(c.createdAt()))
            .param("updatedAt", Timestamp.from(c.updatedAt()))
            .update();
    }

    @Transactional
    public void updateCampaign(ExfiltrationCampaign c) {
        String sql = """
            UPDATE security_data.exfiltration_campaigns
            SET current_stage = :currentStage,
                stages_observed = :stagesObserved,
                status = :status,
                severity = :severity,
                risk_score = :riskScore,
                risk_category = :riskCategory,
                risk_rationale = :riskRationale,
                evidence_completeness = :evidenceCompleteness,
                missing_evidence_details = :missingEvidenceDetails,
                resource_count = :resourceCount,
                endpoint_count = :endpointCount,
                sensitive_domain_count = :sensitiveDomainCount,
                last_observed_at = :lastObservedAt,
                event_count = :eventCount,
                related_event_ids = :relatedEventIds,
                related_incident_ids = :relatedIncidentIds,
                related_rule_ids = :relatedRuleIds,
                updated_at = :updatedAt
            WHERE id = :id
            """;

        jdbcClient.sql(sql)
            .param("id", c.id())
            .param("currentStage", c.currentStage().name())
            .param("stagesObserved", serializeStages(c.stagesObserved()))
            .param("status", c.status().name())
            .param("severity", c.severity())
            .param("riskScore", c.riskScore())
            .param("riskCategory", c.riskCategory())
            .param("riskRationale", c.riskRationale())
            .param("evidenceCompleteness", c.evidenceCompleteness().name())
            .param("missingEvidenceDetails", c.missingEvidenceDetails())
            .param("resourceCount", c.resourceCount())
            .param("endpointCount", c.endpointCount())
            .param("sensitiveDomainCount", c.sensitiveDomainCount())
            .param("lastObservedAt", Timestamp.from(c.lastObservedAt()))
            .param("eventCount", c.eventCount())
            .param("relatedEventIds", serializeUuids(c.relatedEventIds()))
            .param("relatedIncidentIds", serializeUuids(c.relatedIncidentIds()))
            .param("relatedRuleIds", String.join(",", c.relatedRuleIds()))
            .param("updatedAt", Timestamp.from(c.updatedAt()))
            .update();
    }

    public CampaignPageResponse findCampaigns(
            int page,
            int size,
            CampaignStatus status,
            String severity,
            CampaignStage stage,
            String search) {

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        StringBuilder whereClause = new StringBuilder(" WHERE 1=1 ");
        Map<String, Object> params = new HashMap<>();

        if (status != null) {
            whereClause.append(" AND status = :status ");
            params.put("status", status.name());
        }
        if (severity != null && !severity.isBlank()) {
            whereClause.append(" AND severity = :severity ");
            params.put("severity", severity.toUpperCase().trim());
        }
        if (stage != null) {
            whereClause.append(" AND current_stage = :stage ");
            params.put("stage", stage.name());
        }
        if (search != null && !search.isBlank()) {
            whereClause.append(" AND (LOWER(campaign_id) LIKE :search OR LOWER(correlation_identity) LIKE :search OR LOWER(risk_rationale) LIKE :search) ");
            params.put("search", "%" + search.toLowerCase().trim() + "%");
        }

        String countSql = "SELECT COUNT(*) FROM security_data.exfiltration_campaigns " + whereClause;
        var countQuery = jdbcClient.sql(countSql);
        params.forEach(countQuery::param);
        long totalElements = countQuery.query(Long.class).single();

        String dataSql = """
            SELECT id, campaign_id, correlation_identity, tenant_id, client_ip,
                   current_stage, stages_observed, status, severity, risk_score,
                   risk_category, risk_rationale, evidence_completeness, missing_evidence_details,
                   resource_count, endpoint_count, sensitive_domain_count,
                   first_observed_at, last_observed_at, event_count,
                   related_event_ids, related_incident_ids, related_rule_ids,
                   created_at, updated_at
            FROM security_data.exfiltration_campaigns
            """ + whereClause + " ORDER BY last_observed_at DESC LIMIT :limit OFFSET :offset ";

        var dataQuery = jdbcClient.sql(dataSql);
        params.forEach(dataQuery::param);
        dataQuery.param("limit", boundedSize);
        dataQuery.param("offset", offset);

        List<CampaignResponse> campaigns = dataQuery
            .query((rs, rowNum) -> CampaignResponse.fromEntity(mapRowToCampaign(rs)))
            .list();

        return CampaignPageResponse.of(campaigns, boundedPage, boundedSize, totalElements);
    }

    @Transactional
    public void saveTimelineEvent(CampaignTimelineEvent event) {
        String sql = """
            INSERT INTO security_data.campaign_events (
                id, campaign_id, stage, event_id, rule_id,
                timestamp, http_method, request_path, status_code,
                description, created_at
            ) VALUES (
                :id, :campaignId, :stage, :eventId, :ruleId,
                :timestamp, :httpMethod, :requestPath, :statusCode,
                :description, :createdAt
            )
            """;
        jdbcClient.sql(sql)
            .param("id", event.id())
            .param("campaignId", event.campaignId())
            .param("stage", event.stage().name())
            .param("eventId", event.eventId())
            .param("ruleId", event.ruleId())
            .param("timestamp", Timestamp.from(event.timestamp()))
            .param("httpMethod", event.httpMethod())
            .param("requestPath", event.requestPath())
            .param("statusCode", event.statusCode())
            .param("description", event.description())
            .param("createdAt", Timestamp.from(event.createdAt()))
            .update();
    }

    public List<CampaignTimelineEvent> findTimelineByCampaignId(UUID campaignId) {
        String sql = """
            SELECT id, campaign_id, stage, event_id, rule_id,
                   timestamp, http_method, request_path, status_code,
                   description, created_at
            FROM security_data.campaign_events
            WHERE campaign_id = :campaignId
            ORDER BY timestamp ASC
            """;
        return jdbcClient.sql(sql)
            .param("campaignId", campaignId)
            .query((rs, rowNum) -> new CampaignTimelineEvent(
                UUID.fromString(rs.getString("id")),
                UUID.fromString(rs.getString("campaign_id")),
                CampaignStage.valueOf(rs.getString("stage")),
                UUID.fromString(rs.getString("event_id")),
                rs.getString("rule_id"),
                rs.getTimestamp("timestamp").toInstant(),
                rs.getString("http_method"),
                rs.getString("request_path"),
                rs.getInt("status_code"),
                rs.getString("description"),
                rs.getTimestamp("created_at").toInstant()
            ))
            .list();
    }

    @Transactional
    public void saveStatusHistory(CampaignStatusHistory history) {
        String sql = """
            INSERT INTO security_data.campaign_status_history (
                id, campaign_id, previous_status, new_status, changed_by, changed_at, reason
            ) VALUES (
                :id, :campaignId, :previousStatus, :newStatus, :changedBy, :changedAt, :reason
            )
            """;
        jdbcClient.sql(sql)
            .param("id", history.id())
            .param("campaignId", history.campaignId())
            .param("previousStatus", history.previousStatus().name())
            .param("newStatus", history.newStatus().name())
            .param("changedBy", history.changedBy())
            .param("changedAt", Timestamp.from(history.changedAt()))
            .param("reason", history.reason())
            .update();
    }

    public List<CampaignStatusHistory> findStatusHistoryByCampaignId(UUID campaignId) {
        String sql = """
            SELECT id, campaign_id, previous_status, new_status, changed_by, changed_at, reason
            FROM security_data.campaign_status_history
            WHERE campaign_id = :campaignId
            ORDER BY changed_at DESC
            """;
        return jdbcClient.sql(sql)
            .param("campaignId", campaignId)
            .query((rs, rowNum) -> new CampaignStatusHistory(
                UUID.fromString(rs.getString("id")),
                UUID.fromString(rs.getString("campaign_id")),
                CampaignStatus.valueOf(rs.getString("previous_status")),
                CampaignStatus.valueOf(rs.getString("new_status")),
                rs.getString("changed_by"),
                rs.getTimestamp("changed_at").toInstant(),
                rs.getString("reason")
            ))
            .list();
    }

    private ExfiltrationCampaign mapRowToCampaign(ResultSet rs) throws SQLException {
        return new ExfiltrationCampaign(
            UUID.fromString(rs.getString("id")),
            rs.getString("campaign_id"),
            rs.getString("correlation_identity"),
            rs.getString("tenant_id"),
            rs.getString("client_ip"),
            CampaignStage.valueOf(rs.getString("current_stage")),
            deserializeStages(rs.getString("stages_observed")),
            CampaignStatus.valueOf(rs.getString("status")),
            rs.getString("severity"),
            rs.getDouble("risk_score"),
            rs.getString("risk_category"),
            rs.getString("risk_rationale"),
            CampaignEvidenceCompleteness.valueOf(rs.getString("evidence_completeness")),
            rs.getString("missing_evidence_details"),
            rs.getInt("resource_count"),
            rs.getInt("endpoint_count"),
            rs.getInt("sensitive_domain_count"),
            rs.getTimestamp("first_observed_at").toInstant(),
            rs.getTimestamp("last_observed_at").toInstant(),
            rs.getInt("event_count"),
            deserializeUuids(rs.getString("related_event_ids")),
            deserializeUuids(rs.getString("related_incident_ids")),
            deserializeStrings(rs.getString("related_rule_ids")),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant()
        );
    }

    private String serializeStages(List<CampaignStage> stages) {
        if (stages == null || stages.isEmpty()) return "";
        return stages.stream().map(Enum::name).collect(Collectors.joining(","));
    }

    private List<CampaignStage> deserializeStages(String s) {
        if (s == null || s.isBlank()) return List.of();
        return Arrays.stream(s.split(","))
            .filter(str -> !str.isBlank())
            .map(String::trim)
            .map(CampaignStage::valueOf)
            .toList();
    }

    private String serializeUuids(List<UUID> uuids) {
        if (uuids == null || uuids.isEmpty()) return "";
        return uuids.stream().map(UUID::toString).collect(Collectors.joining(","));
    }

    private List<UUID> deserializeUuids(String s) {
        if (s == null || s.isBlank()) return List.of();
        return Arrays.stream(s.split(","))
            .filter(str -> !str.isBlank())
            .map(String::trim)
            .map(UUID::fromString)
            .toList();
    }

    private List<String> deserializeStrings(String s) {
        if (s == null || s.isBlank()) return List.of();
        return Arrays.stream(s.split(","))
            .filter(str -> !str.isBlank())
            .map(String::trim)
            .toList();
    }
}

