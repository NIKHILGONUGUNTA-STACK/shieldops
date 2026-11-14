package com.aegis.gateway.detection.policy;

import com.aegis.gateway.detection.campaign.CampaignEvidenceCompleteness;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

@Repository
public class PolicyRepository {

    private final JdbcClient jdbcClient;

    public PolicyRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Transactional
    public void savePolicyDecision(AdaptivePolicyDecision dec) {
        String sql = """
            INSERT INTO security_data.policy_decisions (
                id, incident_id, campaign_id, policy_id, policy_version, category,
                risk_level, recommended_action, enforcement_level, rationale,
                supporting_evidence, identity_context, tenant_id, evidence_completeness,
                evidence_snapshot, status, analyst_user, analyst_action,
                analyst_rationale, analyst_action_at, decided_at, expires_at, created_at,
                policy_rule
            ) VALUES (
                :id, :incidentId, :campaignId, :policyId, :policyVersion, :category,
                :riskLevel, :recommendedAction, :enforcementLevel, :rationale,
                :supportingEvidence, :identityContext, :tenantId, :evidenceCompleteness,
                :evidenceSnapshot, :status, :analystUser, :analystAction,
                :analystRationale, :analystActionAt, :decidedAt, :expiresAt, :createdAt,
                :policyRule
            )
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                analyst_user = EXCLUDED.analyst_user,
                analyst_action = EXCLUDED.analyst_action,
                analyst_rationale = EXCLUDED.analyst_rationale,
                analyst_action_at = EXCLUDED.analyst_action_at
            """;

        String supportingEvidenceJoined = dec.supportingEvidence() != null && !dec.supportingEvidence().isEmpty()
            ? String.join(",", dec.supportingEvidence())
            : null;

        jdbcClient.sql(sql)
            .param("id", dec.id())
            .param("incidentId", dec.incidentId())
            .param("campaignId", dec.campaignId())
            .param("policyId", dec.policyId())
            .param("policyVersion", dec.policyVersion())
            .param("category", dec.category().name())
            .param("riskLevel", dec.riskLevel())
            .param("recommendedAction", dec.recommendedAction().name())
            .param("enforcementLevel", dec.enforcementLevel())
            .param("rationale", dec.rationale())
            .param("supportingEvidence", supportingEvidenceJoined)
            .param("identityContext", dec.identityContext())
            .param("tenantId", dec.tenantId())
            .param("evidenceCompleteness", dec.evidenceCompleteness() != null ? dec.evidenceCompleteness().name() : "COMPLETE")
            .param("evidenceSnapshot", dec.evidenceSnapshot())
            .param("status", dec.status().name())
            .param("analystUser", dec.analystUser())
            .param("analystAction", dec.analystAction())
            .param("analystRationale", dec.analystRationale())
            .param("analystActionAt", dec.analystActionAt() != null ? Timestamp.from(dec.analystActionAt()) : null)
            .param("decidedAt", Timestamp.from(dec.decidedAt()))
            .param("expiresAt", dec.expiresAt() != null ? Timestamp.from(dec.expiresAt()) : null)
            .param("createdAt", Timestamp.from(dec.createdAt()))
            .param("policyRule", dec.policyId())
            .update();
    }

    public Optional<AdaptivePolicyDecision> findDecisionById(UUID id) {
        String sql = """
            SELECT id, incident_id, campaign_id, policy_id, policy_version, category,
                   risk_level, recommended_action, enforcement_level, rationale,
                   supporting_evidence, identity_context, tenant_id, evidence_completeness,
                   evidence_snapshot, status, analyst_user, analyst_action,
                   analyst_rationale, analyst_action_at, decided_at, expires_at, created_at
            FROM security_data.policy_decisions
            WHERE id = :id
            """;
        return jdbcClient.sql(sql)
            .param("id", id)
            .query(this::mapRowToAdaptiveDecision)
            .optional();
    }

    public List<AdaptivePolicyDecision> findDecisionsByIncidentId(UUID incidentId) {
        String sql = """
            SELECT id, incident_id, campaign_id, policy_id, policy_version, category,
                   risk_level, recommended_action, enforcement_level, rationale,
                   supporting_evidence, identity_context, tenant_id, evidence_completeness,
                   evidence_snapshot, status, analyst_user, analyst_action,
                   analyst_rationale, analyst_action_at, decided_at, expires_at, created_at
            FROM security_data.policy_decisions
            WHERE incident_id = :incidentId
            ORDER BY decided_at DESC
            """;
        return jdbcClient.sql(sql)
            .param("incidentId", incidentId)
            .query(this::mapRowToAdaptiveDecision)
            .list();
    }

    public List<AdaptivePolicyDecision> findDecisionsByCampaignId(UUID campaignId) {
        String sql = """
            SELECT id, incident_id, campaign_id, policy_id, policy_version, category,
                   risk_level, recommended_action, enforcement_level, rationale,
                   supporting_evidence, identity_context, tenant_id, evidence_completeness,
                   evidence_snapshot, status, analyst_user, analyst_action,
                   analyst_rationale, analyst_action_at, decided_at, expires_at, created_at
            FROM security_data.policy_decisions
            WHERE campaign_id = :campaignId
            ORDER BY decided_at DESC
            """;
        return jdbcClient.sql(sql)
            .param("campaignId", campaignId)
            .query(this::mapRowToAdaptiveDecision)
            .list();
    }

    public List<AdaptivePolicyDecision> findDecisions(
        int page, int size, PolicyStatus status, PolicyCategory category, String search
    ) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);
        int offset = boundedPage * boundedSize;

        StringBuilder sql = new StringBuilder("""
            SELECT id, incident_id, campaign_id, policy_id, policy_version, category,
                   risk_level, recommended_action, enforcement_level, rationale,
                   supporting_evidence, identity_context, tenant_id, evidence_completeness,
                   evidence_snapshot, status, analyst_user, analyst_action,
                   analyst_rationale, analyst_action_at, decided_at, expires_at, created_at
            FROM security_data.policy_decisions
            WHERE 1=1
            """);

        Map<String, Object> params = new HashMap<>();

        if (status != null) {
            sql.append(" AND status = :status");
            params.put("status", status.name());
        }
        if (category != null) {
            sql.append(" AND category = :category");
            params.put("category", category.name());
        }
        if (search != null && !search.isBlank()) {
            sql.append(" AND (identity_context ILIKE :search OR policy_id ILIKE :search OR rationale ILIKE :search)");
            params.put("search", "%" + search.trim() + "%");
        }

        sql.append(" ORDER BY decided_at DESC LIMIT :limit OFFSET :offset");
        params.put("limit", boundedSize);
        params.put("offset", offset);

        var spec = jdbcClient.sql(sql.toString());
        params.forEach(spec::param);
        return spec.query(this::mapRowToAdaptiveDecision).list();
    }

    public long countDecisions(PolicyStatus status, PolicyCategory category, String search) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM security_data.policy_decisions WHERE 1=1");
        Map<String, Object> params = new HashMap<>();

        if (status != null) {
            sql.append(" AND status = :status");
            params.put("status", status.name());
        }
        if (category != null) {
            sql.append(" AND category = :category");
            params.put("category", category.name());
        }
        if (search != null && !search.isBlank()) {
            sql.append(" AND (identity_context ILIKE :search OR policy_id ILIKE :search OR rationale ILIKE :search)");
            params.put("search", "%" + search.trim() + "%");
        }

        var spec = jdbcClient.sql(sql.toString());
        params.forEach(spec::param);
        Long count = spec.query(Long.class).single();
        return count != null ? count : 0L;
    }

    @Transactional
    public void updateDecisionStatus(
        UUID decisionId, PolicyStatus status, String analystUser, String action, String rationale
    ) {
        String sql = """
            UPDATE security_data.policy_decisions
            SET status = :status,
                analyst_user = :analystUser,
                analyst_action = :action,
                analyst_rationale = :rationale,
                analyst_action_at = :actionAt
            WHERE id = :id
            """;
        jdbcClient.sql(sql)
            .param("id", decisionId)
            .param("status", status.name())
            .param("analystUser", analystUser)
            .param("action", action)
            .param("rationale", rationale)
            .param("actionAt", Timestamp.from(Instant.now()))
            .update();
    }

    @Transactional
    public void saveDecisionAction(PolicyDecisionAction action) {
        String sql = """
            INSERT INTO security_data.policy_decision_actions (
                id, decision_id, action, analyst_user, analyst_comment, action_at
            ) VALUES (
                :id, :decisionId, :action, :analystUser, :analystComment, :actionAt
            )
            """;
        jdbcClient.sql(sql)
            .param("id", action.id())
            .param("decisionId", action.decisionId())
            .param("action", action.action())
            .param("analystUser", action.analystUser())
            .param("analystComment", action.analystComment())
            .param("actionAt", Timestamp.from(action.actionAt()))
            .update();
    }

    public List<PolicyDecisionAction> findActionsByDecisionId(UUID decisionId) {
        String sql = """
            SELECT id, decision_id, action, analyst_user, analyst_comment, action_at
            FROM security_data.policy_decision_actions
            WHERE decision_id = :decisionId
            ORDER BY action_at ASC
            """;
        return jdbcClient.sql(sql)
            .param("decisionId", decisionId)
            .query(this::mapRowToDecisionAction)
            .list();
    }

    // Policy Registry Queries
    public List<SecurityPolicy> findAllPolicies() {
        String sql = """
            SELECT id, name, version, category, recommended_action, description,
                   enabled, risk_threshold, condition_explanation, effective_from, updated_at
            FROM security_data.security_policies
            ORDER BY id ASC
            """;
        return jdbcClient.sql(sql)
            .query(this::mapRowToPolicy)
            .list();
    }

    public Optional<SecurityPolicy> findPolicyById(String id) {
        String sql = """
            SELECT id, name, version, category, recommended_action, description,
                   enabled, risk_threshold, condition_explanation, effective_from, updated_at
            FROM security_data.security_policies
            WHERE id = :id
            """;
        return jdbcClient.sql(sql)
            .param("id", id)
            .query(this::mapRowToPolicy)
            .optional();
    }

    @Transactional
    public void updatePolicy(SecurityPolicy policy) {
        String sql = """
            UPDATE security_data.security_policies
            SET name = :name,
                version = :version,
                category = :category,
                recommended_action = :recommendedAction,
                description = :description,
                enabled = :enabled,
                risk_threshold = :riskThreshold,
                condition_explanation = :conditionExplanation,
                updated_at = :updatedAt
            WHERE id = :id
            """;
        jdbcClient.sql(sql)
            .param("id", policy.id())
            .param("name", policy.name())
            .param("version", policy.version())
            .param("category", policy.category().name())
            .param("recommendedAction", policy.recommendedAction().name())
            .param("description", policy.description())
            .param("enabled", policy.enabled())
            .param("riskThreshold", policy.riskThreshold())
            .param("conditionExplanation", policy.conditionExplanation())
            .param("updatedAt", Timestamp.from(policy.updatedAt()))
            .update();
    }

    @Transactional
    public void savePolicyAuditHistory(PolicyAuditHistory history) {
        String sql = """
            INSERT INTO security_data.policy_audit_history (
                id, policy_id, previous_version, new_version, changed_by, change_type, change_reason, changed_at
            ) VALUES (
                :id, :policyId, :previousVersion, :newVersion, :changedBy, :changeType, :changeReason, :changedAt
            )
            """;
        jdbcClient.sql(sql)
            .param("id", history.id())
            .param("policyId", history.policyId())
            .param("previousVersion", history.previousVersion())
            .param("newVersion", history.newVersion())
            .param("changedBy", history.changedBy())
            .param("changeType", history.changeType())
            .param("changeReason", history.changeReason())
            .param("changedAt", Timestamp.from(history.changedAt()))
            .update();
    }

    public List<PolicyAuditHistory> findAuditHistoryByPolicyId(String policyId) {
        String sql = """
            SELECT id, policy_id, previous_version, new_version, changed_by, change_type, change_reason, changed_at
            FROM security_data.policy_audit_history
            WHERE policy_id = :policyId
            ORDER BY changed_at DESC
            """;
        return jdbcClient.sql(sql)
            .param("policyId", policyId)
            .query(this::mapRowToAuditHistory)
            .list();
    }

    // Row Mappers
    private AdaptivePolicyDecision mapRowToAdaptiveDecision(ResultSet rs, int rowNum) throws SQLException {
        String suppEv = rs.getString("supporting_evidence");
        List<String> evidenceList = suppEv != null && !suppEv.isBlank()
            ? Arrays.asList(suppEv.split(","))
            : Collections.emptyList();

        String complStr = rs.getString("evidence_completeness");
        CampaignEvidenceCompleteness completeness;
        try {
            completeness = complStr != null ? CampaignEvidenceCompleteness.valueOf(complStr) : CampaignEvidenceCompleteness.COMPLETE;
        } catch (Exception e) {
            completeness = CampaignEvidenceCompleteness.COMPLETE;
        }

        String catStr = rs.getString("category");
        PolicyCategory category;
        try {
            category = catStr != null ? PolicyCategory.valueOf(catStr) : PolicyCategory.GENERAL;
        } catch (Exception e) {
            category = PolicyCategory.GENERAL;
        }

        String actionStr = rs.getString("recommended_action");
        PolicyAction action;
        try {
            action = actionStr != null ? PolicyAction.valueOf(actionStr) : PolicyAction.INVESTIGATE_ACTIVITY;
        } catch (Exception e) {
            action = PolicyAction.INVESTIGATE_ACTIVITY;
        }

        String statusStr = rs.getString("status");
        PolicyStatus status;
        try {
            status = statusStr != null ? PolicyStatus.valueOf(statusStr) : PolicyStatus.RECOMMENDED;
        } catch (Exception e) {
            status = PolicyStatus.RECOMMENDED;
        }

        Timestamp actAt = rs.getTimestamp("analyst_action_at");
        Timestamp expAt = rs.getTimestamp("expires_at");

        return new AdaptivePolicyDecision(
            UUID.fromString(rs.getString("id")),
            rs.getString("incident_id") != null ? UUID.fromString(rs.getString("incident_id")) : null,
            rs.getString("campaign_id") != null ? UUID.fromString(rs.getString("campaign_id")) : null,
            rs.getString("policy_id") != null ? rs.getString("policy_id") : "POL-DEFAULT",
            rs.getString("policy_version") != null ? rs.getString("policy_version") : "1.0.0",
            category,
            rs.getString("risk_level") != null ? rs.getString("risk_level") : "MEDIUM",
            action,
            rs.getString("enforcement_level") != null ? rs.getString("enforcement_level") : "ADVISORY",
            rs.getString("rationale"),
            evidenceList,
            rs.getString("identity_context"),
            rs.getString("tenant_id") != null ? rs.getString("tenant_id") : "tenant-default",
            completeness,
            rs.getString("evidence_snapshot"),
            status,
            rs.getString("analyst_user"),
            rs.getString("analyst_action"),
            rs.getString("analyst_rationale"),
            actAt != null ? actAt.toInstant() : null,
            rs.getTimestamp("decided_at").toInstant(),
            expAt != null ? expAt.toInstant() : null,
            rs.getTimestamp("created_at").toInstant()
        );
    }

    private PolicyDecisionAction mapRowToDecisionAction(ResultSet rs, int rowNum) throws SQLException {
        return new PolicyDecisionAction(
            UUID.fromString(rs.getString("id")),
            UUID.fromString(rs.getString("decision_id")),
            rs.getString("action"),
            rs.getString("analyst_user"),
            rs.getString("analyst_comment"),
            rs.getTimestamp("action_at").toInstant()
        );
    }

    private SecurityPolicy mapRowToPolicy(ResultSet rs, int rowNum) throws SQLException {
        return new SecurityPolicy(
            rs.getString("id"),
            rs.getString("name"),
            rs.getString("version"),
            PolicyCategory.valueOf(rs.getString("category")),
            PolicyAction.valueOf(rs.getString("recommended_action")),
            rs.getString("description"),
            rs.getBoolean("enabled"),
            rs.getDouble("risk_threshold"),
            rs.getString("condition_explanation"),
            rs.getTimestamp("effective_from").toInstant(),
            rs.getTimestamp("updated_at").toInstant()
        );
    }

    private PolicyAuditHistory mapRowToAuditHistory(ResultSet rs, int rowNum) throws SQLException {
        return new PolicyAuditHistory(
            UUID.fromString(rs.getString("id")),
            rs.getString("policy_id"),
            rs.getString("previous_version"),
            rs.getString("new_version"),
            rs.getString("changed_by"),
            rs.getString("change_type"),
            rs.getString("change_reason"),
            rs.getTimestamp("changed_at").toInstant()
        );
    }
}
