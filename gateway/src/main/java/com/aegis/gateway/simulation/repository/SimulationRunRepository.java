package com.aegis.gateway.simulation.repository;

import com.aegis.gateway.simulation.model.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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

@Repository
public class SimulationRunRepository {

    private static final Logger log = LoggerFactory.getLogger(SimulationRunRepository.class);

    private final JdbcClient jdbcClient;
    private final ObjectMapper objectMapper;

    public SimulationRunRepository(JdbcClient jdbcClient, ObjectMapper objectMapper) {
        this.jdbcClient = jdbcClient;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void saveRun(SimulationRunResponse run) {
        if (run == null || run.runId() == null) {
            return;
        }

        String provenanceJson = serializeJson(run.provenanceMetadata());
        Instant now = Instant.now();
        Instant heartbeat = run.lastHeartbeatAt() != null ? run.lastHeartbeatAt() : now;

        SimulationRunConfig cfg = run.config();
        int durationSec = cfg != null && cfg.durationSeconds() != null ? cfg.durationSeconds() : 60;
        double reqRate = cfg != null && cfg.requestRate() != null ? cfg.requestRate() : 10.0;
        int concurrency = cfg != null && cfg.concurrency() != null ? cfg.concurrency() : 1;
        String trafficMix = cfg != null && cfg.trafficMix() != null ? cfg.trafficMix() : "SEQUENTIAL";
        boolean dryRun = cfg != null && Boolean.TRUE.equals(cfg.dryRun());
        Long seed = cfg != null ? cfg.deterministicSeed() : null;

        Integer count = jdbcClient.sql("SELECT COUNT(*) FROM security_data.simulation_runs WHERE run_id = :runId")
            .param("runId", run.runId())
            .query(Integer.class)
            .single();

        if (count != null && count > 0) {
            String updateSql = """
                UPDATE security_data.simulation_runs
                SET status = :status,
                    end_time = :endTime,
                    updated_at = :updatedAt,
                    last_heartbeat_at = :lastHeartbeatAt,
                    total_requests = :totalRequests,
                    requests_2xx = :requests2xx,
                    requests_4xx = :requests4xx,
                    requests_5xx = :requests5xx,
                    all_passed = :allPassed,
                    provenance_json = :provenanceJson,
                    failure_reason = :failureReason,
                    stop_reason = :stopReason,
                    version = version + 1
                WHERE run_id = :runId
                """;

            jdbcClient.sql(updateSql)
                .param("runId", run.runId())
                .param("status", run.status() != null ? run.status().name() : "PENDING")
                .param("endTime", run.endTime() != null ? Timestamp.from(run.endTime()) : null)
                .param("updatedAt", Timestamp.from(now))
                .param("lastHeartbeatAt", Timestamp.from(heartbeat))
                .param("totalRequests", run.totalRequests())
                .param("requests2xx", run.requests2xx())
                .param("requests4xx", run.requests4xx())
                .param("requests5xx", run.requests5xx())
                .param("allPassed", run.allAssertionsPassed())
                .param("provenanceJson", provenanceJson)
                .param("failureReason", run.failureReason())
                .param("stopReason", run.stopReason())
                .update();
        } else {
            String insertSql = """
                INSERT INTO security_data.simulation_runs (
                    run_id, campaign_id, template_id, status, requested_by,
                    start_time, end_time, created_at, updated_at, last_heartbeat_at,
                    duration_seconds, request_rate, concurrency, traffic_mix, dry_run,
                    deterministic_seed, total_requests, requests_2xx, requests_4xx, requests_5xx,
                    all_passed, provenance_json, failure_reason, stop_reason, version
                ) VALUES (
                    :runId, :campaignId, :templateId, :status, :requestedBy,
                    :startTime, :endTime, :createdAt, :updatedAt, :lastHeartbeatAt,
                    :durationSeconds, :requestRate, :concurrency, :trafficMix, :dryRun,
                    :deterministicSeed, :totalRequests, :requests2xx, :requests4xx, :requests5xx,
                    :allPassed, :provenanceJson, :failureReason, :stopReason, 0
                )
                """;

            jdbcClient.sql(insertSql)
                .param("runId", run.runId())
                .param("campaignId", run.campaignId())
                .param("templateId", run.templateId() != null ? run.templateId() : "CUSTOM")
                .param("status", run.status() != null ? run.status().name() : "PENDING")
                .param("requestedBy", run.requestedBy() != null ? run.requestedBy() : "soc-admin")
                .param("startTime", Timestamp.from(run.startTime() != null ? run.startTime() : now))
                .param("endTime", run.endTime() != null ? Timestamp.from(run.endTime()) : null)
                .param("createdAt", Timestamp.from(now))
                .param("updatedAt", Timestamp.from(now))
                .param("lastHeartbeatAt", Timestamp.from(heartbeat))
                .param("durationSeconds", durationSec)
                .param("requestRate", reqRate)
                .param("concurrency", concurrency)
                .param("trafficMix", trafficMix)
                .param("dryRun", dryRun)
                .param("deterministicSeed", seed)
                .param("totalRequests", run.totalRequests())
                .param("requests2xx", run.requests2xx())
                .param("requests4xx", run.requests4xx())
                .param("requests5xx", run.requests5xx())
                .param("allPassed", run.allAssertionsPassed())
                .param("provenanceJson", provenanceJson)
                .param("failureReason", run.failureReason())
                .param("stopReason", run.stopReason())
                .update();
        }

        // Also save child stages if present
        if (run.stages() != null) {
            for (SimulationStageResult stage : run.stages()) {
                saveStage(run.runId(), stage);
            }
        }
    }

    @Transactional
    public void saveStage(String runId, SimulationStageResult stage) {
        if (runId == null || stage == null) {
            return;
        }

        String assertionsJson = serializeJson(stage.assertionResults());
        Instant now = Instant.now();
        Instant executedAt = stage.endTime() != null ? stage.endTime() : (stage.startTime() != null ? stage.startTime() : now);
        String stageId = String.valueOf(stage.stageNumber());

        Integer stageCount = jdbcClient.sql("""
            SELECT COUNT(*) FROM security_data.simulation_run_stages
            WHERE run_id = :runId AND stage_id = :stageId AND scenario_id = :scenarioId
            """)
            .param("runId", runId)
            .param("stageId", stageId)
            .param("scenarioId", stage.scenarioId())
            .query(Integer.class)
            .single();

        if (stageCount != null && stageCount > 0) {
            String updateSql = """
                UPDATE security_data.simulation_run_stages
                SET status = :status,
                    total_requests = :totalRequests,
                    success_requests = :successRequests,
                    failed_requests = :failedRequests,
                    assertions_json = :assertionsJson,
                    executed_at = :executedAt,
                    updated_at = :updatedAt
                WHERE run_id = :runId AND stage_id = :stageId AND scenario_id = :scenarioId
                """;

            jdbcClient.sql(updateSql)
                .param("runId", runId)
                .param("stageId", stageId)
                .param("scenarioId", stage.scenarioId())
                .param("status", stage.status() != null ? stage.status() : "UNKNOWN")
                .param("totalRequests", stage.totalRequests())
                .param("successRequests", stage.successfulRequests())
                .param("failedRequests", stage.failedRequests())
                .param("assertionsJson", assertionsJson)
                .param("executedAt", Timestamp.from(executedAt))
                .param("updatedAt", Timestamp.from(now))
                .update();
        } else {
            String insertSql = """
                INSERT INTO security_data.simulation_run_stages (
                    id, run_id, stage_id, stage_name, scenario_id, status,
                    total_requests, success_requests, failed_requests, assertions_json,
                    executed_at, created_at, updated_at
                ) VALUES (
                    :id, :runId, :stageId, :stageName, :scenarioId, :status,
                    :totalRequests, :successRequests, :failedRequests, :assertionsJson,
                    :executedAt, :createdAt, :updatedAt
                )
                """;

            jdbcClient.sql(insertSql)
                .param("id", UUID.randomUUID())
                .param("runId", runId)
                .param("stageId", stageId)
                .param("stageName", stage.stageName() != null ? stage.stageName() : "Stage " + stage.stageNumber())
                .param("scenarioId", stage.scenarioId())
                .param("status", stage.status() != null ? stage.status() : "UNKNOWN")
                .param("totalRequests", stage.totalRequests())
                .param("successRequests", stage.successfulRequests())
                .param("failedRequests", stage.failedRequests())
                .param("assertionsJson", assertionsJson)
                .param("executedAt", Timestamp.from(executedAt))
                .param("createdAt", Timestamp.from(now))
                .param("updatedAt", Timestamp.from(now))
                .update();
        }
    }

    public void updateHeartbeat(String runId) {
        if (runId == null) return;
        Timestamp now = Timestamp.from(Instant.now());
        jdbcClient.sql("""
            UPDATE security_data.simulation_runs
            SET last_heartbeat_at = :now, updated_at = :now
            WHERE run_id = :runId
            """)
            .param("now", now)
            .param("runId", runId)
            .update();
    }

    public void updateRunStatus(String runId, SimulationRunStatus status, String stopReason, String failureReason) {
        if (runId == null || status == null) return;
        Timestamp now = Timestamp.from(Instant.now());
        boolean isTerminal = (status == SimulationRunStatus.COMPLETED || status == SimulationRunStatus.STOPPED ||
                              status == SimulationRunStatus.FAILED || status == SimulationRunStatus.INTERRUPTED);

        String sql = isTerminal
            ? """
              UPDATE security_data.simulation_runs
              SET status = :status,
                  stop_reason = COALESCE(:stopReason, stop_reason),
                  failure_reason = COALESCE(:failureReason, failure_reason),
                  end_time = COALESCE(end_time, :now),
                  updated_at = :now,
                  version = version + 1
              WHERE run_id = :runId
              """
            : """
              UPDATE security_data.simulation_runs
              SET status = :status,
                  stop_reason = COALESCE(:stopReason, stop_reason),
                  failure_reason = COALESCE(:failureReason, failure_reason),
                  updated_at = :now,
                  version = version + 1
              WHERE run_id = :runId
              """;

        jdbcClient.sql(sql)
            .param("status", status.name())
            .param("stopReason", stopReason)
            .param("failureReason", failureReason)
            .param("now", now)
            .param("runId", runId)
            .update();
    }

    public Optional<SimulationRunResponse> findRunById(String runId) {
        if (runId == null) return Optional.empty();

        String sql = """
            SELECT run_id, campaign_id, template_id, status, requested_by,
                   start_time, end_time, created_at, updated_at, last_heartbeat_at,
                   duration_seconds, request_rate, concurrency, traffic_mix, dry_run,
                   deterministic_seed, total_requests, requests_2xx, requests_4xx, requests_5xx,
                   all_passed, provenance_json, failure_reason, stop_reason, version
            FROM security_data.simulation_runs
            WHERE run_id = :runId
            """;

        Optional<SimulationRunResponse> runOpt = jdbcClient.sql(sql)
            .param("runId", runId)
            .query(this::mapRowToRunResponse)
            .optional();

        if (runOpt.isEmpty()) {
            return Optional.empty();
        }

        SimulationRunResponse run = runOpt.get();
        List<SimulationStageResult> stages = findStagesForRun(runId);
        return Optional.of(new SimulationRunResponse(
            run.runId(),
            run.campaignId(),
            run.templateId(),
            run.status(),
            run.startTime(),
            run.endTime(),
            run.config(),
            stages,
            run.totalRequests(),
            run.requests2xx(),
            run.requests4xx(),
            run.requests5xx(),
            run.allAssertionsPassed(),
            run.provenanceMetadata(),
            run.requestedBy(),
            run.lastHeartbeatAt(),
            run.failureReason(),
            run.stopReason()
        ));
    }

    public List<SimulationRunResponse> findAllRuns(int limit, int offset) {
        int boundedLimit = Math.min(Math.max(1, limit), 100);
        int boundedOffset = Math.max(0, offset);

        String sql = """
            SELECT run_id, campaign_id, template_id, status, requested_by,
                   start_time, end_time, created_at, updated_at, last_heartbeat_at,
                   duration_seconds, request_rate, concurrency, traffic_mix, dry_run,
                   deterministic_seed, total_requests, requests_2xx, requests_4xx, requests_5xx,
                   all_passed, provenance_json, failure_reason, stop_reason, version
            FROM security_data.simulation_runs
            ORDER BY start_time DESC
            LIMIT :limit OFFSET :offset
            """;

        List<SimulationRunResponse> runs = jdbcClient.sql(sql)
            .param("limit", boundedLimit)
            .param("offset", boundedOffset)
            .query(this::mapRowToRunResponse)
            .list();

        List<SimulationRunResponse> populated = new ArrayList<>(runs.size());
        for (SimulationRunResponse run : runs) {
            List<SimulationStageResult> stages = findStagesForRun(run.runId());
            populated.add(new SimulationRunResponse(
                run.runId(),
                run.campaignId(),
                run.templateId(),
                run.status(),
                run.startTime(),
                run.endTime(),
                run.config(),
                stages,
                run.totalRequests(),
                run.requests2xx(),
                run.requests4xx(),
                run.requests5xx(),
                run.allAssertionsPassed(),
                run.provenanceMetadata(),
                run.requestedBy(),
                run.lastHeartbeatAt(),
                run.failureReason(),
                run.stopReason()
            ));
        }
        return populated;
    }

    public List<SimulationStageResult> findStagesForRun(String runId) {
        if (runId == null) return List.of();

        String sql = """
            SELECT id, run_id, stage_id, stage_name, scenario_id, status,
                   total_requests, success_requests, failed_requests, assertions_json,
                   executed_at, created_at, updated_at
            FROM security_data.simulation_run_stages
            WHERE run_id = :runId
            ORDER BY stage_id ASC
            """;

        return jdbcClient.sql(sql)
            .param("runId", runId)
            .query(this::mapRowToStageResult)
            .list();
    }

    @Transactional
    public int reconcileInterruptedRuns(Instant heartbeatCutoff) {
        Timestamp cutoff = Timestamp.from(heartbeatCutoff != null ? heartbeatCutoff : Instant.now().minusSeconds(5));
        Timestamp now = Timestamp.from(Instant.now());

        String sql = """
            UPDATE security_data.simulation_runs
            SET status = 'INTERRUPTED',
                stop_reason = 'Gateway restart / ungraceful termination detected',
                end_time = COALESCE(end_time, :now),
                updated_at = :now,
                version = version + 1
            WHERE status IN ('RUNNING', 'PAUSED')
              AND (last_heartbeat_at IS NULL OR last_heartbeat_at < :cutoff)
            """;

        int count = jdbcClient.sql(sql)
            .param("cutoff", cutoff)
            .param("now", now)
            .update();

        if (count > 0) {
            log.warn("Reconciled {} interrupted simulation run(s) from previous gateway instances", count);
        }
        return count;
    }

    private SimulationRunResponse mapRowToRunResponse(ResultSet rs, int rowNum) throws SQLException {
        String runId = rs.getString("run_id");
        String campaignId = rs.getString("campaign_id");
        String templateId = rs.getString("template_id");
        String statusStr = rs.getString("status");
        SimulationRunStatus status = parseStatus(statusStr);
        String requestedBy = rs.getString("requested_by");

        Timestamp st = rs.getTimestamp("start_time");
        Instant startTime = st != null ? st.toInstant() : Instant.now();

        Timestamp et = rs.getTimestamp("end_time");
        Instant endTime = et != null ? et.toInstant() : null;

        Timestamp hb = rs.getTimestamp("last_heartbeat_at");
        Instant lastHeartbeatAt = hb != null ? hb.toInstant() : null;

        int durationSeconds = rs.getInt("duration_seconds");
        double requestRate = rs.getDouble("request_rate");
        int concurrency = rs.getInt("concurrency");
        String trafficMix = rs.getString("traffic_mix");
        boolean dryRun = rs.getBoolean("dry_run");
        long seed = rs.getLong("deterministic_seed");

        int totalRequests = rs.getInt("total_requests");
        int requests2xx = rs.getInt("requests_2xx");
        int requests4xx = rs.getInt("requests_4xx");
        int requests5xx = rs.getInt("requests_5xx");
        boolean allPassed = rs.getBoolean("all_passed");

        String provJson = rs.getString("provenance_json");
        Map<String, Object> provenance = deserializeMap(provJson);

        String failureReason = rs.getString("failure_reason");
        String stopReason = rs.getString("stop_reason");

        SimulationRunConfig config = new SimulationRunConfig(
            templateId,
            List.of(),
            durationSeconds,
            requestRate,
            concurrency,
            trafficMix,
            seed,
            List.of(),
            List.of(),
            dryRun
        );

        return new SimulationRunResponse(
            runId,
            campaignId,
            templateId,
            status,
            startTime,
            endTime,
            config,
            List.of(),
            totalRequests,
            requests2xx,
            requests4xx,
            requests5xx,
            allPassed,
            provenance,
            requestedBy,
            lastHeartbeatAt,
            failureReason,
            stopReason
        );
    }

    private SimulationStageResult mapRowToStageResult(ResultSet rs, int rowNum) throws SQLException {
        String stageIdStr = rs.getString("stage_id");
        int stageNumber = 1;
        try {
            stageNumber = Integer.parseInt(stageIdStr);
        } catch (Exception ignored) {}

        String stageName = rs.getString("stage_name");
        String scenarioId = rs.getString("scenario_id");
        String status = rs.getString("status");
        int totalRequests = rs.getInt("total_requests");
        int successRequests = rs.getInt("success_requests");
        int failedRequests = rs.getInt("failed_requests");
        String assertionsJson = rs.getString("assertions_json");
        List<ExpectedVsActualAssertion> assertions = deserializeAssertions(assertionsJson);

        Timestamp execAt = rs.getTimestamp("executed_at");
        Instant executedAt = execAt != null ? execAt.toInstant() : Instant.now();

        return new SimulationStageResult(
            stageNumber,
            stageName,
            scenarioId,
            status,
            totalRequests,
            successRequests,
            failedRequests,
            executedAt,
            executedAt,
            0L,
            assertions,
            null
        );
    }

    private SimulationRunStatus parseStatus(String statusStr) {
        if (statusStr == null) return SimulationRunStatus.PENDING;
        try {
            return SimulationRunStatus.valueOf(statusStr.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return SimulationRunStatus.PENDING;
        }
    }

    private String serializeJson(Object obj) {
        if (obj == null) return null;
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            log.debug("JSON serialization failed: {}", e.getMessage());
            return "{}";
        }
    }

    private Map<String, Object> deserializeMap(String json) {
        if (json == null || json.isBlank()) return new LinkedHashMap<>();
        try {
            return objectMapper.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    private List<ExpectedVsActualAssertion> deserializeAssertions(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return objectMapper.readValue(json, new TypeReference<List<ExpectedVsActualAssertion>>() {});
        } catch (Exception e) {
            return List.of();
        }
    }
}
