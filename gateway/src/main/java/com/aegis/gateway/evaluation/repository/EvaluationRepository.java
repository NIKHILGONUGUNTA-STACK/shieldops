package com.aegis.gateway.evaluation.repository;

import com.aegis.gateway.evaluation.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Repository
public class EvaluationRepository {
    private static final Logger log = LoggerFactory.getLogger(EvaluationRepository.class);

    private final NamedParameterJdbcTemplate jdbc;

    public EvaluationRepository(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void saveDataset(EvaluationDataset ds) {
        try {
            String checkSql = "SELECT COUNT(*) FROM security_data.evaluation_datasets WHERE dataset_id = :id";
            Integer count = jdbc.queryForObject(checkSql, new MapSqlParameterSource("id", ds.datasetId()), Integer.class);
            if (count != null && count > 0) {
                return;
            }

            String sql = """
                INSERT INTO security_data.evaluation_datasets (
                    dataset_id, version, manifest_hash, total_scenarios, benign_count,
                    malicious_count, ambiguous_count, incomplete_count, created_at
                ) VALUES (
                    :datasetId, :version, :manifestHash, :totalScenarios, :benignCount,
                    :maliciousCount, :ambiguousCount, :incompleteCount, :createdAt
                )
            """;
            MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("datasetId", ds.datasetId())
                .addValue("version", ds.version())
                .addValue("manifestHash", ds.manifestHash())
                .addValue("totalScenarios", ds.totalScenarios())
                .addValue("benignCount", ds.benignCount())
                .addValue("maliciousCount", ds.maliciousCount())
                .addValue("ambiguousCount", ds.ambiguousCount())
                .addValue("incompleteCount", ds.incompleteCount())
                .addValue("createdAt", Timestamp.from(ds.createdAt() != null ? ds.createdAt() : Instant.now()));
            jdbc.update(sql, p);
        } catch (DataAccessException e) {
            log.warn("Failed to persist evaluation dataset {}: {}", ds.datasetId(), e.getMessage());
        }
    }

    public void saveExperiment(EvaluationExperiment exp) {
        try {
            String checkSql = "SELECT COUNT(*) FROM security_data.evaluation_experiments WHERE experiment_id = :id";
            Integer count = jdbc.queryForObject(checkSql, new MapSqlParameterSource("id", exp.experimentId()), Integer.class);
            if (count != null && count > 0) {
                return;
            }

            String sql = """
                INSERT INTO security_data.evaluation_experiments (
                    experiment_id, dataset_id, experiment_name, status,
                    started_at, completed_at, config_json, created_at
                ) VALUES (
                    :experimentId, :datasetId, :experimentName, :status,
                    :startedAt, :completedAt, :configJson, :createdAt
                )
            """;
            MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("experimentId", exp.experimentId())
                .addValue("datasetId", exp.datasetId())
                .addValue("experimentName", exp.experimentName())
                .addValue("status", exp.status())
                .addValue("startedAt", Timestamp.from(exp.startedAt()))
                .addValue("completedAt", Timestamp.from(exp.completedAt()))
                .addValue("configJson", exp.configJson())
                .addValue("createdAt", Timestamp.from(exp.createdAt() != null ? exp.createdAt() : Instant.now()));
            jdbc.update(sql, p);
        } catch (DataAccessException e) {
            log.warn("Failed to persist evaluation experiment {}: {}", exp.experimentId(), e.getMessage());
        }
    }

    public void saveResult(EvaluationResult res) {
        try {
            String checkSql = "SELECT COUNT(*) FROM security_data.evaluation_results WHERE id = :id";
            Integer count = jdbc.queryForObject(checkSql, new MapSqlParameterSource("id", res.id()), Integer.class);
            if (count != null && count > 0) {
                return;
            }

            String sql = """
                INSERT INTO security_data.evaluation_results (
                    id, experiment_id, evaluation_mode, evaluation_unit, total_samples,
                    true_positives, false_positives, true_negatives, false_negatives,
                    uncertain_handled, precision, recall, f1_score, accuracy,
                    false_positive_rate, false_negative_rate, specificity,
                    median_latency_ms, p95_latency_ms, p99_latency_ms,
                    ci_f1_lower, ci_f1_upper, throughput_eps
                ) VALUES (
                    :id, :experimentId, :evaluationMode, :evaluationUnit, :totalSamples,
                    :truePositives, :falsePositives, :trueNegatives, :falseNegatives,
                    :uncertainHandled, :precision, :recall, :f1Score, :accuracy,
                    :falsePositiveRate, :falseNegativeRate, :specificity,
                    :medianLatencyMs, :p95LatencyMs, :p99LatencyMs,
                    :ciF1Lower, :ciF1Upper, :throughputEps
                )
            """;
            MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("id", res.id())
                .addValue("experimentId", res.experimentId())
                .addValue("evaluationMode", res.evaluationMode())
                .addValue("evaluationUnit", res.evaluationUnit())
                .addValue("totalSamples", res.totalSamples())
                .addValue("truePositives", res.truePositives())
                .addValue("falsePositives", res.falsePositives())
                .addValue("trueNegatives", res.trueNegatives())
                .addValue("falseNegatives", res.falseNegatives())
                .addValue("uncertainHandled", res.uncertainHandled())
                .addValue("precision", res.precision())
                .addValue("recall", res.recall())
                .addValue("f1Score", res.f1Score())
                .addValue("accuracy", res.accuracy())
                .addValue("falsePositiveRate", res.falsePositiveRate())
                .addValue("falseNegativeRate", res.falseNegativeRate())
                .addValue("specificity", res.specificity())
                .addValue("medianLatencyMs", res.medianLatencyMs())
                .addValue("p95LatencyMs", res.p95LatencyMs())
                .addValue("p99LatencyMs", res.p99LatencyMs())
                .addValue("ciF1Lower", res.ciF1Lower())
                .addValue("ciF1Upper", res.ciF1Upper())
                .addValue("throughputEps", res.throughputEps());
            jdbc.update(sql, p);
        } catch (DataAccessException e) {
            log.warn("Failed to persist evaluation result {}: {}", res.id(), e.getMessage());
        }
    }

    public void saveAblation(EvaluationAblation abl) {
        try {
            String checkSql = "SELECT COUNT(*) FROM security_data.evaluation_ablations WHERE id = :id";
            Integer count = jdbc.queryForObject(checkSql, new MapSqlParameterSource("id", abl.id()), Integer.class);
            if (count != null && count > 0) {
                return;
            }

            String sql = """
                INSERT INTO security_data.evaluation_ablations (
                    id, experiment_id, ablation_dimension, precision, recall,
                    f1_score, false_positive_rate, f1_delta
                ) VALUES (
                    :id, :experimentId, :ablationDimension, :precision, :recall,
                    :f1Score, :falsePositiveRate, :f1Delta
                )
            """;
            MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("id", abl.id())
                .addValue("experimentId", abl.experimentId())
                .addValue("ablationDimension", abl.ablationDimension())
                .addValue("precision", abl.precision())
                .addValue("recall", abl.recall())
                .addValue("f1Score", abl.f1Score())
                .addValue("falsePositiveRate", abl.falsePositiveRate())
                .addValue("f1Delta", abl.f1Delta());
            jdbc.update(sql, p);
        } catch (DataAccessException e) {
            log.warn("Failed to persist evaluation ablation {}: {}", abl.id(), e.getMessage());
        }
    }

    public void saveRobustnessFinding(EvaluationRobustnessFinding f) {
        try {
            String checkSql = "SELECT COUNT(*) FROM security_data.evaluation_robustness_findings WHERE id = :id";
            Integer count = jdbc.queryForObject(checkSql, new MapSqlParameterSource("id", f.id()), Integer.class);
            if (count != null && count > 0) {
                return;
            }

            String sql = """
                INSERT INTO security_data.evaluation_robustness_findings (
                    id, experiment_id, test_case, category, expected_behavior,
                    observed_behavior, passed, dimension
                ) VALUES (
                    :id, :experimentId, :testCase, :category, :expectedBehavior,
                    :observedBehavior, :passed, :dimension
                )
            """;
            MapSqlParameterSource p = new MapSqlParameterSource()
                .addValue("id", f.id())
                .addValue("experimentId", f.experimentId())
                .addValue("testCase", f.testCase())
                .addValue("category", f.category())
                .addValue("expectedBehavior", f.expectedBehavior())
                .addValue("observedBehavior", f.observedBehavior())
                .addValue("passed", f.passed())
                .addValue("dimension", f.dimension());
            jdbc.update(sql, p);
        } catch (DataAccessException e) {
            log.warn("Failed to persist evaluation robustness finding {}: {}", f.id(), e.getMessage());
        }
    }

    public Optional<EvaluationExperiment> findLatestExperiment() {
        try {
            String sql = "SELECT * FROM security_data.evaluation_experiments ORDER BY started_at DESC LIMIT 1";
            List<EvaluationExperiment> list = jdbc.query(sql, (rs, rowNum) -> mapExperiment(rs));
            return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
        } catch (DataAccessException e) {
            log.warn("Error querying latest evaluation experiment: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public Optional<EvaluationDataset> findDatasetById(String datasetId) {
        try {
            String sql = "SELECT * FROM security_data.evaluation_datasets WHERE dataset_id = :id";
            List<EvaluationDataset> list = jdbc.query(sql, new MapSqlParameterSource("id", datasetId), (rs, rowNum) -> mapDataset(rs));
            return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
        } catch (DataAccessException e) {
            return Optional.empty();
        }
    }

    public List<EvaluationResult> findResultsByExperimentId(String experimentId) {
        try {
            String sql = "SELECT * FROM security_data.evaluation_results WHERE experiment_id = :id";
            return jdbc.query(sql, new MapSqlParameterSource("id", experimentId), (rs, rowNum) -> mapResult(rs));
        } catch (DataAccessException e) {
            return Collections.emptyList();
        }
    }

    public List<EvaluationAblation> findAblationsByExperimentId(String experimentId) {
        try {
            String sql = "SELECT * FROM security_data.evaluation_ablations WHERE experiment_id = :id ORDER BY ablation_dimension";
            return jdbc.query(sql, new MapSqlParameterSource("id", experimentId), (rs, rowNum) -> mapAblation(rs));
        } catch (DataAccessException e) {
            return Collections.emptyList();
        }
    }

    public List<EvaluationRobustnessFinding> findRobustnessByExperimentId(String experimentId) {
        try {
            String sql = "SELECT * FROM security_data.evaluation_robustness_findings WHERE experiment_id = :id ORDER BY category, test_case";
            return jdbc.query(sql, new MapSqlParameterSource("id", experimentId), (rs, rowNum) -> mapRobustness(rs));
        } catch (DataAccessException e) {
            return Collections.emptyList();
        }
    }

    public List<EvaluationExperiment> findAllExperiments() {
        try {
            String sql = "SELECT * FROM security_data.evaluation_experiments ORDER BY started_at DESC";
            return jdbc.query(sql, (rs, rowNum) -> mapExperiment(rs));
        } catch (DataAccessException e) {
            return Collections.emptyList();
        }
    }

    private EvaluationDataset mapDataset(ResultSet rs) throws SQLException {
        Timestamp ts = rs.getTimestamp("created_at");
        return new EvaluationDataset(
            rs.getString("dataset_id"),
            rs.getString("version"),
            rs.getString("manifest_hash"),
            rs.getInt("total_scenarios"),
            rs.getInt("benign_count"),
            rs.getInt("malicious_count"),
            rs.getInt("ambiguous_count"),
            rs.getInt("incomplete_count"),
            ts != null ? ts.toInstant() : Instant.now()
        );
    }

    private EvaluationExperiment mapExperiment(ResultSet rs) throws SQLException {
        Timestamp start = rs.getTimestamp("started_at");
        Timestamp end = rs.getTimestamp("completed_at");
        Timestamp cr = rs.getTimestamp("created_at");
        return new EvaluationExperiment(
            rs.getString("experiment_id"),
            rs.getString("dataset_id"),
            rs.getString("experiment_name"),
            rs.getString("status"),
            start != null ? start.toInstant() : Instant.now(),
            end != null ? end.toInstant() : Instant.now(),
            rs.getString("config_json"),
            cr != null ? cr.toInstant() : Instant.now()
        );
    }

    private EvaluationResult mapResult(ResultSet rs) throws SQLException {
        Double ciLower = rs.getObject("ci_f1_lower") != null ? rs.getDouble("ci_f1_lower") : null;
        Double ciUpper = rs.getObject("ci_f1_upper") != null ? rs.getDouble("ci_f1_upper") : null;
        return new EvaluationResult(
            rs.getString("id"),
            rs.getString("experiment_id"),
            rs.getString("evaluation_mode"),
            rs.getString("evaluation_unit"),
            rs.getInt("total_samples"),
            rs.getInt("true_positives"),
            rs.getInt("false_positives"),
            rs.getInt("true_negatives"),
            rs.getInt("false_negatives"),
            rs.getInt("uncertain_handled"),
            rs.getDouble("precision"),
            rs.getDouble("recall"),
            rs.getDouble("f1_score"),
            rs.getDouble("accuracy"),
            rs.getDouble("false_positive_rate"),
            rs.getDouble("false_negative_rate"),
            rs.getDouble("specificity"),
            rs.getDouble("median_latency_ms"),
            rs.getDouble("p95_latency_ms"),
            rs.getDouble("p99_latency_ms"),
            ciLower,
            ciUpper,
            rs.getDouble("throughput_eps")
        );
    }

    private EvaluationAblation mapAblation(ResultSet rs) throws SQLException {
        return new EvaluationAblation(
            rs.getString("id"),
            rs.getString("experiment_id"),
            rs.getString("ablation_dimension"),
            rs.getDouble("precision"),
            rs.getDouble("recall"),
            rs.getDouble("f1_score"),
            rs.getDouble("false_positive_rate"),
            rs.getDouble("f1_delta")
        );
    }

    private EvaluationRobustnessFinding mapRobustness(ResultSet rs) throws SQLException {
        return new EvaluationRobustnessFinding(
            rs.getString("id"),
            rs.getString("experiment_id"),
            rs.getString("test_case"),
            rs.getString("category"),
            rs.getString("expected_behavior"),
            rs.getString("observed_behavior"),
            rs.getBoolean("passed"),
            rs.getString("dimension")
        );
    }
}
