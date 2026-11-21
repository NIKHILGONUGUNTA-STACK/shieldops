-- ============================================================================
-- Flyway Migration V11: Research Evaluation & Experimental Validation Schema
-- Phase 7.3.6: Versioned Datasets, Immutable Experiments, and Benchmark Persistence
-- ============================================================================

-- 1. Versioned Evaluation Datasets
CREATE TABLE IF NOT EXISTS security_data.evaluation_datasets (
    dataset_id VARCHAR(64) PRIMARY KEY,
    version VARCHAR(32) NOT NULL,
    manifest_hash VARCHAR(128) NOT NULL,
    total_scenarios INT NOT NULL,
    benign_count INT NOT NULL,
    malicious_count INT NOT NULL,
    ambiguous_count INT NOT NULL,
    incomplete_count INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Immutable Evaluation Experiments
CREATE TABLE IF NOT EXISTS security_data.evaluation_experiments (
    experiment_id VARCHAR(64) PRIMARY KEY,
    dataset_id VARCHAR(64) NOT NULL REFERENCES security_data.evaluation_datasets(dataset_id) ON DELETE CASCADE,
    experiment_name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    config_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Multi-Unit Evaluation Results (Scenario, Event, Campaign)
CREATE TABLE IF NOT EXISTS security_data.evaluation_results (
    id VARCHAR(64) PRIMARY KEY,
    experiment_id VARCHAR(64) NOT NULL REFERENCES security_data.evaluation_experiments(experiment_id) ON DELETE CASCADE,
    evaluation_mode VARCHAR(64) NOT NULL,
    evaluation_unit VARCHAR(32) NOT NULL,
    total_samples INT NOT NULL,
    true_positives INT NOT NULL,
    false_positives INT NOT NULL,
    true_negatives INT NOT NULL,
    false_negatives INT NOT NULL,
    uncertain_handled INT NOT NULL DEFAULT 0,
    precision DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    recall DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    f1_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    accuracy DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    false_positive_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    false_negative_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    specificity DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    median_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    p95_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    p99_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ci_f1_lower DOUBLE PRECISION,
    ci_f1_upper DOUBLE PRECISION,
    throughput_eps DOUBLE PRECISION NOT NULL DEFAULT 0.0
);

-- 4. Controlled Ablation Results
CREATE TABLE IF NOT EXISTS security_data.evaluation_ablations (
    id VARCHAR(64) PRIMARY KEY,
    experiment_id VARCHAR(64) NOT NULL REFERENCES security_data.evaluation_experiments(experiment_id) ON DELETE CASCADE,
    ablation_dimension VARCHAR(64) NOT NULL,
    precision DOUBLE PRECISION NOT NULL,
    recall DOUBLE PRECISION NOT NULL,
    f1_score DOUBLE PRECISION NOT NULL,
    false_positive_rate DOUBLE PRECISION NOT NULL,
    f1_delta DOUBLE PRECISION NOT NULL
);

-- 5. Robustness & Adversarial Edge-Case Findings
CREATE TABLE IF NOT EXISTS security_data.evaluation_robustness_findings (
    id VARCHAR(64) PRIMARY KEY,
    experiment_id VARCHAR(64) NOT NULL REFERENCES security_data.evaluation_experiments(experiment_id) ON DELETE CASCADE,
    test_case VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    expected_behavior TEXT NOT NULL,
    observed_behavior TEXT NOT NULL,
    passed BOOLEAN NOT NULL DEFAULT TRUE,
    dimension VARCHAR(64)
);

-- Query pattern indexes
CREATE INDEX IF NOT EXISTS idx_eval_results_exp_mode
    ON security_data.evaluation_results(experiment_id, evaluation_mode, evaluation_unit);

CREATE INDEX IF NOT EXISTS idx_eval_ablations_exp
    ON security_data.evaluation_ablations(experiment_id);

CREATE INDEX IF NOT EXISTS idx_eval_robustness_exp
    ON security_data.evaluation_robustness_findings(experiment_id);
