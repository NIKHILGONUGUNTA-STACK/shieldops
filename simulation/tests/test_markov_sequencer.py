"""Tests for MarkovSequencer and API sequence traversal engine."""

from pathlib import Path
import pytest

from simulation.ml.models import (
    SequenceAnomalyReport,
    SequenceProfile,
    SequenceStep,
    SessionTrace,
)
from simulation.ml.markov_sequencer import MarkovSequencer


@pytest.fixture
def benign_training_sessions():
    """Generates a realistic set of benign banking sessions."""
    sessions = []
    # 20 standard customer check balance & transfer sessions
    for i in range(20):
        cust_id = f"cust-{100 + i}"
        acc_id = f"acc-{200 + i}"
        steps = [
            SequenceStep(method="POST", path="/auth/login"),
            SequenceStep(method="GET", path=f"/api/v1/customers/{cust_id}"),
            SequenceStep(method="GET", path=f"/api/v1/accounts"),
            SequenceStep(method="GET", path=f"/api/v1/accounts/{acc_id}/balance"),
            SequenceStep(method="POST", path=f"/api/v1/transactions"),
        ]
        sessions.append(SessionTrace(session_id=f"sess-normal-{i}", steps=steps))

    # 10 browsing/view history sessions
    for i in range(10):
        cust_id = f"cust-{300 + i}"
        steps = [
            SequenceStep(method="POST", path="/auth/login"),
            SequenceStep(method="GET", path=f"/api/v1/customers/{cust_id}"),
            SequenceStep(method="GET", path=f"/api/v1/accounts"),
            SequenceStep(method="GET", path=f"/api/v1/transactions"),
        ]
        sessions.append(SessionTrace(session_id=f"sess-browse-{i}", steps=steps))

    return sessions


# ==============================================================================
# Normalization Tests
# ==============================================================================

def test_endpoint_normalization():
    assert MarkovSequencer.normalize_path("/api/v1/customers/cust-12345") == "/api/v1/customers/{id}"
    assert MarkovSequencer.normalize_path("/api/v1/accounts/99887766") == "/api/v1/accounts/{id}"
    assert (
        MarkovSequencer.normalize_path("/api/v1/records/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d")
        == "/api/v1/records/{id}"
    )
    assert MarkovSequencer.normalize_path("/api/v1/accounts?page=1&size=20") == "/api/v1/accounts"

    ep = MarkovSequencer.normalize_endpoint("get", "/api/v1/customers/cust-999")
    assert ep == "GET /api/v1/customers/{id}"


# ==============================================================================
# Model Training Tests
# ==============================================================================

def test_markov_training(benign_training_sessions):
    sequencer = MarkovSequencer()
    profile = sequencer.train(benign_training_sessions, name="test_bank_profile")

    assert profile.total_sessions == 30
    assert profile.total_transitions > 0
    assert "POST /auth/login" in profile.endpoints
    assert "GET /api/v1/customers/{id}" in profile.endpoints
    assert "POST /api/v1/transactions" in profile.endpoints

    # Check that probabilities from POST /auth/login sum to ~1.0
    login_transitions = profile.transition_matrix.get("POST /auth/login", {})
    total_prob = sum(login_transitions.values())
    assert 0.99 <= total_prob <= 1.01

    # In our benign data, /auth/login always transitions to GET /api/v1/customers/{id}
    prob_login_to_cust = login_transitions.get("GET /api/v1/customers/{id}", 0.0)
    assert prob_login_to_cust > 0.95

    # Critical funnels: POST /api/v1/transactions should have a detected funnel predecessor
    assert "POST /api/v1/transactions" in profile.critical_funnels
    assert "GET /api/v1/accounts/{id}/balance" in profile.critical_funnels["POST /api/v1/transactions"]


# ==============================================================================
# Anomaly Evaluation Tests
# ==============================================================================

def test_evaluate_benign_session(benign_training_sessions):
    sequencer = MarkovSequencer()
    profile = sequencer.train(benign_training_sessions)

    benign_session = SessionTrace(
        session_id="test-benign-eval",
        steps=[
            SequenceStep(method="POST", path="/auth/login"),
            SequenceStep(method="GET", path="/api/v1/customers/cust-777"),
            SequenceStep(method="GET", path="/api/v1/accounts"),
            SequenceStep(method="GET", path="/api/v1/accounts/acc-888/balance"),
            SequenceStep(method="POST", path="/api/v1/transactions"),
        ],
    )

    report = sequencer.evaluate_session(benign_session, profile)
    assert report.is_anomalous is False
    assert report.anomaly_score < profile.anomaly_threshold
    assert len(report.violations) == 0


def test_evaluate_anomalous_step_skip(benign_training_sessions):
    sequencer = MarkovSequencer()
    profile = sequencer.train(benign_training_sessions)

    # Attacker jumps straight from login to funds transfer (skipping profile/accounts)
    attacker_session = SessionTrace(
        session_id="test-attack-eval",
        steps=[
            SequenceStep(method="POST", path="/auth/login"),
            SequenceStep(method="POST", path="/api/v1/transactions"),  # Illegal jump!
        ],
    )

    report = sequencer.evaluate_session(attacker_session, profile)
    assert report.is_anomalous is True
    assert len(report.violations) > 0
    assert report.lowest_probability_step is not None
    assert report.lowest_probability_step.from_endpoint == "POST /auth/login"
    assert report.lowest_probability_step.to_endpoint == "POST /api/v1/transactions"
    assert report.lowest_probability_step.probability < 0.005


def test_evaluate_raw_endpoint_sequence(benign_training_sessions):
    sequencer = MarkovSequencer()
    profile = sequencer.train(benign_training_sessions)

    raw_anomalous = [
        "POST /auth/login",
        "DELETE /api/v1/accounts/acc-999",  # Completely unobserved endpoint
    ]

    report = sequencer.evaluate_sequence(raw_anomalous, profile=profile)
    assert report.is_anomalous is True
    assert report.anomaly_score > profile.anomaly_threshold


def test_evaluate_single_or_empty_session():
    sequencer = MarkovSequencer(profile=SequenceProfile())
    single_step = SessionTrace(
        session_id="single-step",
        steps=[SequenceStep(method="GET", path="/health")],
    )
    report = sequencer.evaluate_session(single_step)
    assert report.is_anomalous is False
    assert report.anomaly_score == 0.0


# ==============================================================================
# Serialization & Round-Trip Tests
# ==============================================================================

def test_profile_serialization_round_trip(tmp_path, benign_training_sessions):
    sequencer = MarkovSequencer()
    profile = sequencer.train(benign_training_sessions, name="save_test_profile")

    file_path = tmp_path / "markov_profile.json"
    MarkovSequencer.save_profile(profile, file_path)
    assert file_path.exists()

    loaded_profile = MarkovSequencer.load_profile(file_path)
    assert loaded_profile.name == "save_test_profile"
    assert loaded_profile.total_sessions == profile.total_sessions
    assert loaded_profile.endpoints == profile.endpoints
    assert loaded_profile.critical_funnels == profile.critical_funnels
    assert (
        loaded_profile.transition_matrix["POST /auth/login"]
        == profile.transition_matrix["POST /auth/login"]
    )
