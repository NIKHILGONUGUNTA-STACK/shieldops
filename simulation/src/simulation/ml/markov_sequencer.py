"""Discrete Markov Chain API Sequence Modeling and Workflow Traversal Engine."""

import json
import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from simulation.ml.models import (
    SequenceAnomalyReport,
    SequenceProfile,
    SequenceStep,
    SessionTrace,
    TransitionViolation,
)

# UUID and numeric/slug identifier regex pattern for path normalization
PATH_ID_REGEX = re.compile(
    r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\d+|cust-[a-zA-Z0-9]+|acc-[a-zA-Z0-9]+|txn-[a-zA-Z0-9]+)(?=/|$)"
)


class MarkovSequencer:
    """Unsupervised first-order discrete Markov Chain sequencer for API journey profiling."""

    def __init__(self, profile: Optional[SequenceProfile] = None):
        self.profile = profile

    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalizes dynamic path parameters (UUIDs, integers, customer/account slugs) to {id}."""
        # Strip query parameters if present
        clean_path = path.split("?")[0].rstrip("/") or "/"
        normalized = PATH_ID_REGEX.sub("/{id}", clean_path)
        return normalized

    @classmethod
    def normalize_endpoint(cls, method: str, path: str) -> str:
        """Combines HTTP method and normalized path into a canonical endpoint key."""
        return f"{method.upper().strip()} {cls.normalize_path(path)}"

    def train(
        self,
        sessions: List[SessionTrace],
        name: str = "production_markov_profile",
        laplace_epsilon: float = 1e-4,
        anomaly_threshold: float = 6.0,
        min_funnel_probability: float = 0.50,
    ) -> SequenceProfile:
        """Trains a discrete Markov transition matrix from observed session traces."""
        counts: Dict[str, Dict[str, int]] = {}
        all_endpoints_set = set()
        total_transitions = 0

        for session in sessions:
            if not session.steps or len(session.steps) < 2:
                # Need at least 2 steps to form a transition
                if session.steps:
                    all_endpoints_set.add(
                        self.normalize_endpoint(session.steps[0].method, session.steps[0].path)
                    )
                continue

            for i in range(len(session.steps) - 1):
                from_ep = self.normalize_endpoint(session.steps[i].method, session.steps[i].path)
                to_ep = self.normalize_endpoint(session.steps[i + 1].method, session.steps[i + 1].path)

                all_endpoints_set.add(from_ep)
                all_endpoints_set.add(to_ep)

                if from_ep not in counts:
                    counts[from_ep] = {}
                counts[from_ep][to_ep] = counts[from_ep].get(to_ep, 0) + 1
                total_transitions += 1

        all_endpoints = sorted(list(all_endpoints_set))
        M = len(all_endpoints)
        transition_matrix: Dict[str, Dict[str, float]] = {}

        # Compute smoothed probabilities with Laplace epsilon
        for from_ep in all_endpoints:
            transition_matrix[from_ep] = {}
            row_counts = counts.get(from_ep, {})
            row_sum = sum(row_counts.values())

            # Denominator with smoothing across all M declared/observed endpoints
            denom = row_sum + (M * laplace_epsilon)

            for to_ep in all_endpoints:
                count = row_counts.get(to_ep, 0)
                prob = (count + laplace_epsilon) / denom if denom > 0 else (1.0 / M)
                transition_matrix[from_ep][to_ep] = round(prob, 6)

        # Extract critical funnels (e.g. for endpoints that require specific predecessors)
        critical_funnels = self._extract_critical_funnels(
            counts=counts,
            endpoints=all_endpoints,
            min_probability=min_funnel_probability,
        )

        profile = SequenceProfile(
            name=name,
            version="1.0.0",
            total_sessions=len(sessions),
            total_transitions=total_transitions,
            endpoints=all_endpoints,
            transition_matrix=transition_matrix,
            transition_counts=counts,
            critical_funnels=critical_funnels,
            anomaly_threshold=anomaly_threshold,
        )

        self.profile = profile
        return profile

    def evaluate_session(
        self,
        session: SessionTrace,
        profile: Optional[SequenceProfile] = None,
    ) -> SequenceAnomalyReport:
        """Evaluates a session trace against the trained Markov profile."""
        active_profile = profile or self.profile
        if not active_profile:
            raise ValueError("No SequenceProfile loaded for Markov evaluation.")

        endpoints = [
            self.normalize_endpoint(step.method, step.path) for step in session.steps
        ]
        return self._evaluate_endpoint_list(
            endpoints=endpoints,
            session_id=session.session_id,
            subject_id=session.subject_id,
            profile=active_profile,
        )

    def evaluate_sequence(
        self,
        endpoints: List[str],
        session_id: str = "adhoc-eval",
        subject_id: Optional[str] = None,
        profile: Optional[SequenceProfile] = None,
    ) -> SequenceAnomalyReport:
        """Evaluates a raw list of endpoints (e.g. ['GET /login', 'POST /transfer'])."""
        active_profile = profile or self.profile
        if not active_profile:
            raise ValueError("No SequenceProfile loaded for Markov evaluation.")

        normalized_endpoints = []
        for ep in endpoints:
            parts = ep.strip().split(" ", 1)
            if len(parts) == 2:
                normalized_endpoints.append(self.normalize_endpoint(parts[0], parts[1]))
            else:
                normalized_endpoints.append(self.normalize_path(parts[0]))

        return self._evaluate_endpoint_list(
            endpoints=normalized_endpoints,
            session_id=session_id,
            subject_id=subject_id,
            profile=active_profile,
        )

    def _evaluate_endpoint_list(
        self,
        endpoints: List[str],
        session_id: str,
        subject_id: Optional[str],
        profile: SequenceProfile,
    ) -> SequenceAnomalyReport:
        if len(endpoints) < 2:
            return SequenceAnomalyReport(
                session_id=session_id,
                subject_id=subject_id,
                sequence_length=len(endpoints),
                anomaly_score=0.0,
                is_anomalous=False,
                threshold=profile.anomaly_threshold,
            )

        total_nll = 0.0
        violations: List[TransitionViolation] = []
        lowest_step: Optional[TransitionViolation] = None
        min_prob = 1.0

        num_transitions = len(endpoints) - 1
        for i in range(num_transitions):
            from_ep = endpoints[i]
            to_ep = endpoints[i + 1]

            # Lookup probability from transition matrix or default to small epsilon
            from_row = profile.transition_matrix.get(from_ep, {})
            prob = from_row.get(to_ep, 1e-4)

            nll = -math.log(max(prob, 1e-12))
            total_nll += nll

            # Track lowest probability transition
            violation = TransitionViolation(
                from_endpoint=from_ep,
                to_endpoint=to_ep,
                probability=round(prob, 6),
                neg_log_likelihood=round(nll, 3),
                description=f"Transition from '{from_ep}' to '{to_ep}' has empirical probability {prob:.4%}",
            )

            if prob < min_prob:
                min_prob = prob
                lowest_step = violation

            # Flag as violation if transition probability is statistically anomalous (< 1%)
            if prob < 0.01:
                violations.append(violation)

            # Check critical funnel prerequisite violations
            if to_ep in profile.critical_funnels:
                allowed_predecessors = profile.critical_funnels[to_ep]
                if from_ep not in allowed_predecessors:
                    violations.append(
                        TransitionViolation(
                            from_endpoint=from_ep,
                            to_endpoint=to_ep,
                            probability=round(prob, 6),
                            neg_log_likelihood=round(nll, 3),
                            description=f"Workflow Funnel Violation: Target '{to_ep}' requires predecessor in {allowed_predecessors}, but observed '{from_ep}'",
                        )
                    )

        avg_nll = total_nll / num_transitions
        is_anomalous = (avg_nll > profile.anomaly_threshold) or (len(violations) > 0)

        return SequenceAnomalyReport(
            session_id=session_id,
            subject_id=subject_id,
            sequence_length=len(endpoints),
            anomaly_score=round(avg_nll, 3),
            is_anomalous=is_anomalous,
            threshold=profile.anomaly_threshold,
            violations=violations,
            lowest_probability_step=lowest_step,
        )

    def _extract_critical_funnels(
        self,
        counts: Dict[str, Dict[str, int]],
        endpoints: List[str],
        min_probability: float,
    ) -> Dict[str, List[str]]:
        """Identifies endpoints that almost exclusively follow a specific predecessor."""
        funnels: Dict[str, List[str]] = {}

        # Reverse index: to_ep -> {from_ep: count}
        incoming: Dict[str, Dict[str, int]] = {}
        for from_ep, targets in counts.items():
            for to_ep, count in targets.items():
                if to_ep not in incoming:
                    incoming[to_ep] = {}
                incoming[to_ep][from_ep] = count

        for to_ep, sources in incoming.items():
            total_incoming = sum(sources.values())
            if total_incoming < 5:
                continue

            # Check if one or two predecessors account for the vast majority of transitions
            predecessors = []
            for from_ep, count in sources.items():
                in_ratio = count / total_incoming
                if in_ratio >= min_probability:
                    predecessors.append(from_ep)

            if predecessors:
                funnels[to_ep] = predecessors

        return funnels

    @staticmethod
    def save_profile(profile: SequenceProfile, path: Union[str, Path]) -> None:
        """Serializes trained Markov profile to JSON file."""
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(profile.model_dump(), indent=2), encoding="utf-8")

    @staticmethod
    def load_profile(path: Union[str, Path]) -> SequenceProfile:
        """Loads a serialized Markov profile from JSON file."""
        in_path = Path(path)
        if not in_path.exists():
            raise FileNotFoundError(f"Markov profile not found at: {in_path}")
        data = json.loads(in_path.read_text(encoding="utf-8"))
        return SequenceProfile(**data)
