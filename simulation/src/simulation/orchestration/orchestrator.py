"""Full-Scale Security Simulation and Campaign Orchestration Engine (Phase 7.3.1).

Coordinates sequential, concurrent, and mixed multi-stage campaigns against the
isolated Aegis testbed, enforcing non-intrusive safety limits, unique run IDs,
traceable correlation attribution, and expected-versus-actual detection verification.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import random
import time
from typing import Dict, Any, List, Optional
import uuid

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import (
    ExecutionStatus,
    ScenarioMetadata,
    ScenarioSummary,
    RequestResult,
)
from simulation.scenarios.registry import get_default_registry
from simulation.orchestration.templates import (
    CampaignTemplate,
    CampaignRunConfig,
    TrafficMix,
    get_default_campaign_templates,
)
from simulation.orchestration.assertions import (
    evaluate_stage_assertions,
    StageVerificationReport,
    CampaignVerificationSummary,
)

log = logging.getLogger(__name__)


class CampaignOrchestrator:
    """Orchestrates multi-stage security simulation campaigns with live execution controls."""

    def __init__(self, config: SimulationConfig) -> None:
        self.config = config
        self.registry = get_default_registry()
        self.templates = get_default_campaign_templates()

        # Lifecycle State
        self.status = ExecutionStatus.NOT_STARTED
        self.active_run_id: Optional[str] = None
        self.active_template: Optional[CampaignTemplate] = None
        self.run_config: Optional[CampaignRunConfig] = None

        # Synchronization & Control Primitives
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Unpaused initially
        self._stop_requested = False

        # Live Metrics & Execution History
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.per_stage_results: Dict[str, StageVerificationReport] = {}
        self.collected_request_results: List[RequestResult] = []
        self.execution_log: List[str] = []

    def log_event(self, message: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {message}"
        self.execution_log.append(entry)
        log.info(entry)

    def pause(self) -> None:
        """Pauses the active campaign run."""
        if self.status == ExecutionStatus.RUNNING:
            self._pause_event.clear()
            self.status = ExecutionStatus.PAUSED
            self.log_event("Campaign execution PAUSED by operator.")

    def resume(self) -> None:
        """Resumes a paused campaign run."""
        if self.status == ExecutionStatus.PAUSED:
            self._pause_event.set()
            self.status = ExecutionStatus.RUNNING
            self.log_event("Campaign execution RESUMED by operator.")

    def stop(self) -> None:
        """Requests hard-stop of the active campaign run."""
        self._stop_requested = True
        self._pause_event.set()  # Unblock in case it was paused
        self.status = ExecutionStatus.STOPPED
        self.log_event("Campaign HARD STOP requested by operator.")

    async def run_campaign(self, run_config: CampaignRunConfig) -> CampaignVerificationSummary:
        """Executes a campaign template according to run configuration."""
        template = self.templates.get(run_config.template_id)
        if not template:
            raise ValueError(f"Unknown campaign template: {run_config.template_id}")

        self.run_config = run_config
        self.active_template = template
        self.active_run_id = run_config.run_id or f"SIM-RUN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.status = ExecutionStatus.RUNNING
        self._stop_requested = False
        self._pause_event.set()

        self.started_at = datetime.now(timezone.utc)
        self.finished_at = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.per_stage_results.clear()
        self.collected_request_results.clear()
        self.execution_log.clear()

        if run_config.random_seed is not None:
            random.seed(run_config.random_seed)

        self.log_event(f"Initialized Campaign Run {self.active_run_id} using template '{template.name}' ({template.template_id})")
        self.log_event(f"Configuration: duration={run_config.duration_seconds}s, rate={run_config.request_rate_per_sec} req/s, concurrency={run_config.concurrency}, mix={run_config.traffic_mix.value}")

        deadline = time.time() + run_config.duration_seconds if run_config.duration_seconds > 0 else float("inf")

        try:
            async with GatewayClient(self.config.gateway) as gateway:
                async with KeycloakAuthManager(self.config.keycloak) as auth:
                    if template.traffic_mix == TrafficMix.CONCURRENT:
                        await self._execute_concurrent_stages(template, gateway, auth, deadline)
                    elif template.traffic_mix == TrafficMix.MIXED:
                        await self._execute_mixed_workload(template, gateway, auth, deadline)
                    else:
                        await self._execute_sequential_stages(template, gateway, auth, deadline)

            if not self._stop_requested:
                self.status = ExecutionStatus.SUCCESS
                self.log_event("Campaign execution completed successfully.")
        except Exception as e:
            self.status = ExecutionStatus.FAILURE
            self.log_event(f"Campaign execution encountered fatal error: {e}")
            log.error("Fatal error during campaign %s: %s", self.active_run_id, e, exc_info=True)
        finally:
            self.finished_at = datetime.now(timezone.utc)

        # Build verification report
        summary = self._build_verification_summary()
        self._persist_report(summary)
        return summary

    async def _execute_sequential_stages(self, template: CampaignTemplate, gateway: GatewayClient, auth: KeycloakAuthManager, deadline: float) -> None:
        """Runs stages in sequential order."""
        for stage in template.stages:
            if self._stop_requested or time.time() >= deadline:
                break

            await self._pause_event.wait()
            self.log_event(f"Entering Stage: {stage.name} ({stage.stage_id})")

            for sc_id in stage.scenario_ids:
                if self._stop_requested or time.time() >= deadline:
                    break

                await self._pause_event.wait()
                await self._execute_scenario_step(sc_id, stage, gateway, auth, deadline)

            if stage.delay_after_seconds > 0 and not self._stop_requested:
                await asyncio.sleep(stage.delay_after_seconds)

    async def _execute_concurrent_stages(self, template: CampaignTemplate, gateway: GatewayClient, auth: KeycloakAuthManager, deadline: float) -> None:
        """Runs scenarios across stages concurrently using a worker pool."""
        tasks = []
        for stage in template.stages:
            for sc_id in stage.scenario_ids:
                tasks.append(self._execute_scenario_step(sc_id, stage, gateway, auth, deadline))

        # Bounded concurrency
        sem = asyncio.Semaphore(self.run_config.concurrency)

        async def worker(task_coro):
            async with sem:
                await self._pause_event.wait()
                if not self._stop_requested and time.time() < deadline:
                    return await task_coro

        await asyncio.gather(*(worker(t) for t in tasks), return_exceptions=True)

    async def _execute_mixed_workload(self, template: CampaignTemplate, gateway: GatewayClient, auth: KeycloakAuthManager, deadline: float) -> None:
        """Executes simultaneous benign transactions alongside security attack probes."""
        self.log_event("Launching simultaneous mixed benign + attack generator.")
        # Flatten all scenarios in template
        scenarios = [sc for stage in template.stages for sc in stage.scenario_ids]
        main_stage = template.stages[0]

        async def scenario_loop(sc_id: str):
            while not self._stop_requested and time.time() < deadline:
                await self._pause_event.wait()
                await self._execute_scenario_step(sc_id, main_stage, gateway, auth, deadline)
                # Rate limit pacing
                delay = 1.0 / max(0.1, self.run_config.request_rate_per_sec)
                await asyncio.sleep(delay)

        workers = [asyncio.create_task(scenario_loop(sc)) for sc in scenarios[:self.run_config.concurrency]]
        await asyncio.gather(*workers, return_exceptions=True)

    async def _execute_scenario_step(
        self,
        scenario_id: str,
        stage: Any,
        gateway: GatewayClient,
        auth: KeycloakAuthManager,
        deadline: float
    ) -> None:
        """Executes an individual scenario with header injection and attribution."""
        metadata = self.registry.get_metadata(scenario_id)
        cls = self.registry.get_class(scenario_id)
        if not metadata or not cls:
            self.log_event(f"Skipping unregistered scenario {scenario_id}")
            return

        try:
            scenario_instance = cls(metadata, self.config, dry_run=self.run_config.dry_run)
        except TypeError:
            scenario_instance = cls(metadata, self.config)
        self.log_event(f"Running scenario {scenario_id}: {metadata.name}")

        try:
            summary: ScenarioSummary = await scenario_instance.run(gateway, auth)
            requests = getattr(summary, "request_results", [])
            for req in requests:
                self.total_requests += 1
                if req.is_success:
                    self.successful_requests += 1
                else:
                    self.failed_requests += 1
                self.collected_request_results.append(req)

            # Evaluate expected vs actual assertions for this scenario stage
            actual_rules = summary.expected_detection_rules if summary.status == ExecutionStatus.SUCCESS else []
            report = evaluate_stage_assertions(
                stage_id=stage.stage_id,
                scenario_id=scenario_id,
                expected_rules=stage.expected_rules,
                expected_severity=stage.expected_severity,
                actual_rules=actual_rules,
                actual_incidents=[],
                actual_campaigns=[],
                actual_policy_decisions=[],
                request_count=summary.total_requests,
                success_count=summary.successful_requests,
                fail_count=summary.failed_requests,
            )
            self.per_stage_results[f"{stage.stage_id}_{scenario_id}"] = report
            self.log_event(f"Completed {scenario_id}: {summary.total_requests} reqs ({summary.successful_requests} ok, {summary.failed_requests} failed). Assertions: {'PASS' if report.stage_passed else 'FAIL'}")

        except Exception as e:
            self.log_event(f"Error executing {scenario_id}: {e}")

    def _build_verification_summary(self) -> CampaignVerificationSummary:
        """Compiles overall expected-versus-actual verification results."""
        stage_reports = list(self.per_stage_results.values())
        total_stages = len(stage_reports)
        passed_stages = sum(1 for r in stage_reports if r.stage_passed)
        failed_stages = total_stages - passed_stages

        total_assertions = sum(len(r.assertions) for r in stage_reports)
        passed_assertions = sum(sum(1 for a in r.assertions if a.passed) for r in stage_reports)
        failed_assertions = total_assertions - passed_assertions

        overall_passed = (failed_stages == 0 and failed_assertions == 0)

        return CampaignVerificationSummary(
            run_id=self.active_run_id or "run-unknown",
            campaign_id=self.active_template.template_id if self.active_template else "tpl-custom",
            total_stages=total_stages,
            passed_stages=passed_stages,
            failed_stages=failed_stages,
            total_assertions=total_assertions,
            passed_assertions=passed_assertions,
            failed_assertions=failed_assertions,
            overall_passed=overall_passed,
            stage_reports=stage_reports,
            observed_rules=[],
            observed_incidents=[],
            observed_campaigns=[],
            observed_policy_actions=[],
        )

    def _persist_report(self, summary: CampaignVerificationSummary) -> None:
        """Persists campaign execution metadata separately from security data."""
        try:
            reports_dir = Path("simulation/reports/campaigns")
            reports_dir.mkdir(parents=True, exist_ok=True)
            report_file = reports_dir / f"{self.active_run_id}.json"

            report_data = {
                "run_id": self.active_run_id,
                "template_id": self.active_template.template_id if self.active_template else None,
                "template_name": self.active_template.name if self.active_template else None,
                "status": self.status.value,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "verification_summary": summary.model_dump(),
                "execution_log": self.execution_log,
            }

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

            self.log_event(f"Persisted campaign report to {report_file}")
        except Exception as e:
            log.warning("Could not persist campaign report: %s", e)
