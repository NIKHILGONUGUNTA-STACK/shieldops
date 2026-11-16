"""Campaign templates and configuration models for Phase 7.3.1 simulation orchestration."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class TrafficMix(str, Enum):
    """Execution pattern of simulation traffic."""
    SEQUENTIAL = "SEQUENTIAL"
    CONCURRENT = "CONCURRENT"
    MIXED = "MIXED"


class CampaignStage(BaseModel):
    """Individual stage within a multi-stage campaign."""
    stage_id: str = Field(..., description="Unique stage identifier, e.g. stage-1-recon")
    name: str = Field(..., description="Human-readable stage name")
    description: str = Field(default="", description="Stage operational purpose")
    scenario_ids: List[str] = Field(default_factory=list, description="Scenarios executed in this stage")
    target_identities: List[str] = Field(default_factory=list, description="Synthetic user personas used")
    target_tenants: List[str] = Field(default_factory=lambda: ["DEFAULT_TENANT"], description="Tenant boundaries")
    expected_rules: List[str] = Field(default_factory=list, description="Rules expected to trigger in this stage")
    expected_severity: Optional[str] = Field(default=None, description="Expected incident severity")
    delay_after_seconds: float = Field(default=0.0, description="Pause duration after stage completion")


class CampaignTemplate(BaseModel):
    """Reusable campaign blueprint defining sequential or concurrent multi-stage traffic."""
    template_id: str = Field(..., description="Unique template identifier (e.g. TPL-BENIGN-DAY)")
    name: str = Field(..., description="Campaign template display name")
    description: str = Field(default="", description="High-level description of the campaign workflow")
    category: str = Field(default="BENIGN", description="BENIGN, SECURITY, MIXED, or INFRASTRUCTURE")
    traffic_mix: TrafficMix = Field(default=TrafficMix.SEQUENTIAL, description="Execution pattern")
    stages: List[CampaignStage] = Field(default_factory=list, description="Ordered stages in the campaign")
    default_duration_seconds: int = Field(default=60, description="Recommended run duration")
    default_rate_limit: float = Field(default=5.0, description="Recommended max requests per second")
    default_concurrency: int = Field(default=2, description="Recommended worker concurrency")


class CampaignRunConfig(BaseModel):
    """Runtime configuration for an individual campaign execution run."""
    template_id: str
    run_id: Optional[str] = None
    duration_seconds: int = 60
    request_rate_per_sec: float = 5.0
    concurrency: int = 2
    traffic_mix: TrafficMix = TrafficMix.SEQUENTIAL
    identities: List[str] = Field(default_factory=lambda: ["alex_morgan", "sam_taylor"])
    tenants: List[str] = Field(default_factory=lambda: ["DEFAULT_TENANT"])
    random_seed: Optional[int] = 42
    dry_run: bool = False
    custom_scenario_ids: Optional[List[str]] = None


def get_default_campaign_templates() -> Dict[str, CampaignTemplate]:
    """Returns the standardized suite of 5 campaign templates."""
    return {
        "TPL-BENIGN-WORKDAY": CampaignTemplate(
            template_id="TPL-BENIGN-WORKDAY",
            name="Benign Everyday FinTech Banking Workday",
            description="Continuous legitimate customer flow: logins, account balance reads, transaction pagination, and beneficiary checks with zero false-positive alerts.",
            category="BENIGN",
            traffic_mix=TrafficMix.SEQUENTIAL,
            default_duration_seconds=60,
            default_rate_limit=10.0,
            default_concurrency=2,
            stages=[
                CampaignStage(
                    stage_id="stage-1-login-overview",
                    name="Session Initialization & Profile Read",
                    scenario_ids=["SCEN-BENIGN-01", "SCEN-BENIGN-BENEFICIARY"],
                    target_identities=["alex_morgan", "sam_taylor"],
                    expected_rules=[],
                    expected_severity=None,
                    delay_after_seconds=0.5,
                ),
                CampaignStage(
                    stage_id="stage-2-portfolio-pagination",
                    name="Account Balances & Statement Pagination",
                    scenario_ids=["SCEN-BENIGN-02", "SCEN-BENIGN-PAGINATION"],
                    target_identities=["alex_morgan"],
                    expected_rules=[],
                    expected_severity=None,
                ),
            ],
        ),
        "TPL-BOLA-EXFIL-CAMPAIGN": CampaignTemplate(
            template_id="TPL-BOLA-EXFIL-CAMPAIGN",
            name="Full-Scale Multi-Stage BOLA & Exfiltration Campaign",
            description="Classic APT kill-chain: Actuator reconnaissance -> Sequential 403 BOLA probing -> Confirmed 200 cross-owner exploit -> Rapid bulk extraction.",
            category="SECURITY",
            traffic_mix=TrafficMix.SEQUENTIAL,
            default_duration_seconds=90,
            default_rate_limit=8.0,
            default_concurrency=2,
            stages=[
                CampaignStage(
                    stage_id="stage-1-recon",
                    name="Reconnaissance & Endpoint Discovery",
                    scenario_ids=["SCEN-EXFIL-RECON-PROBE"],
                    target_identities=["attacker_recon"],
                    expected_rules=["RULE-PROBE-01"],
                    expected_severity="LOW",
                    delay_after_seconds=1.0,
                ),
                CampaignStage(
                    stage_id="stage-2-probing",
                    name="Authorization Probing (403 Denials)",
                    scenario_ids=["SCEN-BOLA-02"],
                    target_identities=["attacker_bola"],
                    expected_rules=["RULE-BOLA-02"],
                    expected_severity="MEDIUM",
                    delay_after_seconds=1.0,
                ),
                CampaignStage(
                    stage_id="stage-3-exploitation",
                    name="Confirmed BOLA Unauthorized Extraction",
                    scenario_ids=["SCEN-BOLA-05", "SCEN-BULK-EXTRACT-01"],
                    target_identities=["attacker_bola"],
                    expected_rules=["RULE-BOLA-CONFIRMED-01", "RULE-BULK-EXTRACT-01", "POL-CAMPAIGN-01"],
                    expected_severity="CRITICAL",
                ),
            ],
        ),
        "TPL-LOW-SLOW-STEALTH": CampaignTemplate(
            template_id="TPL-LOW-SLOW-STEALTH",
            name="Low-and-Slow Multi-Domain Extraction Campaign",
            description="Evasive creeping extraction querying sub-threshold request frequencies distributed across Customer, Account, and Transfer domains.",
            category="SECURITY",
            traffic_mix=TrafficMix.SEQUENTIAL,
            default_duration_seconds=120,
            default_rate_limit=2.0,
            default_concurrency=1,
            stages=[
                CampaignStage(
                    stage_id="stage-1-creeping-read",
                    name="Sub-Threshold Distributed Read",
                    scenario_ids=["SCEN-EXFIL-LOW-SLOW-MULTI", "SCEN-EXTRACT-SLOW"],
                    target_identities=["attacker_stealth"],
                    expected_rules=["RULE-ADV-EXTRACT-01", "POL-LOW-SLOW-01"],
                    expected_severity="HIGH",
                ),
            ],
        ),
        "TPL-FULL-MIXED-WORKLOAD": CampaignTemplate(
            template_id="TPL-FULL-MIXED-WORKLOAD",
            name="Full Mixed Production Traffic (Benign + Multi-Vector Attacks)",
            description="High-fidelity live SOC testbed: Benign customer journeys run simultaneously with injection probes, auth tampering, and multi-tenant boundary checks.",
            category="MIXED",
            traffic_mix=TrafficMix.MIXED,
            default_duration_seconds=120,
            default_rate_limit=15.0,
            default_concurrency=4,
            stages=[
                CampaignStage(
                    stage_id="stage-1-mixed-parallel",
                    name="Concurrent Authorized Traffic & Probes",
                    scenario_ids=[
                        "SCEN-BENIGN-01",
                        "SCEN-MIXED-CONCURRENT",
                        "SCEN-SEC-AUTH-ABUSE",
                        "SCEN-SEC-INJECTION-PROBE",
                        "SCEN-MIXED-MULTI-TENANT",
                    ],
                    target_identities=["alex_morgan", "sam_taylor", "attacker_injection", "tenant-2-user"],
                    expected_rules=["RULE-AUTH-01", "RULE-INJ-01", "RULE-BOLA-01"],
                    expected_severity="HIGH",
                ),
            ],
        ),
        "TPL-INFRA-RESILIENCE": CampaignTemplate(
            template_id="TPL-INFRA-RESILIENCE",
            name="Infrastructure & Telemetry Ingestion Resilience",
            description="Evaluates gateway telemetry pipeline performance under sudden traffic bursts, edge boundary conditions, and non-existent microservice recovery.",
            category="INFRASTRUCTURE",
            traffic_mix=TrafficMix.SEQUENTIAL,
            default_duration_seconds=45,
            default_rate_limit=25.0,
            default_concurrency=3,
            stages=[
                CampaignStage(
                    stage_id="stage-1-burst-backlog",
                    name="Burst Telemetry Ingestion",
                    scenario_ids=["SCEN-INFRA-BACKLOG", "SCEN-EDGE-WINDOW-BOUNDARY"],
                    target_identities=["alex_morgan"],
                    expected_rules=[],
                    expected_severity=None,
                ),
                CampaignStage(
                    stage_id="stage-2-unavailable-recovery",
                    name="Service Isolation & Graceful Recovery",
                    scenario_ids=["SCEN-INFRA-UNAVAILABLE"],
                    target_identities=["anonymous"],
                    expected_rules=[],
                    expected_severity=None,
                ),
            ],
        ),
    }

