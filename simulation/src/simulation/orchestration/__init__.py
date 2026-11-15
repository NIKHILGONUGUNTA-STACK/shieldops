"""Campaign orchestration package for ShieldOps simulation."""

from simulation.orchestration.templates import (
    CampaignTemplate,
    CampaignStage,
    CampaignRunConfig,
    TrafficMix,
    get_default_campaign_templates,
)
from simulation.orchestration.assertions import (
    DetectionAssertionResult,
    StageVerificationReport,
    CampaignVerificationSummary,
    evaluate_stage_assertions,
)
from simulation.orchestration.orchestrator import CampaignOrchestrator

__all__ = [
    "CampaignTemplate",
    "CampaignStage",
    "CampaignRunConfig",
    "TrafficMix",
    "get_default_campaign_templates",
    "DetectionAssertionResult",
    "StageVerificationReport",
    "CampaignVerificationSummary",
    "evaluate_stage_assertions",
    "CampaignOrchestrator",
]

