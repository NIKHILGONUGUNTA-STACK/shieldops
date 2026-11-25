"""Tests for Aegis ShieldOps Shift-Left API Security CI Gate."""

import json
from pathlib import Path
import httpx
import pytest
import respx
from typer.testing import CliRunner
import yaml

from simulation.ci_gate.cli import app
from simulation.ci_gate.models import (
    GateFinding,
    GateReport,
    GateSummary,
    GateVerdict,
    Severity,
    FindingType,
)
from simulation.ci_gate.parser import SpecParser
from simulation.ci_gate.reconciler import SpecReconciler
from simulation.ci_gate.reporter import GateReporter

runner = CliRunner(env={"COLUMNS": "160"})

PRODUCTION_SPECS_DIR = Path(__file__).resolve().parent.parent.parent / "gateway" / "src" / "main" / "resources" / "specs"


@pytest.fixture
def clean_spec_file(tmp_path):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Secure Service API", "version": "1.0.0"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/v1/secure/profile": {
                "get": {
                    "summary": "Get authenticated user profile with ownership check",
                    "description": "Verifies subject ownership before returning profile.",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "email": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
    }
    path = tmp_path / "clean_spec.yaml"
    path.write_text(yaml.dump(spec), encoding="utf-8")
    return str(path)


@pytest.fixture
def vulnerable_spec_file(tmp_path):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Vulnerable Service API", "version": "1.0.0"},
        "paths": {
            "/api/v1/unprotected/resource": {
                "post": {
                    "summary": "Unauthenticated mutating action",
                    # No security block!
                    "responses": {
                        "201": {
                            "description": "Created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "ssn": {"type": "string"},
                                            "credit_card": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/api/v1/records/{recordId}": {
                "get": {
                    "summary": "Get record details by id",
                    "parameters": [
                        {
                            "name": "recordId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},  # Insecure format
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Record info",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "secret_key": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
        },
    }
    path = tmp_path / "vuln_spec.yaml"
    path.write_text(yaml.dump(spec), encoding="utf-8")
    return str(path)


# ==============================================================================
# SpecParser Tests
# ==============================================================================

def test_parser_loads_production_specs():
    for spec_name in ["customer-service.yaml", "account-service.yaml", "transaction-service.yaml"]:
        spec_path = PRODUCTION_SPECS_DIR / spec_name
        assert spec_path.exists(), f"Spec missing at {spec_path}"
        parser = SpecParser(str(spec_path))
        summary, findings = parser.analyze()
        assert summary.total_operations > 0
        assert summary.authenticated_operations == summary.total_operations
        assert summary.critical_count == 0
        assert summary.breaking_count == 0
        assert summary.verdict == GateVerdict.PASSED


def test_parser_detects_unauthenticated_mutating_operation(vulnerable_spec_file):
    parser = SpecParser(vulnerable_spec_file)
    summary, findings = parser.analyze()

    mutating_findings = [f for f in findings if f.finding_type == FindingType.UNAUTHENTICATED_MUTATING_OPERATION]
    assert len(mutating_findings) == 1
    assert mutating_findings[0].severity == Severity.CRITICAL
    assert mutating_findings[0].breaking is True
    assert mutating_findings[0].method == "POST"
    assert mutating_findings[0].path == "/api/v1/unprotected/resource"


def test_parser_detects_sensitive_data_exposure(vulnerable_spec_file):
    parser = SpecParser(vulnerable_spec_file)
    summary, findings = parser.analyze()

    leak_findings = [f for f in findings if f.finding_type == FindingType.SENSITIVE_DATA_EXPOSURE]
    # ssn, credit_card, secret_key
    assert len(leak_findings) >= 2
    exposed_fields = [f.details["field"] for f in leak_findings if f.details]
    assert "ssn" in exposed_fields or "credit_card" in exposed_fields or "secret_key" in exposed_fields
    assert all(f.severity == Severity.CRITICAL for f in leak_findings)
    assert all(f.breaking is True for f in leak_findings)


def test_parser_detects_missing_ownership_and_insecure_format(vulnerable_spec_file):
    parser = SpecParser(vulnerable_spec_file)
    summary, findings = parser.analyze()

    bola_findings = [f for f in findings if f.finding_type == FindingType.MISSING_OWNERSHIP_VALIDATION]
    assert len(bola_findings) == 1
    assert bola_findings[0].severity == Severity.HIGH
    assert bola_findings[0].path == "/api/v1/records/{recordId}"

    fmt_findings = [f for f in findings if f.finding_type == FindingType.INSECURE_PARAMETER_FORMAT]
    assert len(fmt_findings) == 1
    assert fmt_findings[0].severity == Severity.LOW
    assert "recordId" in fmt_findings[0].message


def test_parser_nonexistent_file_raises_error():
    with pytest.raises(FileNotFoundError):
        SpecParser("/non/existent/path/spec.yaml")


# ==============================================================================
# SpecReconciler Tests
# ==============================================================================

def test_reconciler_no_changes(clean_spec_file):
    base = SpecParser(clean_spec_file)
    cand = SpecParser(clean_spec_file)
    diffs, breaking = SpecReconciler.compare_specs(base, cand)
    assert len(breaking) == 0
    assert all(d.change_type == "UNCHANGED" for d in diffs)


def test_reconciler_breaking_endpoint_removal(tmp_path, clean_spec_file):
    base = SpecParser(clean_spec_file)

    # Empty candidate spec
    empty_spec = {
        "openapi": "3.0.3",
        "info": {"title": "Empty API", "version": "1.1.0"},
        "paths": {},
    }
    cand_path = tmp_path / "cand_empty.yaml"
    cand_path.write_text(yaml.dump(empty_spec), encoding="utf-8")
    cand = SpecParser(str(cand_path))

    diffs, breaking = SpecReconciler.compare_specs(base, cand)
    assert len(breaking) == 1
    assert breaking[0].finding_type == FindingType.BREAKING_ENDPOINT_REMOVAL
    assert breaking[0].breaking is True
    assert diffs[0].change_type == "REMOVED"
    assert diffs[0].breaking is True


def test_reconciler_breaking_param_addition(tmp_path):
    base_spec = {
        "openapi": "3.0.3",
        "info": {"title": "API", "version": "1.0.0"},
        "paths": {
            "/api/v1/items": {
                "get": {
                    "parameters": [],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    cand_spec = {
        "openapi": "3.0.3",
        "info": {"title": "API", "version": "1.1.0"},
        "paths": {
            "/api/v1/items": {
                "get": {
                    "parameters": [
                        {
                            "name": "mand_filter",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    b_path = tmp_path / "base.yaml"
    b_path.write_text(yaml.dump(base_spec), encoding="utf-8")
    c_path = tmp_path / "cand.yaml"
    c_path.write_text(yaml.dump(cand_spec), encoding="utf-8")

    diffs, breaking = SpecReconciler.compare_specs(SpecParser(str(b_path)), SpecParser(str(c_path)))
    assert len(breaking) == 1
    assert breaking[0].finding_type == FindingType.BREAKING_PARAM_REQUIRED
    assert breaking[0].breaking is True
    assert "mand_filter" in breaking[0].message


@respx.mock
def test_reconciler_gateway_telemetry_shadow_detection(clean_spec_file):
    respx.get("http://gateway.test/api/v1/security/reconciliation/summary").mock(
        return_value=httpx.Response(
            200,
            json={
                "undocumentedEndpointsCount": 3,
                "shadowRoutes": ["/api/v1/internal/admin", "/debug/pprof"],
            },
        )
    )

    cand = SpecParser(clean_spec_file)
    shadow_findings = SpecReconciler.reconcile_with_gateway("http://gateway.test", cand)
    assert len(shadow_findings) == 1
    assert shadow_findings[0].finding_type == FindingType.SHADOW_ROUTE_DETECTED
    assert "3 active shadow endpoints" in shadow_findings[0].message


# ==============================================================================
# GateReporter Tests
# ==============================================================================

def test_reporter_json_format(clean_spec_file):
    parser = SpecParser(clean_spec_file)
    summary, findings = parser.analyze()
    report = GateReport(
        spec_path=clean_spec_file,
        spec_title=parser.title,
        spec_version=parser.version,
        summary=summary,
        findings=findings,
        contract_diffs=[],
        evaluated_at="2026-11-25T12:00:00Z",
    )
    json_out = GateReporter.render_json(report)
    parsed = json.loads(json_out)
    assert parsed["summary"]["verdict"] == "PASSED"
    assert parsed["summary"]["posture_score"] == 100.0


def test_reporter_terminal_format(vulnerable_spec_file):
    parser = SpecParser(vulnerable_spec_file)
    summary, findings = parser.analyze()
    report = GateReport(
        spec_path=vulnerable_spec_file,
        spec_title=parser.title,
        spec_version=parser.version,
        summary=summary,
        findings=findings,
        contract_diffs=[],
        evaluated_at="2026-11-25T12:00:00Z",
    )
    term_out = GateReporter.render_terminal(report)
    assert "AEGIS SHIELDOPS — SHIFT-LEFT API SECURITY CI GATE" in term_out
    assert "FAILED" in term_out
    assert "BLOCKING CI BUILD" in term_out


def test_reporter_markdown_format(clean_spec_file):
    parser = SpecParser(clean_spec_file)
    summary, findings = parser.analyze()
    report = GateReport(
        spec_path=clean_spec_file,
        spec_title=parser.title,
        spec_version=parser.version,
        summary=summary,
        findings=findings,
        contract_diffs=[],
        evaluated_at="2026-11-25T12:00:00Z",
    )
    md_out = GateReporter.render_markdown(report)
    assert "## ✅ Aegis ShieldOps — API Security CI Gate" in md_out
    assert "> [!NOTE]" in md_out
    assert "| **Overall Gate Verdict** | `PASSED` | `PASSED` | 🟢 PASS |" in md_out


# ==============================================================================
# CLI Commands Integration Tests
# ==============================================================================

def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Aegis ShieldOps API Security CI Gate v1.0.0" in result.stdout


def test_cli_scan_clean_spec_passes(clean_spec_file):
    result = runner.invoke(app, ["scan", clean_spec_file])
    assert result.exit_code == 0
    assert "PASSED" in result.stdout
    assert "Posture Score: 100.0 / 100.0" in result.stdout


def test_cli_scan_vulnerable_spec_blocks_build(vulnerable_spec_file):
    result = runner.invoke(app, ["scan", vulnerable_spec_file])
    assert result.exit_code == 1
    assert "FAILED" in result.stdout
    assert "BLOCKING CI BUILD" in result.stdout


def test_cli_scan_no_fail_on_breaking_allows_exit_zero(vulnerable_spec_file):
    result = runner.invoke(app, ["scan", vulnerable_spec_file, "--no-fail-on-breaking"])
    assert result.exit_code == 0
    assert "FAILED" in result.stdout


def test_cli_scan_markdown_output_file(clean_spec_file, tmp_path):
    out_file = tmp_path / "ci_gate_report.md"
    result = runner.invoke(
        app,
        ["scan", clean_spec_file, "--format", "markdown", "--output-file", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "## ✅ Aegis ShieldOps — API Security CI Gate" in content


def test_cli_scan_invalid_spec_file():
    result = runner.invoke(app, ["scan", "/non/existent/spec.yaml"])
    assert result.exit_code == 2
    assert "Error reading specification" in result.output


def test_cli_diff_breaking_removal(tmp_path, clean_spec_file):
    empty_spec = {
        "openapi": "3.0.3",
        "info": {"title": "Empty API", "version": "1.1.0"},
        "paths": {},
    }
    cand_path = tmp_path / "cand_empty.yaml"
    cand_path.write_text(yaml.dump(empty_spec), encoding="utf-8")

    result = runner.invoke(app, ["diff", clean_spec_file, str(cand_path)])
    assert result.exit_code == 1
    assert "BREAKING_ENDPOINT_REMOVAL" in result.stdout
