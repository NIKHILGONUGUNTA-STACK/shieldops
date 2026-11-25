"""Multi-format report renderer for Aegis Shift-Left CI Gate (Terminal, GitHub PR Markdown, JSON)."""

import json
from simulation.ci_gate.models import GateReport, GateVerdict, Severity


class GateReporter:
    """Renders GateReport into terminal ANSI, GitHub Markdown, or JSON formats."""

    @staticmethod
    def render_json(report: GateReport) -> str:
        return json.dumps(report.model_dump(), indent=2)

    @staticmethod
    def render_terminal(report: GateReport) -> str:
        s = report.summary
        verdict_color = "\033[92m" if s.verdict == GateVerdict.PASSED else "\033[91m"
        reset = "\033[0m"
        bold = "\033[1m"
        cyan = "\033[96m"
        yellow = "\033[93m"

        lines = [
            f"{bold}========================================================================{reset}",
            f"{bold}        🛡️  AEGIS SHIELDOPS — SHIFT-LEFT API SECURITY CI GATE{reset}",
            f"{bold}========================================================================{reset}",
            f"Specification: {cyan}{report.spec_title} (v{report.spec_version}){reset}",
            f"File Target:   {report.spec_path}",
            f"Evaluated At:  {report.evaluated_at}",
            f"Gateway Check: {'Connected (' + str(report.gateway_url) + ')' if report.gateway_connected else 'Offline static verification'}",
            "",
            f"{bold}--- GATE VERDICT ---{reset}",
            f"Status:        {verdict_color}{bold}{s.verdict.value}{reset}",
            f"Posture Score: {bold}{s.posture_score} / 100.0{reset}",
            f"Operations:    {s.total_operations} declared ({s.authenticated_operations} auth, {s.unauthenticated_operations} public)",
            f"Discrepancies: {s.critical_count} Critical, {s.high_count} High, {s.medium_count} Medium, {s.low_count} Low",
            f"Breaking Flaws:{bold} {s.breaking_count}{reset}",
            f"{bold}------------------------------------------------------------------------{reset}",
        ]

        if report.contract_diffs:
            lines.append(f"\n{bold}[CONTRACT DIFF SUMMARY]{reset}")
            for d in report.contract_diffs:
                badge = f"[{d.change_type}]"
                if d.change_type == "REMOVED":
                    badge = f"\033[91m{badge}\033[0m"
                elif d.change_type == "ADDED":
                    badge = f"\033[92m{badge}\033[0m"
                elif d.change_type == "MODIFIED":
                    badge = f"\033[93m{badge}\033[0m"
                lines.append(f"  {badge} {d.method:<6} {d.path}")
                for detail in d.details:
                    lines.append(f"     -> {detail}")

        if report.findings:
            lines.append(f"\n{bold}[SECURITY DISCREPANCIES & FINDINGS]{reset}")
            for idx, f in enumerate(report.findings, 1):
                sev_color = "\033[91m" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "\033[93m"
                lines.append(f"  {idx}. {sev_color}[{f.severity.value}]{reset} {f.method} {f.path} ({f.finding_type.value})")
                lines.append(f"     Finding:     {f.message}")
                lines.append(f"     Remediation: {f.remediation}")
                if f.breaking:
                    lines.append(f"     Status:      \033[91m{bold}BLOCKING CI BUILD{reset}")
                lines.append("")
        else:
            lines.append(f"\n\033[92m✓ All declared endpoints satisfy ShieldOps zero-trust security invariants.\033[0m\n")

        lines.append(f"{bold}========================================================================{reset}")
        return "\n".join(lines)

    @staticmethod
    def render_markdown(report: GateReport) -> str:
        s = report.summary
        status_emoji = "✅" if s.verdict == GateVerdict.PASSED else ("⚠️" if s.verdict == GateVerdict.WARNING else "❌")
        callout_type = "NOTE" if s.verdict == GateVerdict.PASSED else ("WARNING" if s.verdict == GateVerdict.WARNING else "CAUTION")

        md = [
            f"## {status_emoji} Aegis ShieldOps — API Security CI Gate",
            "",
            f"> [!{callout_type}]",
            f"> **CI Gate Verdict: `{s.verdict.value}`** | API Posture Score: **`{s.posture_score} / 100.0`** | Breaking Changes: **`{s.breaking_count}`**",
            f"> Target: `{report.spec_title}` (v`{report.spec_version}`) at `{report.spec_path}`",
            "",
            "### 1. Operations & Compliance Summary",
            "",
            "| Metric | Value | Threshold / Target | Status |",
            "| :--- | :---: | :---: | :--- |",
            f"| **Overall Gate Verdict** | `{s.verdict.value}` | `PASSED` | {'🟢 PASS' if s.verdict == GateVerdict.PASSED else '🔴 BLOCKED'} |",
            f"| **Security Posture Score** | **{s.posture_score}%** | ≥ 75.0% | {'🟢 ADEQUATE' if s.posture_score >= 75.0 else '🔴 INADEQUATE'} |",
            f"| **Total Declared Operations** | {s.total_operations} | — | ℹ️ Cataloged |",
            f"| **Authenticated Endpoints** | {s.authenticated_operations} | {s.total_operations} | {'🟢' if s.unauthenticated_operations == 0 else '🟡'} |",
            f"| **Public / Unauthenticated** | {s.unauthenticated_operations} | 0 Mutating | {'🟢' if s.critical_count == 0 else '🔴 LEAK HAZARD'} |",
            f"| **Critical Discrepancies** | {s.critical_count} | 0 | {'🟢 0' if s.critical_count == 0 else '🔴 ' + str(s.critical_count)} |",
            f"| **High Severity Warnings** | {s.high_count} | 0 | {'🟢 0' if s.high_count == 0 else '🟡 ' + str(s.high_count)} |",
            "",
        ]

        if report.contract_diffs:
            md.extend([
                "### 2. Contract Revisions & Structural Diff",
                "",
                "| Change | Method | Endpoint Route | Breaking? | Details |",
                "| :--- | :---: | :--- | :---: | :--- |",
            ])
            for d in report.contract_diffs:
                change_badge = f"`{d.change_type}`"
                breaking_badge = "🚨 **YES**" if d.breaking else "No"
                details_text = "<br>".join(d.details) if d.details else (d.summary or "—")
                md.append(f"| {change_badge} | **`{d.method}`** | `{d.path}` | {breaking_badge} | {details_text} |")
            md.append("")

        if report.findings:
            md.extend([
                "### 3. Detected Security Discrepancies",
                "",
                "| Severity | Finding ID / Type | Target Endpoint | Description | Recommended Shift-Left Fix |",
                "| :--- | :---: | :--- | :--- | :--- |",
            ])
            for f in report.findings:
                sev_badge = f"**`{f.severity.value}`**"
                if f.severity == Severity.CRITICAL:
                    sev_badge = f"🔴 `{f.severity.value}`"
                elif f.severity == Severity.HIGH:
                    sev_badge = f"🟠 `{f.severity.value}`"
                elif f.severity == Severity.MEDIUM:
                    sev_badge = f"🟡 `{f.severity.value}`"

                md.append(f"| {sev_badge} | `{f.id}`<br>`{f.finding_type.value}` | `{f.method} {f.path}` | {f.message} | {f.remediation} |")
            md.append("")
        else:
            md.extend([
                "### 3. Security Findings",
                "",
                "🎉 **Zero security discrepancies detected.** All declared endpoints enforce mandatory authentication, declare valid parameter formats, and satisfy Zero-Trust API invariants.",
                "",
            ])

        md.extend([
            "---",
            f"*Audited by [Aegis ShieldOps API Security Gate](https://github.com/NIKHILGONUGUNTA-STACK/shieldops) at {report.evaluated_at}*",
        ])

        return "\n".join(md)
