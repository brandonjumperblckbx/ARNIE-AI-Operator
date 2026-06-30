"""
ARNIE Chart Vetting — the trust spine of the Helm install path.

When OpenShift's OperatorHub does not carry what the user wants, ARNIE falls back to
finding a Helm chart (or manifest) on GitHub. Deploying third-party content is the
highest-risk thing ARNIE does, so this module makes trust FIRST-CLASS: discovery and
security scanning are chained into a single gated step. Nothing reaches the cluster
without passing through here and producing a risk report the human sees at approval.

Flow:  resolve (GitHub) -> scan (security) -> risk report -> [human approves] -> install

This module does the resolve + scan and returns a single "vetting" result. It does not
generate or apply anything. The install builder consumes a vetting only after the human
has seen its risk report and approved.

Built on the RMCP engine by BLCKBX.
"""

import logging
from typing import Any, Dict, Optional

from github_resolver import GitHubChartResolver
from chart_security import ChartSecurityScanner

log = logging.getLogger("arnie.chart-vetting")


class ChartVetting:
    """Resolves a project to an installable chart/manifest and vets it for safety,
    as one trust-first step."""

    def __init__(self, github_token: str = ""):
        self.resolver = GitHubChartResolver(token=github_token)
        self.scanner = ChartSecurityScanner()

    def set_token(self, github_token: str) -> None:
        """Update the GitHub token (e.g. from ARNIE settings) to raise rate limits."""
        self.resolver = GitHubChartResolver(token=(github_token or "").strip())

    def vet(self, project: str) -> Dict[str, Any]:
        """Resolve + scan a project. Returns a vetting result:

          {
            ok: bool,                  # was an installable artifact found?
            project, repo, method,     # 'helm_chart' | 'manifest' | None
            resolution: {...},         # full resolver output
            security: {...},           # full risk report (risk_level, findings, images)
            summary: str,              # one-line human summary
            recommend: 'proceed' | 'review' | 'caution',
          }

        'recommend' is advisory only — the human always decides at the approval gate.
        """
        resolution = self.resolver.resolve(project)
        if not resolution.get("resolved"):
            return {
                "ok": False,
                "project": project,
                "repo": resolution.get("repo"),
                "method": None,
                "resolution": resolution,
                "security": None,
                "summary": resolution.get("notes", "No installable chart or manifest found."),
                "recommend": "none",
            }

        # Gather what the scanner needs from the resolution.
        method = resolution.get("method")
        values_yaml = resolution.get("values_yaml", "")
        rendered = resolution.get("manifest_text", "")  # for the manifest path
        images = resolution.get("images", [])

        security = self.scanner.scan(
            source_repo=resolution.get("repo"),
            expected_project=project,
            repo_stars=resolution.get("stars"),
            chart_yaml=resolution.get("chart_yaml", ""),
            values_yaml=values_yaml,
            rendered_text=rendered,
            images=images,
        )

        risk = security.get("risk_level", "info")
        recommend = self._recommend(risk)

        return {
            "ok": True,
            "project": project,
            "repo": resolution.get("repo"),
            "method": method,
            "resolution": resolution,
            "security": security,
            "summary": self._summary(resolution, security),
            "recommend": recommend,
        }

    def _recommend(self, risk: str) -> str:
        if risk in ("critical", "high"):
            return "caution"   # strongly flag for human scrutiny
        if risk in ("medium",):
            return "review"    # worth a look
        return "proceed"       # low/info — still requires human approval

    def _summary(self, resolution: Dict[str, Any], security: Dict[str, Any]) -> str:
        method = resolution.get("method")
        repo = resolution.get("repo")
        risk = security.get("risk_level", "info")
        if method == "helm_chart":
            name = resolution.get("chart_name") or "chart"
            ver = resolution.get("chart_version") or "?"
            base = f"Found Helm chart '{name}' (v{ver}) in {repo}."
        elif method == "manifest":
            base = f"Found install manifest(s) in {repo}."
        else:
            base = f"Found {repo}."
        return f"{base} Security risk: {risk}. Review the findings before approving — nothing deploys until you do."
