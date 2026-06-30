"""
ARNIE Chart Security Scanner
Vets a pulled Helm chart or manifest BEFORE it can be deployed, producing a
structured risk report that surfaces at the human approval gate.

ARNIE can discover and pull installable content from GitHub (Helm charts, manifests).
That power needs a gate: ARNIE must never deploy arbitrary third-party content without
first inspecting it for danger and letting a human decide with full information.

This scanner does NOT silently block. It INFORMS — it produces a risk report (findings
with severities) that travels with the staged playbook to the approval screen. The human
sees exactly what the content would do and what is concerning, then approves or rejects.
The approval gate enforces; the scanner illuminates.

Findings cover:
  • Source trust       — is this the official repo, or a fork/typosquat?
  • Image provenance    — which images, from which registries?
  • Privilege red flags — privileged, hostNetwork, hostPath, root, cluster-admin, hostPID
  • Embedded secrets    — hardcoded passwords/tokens/keys
  • OpenShift fit       — will it run under OpenShift's SCC model, or assume root/privileged?

Built on the RMCP engine by BLCKBX.
"""

import re
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("arnie.chart-security")

# Severity ordering for sorting/summary.
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(severity: str, check: str, message: str, detail: str = "") -> Dict[str, str]:
    return {"severity": severity, "check": check, "message": message, "detail": detail}


# Registries generally considered reputable/first-party. Not exhaustive — absence
# isn't proof of danger, it's a prompt to look.
TRUSTED_REGISTRY_PREFIXES = (
    "registry.redhat.io", "registry.access.redhat.com", "quay.io/openshift",
    "registry.k8s.io", "gcr.io/google", "ghcr.io",  # ghcr is project-official often
    "docker.io/library",  # official Docker library images
    "mcr.microsoft.com", "public.ecr.aws",
)

# Privilege/escalation markers to scan template/manifest text for.
PRIVILEGE_PATTERNS = {
    r'privileged:\s*true': ("critical", "privileged_container",
                            "Requests a privileged container (full host access)."),
    r'hostNetwork:\s*true': ("high", "host_network",
                            "Uses the host network namespace."),
    r'hostPID:\s*true': ("high", "host_pid",
                        "Shares the host PID namespace."),
    r'hostIPC:\s*true': ("high", "host_ipc",
                        "Shares the host IPC namespace."),
    r'hostPath:': ("high", "host_path",
                  "Mounts a path from the host filesystem."),
    r'runAsUser:\s*0\b': ("medium", "run_as_root",
                         "Configured to run as root (UID 0) — often blocked on OpenShift."),
    r'allowPrivilegeEscalation:\s*true': ("high", "priv_escalation",
                                         "Allows privilege escalation."),
    r'type:\s*cluster-admin': ("critical", "cluster_admin_rbac",
                              "Binds the cluster-admin role (full cluster control)."),
    r'clusterrole.*admin': ("high", "broad_rbac",
                           "Requests broad cluster-level RBAC."),
}

# Hints that secrets may be hardcoded into chart values/templates.
SECRET_PATTERNS = {
    r'(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\'{}]{6,}': "Possible hardcoded password.",
    r'(secret|token|apikey|api_key|access_key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{12,}': "Possible hardcoded secret/token.",
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----': "Embedded private key.",
}


class ChartSecurityScanner:
    """Produces a risk report for pulled installable content."""

    def scan(
        self,
        *,
        source_repo: Optional[str] = None,
        expected_project: Optional[str] = None,
        repo_stars: Optional[int] = None,
        chart_yaml: str = "",
        values_yaml: str = "",
        rendered_text: str = "",
        images: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Scan pulled content. Pass whatever is available; all args optional.

        rendered_text: the concatenated template/manifest text to scan for privilege
                       flags and secrets. images: explicit list of image refs if known.
        Returns: {risk_level, findings, image_summary, summary}.
        """
        findings: List[Dict[str, str]] = []

        findings += self._check_source(source_repo, expected_project, repo_stars)
        image_summary = self._check_images(images, values_yaml, rendered_text, findings)
        self._check_privileges(rendered_text + "\n" + values_yaml, findings)
        self._check_secrets(values_yaml + "\n" + rendered_text, findings)
        self._check_openshift_fit(rendered_text + "\n" + values_yaml, findings)

        findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
        risk = self._aggregate_risk(findings)
        return {
            "risk_level": risk,
            "findings": findings,
            "image_summary": image_summary,
            "summary": self._summarize(findings, risk),
            "scanned": True,
        }

    # ── source trust ──

    def _check_source(self, repo, expected, stars) -> List[Dict[str, str]]:
        out = []
        if not repo:
            out.append(_finding("medium", "source_unknown",
                                "Install source repository is unknown — provenance cannot be verified."))
            return out
        # Typosquat / fork heuristic: if we expected a project owner and it differs.
        if expected and "/" in repo:
            owner = repo.split("/")[0].lower()
            exp_owner = expected.split("/")[0].lower() if "/" in expected else expected.lower()
            if exp_owner and exp_owner not in owner and owner not in exp_owner:
                out.append(_finding("high", "source_mismatch",
                                    f"Repository owner '{owner}' does not match the expected project "
                                    f"'{exp_owner}'. Could be a fork or typosquat — verify before deploying.",
                                    detail=repo))
        if stars is not None and stars < 25:
            out.append(_finding("medium", "low_popularity",
                                f"Source repo has few stars ({stars}); it may be unofficial or unmaintained.",
                                detail=repo))
        if not out:
            out.append(_finding("info", "source_ok",
                                f"Install source: {repo}.", detail=repo))
        return out

    # ── images ──

    def _check_images(self, images, values_yaml, rendered, findings) -> Dict[str, Any]:
        found = set(images or [])
        # Pull image refs out of values/templates if not provided explicitly.
        for txt in (values_yaml, rendered):
            for m in re.finditer(r'image:\s*["\']?([\w./\-]+(:[\w.\-]+)?)["\']?', txt or ""):
                found.add(m.group(1))
            # repo + tag split style
            for m in re.finditer(r'repository:\s*["\']?([\w./\-]+)["\']?', txt or ""):
                found.add(m.group(1))
        images_list = sorted(i for i in found if "/" in i or ":" in i)
        untrusted = []
        for img in images_list:
            if not any(img.startswith(p) for p in TRUSTED_REGISTRY_PREFIXES):
                untrusted.append(img)
        if untrusted:
            findings.append(_finding(
                "medium", "image_provenance",
                f"{len(untrusted)} image(s) come from registries not on the trusted list — review their source.",
                detail=", ".join(untrusted[:6])))
        if any(":latest" in i or (":" not in i) for i in images_list):
            findings.append(_finding(
                "low", "mutable_image_tag",
                "One or more images use ':latest' or an unpinned tag — the running image can change unexpectedly."))
        return {"images": images_list, "untrusted": untrusted}

    # ── privileges ──

    def _check_privileges(self, text, findings):
        low = text or ""
        for pattern, (sev, check, msg) in PRIVILEGE_PATTERNS.items():
            if re.search(pattern, low, re.IGNORECASE):
                findings.append(_finding(sev, check, msg))

    # ── secrets ──

    def _check_secrets(self, text, findings):
        low = text or ""
        for pattern, msg in SECRET_PATTERNS.items():
            if re.search(pattern, low, re.IGNORECASE):
                findings.append(_finding("high", "embedded_secret", msg))
                break  # one flag is enough to prompt review; avoid noisy repeats

    # ── OpenShift compatibility ──

    def _check_openshift_fit(self, text, findings):
        low = (text or "").lower()
        # Charts that hardcode root or privileged commonly fail on OpenShift's SCCs.
        if "runasuser: 0" in low or "privileged: true" in low:
            findings.append(_finding(
                "medium", "openshift_scc",
                "This content assumes root/privileged execution, which OpenShift's default "
                "SecurityContextConstraints block. It may need an SCC adjustment or a securityContext "
                "change to run on OpenShift."))
        if "fsgroup:" not in low and ("persistentvolumeclaim" in low or "volumeclaimtemplates" in low):
            findings.append(_finding(
                "low", "openshift_fsgroup",
                "Uses persistent storage without an explicit fsGroup; on OpenShift the assigned "
                "UID/GID may not match volume permissions. Verify storage access."))

    # ── aggregate ──

    def _aggregate_risk(self, findings) -> str:
        sevs = {f["severity"] for f in findings}
        if "critical" in sevs:
            return "critical"
        if "high" in sevs:
            return "high"
        if "medium" in sevs:
            return "medium"
        if "low" in sevs:
            return "low"
        return "info"

    def _summarize(self, findings, risk) -> str:
        real = [f for f in findings if f["severity"] not in ("info",)]
        if not real:
            return "No notable security concerns found. Review the source and images before deploying."
        counts: Dict[str, int] = {}
        for f in real:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        parts = [f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda x: SEV_ORDER.get(x[0], 9))]
        return (f"Overall risk: {risk}. Findings: " + ", ".join(parts) +
                ". Review before approving — ARNIE will not deploy until you approve.")
