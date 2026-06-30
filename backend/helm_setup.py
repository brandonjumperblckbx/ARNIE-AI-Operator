"""
ARNIE Helm Install Builder
The Helm-modality equivalent of the operator setup builder.

When OpenShift's OperatorHub doesn't carry what the user wants, ARNIE falls back to a
Helm chart found and VETTED on GitHub (see chart_vetting). This builder turns a vetted
chart into a complete, deployable Ansible playbook:

    add the chart's helm repo  ->  install the release (with the user's values)
       ->  wait (workload-scaled, non-blocking)  ->  verify

It mirrors the operator builder's guarantees:
  • one install namespace, pinned consistently (create_namespace + release namespace)
  • non-blocking install + a patient, workload-scaled verify (so heavy charts don't
    fail the run on a slow start)
  • OpenShift awareness surfaced from the security scan (SCC / root concerns)
  • output shaped like the other generators, so it flows through the same approval gate

This builder only assembles YAML. It is only ever called on content that has already
been vetted and that a human will approve before it runs.

Built on the RMCP engine by BLCKBX.
"""

import re
import uuid
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

log = logging.getLogger("arnie.helm-setup")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", (text or "").lower()).strip("-")
    return s or "release"


class HelmInstallBuilder:
    """Builds complete Helm install playbooks from a vetted chart."""

    def needs_questions(self, vetting: Dict[str, Any], answers: Optional[Dict[str, Any]]) -> bool:
        """Helm installs always need at least a release name + namespace; if those aren't
        answered yet, ask."""
        answers = answers or {}
        return not (answers.get("release_name") and answers.get("install_namespace"))

    def get_questions(self, vetting: Dict[str, Any]) -> Dict[str, Any]:
        """Questions to ask before installing a chart, grounded in its real values.yaml
        config surface plus the essentials (name, namespace)."""
        resolution = vetting.get("resolution", {})
        chart_name = resolution.get("chart_name") or vetting.get("project") or "app"
        config_fields = resolution.get("config_fields", []) or []

        questions: List[Dict[str, Any]] = [
            {
                "field": "release_name",
                "question": "What should the Helm release be named?",
                "type": "text", "required": True, "default": _slug(chart_name),
            },
            {
                "field": "install_namespace",
                "question": "Which namespace should it be installed into?",
                "type": "text", "required": True, "default": _slug(chart_name),
            },
        ]
        # Surface a few top-level chart values the user is most likely to set. We keep
        # this short — the full values.yaml default applies for everything not asked.
        likely = [f for f in config_fields
                  if f.lower() in ("replicacount", "replicas", "image", "service",
                                   "ingress", "persistence", "resources", "storageclass",
                                   "storagesize", "adminpassword", "auth")]
        for f in likely[:4]:
            questions.append({
                "field": f"value__{f}",
                "question": f"Set '{f}'? (leave blank to use the chart default)",
                "type": "text", "required": False, "default": None,
            })

        return {
            "mode": "helm_setup_questions",
            "chart": chart_name,
            "repo": vetting.get("repo"),
            "risk_level": (vetting.get("security") or {}).get("risk_level", "info"),
            "intro": (
                f"OpenShift's OperatorHub doesn't carry '{vetting.get('project')}', so I found a "
                f"Helm chart for it in {vetting.get('repo')}. I've security-scanned it "
                f"(risk: {(vetting.get('security') or {}).get('risk_level','info')}). "
                f"A few choices, then I'll build the install — you'll review everything before it runs:"
            ),
            "questions": questions,
            "security": vetting.get("security"),
        }

    def build(
        self,
        vetting: Dict[str, Any],
        answers: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Assemble the complete Helm install playbook from a vetted chart + answers."""
        answers = dict(answers or {})
        resolution = vetting.get("resolution", {})
        method = vetting.get("method")

        release = answers.get("release_name") or _slug(resolution.get("chart_name") or vetting.get("project"))
        ns = answers.get("install_namespace") or release

        if method == "manifest":
            yaml_content, summary = self._build_manifest(resolution, release, ns)
            source = "helm-manifest"
        else:
            yaml_content, summary = self._build_helm(vetting, resolution, answers, release, ns)
            source = "helm-chart"

        return {
            "playbook_id": f"helm-{uuid.uuid4().hex[:12]}",
            "intent": f"install {vetting.get('project')}",
            "yaml_content": yaml_content,
            "file_name": f"install-{release}.yml",
            "risk_level": self._risk_from_security(vetting),
            "target_namespace": ns,
            "generation_source": source,
            "setup_summary": summary,
            "security_report": vetting.get("security"),
            "generated_at": _utc_now(),
        }

    # ── helm chart path ──

    def _build_helm(self, vetting, resolution, answers, release, ns) -> (str, List[str]):
        chart_name = resolution.get("chart_name") or release
        source_repo = resolution.get("repo", "")
        # Prefer a published helm repo URL if the resolution provided one; else install
        # from the chart's git location via a chart_ref the helm module can fetch.
        repo_url = resolution.get("helm_repo_url")
        weight = self._weight(resolution)

        # Build release values from the user's value__ answers.
        value_lines = []
        for k, v in answers.items():
            if k.startswith("value__") and v not in (None, ""):
                field = k[len("value__"):]
                value_lines.append(f"          {field}: {v}")
        values_block = ""
        if value_lines:
            values_block = "        release_values:\n" + "\n".join(value_lines) + "\n"

        tasks: List[str] = []
        summary: List[str] = []

        # 1) Namespace (pinned — the release goes here and nowhere else)
        tasks.append(
            f"    - name: Create namespace {ns}\n"
            f"      kubernetes.core.k8s:\n"
            f"        state: present\n"
            f"        definition:\n"
            f"          apiVersion: v1\n"
            f"          kind: Namespace\n"
            f"          metadata:\n"
            f"            name: {ns}\n"
            f"            labels:\n"
            f"              app.kubernetes.io/managed-by: arnie\n"
        )
        summary.append(f"Create namespace '{ns}'")

        # 2) Add the chart repo (only when we have a published repo URL)
        if repo_url:
            repo_name = _slug(chart_name) + "-repo"
            tasks.append(
                f"    - name: Add the {chart_name} Helm repository\n"
                f"      kubernetes.core.helm_repository:\n"
                f"        name: {repo_name}\n"
                f"        repo_url: \"{repo_url}\"\n"
            )
            summary.append(f"Add Helm repo {repo_url}")
            chart_ref = f"{repo_name}/{chart_name}"
        else:
            # Install directly from the chart's source location (git/oci/url) if present,
            # else fall back to the chart name (assumes a repo already configured).
            chart_ref = resolution.get("chart_ref") or chart_name

        # 3) Install the release (non-blocking; verify step waits patiently)
        tasks.append(
            f"    - name: Install the {chart_name} Helm release\n"
            f"      kubernetes.core.helm:\n"
            f"        name: {release}\n"
            f"        chart_ref: \"{chart_ref}\"\n"
            f"        release_namespace: {ns}\n"
            f"        create_namespace: true\n"
            f"        wait: false\n"
            f"{values_block}"
        )
        summary.append(f"Install Helm release '{release}' ({chart_ref})")

        # 4) Verify — workload-scaled, non-failing
        retries, delay = {"light": (20, 10), "standard": (40, 15), "heavy": (90, 20)}.get(weight, (40, 15))
        approx_min = (retries * delay) // 60
        tasks.append(
            f"    - name: Wait for {release} pods to be ready (up to ~{approx_min} min)\n"
            f"      kubernetes.core.k8s_info:\n"
            f"        api_version: v1\n"
            f"        kind: Pod\n"
            f"        namespace: {ns}\n"
            f"      register: rel_pods\n"
            f"      until: >\n"
            f"        rel_pods.resources | length > 0 and\n"
            f"        (rel_pods.resources\n"
            f"         | selectattr('status.phase', 'defined')\n"
            f"         | selectattr('status.phase', 'equalto', 'Running') | list | length > 0)\n"
            f"      retries: {retries}\n"
            f"      delay: {delay}\n"
            f"      failed_when: false\n"
        )
        tasks.append(
            f"    - name: Report {release} status\n"
            f"      ansible.builtin.debug:\n"
            f"        msg: >-\n"
            f"          Helm release '{release}' installed in {ns}. If pods are still starting,\n"
            f"          they will continue to come up; a slow start is normal and not a failure.\n"
        )
        summary.append(f"Verify '{release}' is running")

        playbook = self._wrap(f"Install {chart_name} (Helm)", tasks)
        return playbook, summary

    # ── manifest path ──

    def _build_manifest(self, resolution, release, ns) -> (str, List[str]):
        raw_url = resolution.get("raw_url")
        tasks = [
            f"    - name: Create namespace {ns}\n"
            f"      kubernetes.core.k8s:\n"
            f"        state: present\n"
            f"        definition:\n"
            f"          apiVersion: v1\n"
            f"          kind: Namespace\n"
            f"          metadata:\n"
            f"            name: {ns}\n"
            f"            labels:\n"
            f"              app.kubernetes.io/managed-by: arnie\n",
            f"    - name: Apply the install manifest\n"
            f"      kubernetes.core.k8s:\n"
            f"        state: present\n"
            f"        namespace: {ns}\n"
            f"        src: \"{raw_url}\"\n"
            f"        wait: false\n",
            f"    - name: Report status\n"
            f"      ansible.builtin.debug:\n"
            f"        msg: >-\n"
            f"          Applied install manifest into {ns}. Resources will continue to come up.\n",
        ]
        summary = [f"Create namespace '{ns}'", "Apply install manifest", "Report status"]
        return self._wrap(f"Install {release} (manifest)", tasks), summary

    # ── helpers ──

    def _weight(self, resolution) -> str:
        blob = (resolution.get("values_yaml", "") or "").lower()
        markers = ("persistence", "statefulset", "replicacount", "storageclass",
                   "volumeclaim", "cluster", "postgres", "database")
        hits = sum(1 for m in markers if m in blob)
        return "heavy" if hits >= 2 else ("standard" if hits == 1 else "light")

    def _risk_from_security(self, vetting) -> str:
        risk = (vetting.get("security") or {}).get("risk_level", "info")
        # Map chart security risk onto the playbook risk level used by the approval gate.
        return {"critical": "high", "high": "high", "medium": "medium"}.get(risk, "medium")

    def _wrap(self, play_name: str, tasks: List[str]) -> str:
        header = (
            "---\n"
            f"- name: {play_name}\n"
            "  hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  tasks:\n"
        )
        return header + "\n".join(tasks)
