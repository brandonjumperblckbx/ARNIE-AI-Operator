"""
ARNIE GitHub Chart Resolver
Discovery engine for "install whatever you want on OpenShift."

When a user asks to install something that isn't a grounded operator or a known Helm
chart, ARNIE searches GitHub for the project, locates its installable content (a Helm
chart, or raw manifests), and pulls the authoritative source files — Chart.yaml and
values.yaml — so the install is grounded in what the maintainers actually ship, not in
a guess or a stale blog post.

This is the same grounding philosophy as the operator CRD inspection and the cluster
vision: don't hallucinate, read the real thing. Here the "real thing" is the project's
own chart on GitHub.

The resolver only READS from GitHub (search + raw content GET). It produces a resolution
describing what was found and how it would be installed. Nothing is deployed here — the
resolution flows to the security scanner, then to playbook generation, then to the human
approval gate.

Built on the RMCP engine by BLCKBX.
"""

import re
import base64
import logging
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("arnie.github-resolver")

GITHUB_API = "https://api.github.com"

# Where charts commonly live inside a repo.
CHART_PATH_HINTS = [
    "Chart.yaml", "chart/Chart.yaml", "charts/Chart.yaml",
    "helm/Chart.yaml", "deploy/helm/Chart.yaml", "deployment/helm/Chart.yaml",
]

# Where raw install manifests commonly live.
MANIFEST_PATH_HINTS = [
    "install.yaml", "deploy/install.yaml", "manifests/install.yaml",
    "kubernetes/deployment.yaml", "deploy/kubernetes.yaml", "k8s/deployment.yaml",
]


class GitHubChartResolver:
    """Finds and pulls installable content for a project from GitHub (read-only)."""

    def __init__(self, token: str = "", timeout: float = 20.0):
        # An optional token raises rate limits and allows private repos; not required
        # for public discovery. Read-only scopes only.
        self.token = (token or "").strip()
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "User-Agent": "ARNIE-AI"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        try:
            r = httpx.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        except httpx.HTTPError as e:
            log.warning("GitHub request failed: %s", e)
            return None
        if r.status_code == 403 and "rate limit" in r.text.lower():
            log.warning("GitHub rate limit hit (configure a token to raise it).")
            return None
        if r.status_code >= 400:
            return None
        return r.json()

    # ── search ──

    def search_repo(self, query: str) -> List[Dict[str, Any]]:
        """Search GitHub repositories for the project, best matches first."""
        data = self._get(f"{GITHUB_API}/search/repositories",
                         params={"q": query, "sort": "stars", "order": "desc", "per_page": 5})
        if not data:
            return []
        out = []
        for item in data.get("items", []):
            out.append({
                "full_name": item["full_name"],          # owner/repo
                "stars": item.get("stargazers_count", 0),
                "description": item.get("description") or "",
                "default_branch": item.get("default_branch", "main"),
                "html_url": item.get("html_url"),
                "archived": item.get("archived", False),
            })
        return out

    def best_repo(self, project: str) -> Optional[Dict[str, Any]]:
        """Pick the most likely official repo for a project name."""
        candidates = self.search_repo(project)
        if not candidates:
            return None
        name = project.lower().replace(" ", "-").replace("_", "-")
        # Prefer an exact-ish repo-name match, else the highest-starred non-archived.
        for c in candidates:
            repo_name = c["full_name"].split("/")[-1].lower()
            if repo_name == name or name in repo_name:
                if not c["archived"]:
                    return c
        for c in candidates:
            if not c["archived"]:
                return c
        return candidates[0]

    # ── locate + pull chart ──

    def _raw_file(self, full_name: str, path: str, branch: str) -> Optional[str]:
        """Fetch a file's text content via the contents API (works for public + private)."""
        data = self._get(f"{GITHUB_API}/repos/{full_name}/contents/{path}",
                         params={"ref": branch})
        if not data or not isinstance(data, dict):
            return None
        if data.get("encoding") == "base64" and data.get("content"):
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    def find_chart(self, full_name: str, branch: str) -> Optional[Dict[str, Any]]:
        """Look for a Helm chart in the usual locations; return its Chart.yaml +
        values.yaml text if found."""
        for chart_path in CHART_PATH_HINTS:
            chart_yaml = self._raw_file(full_name, chart_path, branch)
            if chart_yaml and "name:" in chart_yaml:
                base = chart_path.rsplit("Chart.yaml", 1)[0]
                values_yaml = self._raw_file(full_name, base + "values.yaml", branch) or ""
                return {
                    "kind": "helm_chart",
                    "source_repo": full_name,
                    "chart_path": chart_path,
                    "chart_yaml": chart_yaml,
                    "values_yaml": values_yaml,
                    "chart_name": self._yaml_field(chart_yaml, "name"),
                    "chart_version": self._yaml_field(chart_yaml, "version"),
                    "app_version": self._yaml_field(chart_yaml, "appVersion"),
                }
        return None

    def find_chart_in_sibling_repo(self, full_name: str) -> Optional[Dict[str, Any]]:
        """Many projects publish their chart in a separate '<owner>/helm-charts' (or
        similar) repo rather than the main repo. Check those common siblings."""
        owner = full_name.split("/")[0]
        project = full_name.split("/")[-1]
        sibling_candidates = [
            f"{owner}/helm-charts",
            f"{owner}/charts",
            f"{owner}/helm",
            f"{owner}/{project}-helm",
            f"{owner}/{project}-charts",
        ]
        # Within a charts repo, the chart usually lives under charts/<name>/Chart.yaml.
        inner_paths = [
            f"charts/{project}/Chart.yaml",
            f"charts/{project}/Chart.yaml",
            f"{project}/Chart.yaml",
            "Chart.yaml",
        ]
        for sib in sibling_candidates:
            repo_meta = self._get(f"{GITHUB_API}/repos/{sib}")
            if not repo_meta or not isinstance(repo_meta, dict):
                continue
            branch = repo_meta.get("default_branch", "main")
            for path in inner_paths:
                chart_yaml = self._raw_file(sib, path, branch)
                if chart_yaml and "name:" in chart_yaml:
                    base = path.rsplit("Chart.yaml", 1)[0]
                    values_yaml = self._raw_file(sib, base + "values.yaml", branch) or ""
                    return {
                        "kind": "helm_chart",
                        "source_repo": sib,
                        "chart_path": path,
                        "chart_yaml": chart_yaml,
                        "values_yaml": values_yaml,
                        "chart_name": self._yaml_field(chart_yaml, "name"),
                        "chart_version": self._yaml_field(chart_yaml, "version"),
                        "app_version": self._yaml_field(chart_yaml, "appVersion"),
                    }
        return None

    def find_manifest(self, full_name: str, branch: str) -> Optional[Dict[str, Any]]:
        """Fallback: look for a raw install manifest."""
        for path in MANIFEST_PATH_HINTS:
            text = self._raw_file(full_name, path, branch)
            if text and ("kind:" in text and "apiVersion:" in text):
                return {
                    "kind": "manifest",
                    "manifest_path": path,
                    "manifest_text": text,
                    "raw_url": f"https://raw.githubusercontent.com/{full_name}/{branch}/{path}",
                }
        return None

    # ── top-level resolution ──

    def resolve(self, project: str) -> Dict[str, Any]:
        """Resolve a free-text project name into an installable artifact.

        Returns a dict describing what was found:
          {resolved, project, repo, method, ...artifact fields..., notes}
        method is one of: 'helm_chart', 'manifest', or None (not found).
        """
        repo = self.best_repo(project)
        if not repo:
            return {"resolved": False, "project": project,
                    "notes": "Could not find a matching repository on GitHub."}

        full_name = repo["full_name"]
        branch = repo["default_branch"]

        chart = self.find_chart(full_name, branch)
        if not chart:
            # Many projects ship their chart in a separate helm-charts repo.
            chart = self.find_chart_in_sibling_repo(full_name)
        if chart:
            return {
                "resolved": True,
                "project": project,
                "repo": chart.get("source_repo", full_name),
                "main_repo": full_name,
                "stars": repo["stars"],
                "method": "helm_chart",
                "default_branch": branch,
                **chart,
                "config_fields": self._values_top_keys(chart.get("values_yaml", "")),
                "images": self._scan_images(chart.get("values_yaml", "")),
                "notes": f"Found a Helm chart '{chart.get('chart_name')}' in {chart.get('source_repo', full_name)}.",
            }

        manifest = self.find_manifest(full_name, branch)
        if manifest:
            return {
                "resolved": True,
                "project": project,
                "repo": full_name,
                "stars": repo["stars"],
                "method": "manifest",
                "default_branch": branch,
                **manifest,
                "images": self._scan_images(manifest.get("manifest_text", "")),
                "notes": f"Found install manifest(s) in {full_name}.",
            }

        return {
            "resolved": False,
            "project": project,
            "repo": full_name,
            "stars": repo["stars"],
            "notes": (f"Found the repo {full_name}, but no Helm chart or standard install "
                      f"manifest in the usual locations. It may publish a chart elsewhere "
                      f"(e.g. a separate helm-charts repo) or use another install method."),
        }

    # ── small parsers (intentionally lightweight; full YAML parse happens downstream) ──

    def _yaml_field(self, text: str, field: str) -> Optional[str]:
        m = re.search(rf'^{field}:\s*["\']?([^"\'\n]+)', text or "", re.MULTILINE)
        return m.group(1).strip() if m else None

    def _values_top_keys(self, values_yaml: str) -> List[str]:
        """Top-level configurable keys in values.yaml — the real config surface to
        turn into questions for the user."""
        keys = []
        for line in (values_yaml or "").splitlines():
            m = re.match(r'^([a-zA-Z][\w-]*):', line)
            if m and not line.startswith(" "):
                keys.append(m.group(1))
        # de-dupe, keep order
        seen = set()
        return [k for k in keys if not (k in seen or seen.add(k))]

    def _scan_images(self, text: str) -> List[str]:
        found = set()
        for m in re.finditer(r'(?:image|repository):\s*["\']?([\w./\-]+(:[\w.\-]+)?)["\']?', text or ""):
            val = m.group(1)
            if "/" in val or ":" in val:
                found.add(val)
        return sorted(found)
