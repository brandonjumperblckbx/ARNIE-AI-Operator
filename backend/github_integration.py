"""
ARNIE GitHub Integration
Pushes approved Ansible playbooks to a configured GitHub repository.
Full audit trail linking conversations → approvals → commits.
"""

import os
import base64
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import httpx

log = logging.getLogger("arnie.github")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class GitHubPusher:
    """Pushes playbooks to a GitHub repo via the GitHub API."""

    def __init__(self):
        self.token = os.environ.get("ARNIE_GITHUB_TOKEN", "")
        self.repo = os.environ.get("ARNIE_GITHUB_REPO", "")  # owner/repo
        self.branch = os.environ.get("ARNIE_GITHUB_BRANCH", "main")
        self.playbook_dir = os.environ.get("ARNIE_PLAYBOOK_DIR", "")  # subdirectory in repo
        self.base_url = "https://api.github.com"

    def is_configured(self) -> bool:
        return bool(self.token and self.repo)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _file_path(self, file_name: str) -> str:
        if self.playbook_dir:
            return f"{self.playbook_dir.strip('/')}/{file_name}"
        return file_name

    async def push_playbook(
        self,
        file_name: str,
        content: str,
        commit_message: str,
    ) -> Dict[str, Any]:
        """Push a playbook file to the configured GitHub repo."""
        if not self.is_configured():
            raise RuntimeError("GitHub not configured — set ARNIE_GITHUB_TOKEN and ARNIE_GITHUB_REPO")

        path = self._file_path(file_name)
        url = f"{self.base_url}/repos/{self.repo}/contents/{path}"

        # Check if file already exists (need SHA for updates)
        sha = None
        async with httpx.AsyncClient(timeout=15) as client:
            check = await client.get(url, headers=self._headers(),
                                     params={"ref": self.branch})
            if check.status_code == 200:
                sha = check.json().get("sha")

        # Create or update
        payload: Dict[str, Any] = {
            "message": commit_message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": self.branch,
        }
        if sha:
            payload["sha"] = sha

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.put(url, headers=self._headers(), json=payload)

        if resp.status_code not in (200, 201):
            detail = resp.json().get("message", resp.text)
            raise RuntimeError(f"GitHub push failed ({resp.status_code}): {detail}")

        result = resp.json()
        commit = result.get("commit", {})

        return {
            "commit_sha": commit.get("sha", ""),
            "commit_url": commit.get("html_url", ""),
            "file_path": path,
            "repo": self.repo,
            "branch": self.branch,
            "created": sha is None,
            "updated": sha is not None,
            "timestamp": _utc_now(),
        }

    async def get_status(self) -> Dict[str, Any]:
        """Check GitHub connection and repo accessibility."""
        if not self.is_configured():
            return {
                "configured": False,
                "message": "ARNIE_GITHUB_TOKEN and ARNIE_GITHUB_REPO not set",
            }

        try:
            url = f"{self.base_url}/repos/{self.repo}"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=self._headers())

            if resp.status_code == 200:
                repo = resp.json()
                return {
                    "configured": True,
                    "connected": True,
                    "repo": self.repo,
                    "branch": self.branch,
                    "playbook_dir": self.playbook_dir or "(root)",
                    "private": repo.get("private", True),
                    "default_branch": repo.get("default_branch"),
                    "timestamp": _utc_now(),
                }
            else:
                return {
                    "configured": True,
                    "connected": False,
                    "error": resp.json().get("message", "Unknown error"),
                }
        except Exception as e:
            return {
                "configured": True,
                "connected": False,
                "error": str(e),
            }

    async def get_history(self, limit: int = 20) -> Dict[str, Any]:
        """List recent commits to the playbook repo."""
        if not self.is_configured():
            return {"commits": [], "error": "Not configured"}

        try:
            url = f"{self.base_url}/repos/{self.repo}/commits"
            params = {"sha": self.branch, "per_page": limit}
            if self.playbook_dir:
                params["path"] = self.playbook_dir

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=self._headers(), params=params)

            if resp.status_code != 200:
                return {"commits": [], "error": resp.json().get("message")}

            commits = [
                {
                    "sha": c["sha"][:8],
                    "message": c["commit"]["message"].split("\n")[0],
                    "author": c["commit"]["author"]["name"],
                    "date": c["commit"]["author"]["date"],
                    "url": c["html_url"],
                }
                for c in resp.json()
            ]
            return {"commits": commits, "timestamp": _utc_now()}

        except Exception as e:
            return {"commits": [], "error": str(e)}
