"""
ARNIE AAP Integration
Triggers Ansible Automation Platform project syncs and job template launches.
Monitors job status and surfaces results back into the ARNIE chat interface.
"""

import os
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import httpx

log = logging.getLogger("arnie.aap")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AAPClient:
    """Ansible Automation Platform REST API client."""

    def __init__(self):
        self.base_url = os.environ.get("ARNIE_AAP_URL", "").rstrip("/")
        self.token = os.environ.get("ARNIE_AAP_TOKEN", "")
        self.project_id = os.environ.get("ARNIE_AAP_PROJECT_ID", "")
        self.job_template_id = os.environ.get("ARNIE_AAP_JOB_TEMPLATE_ID", "")
        self.verify_ssl = os.environ.get("ARNIE_AAP_VERIFY_SSL", "false").lower() == "true"

    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    async def _request(self, method: str, path: str,
                       json_data: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=30, verify=self.verify_ssl) as client:
            resp = await client.request(method, url, headers=self._headers(), json=json_data)
            if resp.status_code >= 400:
                detail = resp.text[:500]
                raise RuntimeError(f"AAP {method} {path} failed ({resp.status_code}): {detail}")
            return resp.json() if resp.content else {}

    async def sync_project(self) -> Dict[str, Any]:
        """Trigger a project sync so AAP pulls the latest playbooks from GitHub."""
        if not self.project_id:
            raise RuntimeError("ARNIE_AAP_PROJECT_ID not set")
        result = await self._request("POST", f"/api/v2/projects/{self.project_id}/update/")
        return {
            "status": "syncing",
            "project_id": self.project_id,
            "timestamp": _utc_now(),
            "detail": result,
        }

    async def launch_job(self, playbook: str,
                         extra_vars: Optional[Dict] = None) -> Dict[str, Any]:
        """Launch a job template to run a specific playbook."""
        if not self.job_template_id:
            raise RuntimeError("ARNIE_AAP_JOB_TEMPLATE_ID not set")

        payload: Dict[str, Any] = {}
        if extra_vars:
            payload["extra_vars"] = extra_vars
        # AAP job template should be configured with the project and playbook
        # If the template allows playbook override, include it
        if playbook:
            payload["playbook"] = playbook

        result = await self._request(
            "POST",
            f"/api/v2/job_templates/{self.job_template_id}/launch/",
            json_data=payload if payload else None,
        )

        job_id = str(result.get("id", result.get("job", "")))
        return {
            "job_id": job_id,
            "job_url": f"{self.base_url}/#/jobs/playbook/{job_id}",
            "status": result.get("status", "pending"),
            "playbook": playbook,
            "timestamp": _utc_now(),
        }

    async def sync_and_launch(self, playbook: str,
                              extra_vars: Optional[Dict] = None) -> Dict[str, Any]:
        """Sync the project then launch the job."""
        # Sync
        try:
            await self.sync_project()
        except Exception as e:
            log.warning("Project sync failed (continuing): %s", e)

        # Wait a moment for sync, then launch
        import asyncio
        await asyncio.sleep(3)

        return await self.launch_job(playbook, extra_vars)

    async def get_job(self, job_id: str) -> Dict[str, Any]:
        """Get detailed job status and output."""
        result = await self._request("GET", f"/api/v2/jobs/{job_id}/")
        stdout = ""
        try:
            stdout_result = await self._request("GET", f"/api/v2/jobs/{job_id}/stdout/?format=txt")
            stdout = str(stdout_result) if stdout_result else ""
        except Exception:
            pass

        return {
            "job_id": job_id,
            "status": result.get("status", "unknown"),
            "started": result.get("started"),
            "finished": result.get("finished"),
            "elapsed": result.get("elapsed"),
            "failed": result.get("failed", False),
            "playbook": result.get("playbook"),
            "stdout": stdout[:5000],
            "timestamp": _utc_now(),
        }

    async def list_jobs(self, limit: int = 20) -> Dict[str, Any]:
        """List recent job runs."""
        if not self.is_configured():
            return {"jobs": [], "error": "AAP not configured"}

        try:
            result = await self._request(
                "GET",
                f"/api/v2/jobs/?order_by=-created&page_size={limit}",
            )
            jobs = [
                {
                    "id": str(j.get("id", "")),
                    "name": j.get("name", ""),
                    "status": j.get("status", ""),
                    "started": j.get("started"),
                    "finished": j.get("finished"),
                    "playbook": j.get("playbook"),
                    "failed": j.get("failed", False),
                }
                for j in result.get("results", [])
            ]
            return {"jobs": jobs, "count": len(jobs), "timestamp": _utc_now()}
        except Exception as e:
            return {"jobs": [], "error": str(e)}

    async def get_status(self) -> Dict[str, Any]:
        """Check AAP connection status."""
        if not self.is_configured():
            return {
                "configured": False,
                "message": "ARNIE_AAP_URL and ARNIE_AAP_TOKEN not set",
            }
        try:
            result = await self._request("GET", "/api/v2/ping/")
            return {
                "configured": True,
                "connected": True,
                "version": result.get("version", "unknown"),
                "base_url": self.base_url,
                "project_id": self.project_id,
                "job_template_id": self.job_template_id,
                "timestamp": _utc_now(),
            }
        except Exception as e:
            return {
                "configured": True,
                "connected": False,
                "error": str(e),
            }
