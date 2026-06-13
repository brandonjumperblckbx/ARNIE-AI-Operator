"""
ARNIE Approval Engine
Human-in-the-loop approval workflow for generated Ansible playbooks.
No playbook reaches GitHub or AAP without explicit human approval.
"""

import json
import uuid
import threading
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("arnie.approval-engine")


@dataclass
class ApprovalRequest:
    playbook_id: str
    intent: str
    yaml_content: str
    validation: Dict[str, Any]
    blast_radius: Dict[str, Any]
    risk_level: str = "medium"
    requested_by: str = "operator"
    conversation_id: Optional[str] = None


@dataclass
class ApprovalDecision:
    actor: str = "operator"
    reason: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        norm = value.replace("Z", "+00:00")
        return datetime.fromisoformat(norm)
    except ValueError:
        return None


class ApprovalEngine:
    """JSON-backed approval ledger for staged playbook workflows."""

    def __init__(self, state_dir: str):
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "approvals.json"
        self.lock = threading.Lock()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    # ── Internal persistence ──

    def _read(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"approvals": [], "audit": []}
        try:
            with self.path.open("r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"approvals": [], "audit": []}
        return {
            "approvals": data.get("approvals", []),
            "audit": data.get("audit", []),
        }

    def _write(self, data: Dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w") as f:
            json.dump(data, f, indent=2, sort_keys=True, default=str)
        tmp.replace(self.path)

    def _audit(self, data: Dict[str, Any], approval_id: str,
               event: str, actor: str, reason: str = "",
               metadata: Optional[Dict[str, Any]] = None) -> None:
        data["audit"].insert(0, {
            "id": str(uuid.uuid4()),
            "approval_id": approval_id,
            "event": event,
            "actor": actor,
            "reason": reason,
            "metadata": metadata or {},
            "created_at": _utc_now(),
        })
        data["audit"] = data["audit"][:1000]

    def _ttl_minutes(self, risk_level: str) -> int:
        return {
            "low": 480,
            "medium": 240,
            "high": 60,
            "critical": 30,
        }.get(risk_level, 240)

    def _expire(self, data: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        for a in data["approvals"]:
            if a.get("status") != "pending_approval":
                continue
            exp = _parse_ts(a.get("expires_at"))
            if exp and exp < now:
                a["status"] = "expired"
                a["updated_at"] = _utc_now()
                self._audit(data, a["id"], "expired", "system", "Approval window expired")

    # ── Public API ──

    def stage(self, req: ApprovalRequest) -> Dict[str, Any]:
        """Stage a playbook for human approval."""
        approval_id = f"apv-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        file_slug = req.playbook_id.replace("pb-", "")
        file_name = f"{file_slug}.yml"
        # Try to build a cleaner filename from intent
        import re
        intent_slug = re.sub(r'[^a-z0-9]+', '-', req.intent.lower().strip())[:50].strip('-')
        if intent_slug:
            file_name = f"{intent_slug}.yml"

        approval = {
            "id": approval_id,
            "playbook_id": req.playbook_id,
            "intent": req.intent,
            "yaml_content": req.yaml_content,
            "file_name": file_name,
            "validation": req.validation,
            "blast_radius": req.blast_radius,
            "risk_level": req.risk_level,
            "status": "pending_approval",
            "requested_by": req.requested_by,
            "conversation_id": req.conversation_id,
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=self._ttl_minutes(req.risk_level))
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "created_at": now,
            "updated_at": now,
            "approved_by": None,
            "approved_at": None,
            "rejection": None,
            "github_push": None,
            "aap_execution": None,
            "edit_history": [],
        }

        with self.lock:
            data = self._read()
            data["approvals"].insert(0, approval)
            self._audit(data, approval_id, "staged", req.requested_by,
                        f"Playbook staged for approval: {req.intent[:100]}")
            self._write(data)

        return approval

    def get(self, approval_id: str) -> Dict[str, Any]:
        with self.lock:
            data = self._read()
            self._expire(data)
            for a in data["approvals"]:
                if a["id"] == approval_id:
                    return a
        raise ValueError(f"Approval not found: {approval_id}")

    def list_approvals(self) -> List[Dict[str, Any]]:
        with self.lock:
            data = self._read()
            self._expire(data)
            return data["approvals"]

    def approve(self, approval_id: str, decision: ApprovalDecision) -> Dict[str, Any]:
        with self.lock:
            data = self._read()
            self._expire(data)
            for a in data["approvals"]:
                if a["id"] == approval_id:
                    if a["status"] != "pending_approval":
                        raise ValueError(f"Cannot approve: status is {a['status']}")
                    a["status"] = "approved"
                    a["approved_by"] = decision.actor
                    a["approved_at"] = _utc_now()
                    a["updated_at"] = _utc_now()
                    self._audit(data, approval_id, "approved", decision.actor, decision.reason)
                    self._write(data)
                    return a
        raise ValueError(f"Approval not found: {approval_id}")

    def reject(self, approval_id: str, decision: ApprovalDecision) -> Dict[str, Any]:
        with self.lock:
            data = self._read()
            for a in data["approvals"]:
                if a["id"] == approval_id:
                    if a["status"] in ("executed",):
                        raise ValueError("Cannot reject an executed playbook")
                    a["status"] = "rejected"
                    a["rejection"] = {
                        "actor": decision.actor,
                        "reason": decision.reason,
                        "rejected_at": _utc_now(),
                    }
                    a["updated_at"] = _utc_now()
                    self._audit(data, approval_id, "rejected", decision.actor, decision.reason)
                    self._write(data)
                    return a
        raise ValueError(f"Approval not found: {approval_id}")

    def edit(self, approval_id: str, new_yaml: str, validation: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            data = self._read()
            for a in data["approvals"]:
                if a["id"] == approval_id:
                    if a["status"] != "pending_approval":
                        raise ValueError("Can only edit pending approvals")
                    a["edit_history"].append({
                        "previous_yaml": a["yaml_content"],
                        "edited_at": _utc_now(),
                    })
                    a["yaml_content"] = new_yaml
                    a["validation"] = validation
                    a["updated_at"] = _utc_now()
                    self._audit(data, approval_id, "edited", "operator", "Playbook YAML edited")
                    self._write(data)
                    return a
        raise ValueError(f"Approval not found: {approval_id}")

    def record_push(self, approval_id: str, push_result: Dict[str, Any]) -> None:
        with self.lock:
            data = self._read()
            for a in data["approvals"]:
                if a["id"] == approval_id:
                    a["github_push"] = push_result
                    a["updated_at"] = _utc_now()
                    self._audit(data, approval_id, "pushed",
                                a.get("approved_by", "system"),
                                f"Pushed to GitHub: {push_result.get('commit_sha', '')[:8]}")
                    self._write(data)
                    return

    def record_execution(self, approval_id: str, aap_result: Dict[str, Any]) -> None:
        with self.lock:
            data = self._read()
            for a in data["approvals"]:
                if a["id"] == approval_id:
                    a["status"] = "executed"
                    a["aap_execution"] = aap_result
                    a["updated_at"] = _utc_now()
                    self._audit(data, approval_id, "executed",
                                a.get("approved_by", "system"),
                                f"AAP job launched: {aap_result.get('job_id', 'unknown')}")
                    self._write(data)
                    return

    def get_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            data = self._read()
            return data["audit"][:limit]
