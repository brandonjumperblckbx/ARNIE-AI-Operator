"""
RMCP Agent Runtime
Cognitive agent pipeline with memory, traces, and verification.
Shared engine component powering both BLCK-BRT and ARNIE.
"""

import json
import uuid
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("rmcp.agent-runtime")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AgentResult:
    response: str
    conversation_id: str
    actions_taken: List[str] = field(default_factory=list)
    trace_id: Optional[str] = None
    agent_mode: str = "chat"
    verification_status: Optional[str] = None


class AgentMemoryStore:
    """JSON-backed conversation memory and trace storage."""

    def __init__(self, state_dir: str):
        self.state_dir = Path(state_dir)
        self.conversations_dir = self.state_dir / "conversations"
        self.traces_dir = self.state_dir / "traces"
        self.conversations_dir.mkdir(parents=True, exist_ok=True)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.writable = True
        self.lock = threading.Lock()

    def _conv_path(self, cid: str) -> Path:
        return self.conversations_dir / f"{cid}.json"

    def _trace_path(self, cid: str) -> Path:
        return self.traces_dir / f"{cid}.json"

    def load(self, conversation_id: str) -> Dict[str, Any]:
        path = self._conv_path(conversation_id)
        if path.exists():
            try:
                with path.open("r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "conversation_id": conversation_id,
            "turns": [],
            "summary": "",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }

    def save(self, conversation_id: str, data: Dict[str, Any]) -> None:
        with self.lock:
            data["updated_at"] = _utc_now()
            path = self._conv_path(conversation_id)
            tmp = path.with_suffix(".tmp")
            with tmp.open("w") as f:
                json.dump(data, f, indent=2, default=str)
            tmp.replace(path)

    def append_turn(self, conversation_id: str, role: str, content: str) -> None:
        data = self.load(conversation_id)
        data["turns"].append({
            "role": role,
            "content": content,
            "timestamp": _utc_now(),
        })
        data["turns"] = data["turns"][-50:]  # Keep last 50 turns
        self.save(conversation_id, data)

    def save_trace(self, conversation_id: str, trace: Dict[str, Any]) -> None:
        with self.lock:
            path = self._trace_path(conversation_id)
            traces = []
            if path.exists():
                try:
                    with path.open("r") as f:
                        traces = json.load(f)
                except Exception:
                    traces = []
            traces.insert(0, trace)
            traces = traces[:100]
            tmp = path.with_suffix(".tmp")
            with tmp.open("w") as f:
                json.dump(traces, f, indent=2, default=str)
            tmp.replace(path)

    def list_traces(self, conversation_id: str) -> List[Dict[str, Any]]:
        path = self._trace_path(conversation_id)
        if path.exists():
            try:
                with path.open("r") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def snapshot(self, conversation_id: str) -> Dict[str, Any]:
        data = self.load(conversation_id)
        traces = self.list_traces(conversation_id)
        return {
            "conversation_id": conversation_id,
            "summary": data.get("summary", ""),
            "recent_turns": data.get("turns", [])[-10:],
            "trace_count": len(traces),
            "updated_at": data.get("updated_at", _utc_now()),
        }


class AgentPipeline:
    """RMCP cognitive agent pipeline — processes prompts through the AI model
    with memory, tracing, and verification."""

    def __init__(self, model_provider, memory: AgentMemoryStore):
        self.model_provider = model_provider
        self.memory = memory

    async def run_chat(
        self,
        message: str,
        conversation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Run a message through the agent pipeline."""
        cid = conversation_id or str(uuid.uuid4())
        trace_id = f"tr-{uuid.uuid4().hex[:10]}"
        actions_taken: List[str] = []
        ctx = context or {}

        # Load conversation history
        conv = self.memory.load(cid)
        history = conv.get("turns", [])

        # Build prompt with history context
        history_text = ""
        if history:
            recent = history[-6:]  # Last 6 turns for context
            history_text = "\n".join(
                f"{'User' if t['role'] == 'user' else 'ARNIE'}: {t['content'][:500]}"
                for t in recent
            )
            history_text = f"\n\nConversation history:\n{history_text}\n\n"

        system = ctx.get("system_prompt", (
            "You are ARNIE — Ansible Remediation & Navigation Intelligence Engine. "
            "You help operators manage OpenShift and Kubernetes infrastructure by "
            "generating, validating, and deploying Ansible playbooks. "
            "Be direct, technical, and precise. When an operator describes what they "
            "need done, explain what you'll automate and generate the playbook."
        ))

        full_prompt = f"{history_text}User: {message}"

        # Call model
        try:
            if hasattr(self.model_provider, 'complete'):
                result = await self.model_provider.complete(full_prompt, system=system)
                response = result if isinstance(result, str) else getattr(result, 'content', str(result))
            elif hasattr(self.model_provider, 'chat'):
                result = await self.model_provider.chat(full_prompt, system=system)
                response = result if isinstance(result, str) else str(result)
            else:
                response = f"ARNIE received your request: {message}. Model provider not available."
            actions_taken.append("model_inference")
        except Exception as e:
            log.error("Agent pipeline model call failed: %s", e)
            response = (
                f"I understand you want to: {message}\n\n"
                f"The AI model is currently unavailable ({e}), but I can still generate "
                f"playbooks using templates. Would you like me to proceed with a template?"
            )
            actions_taken.append("model_fallback")

        # Save to memory
        self.memory.append_turn(cid, "user", message)
        self.memory.append_turn(cid, "assistant", response)

        # Save trace
        self.memory.save_trace(cid, {
            "trace_id": trace_id,
            "message": message[:200],
            "response_length": len(response),
            "actions_taken": actions_taken,
            "context_keys": list(ctx.keys()),
            "timestamp": _utc_now(),
        })

        return AgentResult(
            response=response,
            conversation_id=cid,
            actions_taken=actions_taken,
            trace_id=trace_id,
            agent_mode="chat",
        )
