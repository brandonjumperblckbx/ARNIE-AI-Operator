"""
RMCP Claude Service
Anthropic Claude API provider for the RMCP engine.
Shared component used by both BLCK-BRT and ARNIE.
"""

import os
import json
import logging
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("rmcp.claude-service")


class ClaudeService:
    """Claude API client implementing the RMCP model provider interface."""

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        self.model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
        self.max_tokens = int(os.environ.get("RMCP_MAX_TOKENS", "4096"))
        self.timeout = int(os.environ.get("RMCP_TIMEOUT", "120"))
        self.provider_name = "claude"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> str:
        """Send a completion request to Claude."""
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = ""
        if isinstance(data, dict):
            blocks = data.get("content", [])
            if isinstance(blocks, list) and blocks:
                first = blocks[0]
                if isinstance(first, dict):
                    content = str(first.get("text", ""))

        return content

    async def chat(self, prompt: str, system: Optional[str] = None) -> str:
        """Alias for complete — maintains interface compatibility."""
        return await self.complete(prompt, system=system)

    async def list_local_models(self) -> List[str]:
        """Claude is cloud-only — no local models."""
        return []
