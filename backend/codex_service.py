"""
RMCP Codex Service
OpenAI Codex API provider for the RMCP engine.
"""

import os
import logging
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("rmcp.codex-service")


class CodexService:
    """OpenAI Codex client implementing the RMCP model provider interface."""

    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.model = os.environ.get("CODEX_MODEL", "gpt-4.1-mini")
        self.max_tokens = int(os.environ.get("RMCP_MAX_TOKENS", "4096"))
        self.timeout = int(os.environ.get("RMCP_TIMEOUT", "120"))
        self.provider_name = "codex"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def complete(
            self,
            prompt: str,
            system: Optional[str] = None,
    ) -> str:
        """Send a completion request to OpenAI."""
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY not set")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = ""
        if isinstance(data, dict):
            choices = data.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")

        return content

    async def chat(self, prompt: str, system: Optional[str] = None) -> str:
        """Alias for complete."""
        return await self.complete(prompt, system=system)

    async def list_local_models(self) -> List[str]:
        """Codex is cloud-only."""
        return []