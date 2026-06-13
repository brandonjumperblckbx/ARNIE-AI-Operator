"""
RMCP Model Provider Factory
Shared engine component — selects the active AI model provider (Ollama or Claude).
"""

import os
import logging
from typing import Optional

log = logging.getLogger("rmcp.model-providers")


def get_model_provider():
    """Factory function returning the active model provider instance."""
    provider = os.environ.get("RMCP_PROVIDER",
               os.environ.get("MODEL_PROVIDER", "ollama")).strip().lower()

    if provider == "claude":
        from claude_service import ClaudeService
        return ClaudeService()

    # Default: Ollama via ModelRouter
    from model_router import ModelRouter
    return ModelRouter()
