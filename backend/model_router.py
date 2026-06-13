from __future__ import annotations

import asyncio
import json
import logging
import os
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import httpx

try:
    import yaml
except Exception:  # pragma: no cover - optional dependency fallback
    yaml = None

log = logging.getLogger("rmcp.model-router")
_HERE = Path(__file__).resolve().parent
_MODEL_CONFIG_PATH = (_HERE.parents[3] / "rmcp" / "deployments" / "blck-brt" / "models" / "model.yaml").resolve()


class Provider(str, Enum):
    OLLAMA = "ollama"
    CLAUDE = "claude"


class OllamaModel(str, Enum):
    LLAMA = "llama3.1:8b"
    MISTRAL = "mistral:7b"
    QWEN = "qwen2.5:7b"
    PHI = "phi3.5"
    DEEPSEEK = "deepseek-r1:8b"


MODEL_DESCRIPTIONS: dict[OllamaModel, str] = {
    OllamaModel.LLAMA: "Best all-around - policy generation, instruction following",
    OllamaModel.MISTRAL: "Fast on CPU - structured output, YAML/JSON tasks",
    OllamaModel.QWEN: "Strong code and structured tasks - good RMCP artifact generation",
    OllamaModel.PHI: "Lightest footprint - fastest CPU inference, lighter tasks",
    OllamaModel.DEEPSEEK: "Best reasoning - security analysis, complex policy decisions",
}


STATIC_MODEL_CATALOG: dict[str, Any] = {
    "version": "1.0",
    "updated": "2026-05-23",
    "owner": "BLCKBX",
    "protocol": "RMCP",
    "defaults": {
        "provider": "ollama",
        "model": OllamaModel.LLAMA.value,
        "max_tokens": 4096,
        "timeout_seconds": 120,
        "auto_pull": True,
        "fallback_to_claude": True,
        "claude_model": "claude-sonnet-4-20250514",
    },
    "ollama_models": [
        {
            "id": OllamaModel.LLAMA.value,
            "name": "Llama 3.1 8B",
            "provider": "meta",
            "size_gb": 4.7,
            "quantization": "Q4_K_M",
            "context_window": 128000,
            "description": "Best all-around model for policy generation and instruction following",
            "strengths": [
                "policy_generation",
                "instruction_following",
                "structured_output",
                "rmcp_artifact_generation",
            ],
            "capability_groups": [
                "core_intelligence",
                "compliance_mapping",
                "threat_intelligence",
                "audit_evidence",
            ],
            "blck_brt_default": True,
            "recommended_for": [
                "SOC2 compliance package generation",
                "RMCP SemanticPolicy generation",
                "General security policy drafting",
                "Multi-framework compliance mapping",
            ],
            "performance": {
                "cpu_inference": "good",
                "response_quality": "high",
                "structured_output": "high",
            },
        },
        {
            "id": OllamaModel.MISTRAL.value,
            "name": "Mistral 7B",
            "provider": "mistral-ai",
            "size_gb": 4.1,
            "quantization": "Q4_K_M",
            "context_window": 32000,
            "description": "Fast on CPU with strong structured output and YAML/JSON generation",
            "strengths": [
                "fast_inference",
                "yaml_generation",
                "json_output",
                "structured_tasks",
            ],
            "capability_groups": [
                "policy_deployment",
                "network_control",
                "secret_management",
            ],
            "blck_brt_default": False,
            "recommended_for": [
                "RMCP YAML artifact generation",
                "Network policy drafting",
                "Fast policy validation",
                "Structured JSON output tasks",
            ],
            "performance": {
                "cpu_inference": "excellent",
                "response_quality": "good",
                "structured_output": "excellent",
            },
        },
        {
            "id": OllamaModel.QWEN.value,
            "name": "Qwen 2.5 7B",
            "provider": "alibaba",
            "size_gb": 4.4,
            "quantization": "Q4_K_M",
            "context_window": 128000,
            "description": "Strong code and structured task performance, excellent RMCP artifact generation",
            "strengths": [
                "code_generation",
                "structured_output",
                "rmcp_artifacts",
                "multi_language",
            ],
            "capability_groups": [
                "core_intelligence",
                "autonomous_response",
                "integration_automation",
            ],
            "blck_brt_default": False,
            "recommended_for": [
                "AAP playbook generation",
                "TypeScript/Python code generation",
                "Complex RMCP artifact suites",
                "Multi-file security package generation",
            ],
            "performance": {
                "cpu_inference": "good",
                "response_quality": "high",
                "structured_output": "excellent",
            },
        },
        {
            "id": OllamaModel.PHI.value,
            "name": "Phi 3.5 Mini",
            "provider": "microsoft",
            "size_gb": 2.2,
            "quantization": "Q4_K_M",
            "context_window": 128000,
            "description": "Smallest footprint, fastest CPU inference for lightweight tasks",
            "strengths": [
                "fast_inference",
                "low_memory",
                "lightweight_tasks",
                "quick_validation",
            ],
            "capability_groups": [
                "monitoring_detection",
                "evidence_audit",
            ],
            "blck_brt_default": False,
            "recommended_for": [
                "Quick policy validation",
                "Drift detection summaries",
                "Alert triage",
                "Lightweight capability execution",
            ],
            "performance": {
                "cpu_inference": "excellent",
                "response_quality": "moderate",
                "structured_output": "good",
            },
        },
        {
            "id": OllamaModel.DEEPSEEK.value,
            "name": "DeepSeek R1 8B",
            "provider": "deepseek",
            "size_gb": 4.9,
            "quantization": "Q4_K_M",
            "context_window": 128000,
            "description": "Best reasoning model for complex security analysis and policy decisions",
            "strengths": [
                "complex_reasoning",
                "security_analysis",
                "vulnerability_assessment",
                "policy_decisions",
            ],
            "capability_groups": [
                "threat_intelligence",
                "adversarial_simulation",
                "incident_response",
                "ai_ml_security",
            ],
            "blck_brt_default": False,
            "recommended_for": [
                "CVE impact analysis",
                "Adversarial policy red-teaming",
                "Complex incident response decisions",
                "AI security vulnerability assessment",
            ],
            "performance": {
                "cpu_inference": "moderate",
                "response_quality": "excellent",
                "structured_output": "good",
            },
        },
    ],
    "claude_models": [
        {
            "id": "claude-sonnet-4-20250514",
            "name": "Claude Sonnet 4",
            "provider": "anthropic",
            "description": "Primary Claude model for complex compliance generation and enterprise tasks",
            "blck_brt_default": True,
        }
    ],
    "capability_routing": {
        "core_intelligence": {"primary": OllamaModel.LLAMA.value, "fallback": "claude-sonnet-4-20250514"},
        "compliance_mapping": {"primary": OllamaModel.LLAMA.value, "fallback": "claude-sonnet-4-20250514"},
        "threat_intelligence": {"primary": OllamaModel.DEEPSEEK.value, "fallback": OllamaModel.LLAMA.value},
        "autonomous_response": {"primary": OllamaModel.QWEN.value, "fallback": OllamaModel.LLAMA.value},
        "monitoring_detection": {"primary": OllamaModel.PHI.value, "fallback": OllamaModel.MISTRAL.value},
        "evidence_audit": {"primary": OllamaModel.PHI.value, "fallback": OllamaModel.LLAMA.value},
        "integration_automation": {"primary": OllamaModel.QWEN.value, "fallback": OllamaModel.MISTRAL.value},
        "network_control": {"primary": OllamaModel.MISTRAL.value, "fallback": OllamaModel.LLAMA.value},
        "secret_management": {"primary": OllamaModel.MISTRAL.value, "fallback": OllamaModel.LLAMA.value},
        "access_control": {"primary": OllamaModel.LLAMA.value, "fallback": "claude-sonnet-4-20250514"},
        "incident_response": {"primary": OllamaModel.DEEPSEEK.value, "fallback": "claude-sonnet-4-20250514"},
        "ai_ml_security": {"primary": OllamaModel.DEEPSEEK.value, "fallback": "claude-sonnet-4-20250514"},
        "enterprise_features": {"primary": "claude-sonnet-4-20250514", "fallback": OllamaModel.LLAMA.value},
        "adversarial_simulation": {"primary": OllamaModel.DEEPSEEK.value, "fallback": OllamaModel.LLAMA.value},
    },
    "minio_backup": {
        "enabled": False,
        "endpoint": "minio.aistor.svc.cluster.local:443",
        "bucket": "blck-brt-models",
        "sync_on_pull": True,
        "tls": True,
    },
}


def _parse_provider(value: str | Provider | None) -> Provider:
    if isinstance(value, Provider):
        return value
    normalized = str(value or Provider.OLLAMA.value).strip().lower()
    return Provider.CLAUDE if normalized == Provider.CLAUDE.value else Provider.OLLAMA


def _parse_model(value: str | OllamaModel | None) -> OllamaModel:
    if isinstance(value, OllamaModel):
        return value
    normalized = str(value or OllamaModel.LLAMA.value).strip()
    aliases = {
        "llama3.1": OllamaModel.LLAMA,
        "llama3": OllamaModel.LLAMA,
        "mistral": OllamaModel.MISTRAL,
        "qwen2.5": OllamaModel.QWEN,
        "qwen": OllamaModel.QWEN,
        "phi3.5": OllamaModel.PHI,
        "phi3.5:mini": OllamaModel.PHI,
        "phi3": OllamaModel.PHI,
        "deepseek-r1": OllamaModel.DEEPSEEK,
        "deepseek": OllamaModel.DEEPSEEK,
    }
    if normalized in aliases:
        return aliases[normalized]
    for model in OllamaModel:
        if normalized == model.value:
            return model
    return OllamaModel.LLAMA


def _copy_catalog() -> dict[str, Any]:
    return deepcopy(STATIC_MODEL_CATALOG)


@lru_cache(maxsize=1)
def _load_model_manifest() -> dict[str, Any]:
    if yaml is None or not _MODEL_CONFIG_PATH.exists():
        return _copy_catalog()

    try:
        with _MODEL_CONFIG_PATH.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)
    except Exception:
        return _copy_catalog()

    return payload if isinstance(payload, dict) else _copy_catalog()


def _manifest_defaults() -> dict[str, Any]:
    manifest = _load_model_manifest()
    defaults = manifest.get("defaults", {})
    return defaults if isinstance(defaults, dict) else {}


def _supported_models_from_catalog(catalog: dict[str, Any]) -> list[dict[str, str]]:
    supported_models: list[dict[str, str]] = []
    for item in catalog.get("ollama_models", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("id", "") or "").strip()
        if not name:
            continue
        supported_models.append(
            {
                "name": name,
                "description": str(item.get("description", "") or item.get("name", "") or "").strip(),
            }
        )
    return supported_models


def parse_ollama_model(value: str | OllamaModel | None) -> OllamaModel:
    return _parse_model(value)


def resolve_ollama_model(value: str | OllamaModel | None) -> Optional[OllamaModel]:
    if isinstance(value, OllamaModel):
        return value
    normalized = str(value or "").strip()
    aliases = {
        "llama3.1": OllamaModel.LLAMA,
        "llama3": OllamaModel.LLAMA,
        "mistral": OllamaModel.MISTRAL,
        "qwen2.5": OllamaModel.QWEN,
        "qwen": OllamaModel.QWEN,
        "phi3.5": OllamaModel.PHI,
        "phi3.5:mini": OllamaModel.PHI,
        "phi3": OllamaModel.PHI,
        "deepseek-r1": OllamaModel.DEEPSEEK,
        "deepseek": OllamaModel.DEEPSEEK,
    }
    if normalized in aliases:
        return aliases[normalized]
    for model in OllamaModel:
        if normalized == model.value:
            return model
    return None


@dataclass
class RouterConfig:
    provider: Provider = field(
        default_factory=lambda: _parse_provider(
            os.getenv("BLCK_BRT_PROVIDER")
            or os.getenv("MODEL_PROVIDER")
            or _manifest_defaults().get("provider")
            or "ollama"
        )
    )
    ollama_model: OllamaModel = field(
        default_factory=lambda: _parse_model(
            os.getenv("BLCK_BRT_MODEL")
            or os.getenv("OLLAMA_MODEL")
            or _manifest_defaults().get("model")
            or OllamaModel.LLAMA.value
        )
    )
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    )
    claude_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    claude_model: str = field(
        default_factory=lambda: os.getenv("CLAUDE_MODEL") or str(_manifest_defaults().get("claude_model", "claude-sonnet-4-20250514"))
    )
    max_tokens: int = field(default_factory=lambda: int(os.getenv("BLCK_BRT_MAX_TOKENS", "4096")))
    timeout: int = field(default_factory=lambda: int(os.getenv("BLCK_BRT_TIMEOUT", "120")))
    auto_pull: bool = field(
        default_factory=lambda: (
            os.getenv("BLCK_BRT_AUTO_PULL")
            if os.getenv("BLCK_BRT_AUTO_PULL") is not None
            else str(_manifest_defaults().get("auto_pull", True))
        ).strip().lower() == "true"
    )
    fallback_to_claude: bool = field(
        default_factory=lambda: (
            os.getenv("BLCK_BRT_FALLBACK")
            if os.getenv("BLCK_BRT_FALLBACK") is not None
            else str(_manifest_defaults().get("fallback_to_claude", True))
        ).strip().lower() == "true"
    )


@dataclass
class ModelResponse:
    content: str
    provider: Provider
    model: str
    tokens_used: Optional[int] = None
    fallback_used: bool = False


class ModelRouter:
    def __init__(self, config: Optional[RouterConfig] = None) -> None:
        self.config = config or RouterConfig()
        log.info(
            "BLCK-BRT Model Router initialized - provider=%s model=%s",
            self.config.provider.value,
            self.config.ollama_model.value,
        )

    def set_model(self, model: OllamaModel | str) -> None:
        self.config.ollama_model = _parse_model(model)
        log.info("Model switched to: %s", self.config.ollama_model.value)

    def set_provider(self, provider: Provider | str) -> None:
        self.config.provider = _parse_provider(provider)
        log.info("Provider switched to: %s", self.config.provider.value)

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        provider: Optional[Provider | str] = None,
        model: Optional[OllamaModel | str] = None,
    ) -> ModelResponse:
        target_provider = _parse_provider(provider) if provider is not None else self.config.provider
        target_model = _parse_model(model) if model is not None else self.config.ollama_model

        if target_provider == Provider.CLAUDE:
            return await self._call_claude(prompt, system)

        try:
            return await self._call_ollama(prompt, system, target_model)
        except Exception as exc:
            log.warning("Ollama failed: %s", exc)
            if self.config.fallback_to_claude and self.config.claude_api_key:
                response = await self._call_claude(prompt, system)
                response.fallback_used = True
                return response
            raise

    async def pull_model(
        self,
        model: OllamaModel | str,
        progress_callback: Optional[Any] = None,
    ) -> bool:
        target = _parse_model(model)
        log.info("Pulling model: %s", target.value)

        url = f"{self.config.ollama_base_url}/api/pull"
        try:
            async with httpx.AsyncClient(timeout=600) as client:
                async with client.stream("POST", url, json={"name": target.value}) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        status = str(data.get("status", ""))
                        total = data.get("total")
                        completed = data.get("completed")
                        percent = None
                        if isinstance(total, (int, float)) and isinstance(completed, (int, float)) and total > 0:
                            percent = max(0, min(100, int((completed / total) * 100)))
                        if progress_callback is not None:
                            try:
                                result = progress_callback(
                                    {
                                        "status": status,
                                        "total": total,
                                        "completed": completed,
                                        "percent": percent,
                                        "message": status or "pulling",
                                    }
                                )
                                if asyncio.iscoroutine(result):
                                    await result
                            except Exception:
                                pass
                        if status == "success":
                            log.info("Model ready: %s", target.value)
            return True
        except Exception as exc:
            log.error("Failed to pull %s: %s", target.value, exc)
            return False

    async def list_local_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.config.ollama_base_url}/api/tags")
                response.raise_for_status()
                data = response.json()
            models = data.get("models", []) if isinstance(data, dict) else []
            result: list[str] = []
            for model in models:
                if isinstance(model, dict):
                    name = model.get("name")
                    if isinstance(name, str) and name:
                        result.append(name)
            return result
        except Exception:
            return []

    def supported_models(self) -> list[dict[str, str]]:
        return [
            {
                "name": model.value,
                "description": MODEL_DESCRIPTIONS[model],
            }
            for model in OllamaModel
        ]

    async def _call_ollama(self, prompt: str, system: Optional[str], model: OllamaModel) -> ModelResponse:
        url = f"{self.config.ollama_base_url}/api/chat"
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": model.value,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": self.config.max_tokens},
        }

        if self.config.auto_pull:
            local = await self.list_local_models()
            if model.value not in local:
                log.info("%s not found locally - pulling now", model.value)
                if not await self.pull_model(model):
                    raise RuntimeError(f"Failed to pull {model.value}")

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        content = ""
        if isinstance(data, dict):
            content = str(data.get("message", {}).get("content", "") or "")
        tokens = data.get("eval_count") if isinstance(data, dict) else None
        return ModelResponse(content=content, provider=Provider.OLLAMA, model=model.value, tokens_used=tokens)

    async def _call_claude(self, prompt: str, system: Optional[str]) -> ModelResponse:
        if not self.config.claude_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set - cannot use Claude provider")

        headers = {
            "x-api-key": self.config.claude_api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.config.claude_model,
            "max_tokens": self.config.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        content = ""
        tokens = None
        if isinstance(data, dict):
            blocks = data.get("content", [])
            if isinstance(blocks, list) and blocks:
                first = blocks[0]
                if isinstance(first, dict):
                    content = str(first.get("text", "") or "")
            usage = data.get("usage", {})
            if isinstance(usage, dict):
                tokens = usage.get("output_tokens")
        return ModelResponse(content=content, provider=Provider.CLAUDE, model=self.config.claude_model, tokens_used=tokens)


async def interactive_model_setup(router: ModelRouter) -> None:
    print("\n╔══════════════════════════════════════════════════╗")
    print("║        BLCK-BRT Model Selection                  ║")
    print("╚══════════════════════════════════════════════════╝\n")
    for index, model in enumerate(OllamaModel, 1):
        print(f"  {index}. {model.value}")
        print(f"     {MODEL_DESCRIPTIONS[model]}\n")
    print("  6. Use Claude API (requires ANTHROPIC_API_KEY)\n")

    choice = input("Select model [1-6]: ").strip()
    if choice == "6":
        router.set_provider(Provider.CLAUDE)
        print("  ✅ Claude API selected\n")
        return

    try:
        router.set_model(list(OllamaModel)[int(choice) - 1])
    except Exception:
        router.set_model(OllamaModel.LLAMA)
        print("  Invalid selection - defaulting to llama3.1:8b")

    router.set_provider(Provider.OLLAMA)
    local = await router.list_local_models()
    if router.config.ollama_model.value not in local:
        pull = input(f"\n  {router.config.ollama_model.value} not found locally. Pull now? [Y/n]: ").strip().lower()
        if pull != "n":
            await router.pull_model(router.config.ollama_model)
    else:
        print(f"\n  ✅ {router.config.ollama_model.value} already available locally\n")


def build_model_catalog() -> dict[str, Any]:
    config = RouterConfig()
    catalog = _load_model_manifest()
    if not isinstance(catalog, dict):
        catalog = _copy_catalog()
    catalog["provider"] = config.provider.value
    catalog["selected_model"] = config.ollama_model.value
    supported_models = _supported_models_from_catalog(catalog)
    if not supported_models:
        supported_models = [
            {
                "name": model.value,
                "description": MODEL_DESCRIPTIONS[model],
            }
            for model in OllamaModel
        ]
    catalog["supported_models"] = supported_models
    return catalog
