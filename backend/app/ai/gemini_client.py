"""Gemini API client: authentication, model config, timeouts, error mapping. Nothing else."""
from __future__ import annotations

import json
import logging
from typing import Any

from app.ai.provider import (
    AIProvider,
    AIProviderError,
    EmptyResponseError,
    InvalidApiKeyError,
    MalformedResponseError,
    MissingApiKeyError,
    ModelUnavailableError,
    ProviderNetworkError,
    ProviderResponse,
    ProviderTimeoutError,
    RateLimitedError,
)
from app.config import AiSettings, get_ai_settings

logger = logging.getLogger(__name__)


class GeminiClient(AIProvider):
    name = "gemini"

    def __init__(self, settings: AiSettings | None = None, sdk_client: Any | None = None, usage: Any | None | bool = None):
        """`sdk_client` lets tests inject a fake `google.genai.Client`; it is never needed in production.

        ``usage`` (``AiUsage``) enforces the AI on/off switch and daily limit, caches identical requests and counts them. In
        production it is always on; an injected fake SDK client opts out unless a usage object is passed explicitly.
        """
        self._settings = settings or get_ai_settings()
        self._client = sdk_client
        if usage is None and sdk_client is None:
            from app.services.ai_usage import get_ai_usage

            usage = get_ai_usage()
        self._usage = None if usage is False else usage  # False: explicitly ungated (the Settings connection test, which counts itself)

    @property
    def model(self) -> str:
        return self._settings.gemini_model

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        key = self._settings.api_key_value()
        if not key:
            raise MissingApiKeyError()
        from google import genai  # lazy: importing the SDK is not needed unless AI is used
        from google.genai import types

        timeout_ms = int(self._settings.gemini_timeout_seconds * 1000)
        self._client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=timeout_ms))
        return self._client

    def generate_structured(
        self, *, system_instruction: str, user_content: str, response_schema: type
    ) -> ProviderResponse:
        if self._usage is None:
            return self._generate(system_instruction, user_content, response_schema)
        fingerprint = f"{self.model}\x00{getattr(response_schema, '__name__', '')}\x00{system_instruction}\x00{user_content}"
        return self._usage.run(fingerprint, lambda: self._generate(system_instruction, user_content, response_schema))

    def _generate(self, system_instruction: str, user_content: str, response_schema: type) -> ProviderResponse:
        client = self._get_client()
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=response_schema,
            temperature=0.2,
            max_output_tokens=self._settings.gemini_max_output_tokens,
        )
        try:
            response = client.models.generate_content(model=self.model, contents=user_content, config=config)
        except AIProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to a controlled error below
            raise self._map_exception(exc) from None
        return ProviderResponse(data=self._parse(response), model=self.model)

    # ------------------------------------------------------------------ helpers
    def _redact(self, text: str) -> str:
        key = self._settings.api_key_value()
        return text.replace(key, "[REDACTED]") if key else text

    def _map_exception(self, exc: Exception) -> AIProviderError:
        # Log only the exception type and a redacted, truncated message - never request contents.
        logger.warning("Gemini request failed: %s: %s", type(exc).__name__, self._redact(str(exc))[:200])
        name = type(exc).__name__
        text = str(exc).lower()
        code = getattr(exc, "code", None)
        if isinstance(exc, TimeoutError) or "timeout" in name.lower() or "timed out" in text:
            return ProviderTimeoutError()
        if isinstance(code, int):
            if code == 429:
                return RateLimitedError()
            if code in (401, 403) or "api key not valid" in text or "api_key_invalid" in text:
                return InvalidApiKeyError()
            if code == 400 and "api key" in text:
                return InvalidApiKeyError()
            if code in (404, 500, 502, 503, 504):
                return ModelUnavailableError()
            return AIProviderError(f"Gemini API returned an error (HTTP {code}).")
        if any(s in name for s in ("Connect", "Network", "Transport", "Protocol")) or isinstance(exc, OSError):
            return ProviderNetworkError()
        return AIProviderError("The Gemini request failed unexpectedly.")

    @staticmethod
    def _parse(response: Any) -> dict[str, Any]:
        text = getattr(response, "text", None)
        if not text or not str(text).strip():
            raise EmptyResponseError()
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            raise MalformedResponseError() from None
        if not isinstance(data, dict):
            raise MalformedResponseError("The model returned JSON that is not an object.")
        return data
