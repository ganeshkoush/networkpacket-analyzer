"""Provider abstraction: the rest of PacketMind talks to an LLM only through `AIProvider`."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


class AIProviderError(Exception):
    """Base class for controlled AI failures. `code` is stable; `message` is safe to show a user."""

    code = "ai_error"
    retryable = False

    def __init__(self, message: str | None = None):
        super().__init__(message or self.default_message)
        self.message = message or self.default_message

    default_message = "The AI provider failed."


class MissingApiKeyError(AIProviderError):
    code = "missing_api_key"
    default_message = "GEMINI_API_KEY is not set. Add it to your environment or .env file."


class InvalidApiKeyError(AIProviderError):
    code = "invalid_api_key"
    default_message = "The Gemini API key was rejected. Check GEMINI_API_KEY."


class ProviderTimeoutError(AIProviderError):
    code = "timeout"
    retryable = True
    default_message = "The Gemini request timed out. Try again."


class RateLimitedError(AIProviderError):
    code = "rate_limited"
    retryable = True
    default_message = "The Gemini API rate limit or quota was reached. Wait and try again."


class ProviderNetworkError(AIProviderError):
    code = "network_error"
    retryable = True
    default_message = "Could not reach the Gemini API. Check the network connection."


class ModelUnavailableError(AIProviderError):
    code = "model_unavailable"
    default_message = "The configured Gemini model is unavailable. Check GEMINI_MODEL."


class EmptyResponseError(AIProviderError):
    code = "empty_response"
    retryable = True
    default_message = "The model returned an empty response."


class MalformedResponseError(AIProviderError):
    code = "malformed_response"
    retryable = True
    default_message = "The model returned a response that is not valid JSON."


class AiDisabledError(AIProviderError):
    code = "ai_disabled"
    default_message = "AI features are turned off in Settings → Security."


class DailyLimitReachedError(AIProviderError):
    code = "daily_limit_reached"
    default_message = "The daily AI request limit was reached. Raise it in Settings → AI Usage, or try again tomorrow."


class InvalidOutputError(AIProviderError):
    code = "invalid_output"
    default_message = "The model output failed validation and was discarded."


@dataclass(frozen=True)
class ProviderResponse:
    data: dict[str, Any]  # parsed JSON object
    model: str


class AIProvider(ABC):
    """Minimal interface an LLM backend must implement. No tools or commands are executed through it."""

    name: str = "provider"

    @abstractmethod
    def generate_structured(
        self, *, system_instruction: str, user_content: str, response_schema: type
    ) -> ProviderResponse:
        """Return one JSON object conforming to `response_schema` (a pydantic model class).

        Must raise an `AIProviderError` subclass on any failure - never a raw SDK exception.
        """
