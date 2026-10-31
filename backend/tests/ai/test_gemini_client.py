import httpx
import pytest
from google.genai import errors

from app.ai.gemini_client import GeminiClient
from app.ai.provider import (
    AIProviderError, EmptyResponseError, InvalidApiKeyError, MalformedResponseError, MissingApiKeyError,
    ModelUnavailableError, ProviderNetworkError, ProviderTimeoutError, RateLimitedError)
from app.ai.schemas import InvestigationResult
from app.config import AiSettings

KEY = "AIza-test-secret-key-123"


def settings(key=KEY, **kw):
    return AiSettings(_env_file=None, gemini_api_key=key, **kw)


class Resp:
    def __init__(self, text):
        self.text = text


class SdkClient:
    def __init__(self, result):
        self.result, self.kwargs = result, None
        self.models = self

    def generate_content(self, **kwargs):
        self.kwargs = kwargs
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def call(result, **kw):
    c = GeminiClient(settings(**kw), sdk_client=SdkClient(result))
    return c.generate_structured(system_instruction="s", user_content="u", response_schema=InvestigationResult), c


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(MissingApiKeyError) as e:
        GeminiClient(settings(key=None)).generate_structured(
            system_instruction="s", user_content="u", response_schema=InvestigationResult)
    assert "GEMINI_API_KEY" in e.value.message
    with pytest.raises(MissingApiKeyError):
        GeminiClient(settings(key="   ")).generate_structured(
            system_instruction="s", user_content="u", response_schema=InvestigationResult)


def test_settings_read_env_and_default_model(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-custom")
    s = AiSettings(_env_file=None)
    assert s.api_key_value() == "k" and s.gemini_model == "gemini-custom"
    monkeypatch.delenv("GEMINI_MODEL")
    assert AiSettings(_env_file=None).gemini_model == "gemini-2.5-flash"


def test_key_not_in_repr():
    assert "secret" not in repr(settings()) and "secret" not in str(settings())


def test_success_uses_configured_model_and_json_mode():
    resp, c = call(Resp('{"a": 1}'), gemini_model="gemini-x")
    assert resp.data == {"a": 1} and resp.model == "gemini-x"
    kw = c._client.kwargs
    assert kw["model"] == "gemini-x" and kw["config"].response_mime_type == "application/json"


@pytest.mark.parametrize("text", [None, "", "   "])
def test_empty_response(text):
    with pytest.raises(EmptyResponseError):
        call(Resp(text))


@pytest.mark.parametrize("text", ["not json", "[1,2]", '{"a":'])
def test_malformed_response(text):
    with pytest.raises(MalformedResponseError):
        call(Resp(text))


@pytest.mark.parametrize("exc, expected", [
    (httpx.ReadTimeout("timed out"), ProviderTimeoutError),
    (TimeoutError(), ProviderTimeoutError),
    (httpx.ConnectError("dns fail"), ProviderNetworkError),
    (errors.ClientError(429, {"error": {"message": "quota"}}), RateLimitedError),
    (errors.ClientError(401, {"error": {"message": "nope"}}), InvalidApiKeyError),
    (errors.ClientError(400, {"error": {"message": "API key not valid. Please pass a valid API key."}}), InvalidApiKeyError),
    (errors.ClientError(404, {"error": {"message": "model not found"}}), ModelUnavailableError),
    (errors.ServerError(503, {"error": {"message": "overloaded"}}), ModelUnavailableError),
    (RuntimeError("boom"), AIProviderError),
])
def test_api_failures_map_to_controlled_errors(exc, expected):
    with pytest.raises(expected) as e:
        call(exc)
    assert type(e.value) is expected


def test_key_never_appears_in_errors_or_logs(caplog):
    exc = errors.ClientError(400, {"error": {"message": f"bad request key={KEY}"}})
    with pytest.raises(AIProviderError) as e:
        call(exc)
    assert KEY not in e.value.message and KEY not in caplog.text
