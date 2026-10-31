"""Secrets (the Gemini API key) live in the operating system's keychain, never in a settings file, the database or a log.

``KeyringSecretStore`` uses the platform store (macOS Keychain, Windows Credential Locker, Secret Service on Linux). If no
secure store is available PacketMind refuses to persist a key (the environment variable ``GEMINI_API_KEY`` still works).
The key is only ever *read* by the Gemini client; no API returns it.
"""
from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)
SERVICE = "PacketMind"


class SecretStoreUnavailable(Exception):
    """No secure storage on this machine, so a secret cannot be stored."""


class SecretStore(ABC):
    @property
    @abstractmethod
    def available(self) -> bool: ...

    @property
    def backend_name(self) -> str:
        return type(self).__name__

    @abstractmethod
    def get(self, name: str) -> str | None: ...

    @abstractmethod
    def set(self, name: str, value: str) -> None: ...

    @abstractmethod
    def delete(self, name: str) -> None: ...


class KeyringSecretStore(SecretStore):
    def __init__(self) -> None:
        try:
            import keyring
            from keyring.backends import fail, null

            backend = keyring.get_keyring()
            self._keyring = keyring
            self._backend = type(backend).__name__
            self._ok = not isinstance(backend, (fail.Keyring, null.Keyring))
        except Exception:  # keyring missing or broken: behave as "no secure storage"
            self._keyring, self._backend, self._ok = None, "none", False

    @property
    def available(self) -> bool:
        return self._ok

    @property
    def backend_name(self) -> str:
        return self._backend

    def get(self, name: str) -> str | None:
        if not self._ok:
            return None
        try:
            return self._keyring.get_password(SERVICE, name) or None
        except Exception:
            logger.warning("Could not read a secret from the system keychain")
            return None

    def set(self, name: str, value: str) -> None:
        if not self._ok:
            raise SecretStoreUnavailable("No secure storage is available on this computer.")
        try:
            self._keyring.set_password(SERVICE, name, value)
        except Exception:
            logger.warning("Could not write a secret to the system keychain")
            raise SecretStoreUnavailable("The system keychain refused to store the key.") from None

    def delete(self, name: str) -> None:
        if not self._ok:
            return
        try:
            self._keyring.delete_password(SERVICE, name)
        except Exception:  # already absent
            pass


class MemorySecretStore(SecretStore):
    """For tests: behaves like a keychain without touching the real one."""

    def __init__(self, available: bool = True) -> None:
        self._available, self._data = available, {}

    @property
    def available(self) -> bool:
        return self._available

    def get(self, name: str) -> str | None:
        return self._data.get(name)

    def set(self, name: str, value: str) -> None:
        if not self._available:
            raise SecretStoreUnavailable("No secure storage is available on this computer.")
        self._data[name] = value

    def delete(self, name: str) -> None:
        self._data.pop(name, None)


GEMINI_KEY = "gemini_api_key"
_store: SecretStore | None = None
_lock = threading.Lock()


def get_secret_store() -> SecretStore:
    global _store
    with _lock:
        if _store is None:
            _store = KeyringSecretStore()
        return _store


def stored_gemini_key() -> str | None:
    """The key the user saved in the keychain (None if none, or the keychain is unavailable). Never logged."""
    try:
        key = get_secret_store().get(GEMINI_KEY)
    except Exception:
        return None
    return key.strip() if key and key.strip() else None
