"""Abstract secret backend interface.

Backends provide a uniform way to load/store secrets regardless of the
underlying storage (local vault, Bitwarden, 1Password, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BackendError(Exception):
    """Backend operation failed."""


class SecretBackend(ABC):
    """Abstract interface for secret storage backends."""

    @abstractmethod
    def unlock(self, password: str) -> str:
        """Authenticate and return a session token/key for subsequent calls.

        For Bitwarden: runs `bw unlock`, returns BW_SESSION.
        For local vault: runs Argon2id KDF, returns derived key hex.
        """

    @abstractmethod
    def lock(self, session: str) -> None:
        """End the session."""

    @abstractmethod
    def is_unlocked(self) -> bool:
        """Check if a session is currently active."""

    @abstractmethod
    def load_secrets(self, session: str) -> dict[str, str]:
        """Return all secrets as {name: value}."""

    @abstractmethod
    def set_secret(self, session: str, name: str, value: str) -> None:
        """Store or update a secret."""

    @abstractmethod
    def remove_secret(self, session: str, name: str) -> None:
        """Remove a secret by name."""

    @abstractmethod
    def list_names(self, session: str) -> list[str]:
        """Return sorted list of secret names."""

    @abstractmethod
    def fingerprint(self) -> str | None:
        """Cheap content fingerprint to detect changes. None if unavailable."""
