"""Bitwarden CLI backend for key-amnesia.

Stores secrets as Secure Notes in a dedicated Bitwarden folder.
Requires `bw` CLI installed, logged in, and server URL configured.

Each secret is a Secure Note item:
  - name (title) = secret name
  - notes = secret value
  - folder = "key-amnesia" (auto-created if missing)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from typing import Any

from key_amnesia.backend import BackendError, SecretBackend

FOLDER_NAME = "key-amnesia"
ITEM_TYPE_SECURE_NOTE = 2


def _bw_available() -> bool:
    return shutil.which("bw") is not None


def _run_bw(
    args: list[str],
    *,
    session: str | None = None,
    input_data: str | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Run a bw CLI command. Raises BackendError on failure."""
    cmd = ["bw"] + args
    env = os.environ.copy()
    if session:
        env["BW_SESSION"] = session
    env["BW_NOINTERACTION"] = "true"
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            input=input_data,
        )
    except FileNotFoundError:
        raise BackendError(
            "Bitwarden CLI (bw) not found. Install: https://bitwarden.com/help/cli/"
        )
    except subprocess.TimeoutExpired:
        raise BackendError(f"bw command timed out: {' '.join(args)}")
    return result


def _check_bw_status() -> dict[str, Any]:
    """Check bw status. Returns parsed status dict."""
    result = _run_bw(["status"])
    if result.returncode != 0:
        raise BackendError(f"bw status failed: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise BackendError(f"bw status returned invalid JSON: {result.stdout[:200]}")


class BitwardenBackend(SecretBackend):
    """Bitwarden CLI-backed secret storage."""

    def __init__(self) -> None:
        self._folder_id: str | None = None
        self._last_sync: float = 0

    def unlock(self, password: str) -> str:
        if not _bw_available():
            raise BackendError(
                "Bitwarden CLI (bw) not found. Install: https://bitwarden.com/help/cli/"
            )
        status = _check_bw_status()
        state = status.get("status", "")
        if state == "unauthenticated":
            raise BackendError(
                "Not logged in to Bitwarden. Run: bw login"
            )
        if state in ("locked", "unlocked"):
            session = os.environ.get("BW_SESSION", "")
            if state == "unlocked" and session:
                self._ensure_folder(session)
                return session
            session = self._do_unlock(password)
            self._ensure_folder(session)
            return session
        raise BackendError(f"Unknown bw status: {state}")

    def _do_unlock(self, password: str) -> str:
        """Unlock bw vault using --passwordenv to avoid stdin issues."""
        env_key = "_KEYGATE_BW_PW"
        cmd = ["bw", "unlock", "--raw", "--passwordenv", env_key]
        env = os.environ.copy()
        env[env_key] = password
        env["BW_NOINTERACTION"] = "true"
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60.0,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise BackendError("bw unlock timed out")
        if result.returncode != 0:
            err = result.stderr.strip()
            if "Invalid master password" in err or "invalid" in err.lower():
                raise BackendError("Invalid master password")
            raise BackendError(f"bw unlock failed: {err}")
        session = result.stdout.strip()
        if not session:
            raise BackendError("bw unlock returned empty session")
        return session

    def lock(self, session: str) -> None:
        _run_bw(["lock"], session=session)

    def is_unlocked(self) -> bool:
        try:
            status = _check_bw_status()
            return status.get("status") == "unlocked"
        except BackendError:
            return False

    def _ensure_folder(self, session: str) -> None:
        """Find or create the key-amnesia folder in Bitwarden."""
        if self._folder_id is not None:
            return
        result = _run_bw(["list", "folders", "--search", FOLDER_NAME], session=session)
        if result.returncode != 0:
            raise BackendError(f"bw list folders failed: {result.stderr.strip()}")
        try:
            folders = json.loads(result.stdout)
        except json.JSONDecodeError:
            folders = []
        for f in folders:
            if f.get("name") == FOLDER_NAME:
                self._folder_id = f["id"]
                return
        # Create folder
        import base64
        folder_json = json.dumps({"name": FOLDER_NAME})
        encoded = base64.b64encode(folder_json.encode()).decode()
        result = _run_bw(["create", "folder", encoded], session=session)
        if result.returncode != 0:
            raise BackendError(f"Failed to create folder: {result.stderr.strip()}")
        try:
            created = json.loads(result.stdout)
            self._folder_id = created["id"]
        except (json.JSONDecodeError, KeyError):
            raise BackendError("Failed to parse created folder response")

    def _sync_if_stale(self, session: str) -> None:
        """Sync vault if last sync was more than 30s ago."""
        now = time.time()
        if now - self._last_sync > 30:
            _run_bw(["sync"], session=session, timeout=60.0)
            self._last_sync = now

    def _list_items(self, session: str) -> list[dict[str, Any]]:
        """List all items in the key-amnesia folder."""
        self._ensure_folder(session)
        assert self._folder_id is not None
        result = _run_bw(
            ["list", "items", "--folderid", self._folder_id],
            session=session,
        )
        if result.returncode != 0:
            raise BackendError(f"bw list items failed: {result.stderr.strip()}")
        try:
            items = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        return [i for i in items if i.get("type") == ITEM_TYPE_SECURE_NOTE]

    def load_secrets(self, session: str) -> dict[str, str]:
        self._sync_if_stale(session)
        items = self._list_items(session)
        secrets: dict[str, str] = {}
        for item in items:
            name = item.get("name", "")
            value = item.get("notes", "")
            if name:
                secrets[name] = value or ""
        return secrets

    def set_secret(self, session: str, name: str, value: str) -> None:
        self._ensure_folder(session)
        assert self._folder_id is not None
        existing = self._find_item_by_name(session, name)
        if existing:
            existing["notes"] = value
            import base64
            encoded = base64.b64encode(json.dumps(existing).encode()).decode()
            result = _run_bw(
                ["edit", "item", existing["id"], encoded],
                session=session,
            )
            if result.returncode != 0:
                raise BackendError(f"bw edit item failed: {result.stderr.strip()}")
        else:
            import base64
            item = {
                "type": ITEM_TYPE_SECURE_NOTE,
                "name": name,
                "notes": value,
                "secureNote": {"type": 0},
                "folderId": self._folder_id,
            }
            encoded = base64.b64encode(json.dumps(item).encode()).decode()
            result = _run_bw(["create", "item", encoded], session=session)
            if result.returncode != 0:
                raise BackendError(f"bw create item failed: {result.stderr.strip()}")

    def remove_secret(self, session: str, name: str) -> None:
        existing = self._find_item_by_name(session, name)
        if not existing:
            raise BackendError(f"Secret not found: {name}")
        result = _run_bw(["delete", "item", existing["id"]], session=session)
        if result.returncode != 0:
            raise BackendError(f"bw delete item failed: {result.stderr.strip()}")

    def list_names(self, session: str) -> list[str]:
        self._sync_if_stale(session)
        items = self._list_items(session)
        return sorted(item.get("name", "") for item in items if item.get("name"))

    def _find_item_by_name(self, session: str, name: str) -> dict[str, Any] | None:
        items = self._list_items(session)
        for item in items:
            if item.get("name") == name:
                return item
        return None

    def fingerprint(self) -> str | None:
        """Content fingerprint based on item list hash."""
        session = os.environ.get("BW_SESSION")
        if not session:
            return None
        try:
            items = self._list_items(session)
        except BackendError:
            return None
        content = json.dumps(
            sorted((i.get("name", ""), i.get("revisionDate", "")) for i in items),
            separators=(",", ":"),
        )
        return hashlib.sha256(content.encode()).hexdigest()[:32]
