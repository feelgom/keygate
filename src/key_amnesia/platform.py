"""OS-specific process spawn helpers for isolated-console prompts."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, TextIO

from key_amnesia import theme

# Linux X11/Wayland terminal emulators, tried in order (first on PATH wins).
_LINUX_EMULATORS: tuple[str, ...] = (
    "x-terminal-emulator",
    "gnome-terminal",
    "konsole",
    "xterm",
)

_LINUX_EMULATOR_DESCRIPTIONS: dict[str, str] = {
    "x-terminal-emulator": "uses your distro's configured default terminal",
    "gnome-terminal": "full-featured, best if you're on GNOME",
    "konsole": "full-featured, best if you're on KDE",
    "xterm": "lightest and fastest, no desktop-environment dependencies",
}

# Package-manager detection order (first on PATH wins).
_PKG_MANAGERS: tuple[tuple[str, str], ...] = (
    ("apt-get", "sudo apt-get install {pkg}"),
    ("apt", "sudo apt install {pkg}"),
    ("dnf", "sudo dnf install {pkg}"),
    ("pacman", "sudo pacman -S {pkg}"),
    ("apk", "sudo apk add {pkg}"),
    ("zypper", "sudo zypper install {pkg}"),
)

# Brief pause after spawn to catch an emulator that launches then exits right
# away (e.g. a broken alias, or a build that doesn't accept our -e/-- flag).
# Overridable so tests don't pay this cost.
_POLL_DELAY_S = 0.15

# macOS: open/osascript return immediately — parent polls a PID file written by
# a wrapper that then execs the helper. Overridable for tests.
_MACOS_PID_WAIT_S = 8.0
_MACOS_PID_POLL_S = 0.05

# Visible Terminal.app window path is unconfirmed by a real Mac user.
MACOS_SPAWN_EXPERIMENTAL = True

# Embedded into the temp wrapper script; must stay self-contained (no imports
# from key_amnesia — the wrapper may run before the package is on PYTHONPATH
# the way Terminal.app launches it).
_MACOS_WRAPPER_SOURCE = '''\
import json
import os
import sys

def main() -> None:
    if len(sys.argv) < 4:
        sys.stderr.write("key-amnesia macOS wrapper: missing args\\n")
        sys.exit(2)
    env_path, pid_path = sys.argv[1], sys.argv[2]
    helper = sys.argv[3:]
    with open(env_path, "r", encoding="utf-8") as f:
        env = json.load(f)
    try:
        os.unlink(env_path)
    except OSError:
        pass
    os.environ.clear()
    os.environ.update({str(k): str(v) for k, v in env.items()})
    with open(pid_path, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.execvpe(helper[0], helper, os.environ)

if __name__ == "__main__":
    main()
'''


class PidFileProcess:
    """Popen-like handle bound to a helper PID from a PID file (macOS).

    ``open -a Terminal`` / ``osascript`` exit immediately, so the launcher
    Popen cannot be waited on for parent-death or cancel. The wrapper records
    its PID (stable across ``exec`` of the helper) and this object exposes
    ``poll`` / ``terminate`` against that PID.
    """

    def __init__(
        self,
        pid: int,
        *,
        cleanup_paths: list[Path] | None = None,
        cleanup_dir: Path | None = None,
    ) -> None:
        self.pid = int(pid)
        self.returncode: int | None = None
        self._cleanup_paths = list(cleanup_paths or [])
        self._cleanup_dir = cleanup_dir

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            self.returncode = 0
            self._cleanup()
            return 0
        except PermissionError:
            # Exists but not signalable — treat as alive.
            return None
        except OSError:
            self.returncode = 0
            self._cleanup()
            return 0
        return None

    def terminate(self) -> None:
        try:
            os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass

    def _cleanup(self) -> None:
        for p in self._cleanup_paths:
            try:
                p.unlink(missing_ok=True)  # type: ignore[call-arg]
            except TypeError:
                # Python <3.8 missing_ok — not our floor, but be safe.
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass
            except OSError:
                pass
        if self._cleanup_dir is not None:
            try:
                self._cleanup_dir.rmdir()
            except OSError:
                pass


def _has_interactive_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _linux_emulator_argv(emulator: str, argv: list[str]) -> list[str]:
    """Build emulator + helper argv. Secrets stay in env, never on argv."""
    name = os.path.basename(emulator)
    if name == "gnome-terminal":
        # gnome-terminal deprecated -e; -- separates options from the command.
        return [emulator, "--", *argv]
    return [emulator, "-e", *argv]


def _process_alive(proc: Any) -> bool:
    """Best-effort liveness check shortly after spawn.

    Treat a stub without a working `.poll()` (e.g. an unconfigured test
    double) as alive rather than reject it — this only needs to catch a
    *real* process that has already exited.
    """
    poll = getattr(proc, "poll", None)
    if not callable(poll):
        return True
    try:
        return poll() is None
    except Exception:
        return True


def _no_emulator_oserror() -> OSError:
    return OSError(
        "No suitable terminal emulator found "
        f"(tried {', '.join(_LINUX_EMULATORS)}). Fail closed."
    )


def _open_controlling_tty() -> TextIO | None:
    """Open the controlling terminal, or None if unavailable."""
    try:
        return open("/dev/tty", "r+", encoding="utf-8", errors="replace")
    except OSError:
        return None


def _tty_readline(tty: TextIO, prompt: str) -> str:
    tty.write(prompt)
    tty.flush()
    return tty.readline().strip()


def _pkg_install_command(package: str) -> str | None:
    """Return a one-line install command for *package*, or None if unknown pm."""
    for binary, template in _PKG_MANAGERS:
        if shutil.which(binary):
            return template.format(pkg=package)
    return None


def _try_spawn_linux_emulators(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> tuple[Any | None, list[str]]:
    """Try each known emulator on PATH. Return (proc_or_None, names_tried)."""
    tried: list[str] = []
    for name in _LINUX_EMULATORS:
        path = shutil.which(name)
        if not path:
            continue
        tried.append(name)
        cmd = _linux_emulator_argv(path, argv)
        try:
            # No stdin/stdout/stderr kwargs — emulator owns stdio.
            proc = popen_fn(cmd, env=env, close_fds=True)
        except OSError:
            continue
        if _POLL_DELAY_S:
            time.sleep(_POLL_DELAY_S)
        if _process_alive(proc):
            return proc, tried
        # Launched but exited immediately (bad invocation, broken alias) —
        # don't report false success; try the next emulator instead.
        continue
    return None, tried


def _offer_linux_emulator_install(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> Any | None:
    """Interactive /dev/tty recovery when no emulator is on PATH.

    Returns a live process if the user installs and retry succeeds; otherwise
    None (caller raises the existing OSError). Never prompts on the headless
    branch — that path never reaches here. Never asks for a password.
    """
    tty = _open_controlling_tty()
    if tty is None:
        return None

    err = _no_emulator_oserror()
    try:
        theme.warn(str(err), file=tty)
        answer = _tty_readline(tty, "Install one now? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            return None

        theme.info("Choose a terminal emulator to install:", file=tty)
        for i, name in enumerate(_LINUX_EMULATORS, start=1):
            desc = _LINUX_EMULATOR_DESCRIPTIONS.get(name, "")
            theme.info(f"  {i}) {name} - {desc}", file=tty)
        skip_n = len(_LINUX_EMULATORS) + 1
        theme.info(f"  {skip_n}) skip, don't install anything", file=tty)

        choice_raw = _tty_readline(tty, "Choice: ").strip()
        try:
            choice = int(choice_raw)
        except ValueError:
            return None
        if choice == skip_n or choice < 1 or choice > skip_n:
            return None

        package = _LINUX_EMULATORS[choice - 1]
        cmd = _pkg_install_command(package)
        if cmd is not None:
            theme.info("Run this in another shell (not executed by key-amnesia):", file=tty)
            theme.out(f"  {cmd}", file=tty)
        else:
            theme.info(
                f"Install package '{package}' with your distro's package manager "
                "(no known package manager found on PATH).",
                file=tty,
            )
        _tty_readline(tty, "Press Enter after installing… ")

        retry = _tty_readline(tty, "Installed it? Retry now? [y/N] ").strip().lower()
        if retry not in ("y", "yes"):
            return None

        proc, tried = _try_spawn_linux_emulators(argv, env, popen_fn=popen_fn)
        if proc is not None:
            return proc
        if tried:
            # Found but none stayed running — surface the same message as the
            # normal path rather than the "none on PATH" OSError.
            raise OSError(
                f"Terminal emulator(s) found ({', '.join(tried)}) but none stayed "
                "running (bad invocation or immediate exit). Fail closed."
            )
        return None
    finally:
        try:
            tty.close()
        except Exception:
            pass


def _spawn_linux(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> Any:
    if not _has_interactive_display():
        raise OSError(
            "No interactive display available (DISPLAY/WAYLAND_DISPLAY unset); "
            "cannot spawn isolated console. Fail closed."
        )

    proc, tried = _try_spawn_linux_emulators(argv, env, popen_fn=popen_fn)
    if proc is not None:
        return proc

    if tried:
        raise OSError(
            f"Terminal emulator(s) found ({', '.join(tried)}) but none stayed "
            "running (bad invocation or immediate exit). Fail closed."
        )

    # Display present, nothing on PATH — one interactive install offer via /dev/tty.
    offered = _offer_linux_emulator_install(argv, env, popen_fn=popen_fn)
    if offered is not None:
        return offered
    raise _no_emulator_oserror()


def _applescript_quote(s: str) -> str:
    """Quote *s* as an AppleScript string literal."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _wait_for_pid_file(pid_path: Path, *, timeout_s: float | None = None) -> int:
    """Poll *pid_path* until it contains a positive integer PID."""
    limit = _MACOS_PID_WAIT_S if timeout_s is None else timeout_s
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        try:
            text = pid_path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if text.isdigit():
            pid = int(text)
            if pid > 0:
                return pid
        if _MACOS_PID_POLL_S:
            time.sleep(_MACOS_PID_POLL_S)
    raise OSError(
        "macOS isolated-console helper did not record a PID in time "
        "(Terminal/osascript may have failed to launch). Fail closed."
    )


def _macos_launcher_argv(
    wrapper_py: Path,
    env_file: Path,
    pid_file: Path,
    helper_argv: list[str],
    *,
    command_file: Path | None = None,
) -> list[str]:
    """Build osascript/open argv. Secrets stay in *env_file*, never on argv."""
    inner = " ".join(
        shlex.quote(p)
        for p in [
            sys.executable,
            str(wrapper_py),
            str(env_file),
            str(pid_file),
            *helper_argv,
        ]
    )
    osascript = shutil.which("osascript")
    if osascript:
        script = (
            'tell application "Terminal"\n'
            f"  do script {_applescript_quote(inner)}\n"
            "  activate\n"
            "end tell"
        )
        return [osascript, "-e", script]

    open_bin = shutil.which("open")
    if open_bin and command_file is not None:
        return [open_bin, "-a", "Terminal", str(command_file)]

    raise OSError(
        "Neither osascript nor open found on PATH; cannot spawn macOS "
        "isolated console. Fail closed."
    )


def _spawn_macos(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any],
) -> PidFileProcess:
    """Spawn helper via Terminal.app using a PID-file wrapper.

    ``open`` / ``osascript`` return immediately; the wrapper writes its PID
    then ``exec``s the helper so parent-death / ``poll`` / ``terminate`` track
    the real helper, not the launcher.
    """
    tmp = Path(tempfile.mkdtemp(prefix="key-amnesia-macos-"))
    try:
        try:
            tmp.chmod(0o700)
        except OSError:
            pass

        env_file = tmp / "env.json"
        pid_file = tmp / "helper.pid"
        wrapper_py = tmp / "wrapper.py"
        command_file = tmp / "run.command"

        env_file.write_text(
            json.dumps({str(k): str(v) for k, v in env.items()}),
            encoding="utf-8",
        )
        try:
            env_file.chmod(0o600)
        except OSError:
            pass

        wrapper_py.write_text(_MACOS_WRAPPER_SOURCE, encoding="utf-8")
        try:
            wrapper_py.chmod(0o700)
        except OSError:
            pass

        # open -a Terminal fallback: a .command file Terminal will execute.
        inner = " ".join(
            shlex.quote(p)
            for p in [
                sys.executable,
                str(wrapper_py),
                str(env_file),
                str(pid_file),
                *argv,
            ]
        )
        command_file.write_text("#!/bin/bash\nexec " + inner + "\n", encoding="utf-8")
        try:
            command_file.chmod(0o700)
        except OSError:
            pass

        launch_argv = _macos_launcher_argv(
            wrapper_py, env_file, pid_file, argv, command_file=command_file
        )
        # Launcher env is the *caller's* environment without prompt secrets —
        # those live only in env.json until the wrapper loads and unlinks it.
        try:
            popen_fn(launch_argv, close_fds=True)
        except OSError as e:
            raise OSError(
                f"Failed to launch macOS Terminal for isolated console: {e}. "
                "Fail closed."
            ) from e

        helper_pid = _wait_for_pid_file(pid_file)
        return PidFileProcess(
            helper_pid,
            cleanup_paths=[env_file, pid_file, wrapper_py, command_file],
            cleanup_dir=tmp,
        )
    except Exception:
        # Best-effort scrub of the temp dir (may still hold env.json).
        for p in tmp.iterdir() if tmp.exists() else []:
            try:
                p.unlink()
            except OSError:
                pass
        try:
            tmp.rmdir()
        except OSError:
            pass
        raise


def spawn_isolated_console(
    argv: list[str],
    env: dict[str, str],
    *,
    popen_fn: Callable[..., Any] | None = None,
) -> Any:
    """Spawn *argv* in an isolated console; sensitive data only in *env*.

    Windows: CREATE_NEW_CONSOLE, no stdio kwargs.
    Linux: first available of x-terminal-emulator / gnome-terminal / konsole /
    xterm when DISPLAY or WAYLAND_DISPLAY is set; otherwise fail closed.
    macOS (experimental): Terminal.app via osascript/open + PID-file wrapper
    so parent-death tracks the helper, not the short-lived launcher.
    Other platforms: fail closed.
    """
    popen = popen_fn or subprocess.Popen

    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
        # No stdin/stdout/stderr kwargs — new console owns stdio.
        return popen(
            argv,
            env=env,
            creationflags=creationflags,
            close_fds=False,
        )

    if sys.platform.startswith("linux"):
        return _spawn_linux(argv, env, popen_fn=popen)

    if sys.platform == "darwin":
        return _spawn_macos(argv, env, popen_fn=popen)

    raise OSError(
        "Isolated-console spawn is not implemented on this platform "
        f"({sys.platform}); fail closed."
    )
