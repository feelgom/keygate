#!/bin/bash
# keygate installer — installs skill + hook for Claude Code and Codex
# Usage: ./install.sh
# No Python dependencies required for Bitwarden-only mode.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_SRC="$SCRIPT_DIR/dist/claude-skill/keygate.md"
HOOK_SRC="$SCRIPT_DIR/src/key_amnesia/hooks/secret_guard.py"

echo "keygate installer"
echo "================="
echo ""

# --- Claude Code ---
CLAUDE_SKILLS="$HOME/.claude/skills/keygate"
CLAUDE_SETTINGS="$HOME/.claude/settings.json"

mkdir -p "$CLAUDE_SKILLS"
cp "$SKILL_SRC" "$CLAUDE_SKILLS/SKILL.md"
echo "[ok] Claude Code skill installed: $CLAUDE_SKILLS/SKILL.md"

# Install hook into Claude Code settings.json
if command -v python3 &>/dev/null; then
    python3 - "$CLAUDE_SETTINGS" "$SCRIPT_DIR" <<'PYTHON'
import json, sys
from pathlib import Path

settings_path = Path(sys.argv[1])
script_dir = sys.argv[2]
hook_cmd = f"python3 {script_dir}/src/key_amnesia/hooks/secret_guard.py"

settings = {}
if settings_path.exists():
    try:
        settings = json.loads(settings_path.read_text())
    except Exception:
        pass

hooks = settings.setdefault("hooks", {})
pretooluse = hooks.get("PreToolUse", [])
if not isinstance(pretooluse, list):
    pretooluse = []

# Remove existing keygate/key-amnesia hooks
pretooluse = [e for e in pretooluse if not (
    isinstance(e, dict) and any(
        "key_amnesia" in str(h.get("command", "")) or "key-amnesia" in str(h.get("command", ""))
        for h in (e.get("hooks", []) or []) if isinstance(h, dict)
    )
)]

pretooluse.append({
    "matcher": "Bash|Write|Edit",
    "hooks": [{"type": "command", "command": hook_cmd}],
})
hooks["PreToolUse"] = pretooluse
settings_path.parent.mkdir(parents=True, exist_ok=True)
settings_path.write_text(json.dumps(settings, indent=2) + "\n")
print(f"[ok] Claude Code hook installed in: {settings_path}")
PYTHON
else
    echo "[skip] python3 not found — hook not installed (skill still works)"
fi

# --- Codex ---
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CODEX_SKILLS="$CODEX_HOME/skills/keygate"

mkdir -p "$CODEX_SKILLS"
cp "$SKILL_SRC" "$CODEX_SKILLS/SKILL.md"
echo "[ok] Codex skill installed: $CODEX_SKILLS/SKILL.md"

echo ""
echo "Done! Next steps:"
echo "  1. Install Bitwarden CLI: brew install bitwarden-cli"
echo "  2. Login: bw login"
echo "  3. Create config: mkdir -p ~/.keygate && echo '{\"backend\":\"bitwarden\"}' > ~/.keygate/config.json"
echo "  4. In a separate terminal: kg unlock"
echo "  5. Your AI agent can now use: kg run --secret NAME -- <command>"
