# macOS

**Not implemented yet** (planned as experimental in a later release).

Today, isolated-console spawn on macOS **fails closed** — same as any
unsupported platform. Password prompts that need a separate window will
not work; headless / no-display paths deny by design.

When experimental support lands it is expected to use a PID-file wrapper
around `osascript` / `open` so parent-death and cancel semantics still
work. Until a real Mac user confirms the visible window path, treat any
macOS notes as experimental.

Windows and Linux remain the supported platforms for daily use.
