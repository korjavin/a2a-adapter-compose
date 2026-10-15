"""Container entrypoint: serve claude or codex as an A2A agent, configured by env."""

import argparse
import os
import shlex
import sys

HARNESSES = ("claude", "codex")
WORKSPACE = "/workspace"


def parse_bool(name, default):
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    sys.exit(f"{name} must be a boolean (true/false), got {raw!r}")


def require(name, choices=None):
    value = os.environ.get(name, "").strip()
    if not value or (choices and value not in choices):
        allowed = f" (one of: {', '.join(choices)})" if choices else ""
        sys.exit(f"{name} is required{allowed}, got {value!r}")
    return value


def main():
    harness = require("A2A_HARNESS", HARNESSES)
    domain = require("A2A_DOMAIN")
    skip = parse_bool("A2A_SKIP_PERMISSIONS", True)
    port = int(os.environ.get("A2A_PORT", "9000"))
    timeout = int(os.environ.get("A2A_TIMEOUT", "600"))
    agent_args = shlex.split(os.environ.get("A2A_AGENT_ARGS", ""))

    from a2a_adapter import build_agent_card, serve_agent
    from a2a_adapter.cli import _validate_agent_args  # upstream managed-flag guard

    # exits 2 with a clear message if A2A_AGENT_ARGS touches a flag the adapter owns
    _validate_agent_args(argparse.ArgumentParser(prog="A2A_AGENT_ARGS"), harness, agent_args)

    common = dict(
        working_dir=WORKSPACE,
        cli_args=agent_args,
        timeout=timeout,
        name=os.environ.get("A2A_NAME", ""),
        description=os.environ.get("A2A_DESCRIPTION", ""),
    )
    if harness == "claude":
        from a2a_adapter import ClaudeCodeAdapter

        adapter = ClaudeCodeAdapter(skip_permissions=skip, **common)
        # ponytail: upstream assigns a random per-process session_id, which orphans
        # the persisted sessions.json mapping on restart; a constructor arg upstream
        # would replace this attribute poke.
        adapter.session_id = os.environ.get("A2A_SESSION_PREFIX", "a2a")
    else:
        from a2a_adapter import CodexAdapter

        # workspace need not be a git repo
        adapter = CodexAdapter(bypass_approvals=skip, skip_git_check=True, **common)

    card = build_agent_card(adapter, url=f"https://{domain}/")
    print(f"Serving {harness} on :{port}, card url https://{domain}/", flush=True)
    serve_agent(adapter, agent_card=card, host="0.0.0.0", port=port)


def self_check():
    def env(**kv):
        for k in ("A2A_HARNESS", "A2A_SKIP_PERMISSIONS"):
            os.environ.pop(k, None)
        os.environ.update(kv)

    def exits(fn, *a):
        try:
            fn(*a)
        except SystemExit as e:
            return e.code not in (0, None)
        return False

    env()
    assert parse_bool("A2A_SKIP_PERMISSIONS", True) is True
    for raw, want in (("false", False), ("0", False), ("TRUE", True), ("yes", True)):
        env(A2A_SKIP_PERMISSIONS=raw)
        assert parse_bool("A2A_SKIP_PERMISSIONS", True) is want, raw
    env(A2A_SKIP_PERMISSIONS="maybe")
    assert exits(parse_bool, "A2A_SKIP_PERMISSIONS", True)
    env()
    assert exits(require, "A2A_HARNESS", HARNESSES)
    env(A2A_HARNESS="gpt")
    assert exits(require, "A2A_HARNESS", HARNESSES)
    env(A2A_HARNESS="codex")
    assert require("A2A_HARNESS", HARNESSES) == "codex"
    print("self-check ok")


if __name__ == "__main__":
    self_check() if sys.argv[1:] == ["--self-check"] else main()
