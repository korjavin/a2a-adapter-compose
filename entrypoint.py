"""Host wrapper: serve the host's claude or codex CLI as an A2A agent on a unix socket, configured by env."""

import argparse
import hmac
import os
import shlex
import socket
import stat
import subprocess
import sys

HARNESSES = ("claude", "codex")


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


def require_dir(name):
    value = require(name)
    if not os.path.isdir(value):
        sys.exit(f"{name} must be an existing directory, got {value!r}")
    return value


def require_url(name):
    value = require(name)
    if not value.startswith("https://") or len(value) == len("https://"):
        sys.exit(f"{name} must be a full https:// URL, got {value!r}")
    return value


def require_api_key(name="A2A_API_KEY"):
    """Same rule as the compose check: lowercase hex, >=32 chars. Fail closed otherwise."""
    raw = os.environ.get(name, "")
    if len(raw) < 32 or raw.strip("0123456789abcdef"):
        sys.exit(f"{name} must be lowercase hex, at least 32 chars, the same key Traefik checks (fail closed)")
    return raw


def require_bearer(app, key):
    """ASGI wrapper: refuse any request without "Authorization: Bearer <key>", like the Traefik router rule.
    The socat bridge sits on the shared Traefik network, so a neighbour container can skip that rule."""
    want = f"Bearer {key}".encode()

    async def guarded(scope, receive, send):
        # any matching value passes, as with Traefik's Header(); lifespan is not a request
        if scope["type"] == "lifespan" or any(
                name == b"authorization" and hmac.compare_digest(value, want) for name, value in scope["headers"]):
            return await app(scope, receive, send)
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")]})
            await send({"type": "http.response.body", "body": b"unauthorized\n"})
        # anything else (websocket): never accepted, uvicorn rejects it

    return guarded


def require_private_dir(path):
    """uvicorn chmods the socket 0666 and A2A_YOLO means shell access: the dir is the only gate."""
    try:
        st = os.stat(path)
    except OSError as e:
        sys.exit(f"A2A_SOCKET dir {path!r}: {e}")
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        sys.exit(f"A2A_SOCKET dir {path!r} must be owned by this user with mode 0700, "
                 f"got uid={st.st_uid} mode={stat.S_IMODE(st.st_mode):o}")


def clear_stale_socket(path):
    """uvicorn won't bind over an existing path: unlink a leftover socket, refuse anything else."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(mode):
        sys.exit(f"A2A_SOCKET {path!r} exists and is not a socket; refusing to remove it")
    with socket.socket(socket.AF_UNIX) as probe:
        try:
            probe.connect(path)
        except ConnectionRefusedError:
            os.unlink(path)  # nobody listening: stale
            return
        except OSError as e:
            sys.exit(f"A2A_SOCKET {path!r} exists and can't be probed ({e}); refusing to remove it")
    sys.exit(f"A2A_SOCKET {path!r} has a live listener; another instance is running?")


def main():
    harness = require("A2A_HARNESS", HARNESSES)
    public_url = require_url("A2A_PUBLIC_URL")
    cwd = require_dir("A2A_CWD")
    state_dir = require_dir("A2A_STATE_DIR")
    sock = require("A2A_SOCKET")
    api_key = require_api_key()
    require_private_dir(os.path.dirname(os.path.abspath(sock)))
    yolo = parse_bool("A2A_YOLO", True)
    timeout = int(os.environ.get("A2A_TIMEOUT", "600"))
    agent_args = shlex.split(os.environ.get("A2A_AGENT_ARGS", ""))

    import uvicorn
    from a2a_adapter import build_agent_card, to_a2a
    from a2a_adapter.cli import _validate_agent_args  # upstream managed-flag guard

    # exits 2 with a clear message if A2A_AGENT_ARGS touches a flag the adapter owns
    _validate_agent_args(argparse.ArgumentParser(prog="A2A_AGENT_ARGS"), harness, agent_args)

    # host CLIs float (not pinned here): log the version for debugging; missing binary is fatal
    try:
        out = subprocess.run([harness, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        sys.exit(f"{harness} --version failed: {e}")
    print(f"{harness} --version: {(out.stdout or out.stderr).strip()}", flush=True)

    common = dict(
        working_dir=cwd,
        cli_args=agent_args,
        timeout=timeout,
        name=os.environ.get("A2A_NAME", ""),
        description=os.environ.get("A2A_DESCRIPTION", ""),
        # keep the context->session map out of the workspace (the owner's repo)
        session_store_path=os.path.join(state_dir, f"{harness}-sessions.json"),
    )
    if harness == "claude":
        from a2a_adapter import ClaudeCodeAdapter

        adapter = ClaudeCodeAdapter(skip_permissions=yolo, **common)
        # ponytail: upstream assigns a random per-process session_id, which orphans
        # the persisted sessions.json mapping on restart; a constructor arg upstream
        # would replace this attribute poke.
        adapter.session_id = os.environ.get("A2A_SESSION_PREFIX", "a2a")
    else:
        from a2a_adapter import CodexAdapter

        # workspace need not be a git repo
        adapter = CodexAdapter(bypass_approvals=yolo, skip_git_check=True, **common)

    card = build_agent_card(adapter, url=public_url)
    clear_stale_socket(sock)
    print(f"Serving {harness} on unix:{sock}, card url {public_url}", flush=True)
    # serve_agent() minus the bare app: same to_a2a + uvicorn.run, wrapped in the key check
    uvicorn.run(require_bearer(to_a2a(adapter, card), api_key), uds=sock, log_level="info")


def self_check():
    import tempfile

    import asyncio

    names = ("A2A_HARNESS", "A2A_YOLO", "A2A_PUBLIC_URL", "A2A_CWD", "A2A_API_KEY")

    def env(**kv):
        for k in names:
            os.environ.pop(k, None)
        os.environ.update(kv)

    def exits(fn, *a):
        try:
            fn(*a)
        except SystemExit as e:
            return e.code not in (0, None)
        return False

    env()
    assert parse_bool("A2A_YOLO", True) is True
    for raw, want in (("false", False), ("0", False), ("TRUE", True), ("yes", True)):
        env(A2A_YOLO=raw)
        assert parse_bool("A2A_YOLO", True) is want, raw
    env(A2A_YOLO="maybe")
    assert exits(parse_bool, "A2A_YOLO", True)
    env()
    assert exits(require, "A2A_HARNESS", HARNESSES)
    env(A2A_HARNESS="gpt")
    assert exits(require, "A2A_HARNESS", HARNESSES)
    env(A2A_HARNESS="codex")
    assert require("A2A_HARNESS", HARNESSES) == "codex"

    for bad in ("", "http://a2a.example.com/", "a2a.example.com", "https://"):
        env(A2A_PUBLIC_URL=bad)
        assert exits(require_url, "A2A_PUBLIC_URL"), bad
    env(A2A_PUBLIC_URL="https://a2a.example.com/")
    assert require_url("A2A_PUBLIC_URL") == "https://a2a.example.com/"

    key = "0123456789abcdef" * 2
    for bad in (None, "", "ab" * 15, key.upper(), key + " ", key + ",x"):
        env() if bad is None else env(A2A_API_KEY=bad)
        assert exits(require_api_key), bad
    env(A2A_API_KEY=key)
    assert require_api_key() == key

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    guarded = require_bearer(inner, key)

    def status(scope_type, *headers):
        sent = []

        async def send(msg):
            sent.append(msg)

        asyncio.run(guarded({"type": scope_type, "headers": list(headers)}, None, send))
        return sent[0]["status"] if sent else None

    auth, good = b"authorization", b"Bearer " + key.encode()
    assert status("http") == 401
    for bad in (good.upper(), b"bearer " + key.encode(), key.encode(), b"Bearer ", good + b"x", good[:-1]):
        assert status("http", (auth, bad)) == 401, bad
    assert status("http", (auth, good)) == 200
    assert status("http", (auth, b"Bearer x"), (auth, good)) == 200  # any value matches, like Header()
    assert status("http", (b"x-authorization", good)) == 401
    assert status("websocket", (auth, b"Bearer x")) is None  # never reaches the app
    assert status("lifespan") == 200

    with tempfile.TemporaryDirectory() as d:
        env()
        assert exits(require_dir, "A2A_CWD")
        env(A2A_CWD=os.path.join(d, "missing"))
        assert exits(require_dir, "A2A_CWD")
        env(A2A_CWD=d)
        assert require_dir("A2A_CWD") == d

        os.chmod(d, 0o700)
        require_private_dir(d)
        os.chmod(d, 0o750)
        assert exits(require_private_dir, d)
        os.chmod(d, 0o700)

        plain = os.path.join(d, "plain")
        open(plain, "w").close()
        assert exits(clear_stale_socket, plain) and os.path.exists(plain)
        assert exits(clear_stale_socket, d) and os.path.isdir(d)
        clear_stale_socket(os.path.join(d, "absent.sock"))  # no-op
        stale = os.path.join(d, "s.sock")
        s = socket.socket(socket.AF_UNIX)
        s.bind(stale)
        s.listen()
        assert exits(clear_stale_socket, stale) and os.path.exists(stale)  # live: keep
        s.close()
        clear_stale_socket(stale)
        assert not os.path.exists(stale)
    env()
    print("self-check ok")


if __name__ == "__main__":
    self_check() if sys.argv[1:] == ["--self-check"] else main()
