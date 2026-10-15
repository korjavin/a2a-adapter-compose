"""Read-only host-side dashboard service for A2A adapter conversations, running requests, and errors."""

import base64
import collections
import grp
import hashlib
import hmac
import html
import http.server
import json
import os
import pwd
import re
import shlex
import socket
import socketserver
import subprocess
import sys
import time
import urllib.parse

# Units run with `python -I` which drops script dir from sys.path; restore it explicitly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from entrypoint import HARNESSES, clear_stale_socket, require, require_dir, require_private_dir

STYLE_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0f141c; color: #d8dee9; line-height: 1.5; }
h1, h2, h3 { color: #88c0d0; margin-top: 1.5rem; margin-bottom: 0.5rem; }
a { color: #81a1c1; text-decoration: none; font-weight: 500; }
a:hover { text-decoration: underline; }
.meta { color: #81a1c1; font-size: 0.95rem; margin-bottom: 1.5rem; }
.meta span { margin-right: 1.5rem; }
table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: #1a2332; border-radius: 4px; overflow: hidden; }
th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #2e3b52; vertical-align: top; }
th { background: #243046; color: #eceff4; font-weight: 600; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.5px; }
tr:hover { background: #202b3d; }
.badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 3px; font-size: 0.8rem; font-weight: 600; }
.badge-running { background: #a3be8c; color: #1a2332; }
.badge-new { background: #ebcb8b; color: #1a2332; }
.badge-user { background: #5e81ac; color: #eceff4; }
.badge-assistant { background: #b48ead; color: #eceff4; }
.badge-tool { background: #434c5e; color: #d8dee9; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.8rem; margin-right: 0.3rem; }
pre { background: #1a2332; padding: 1rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; border: 1px solid #2e3b52; font-family: monospace; font-size: 0.9rem; }
.turn { margin-bottom: 1.5rem; background: #1a2332; border-radius: 6px; padding: 1rem; border: 1px solid #2e3b52; }
.turn-header { font-weight: bold; margin-bottom: 0.5rem; display: flex; align-items: center; justify-content: space-between; }
.tools-list { margin-top: 0.5rem; margin-bottom: 0.5rem; }
.notice { background: #2e3440; border-left: 4px solid #ebcb8b; padding: 0.75rem 1rem; margin-bottom: 1.5rem; border-radius: 2px; }
.empty { color: #4c566a; font-style: italic; }
"""

STYLE_HASH = base64.b64encode(hashlib.sha256(STYLE_CSS.strip().encode("utf-8")).digest()).decode("ascii")
CSP_HEADER = f"default-src 'none'; style-src 'sha256-{STYLE_HASH}'; frame-ancestors 'none'"


def parse_allowed_emails(raw: str) -> set[str]:
    """Parse comma-separated emails, lowercased. Fail closed if empty."""
    if not raw or not raw.strip():
        sys.exit("A2A_DASH_ALLOWED_EMAILS is required and cannot be empty (fail closed)")
    emails = {e.strip().lower() for e in raw.split(",") if e.strip()}
    if not emails:
        sys.exit("A2A_DASH_ALLOWED_EMAILS contains no valid emails (fail closed)")
    return emails


# Set by the Traefik dash router (headers middleware, after forwardAuth). Neighbour containers on the
# shared Traefik network can reach the socat bridge directly and forge X-Forwarded-Email, but not this.
SECRET_HEADER = "X-A2A-Dash-Secret"


def parse_dash_secret(raw: str) -> str:
    """Same rule as the compose check: lowercase hex, >=32 chars. Fail closed otherwise."""
    if len(raw) < 32 or raw.strip("0123456789abcdef"):
        sys.exit("A2A_DASH_SECRET must be lowercase hex, at least 32 chars (openssl rand -hex 32) (fail closed)")
    return raw


def can_read_journal() -> bool:
    """Check if current user can read journal without sudo (root, adm, or systemd-journal group)."""
    if os.geteuid() == 0:
        return True
    try:
        gids = set(os.getgroups())
        gids.add(os.getgid())
        for gid in gids:
            try:
                if grp.getgrgid(gid).gr_name in ("adm", "systemd-journal"):
                    return True
            except (KeyError, OSError):
                pass
    except Exception:
        pass
    return False


def get_recent_errors(harness: str, user: str | None = None) -> str:
    """Last ~50 lines of unit journal filtered to warnings/errors if readable, else safe message."""
    if not can_read_journal():
        return "journal not readable"
    if not user:
        try:
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            user = os.environ.get("USER", "root")
    unit = os.environ.get("A2A_UNIT_NAME", f"a2a-adapter-{harness}@{user}")
    try:
        r = subprocess.run(
            ["journalctl", "-u", unit, "-p", "4", "-n", "50", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return f"journalctl exited {r.returncode}: {r.stderr.strip() or r.stdout.strip()}"
        out = r.stdout.strip()
        return out if out else "No recent errors or warnings in journal."
    except FileNotFoundError:
        return "journalctl not found on host"
    except Exception as e:
        return f"failed to read journal: {e}"


def get_claude_transcript_slug(cwd: str) -> str:
    # Claude CLI slug rule: replaces every non-alphanumeric character with '-'
    return re.sub(r"[^A-Za-z0-9]", "-", os.path.abspath(cwd))


def get_claude_transcript_path(cwd: str, session_id: str, home: str | None = None) -> str:
    slug = get_claude_transcript_slug(cwd)
    home_dir = home or os.environ.get("HOME", os.path.expanduser("~"))
    return os.path.join(home_dir, ".claude", "projects", slug, f"{session_id}.jsonl")


def extract_prompt_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text", "")
                if text:
                    parts.append(text)
        return " ".join(parts)
    return ""


def inspect_claude_transcript(transcript_path: str):
    """Return (first_prompt_truncated, user_turns_count)."""
    first_prompt = None
    user_turns = 0
    try:
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if d.get("type") == "user":
                    # Claude Code records toolUseResult as user turn; skip raw tool results
                    if "toolUseResult" in d:
                        continue
                    msg = d.get("message", {})
                    content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
                    if isinstance(content, list) and any(
                        isinstance(c, dict) and c.get("type") == "tool_result" for c in content
                    ):
                        continue
                    text = extract_prompt_text(content).strip()
                    user_turns += 1
                    if first_prompt is None and text:
                        first_prompt = text[:100] + ("..." if len(text) > 100 else "")
    except OSError:
        pass
    return first_prompt or "n/a", user_turns


def parse_claude_transcript_full(transcript_path: str, max_turns: int = 150):
    """Parse user/assistant text turns and tool-call names, newest last, size-capped."""
    turns = collections.deque(maxlen=max_turns)
    total_found = 0
    try:
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                entry_type = d.get("type")
                if entry_type == "user":
                    if "toolUseResult" in d:
                        continue
                    msg = d.get("message", {})
                    content = msg.get("content", "") if isinstance(msg, dict) else str(msg)
                    if isinstance(content, list) and any(
                        isinstance(c, dict) and c.get("type") == "tool_result" for c in content
                    ):
                        continue
                    text = extract_prompt_text(content)
                    if text:
                        total_found += 1
                        turns.append({"role": "user", "text": text, "timestamp": d.get("timestamp", "")})
                elif entry_type == "assistant":
                    msg = d.get("message", {})
                    content = msg.get("content", []) if isinstance(msg, dict) else []
                    tools = []
                    text_parts = []
                    if isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict):
                                if item.get("type") == "tool_use":
                                    tools.append(item.get("name", "unknown"))
                                elif item.get("type") == "text":
                                    t = item.get("text", "")
                                    if t:
                                        text_parts.append(t)
                    elif isinstance(content, str) and content:
                        text_parts.append(content)
                    text = "\n".join(text_parts).strip()
                    if text or tools:
                        total_found += 1
                        turns.append({
                            "role": "assistant",
                            "text": text,
                            "tools": tools,
                            "timestamp": d.get("timestamp", ""),
                        })
    except OSError as e:
        return [], 0, str(e)
    return list(turns), total_found, None


def load_sessions(state_dir: str, harness: str, session_prefix: str = "a2a") -> list[dict]:
    """Read <A2A_STATE_DIR>/<harness>-sessions.json into list of session dicts."""
    sessions_file = os.path.join(state_dir, f"{harness}-sessions.json")
    if not os.path.isfile(sessions_file):
        return []
    try:
        with open(sessions_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return []
    except (OSError, json.JSONDecodeError):
        return []

    prefix_strip = f"{session_prefix}-"
    results = []
    for key, session_id in data.items():
        key_str = str(key)
        sess_str = str(session_id)
        context_id = key_str[len(prefix_strip):] if key_str.startswith(prefix_strip) else key_str
        results.append({
            "key": key_str,
            "context_id": context_id,
            "session_id": sess_str,
        })
    return results


def read_argv(pid: str, cmd: str, proc_root: str = "/proc") -> list[str]:
    """Real argv from /proc/<pid>/cmdline (NUL-separated); ps args loses boundaries inside a prompt."""
    try:
        with open(os.path.join(proc_root, pid, "cmdline"), "rb") as f:
            raw = f.read()
        if raw:
            return raw.rstrip(b"\0").decode("utf-8", "replace").split("\0")
    except OSError:
        pass
    # ponytail: no /proc (macOS dev box, process gone) -> best-effort split, may mismap a prompt with --resume
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def get_running_processes(harness: str, session_map: dict[str, str], ps_output: str | None = None,
                          proc_root: str = "/proc") -> list[dict]:
    """Find running claude/codex processes for instance user, mapped to conversation."""
    if ps_output is None:
        try:
            uid = os.getuid()
            r = subprocess.run(
                ["ps", "-u", str(uid), "-o", "pid=,etime=,args="],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode != 0:
                r = subprocess.run(
                    ["ps", "-o", "pid=,etime=,args="],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            ps_output = r.stdout
        except Exception:
            return []

    procs = []
    for line in ps_output.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid, etime, cmd = parts[0], parts[1], parts[2]
        if not pid.isdigit():
            continue
        argv = read_argv(pid, cmd, proc_root)
        if not argv:
            continue
        prog = argv[0].split("/")[-1]
        if harness == "claude":
            if "claude" not in prog or "-p" not in argv:
                continue
        elif harness == "codex":
            if "codex" not in prog or "exec" not in argv:
                continue
        else:
            continue

        session_id = None
        if "--resume" in argv:
            idx = argv.index("--resume")
            if idx + 1 < len(argv):
                session_id = argv[idx + 1]
        elif harness == "codex" and "resume" in argv:
            idx = argv.index("resume")
            if idx + 1 < len(argv):
                session_id = argv[idx + 1]

        conversation = session_map.get(session_id, session_id) if session_id else "new"
        procs.append({
            "pid": pid,
            "etime": etime,
            "conversation": conversation,
            "session_id": session_id,
            "cmd": cmd,
        })
    return procs


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    harness: str = "claude"
    cwd: str = ""
    state_dir: str = ""
    allowed_emails: set[str] = set()
    dash_secret: str = ""
    session_prefix: str = "a2a"

    # Injected for testing
    mock_ps_output: str | None = None
    home_dir: str | None = None
    proc_root: str = "/proc"

    def send_security_headers(self, status: int = 200, content_type: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Security-Policy", CSP_HEADER)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()

    def check_auth(self) -> bool:
        secret = self.headers.get(SECRET_HEADER, "").encode("utf-8", "replace")
        via_router = bool(self.dash_secret) and hmac.compare_digest(secret, self.dash_secret.encode())
        email = self.headers.get("X-Forwarded-Email", "").strip().lower()
        if not via_router or not email or email not in self.allowed_emails:
            self.send_security_headers(403)
            body = (
                "<!DOCTYPE html><html><head><title>403 Forbidden</title>"
                f"<style>{STYLE_CSS.strip()}</style></head><body>"
                "<h1>403 Forbidden</h1>"
                "<p>Access denied: not via the dashboard router, or email not in A2A_DASH_ALLOWED_EMAILS.</p>"
                "</body></html>"
            )
            self.wfile.write(body.encode("utf-8"))
            return False
        return True

    def do_POST(self):
        self.send_security_headers(405)
        self.wfile.write(b"405 Method Not Allowed (read-only service)")

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        self.do_POST()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self.send_security_headers(200, "text/plain; charset=utf-8")
            self.wfile.write(b"ok\n")
            return

        if not self.check_auth():
            return

        if path == "/":
            self.render_dashboard()
        elif path == "/transcript":
            query = urllib.parse.parse_qs(parsed.query)
            session_id = query.get("session", [""])[0].strip()
            self.render_transcript(session_id)
        else:
            self.send_security_headers(404)
            self.wfile.write(b"404 Not Found")

    def render_dashboard(self):
        sessions = load_sessions(self.state_dir, self.harness, self.session_prefix)
        session_to_ctx = {s["session_id"]: s["context_id"] for s in sessions}

        # Running processes
        running_procs = get_running_processes(self.harness, session_to_ctx, self.mock_ps_output, self.proc_root)
        running_sessions = {p["session_id"] for p in running_procs if p["session_id"]}

        # Enrich sessions with transcript info
        conv_rows = []
        for s in sessions:
            sess_id = s["session_id"]
            if self.harness == "claude":
                tpath = get_claude_transcript_path(self.cwd, sess_id, self.home_dir)
                if os.path.isfile(tpath):
                    st = os.stat(tpath)
                    mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                    size_kb = f"{st.st_size / 1024:.1f} KB"
                    first_prompt, turns = inspect_claude_transcript(tpath)
                    has_transcript = True
                else:
                    mtime_str = "n/a"
                    size_kb = "n/a"
                    first_prompt = "n/a"
                    turns = "n/a"
                    has_transcript = False
            else:
                # Codex stores its own thread files
                mtime_str = "n/a"
                size_kb = "n/a"
                first_prompt = "n/a"
                turns = "n/a"
                has_transcript = False

            conv_rows.append({
                "context_id": s["context_id"],
                "session_id": sess_id,
                "first_prompt": first_prompt,
                "turns": turns,
                "mtime": mtime_str,
                "size": size_kb,
                "is_running": sess_id in running_sessions,
                "has_transcript": has_transcript,
            })

        # Recent errors
        errors_text = get_recent_errors(self.harness)

        # Build HTML
        try:
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            user = os.environ.get("USER", "unknown")

        out = [
            "<!DOCTYPE html>",
            "<html><head>",
            "<meta charset=\"utf-8\">",
            "<meta http-equiv=\"refresh\" content=\"10\">",
            "<title>A2A Agent Dashboard</title>",
            f"<style>{STYLE_CSS.strip()}</style>",
            "</head><body>",
            f"<h1>A2A Agent Dashboard: {html.escape(self.harness)}</h1>",
            "<div class=\"meta\">",
            f"<span><strong>User:</strong> {html.escape(user)}</span>",
            f"<span><strong>Harness:</strong> {html.escape(self.harness)}</span>",
            f"<span><strong>CWD:</strong> {html.escape(self.cwd)}</span>",
            f"<span><strong>State:</strong> {html.escape(self.state_dir)}</span>",
            "</div>",
        ]

        # Running Section
        out.append("<h2>Running Now</h2>")
        if running_procs:
            out.append("<table><thead><tr><th>PID</th><th>Elapsed</th><th>Conversation</th><th>Command</th></tr></thead><tbody>")
            for p in running_procs:
                conv_badge = (
                    f"<span class=\"badge badge-new\">new</span>"
                    if p["conversation"] == "new"
                    else f"<span class=\"badge badge-running\">{html.escape(p['conversation'])}</span>"
                )
                out.append(
                    f"<tr><td>{html.escape(p['pid'])}</td>"
                    f"<td>{html.escape(p['etime'])}</td>"
                    f"<td>{conv_badge}</td>"
                    f"<td><code>{html.escape(p['cmd'])}</code></td></tr>"
                )
            out.append("</tbody></table>")
        else:
            out.append("<p class=\"empty\">No active agent processes currently running.</p>")

        # Conversations Section
        out.append("<h2>Conversations</h2>")
        if conv_rows:
            out.append(
                "<table><thead><tr>"
                "<th>Status</th><th>Context ID</th><th>CLI Session ID</th>"
                "<th>First Prompt</th><th>Turns</th><th>Last Activity</th><th>Size</th><th>Action</th>"
                "</tr></thead><tbody>"
            )
            for c in conv_rows:
                status_badge = (
                    "<span class=\"badge badge-running\">running</span>"
                    if c["is_running"]
                    else "<span class=\"empty\">idle</span>"
                )
                action_link = (
                    f"<a href=\"/transcript?session={html.escape(c['session_id'], quote=True)}\">View Transcript</a>"
                    if c["has_transcript"]
                    else "<span class=\"empty\">n/a</span>"
                )
                out.append(
                    f"<tr><td>{status_badge}</td>"
                    f"<td><strong>{html.escape(c['context_id'])}</strong></td>"
                    f"<td><code>{html.escape(c['session_id'])}</code></td>"
                    f"<td>{html.escape(str(c['first_prompt']))}</td>"
                    f"<td>{html.escape(str(c['turns']))}</td>"
                    f"<td>{html.escape(c['mtime'])}</td>"
                    f"<td>{html.escape(c['size'])}</td>"
                    f"<td>{action_link}</td></tr>"
                )
            out.append("</tbody></table>")
        else:
            out.append("<p class=\"empty\">No conversations recorded yet in sessions store.</p>")

        # Recent Errors Section
        out.append("<h2>Recent Errors / Warnings (Unit Journal)</h2>")
        out.append(f"<pre><code>{html.escape(errors_text)}</code></pre>")

        out.append("</body></html>")
        html_bytes = "\n".join(out).encode("utf-8")
        self.send_security_headers(200)
        self.wfile.write(html_bytes)

    def render_transcript(self, session_id: str):
        if not session_id or not session_id.replace("-", "").isalnum():
            self.send_security_headers(400)
            self.wfile.write(b"400 Bad Request: invalid session id")
            return

        sessions = load_sessions(self.state_dir, self.harness, self.session_prefix)
        session_to_ctx = {s["session_id"]: s["context_id"] for s in sessions}
        context_id = session_to_ctx.get(session_id)
        if context_id is None:  # only A2A conversations, not every session in the cwd's project dir
            self.send_security_headers(404)
            self.wfile.write(b"404 Not Found: session not in the sessions store")
            return

        if self.harness != "claude":
            self.send_security_headers(200)
            body = (
                "<!DOCTYPE html><html><head><title>Transcript</title>"
                f"<style>{STYLE_CSS.strip()}</style></head><body>"
                "<p><a href=\"/\">&larr; Back to Dashboard</a></p>"
                "<h1>Transcript</h1>"
                "<p class=\"notice\">Transcript viewing is supported for Claude sessions. Codex CLI manages thread files internally.</p>"
                "</body></html>"
            )
            self.wfile.write(body.encode("utf-8"))
            return

        tpath = get_claude_transcript_path(self.cwd, session_id, self.home_dir)
        if not os.path.isfile(tpath):
            self.send_security_headers(404)
            self.wfile.write(b"404 Not Found: transcript file does not exist")
            return

        turns, total_found, err = parse_claude_transcript_full(tpath)
        if err:
            self.send_security_headers(500)
            self.wfile.write(f"500 Internal Error reading transcript: {html.escape(err)}".encode("utf-8"))
            return

        out = [
            "<!DOCTYPE html>",
            "<html><head>",
            "<meta charset=\"utf-8\">",
            f"<title>Transcript: {html.escape(context_id)}</title>",
            f"<style>{STYLE_CSS.strip()}</style>",
            "</head><body>",
            "<p><a href=\"/\">&larr; Back to Dashboard</a></p>",
            f"<h1>Transcript: {html.escape(context_id)}</h1>",
            "<div class=\"meta\">",
            f"<span><strong>CLI Session ID:</strong> <code>{html.escape(session_id)}</code></span>",
            f"<span><strong>Turns Shown:</strong> {len(turns)} / {total_found}</span>",
            "</div>",
        ]

        if total_found > len(turns):
            out.append(f"<div class=\"notice\">Displaying last {len(turns)} turns (capped from {total_found} turns).</div>")

        if not turns:
            out.append("<p class=\"empty\">No user or assistant text turns found in transcript.</p>")
        else:
            for turn in turns:
                role = turn["role"]
                timestamp = html.escape(turn.get("timestamp", ""))
                if role == "user":
                    out.append(
                        "<div class=\"turn\">"
                        f"<div class=\"turn-header\"><span class=\"badge badge-user\">User</span>"
                        f"<small>{timestamp}</small></div>"
                        f"<pre>{html.escape(turn['text'])}</pre>"
                        "</div>"
                    )
                else:
                    tools_html = ""
                    if turn.get("tools"):
                        tool_badges = "".join(f"<span class=\"badge-tool\">{html.escape(t)}</span>" for t in turn["tools"])
                        tools_html = f"<div class=\"tools-list\"><strong>Tools called:</strong> {tool_badges}</div>"
                    text_html = f"<pre>{html.escape(turn['text'])}</pre>" if turn.get("text") else ""
                    out.append(
                        "<div class=\"turn\">"
                        f"<div class=\"turn-header\"><span class=\"badge badge-assistant\">Assistant</span>"
                        f"<small>{timestamp}</small></div>"
                        f"{tools_html}"
                        f"{text_html}"
                        "</div>"
                    )

        out.append("</body></html>")
        html_bytes = "\n".join(out).encode("utf-8")
        self.send_security_headers(200)
        self.wfile.write(html_bytes)

    def address_string(self):
        return "unix"

    def log_message(self, format, *args):
        # Override BaseHTTPRequestHandler log to keep output clean or stdout format
        sys.stdout.write(f"[dashboard] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()


class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True

    def server_bind(self):
        self.socket.bind(self.server_address)
        self.server_name = "unix"
        self.server_port = 0


def run_dashboard(harness: str, cwd: str, state_dir: str, sock: str, allowed_emails: set[str], dash_secret: str,
                  session_prefix: str = "a2a"):
    clear_stale_socket(sock)
    handler_cls = DashboardHandler
    handler_cls.harness = harness
    handler_cls.cwd = cwd
    handler_cls.state_dir = state_dir
    handler_cls.allowed_emails = allowed_emails
    handler_cls.dash_secret = dash_secret
    handler_cls.session_prefix = session_prefix

    server = ThreadingUnixHTTPServer(sock, handler_cls)
    try:
        os.chmod(sock, 0o666)  # private 0700 dir ensures isolation; allows ingress socat bridge
    except OSError:
        pass

    print(f"Serving dashboard ({harness}) on unix:{sock}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            os.unlink(sock)
        except OSError:
            pass


def self_check():
    import tempfile
    import threading
    import time
    import urllib.request

    print("Running dashboard self-check...", flush=True)

    # 1. Email allowlist fail closed
    assert parse_allowed_emails("alice@example.com, bob@example.com") == {"alice@example.com", "bob@example.com"}
    assert parse_allowed_emails("  ALICE@EXAMPLE.COM  ") == {"alice@example.com"}

    def exits(fn, *a):
        try:
            fn(*a)
        except SystemExit as e:
            return e.code not in (0, None)
        return False

    assert exits(parse_allowed_emails, "")
    assert exits(parse_allowed_emails, "   ")
    assert exits(parse_allowed_emails, ",,,")
    secret = "0123456789abcdef" * 2
    assert parse_dash_secret(secret) == secret
    for bad in ("", "ab" * 15, secret.upper(), secret + " ", secret + ",x"):
        assert exits(parse_dash_secret, bad), bad

    # 2. Slug calculation test (non-alphanumeric replacement for dots, underscores, slashes)
    assert get_claude_transcript_slug("/srv/my_repo.v1") == "-srv-my-repo-v1"
    assert get_claude_transcript_slug("/path.with.dots/and_underscores") == "-path-with-dots-and-underscores"

    # 3. Fixture setup with punctuated directory name
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o700)
        sock_path = os.path.join(d, "dash.sock")
        state_dir = os.path.join(d, "state")
        os.makedirs(state_dir, exist_ok=True)
        cwd_dir = os.path.join(d, "repo_work.v1")
        os.makedirs(cwd_dir, exist_ok=True)
        home_dir = os.path.join(d, "home")
        os.makedirs(home_dir, exist_ok=True)

        # Fixture sessions.json
        sessions_data = {
            "a2a-context-normal": "session-normal",
            "a2a-context-xss": "session-xss",
        }
        with open(os.path.join(state_dir, "claude-sessions.json"), "w") as f:
            json.dump(sessions_data, f)

        # Fixture transcripts using slug rule
        proj_slug = get_claude_transcript_slug(cwd_dir)
        assert "_" not in proj_slug and "." not in proj_slug
        transcript_dir = os.path.join(home_dir, ".claude", "projects", proj_slug)
        os.makedirs(transcript_dir, exist_ok=True)

        # session-normal: 2 user turns, 1 assistant with tools
        with open(os.path.join(transcript_dir, "session-normal.jsonl"), "w") as f:
            f.write(json.dumps({
                "type": "user",
                "message": {"content": "First normal prompt for testing"},
                "timestamp": "2026-10-15T10:00:00Z"
            }) + "\n")
            f.write(json.dumps({
                "type": "assistant",
                "message": {
                    "content": [
                        {"type": "text", "text": "I am working on it."},
                        {"type": "tool_use", "name": "Bash", "input": {"cmd": "ls"}}
                    ]
                },
                "timestamp": "2026-10-15T10:00:05Z"
            }) + "\n")
            # Raw tool output (should be skipped)
            f.write(json.dumps({
                "type": "user",
                "toolUseResult": {"stdout": "secret output"},
                "message": {"content": [{"type": "tool_result", "content": "secret output"}]},
            }) + "\n")
            f.write(json.dumps({
                "type": "user",
                "message": {"content": "Second turn question"},
                "timestamp": "2026-10-15T10:01:00Z"
            }) + "\n")

        # session-xss: XSS in prompt & tool name
        xss_payload = "<script>alert('pwned')</script><img src=x onerror=alert(1)>"
        with open(os.path.join(transcript_dir, "session-xss.jsonl"), "w") as f:
            f.write(json.dumps({
                "type": "user",
                "message": {"content": xss_payload},
                "timestamp": "2026-10-15T11:00:00Z"
            }) + "\n")
            f.write(json.dumps({
                "type": "assistant",
                "message": {
                    "content": [
                        {"type": "tool_use", "name": "<script>badTool</script>"},
                        {"type": "text", "text": "<b>escaped response</b>"}
                    ]
                },
                "timestamp": "2026-10-15T11:00:10Z"
            }) + "\n")

        # Verify listing & turn counting
        sessions = load_sessions(state_dir, "claude", "a2a")
        assert len(sessions) == 2
        ctx_map = {s["context_id"]: s["session_id"] for s in sessions}
        assert ctx_map["context-normal"] == "session-normal"
        assert ctx_map["context-xss"] == "session-xss"

        first_p, turns = inspect_claude_transcript(os.path.join(transcript_dir, "session-normal.jsonl"))
        assert first_p == "First normal prompt for testing", first_p
        assert turns == 2, f"Expected 2 user turns, got {turns}"

        # Verify running process mapping. ps args drops quoting, so a prompt containing "--resume x"
        # looks like a flag there; the argv boundaries come from <proc_root>/<pid>/cmdline.
        proc_root = os.path.join(d, "proc")
        fake_ps = (
            " 1001   00:45 claude -p fix --resume session-xss please --resume session-normal\n"
            " 1002   00:05 claude -p new prompt\n"
            " 1003   01:10 bash -c sleep 10\n"
        )
        for pid, argv in (("1001", ["claude", "-p", "fix --resume session-xss please", "--resume", "session-normal"]),
                          ("1002", ["claude", "-p", "new prompt"]), ("1003", ["bash", "-c", "sleep 10"])):
            os.makedirs(os.path.join(proc_root, pid))
            with open(os.path.join(proc_root, pid, "cmdline"), "wb") as f:
                f.write("\0".join(argv).encode() + b"\0")
        ctx_by_session = {"session-normal": "context-normal", "session-xss": "context-xss"}
        procs = get_running_processes("claude", ctx_by_session, fake_ps, proc_root)
        assert len(procs) == 2, procs
        assert procs[0]["conversation"] == "context-normal", procs[0]
        assert procs[0]["pid"] == "1001"
        assert procs[0]["etime"] == "00:45"
        assert procs[1]["conversation"] == "new"
        assert procs[1]["pid"] == "1002"
        # no cmdline (non-Linux, process gone): shlex fallback still maps a plain command
        procs = get_running_processes("claude", ctx_by_session, " 7   00:01 claude -p 'x' --resume session-xss\n",
                                      os.path.join(d, "noproc"))
        assert procs[0]["conversation"] == "context-xss", procs

        # Start live server on unix socket
        handler_cls = type("TestDashboardHandler", (DashboardHandler,), {
            "harness": "claude",
            "cwd": cwd_dir,
            "state_dir": state_dir,
            "allowed_emails": {"alice@example.com"},
            "dash_secret": secret,
            "session_prefix": "a2a",
            "home_dir": home_dir,
            "mock_ps_output": fake_ps,
            "proc_root": proc_root,
        })

        clear_stale_socket(sock_path)
        server = ThreadingUnixHTTPServer(sock_path, handler_cls)
        # Verify no TCP listener:
        assert server.socket.family == socket.AF_UNIX
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        time.sleep(0.1)

        def request(path="/", headers=None, method="GET"):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(sock_path)
            hdrs = [f"{method} {path} HTTP/1.1", "Host: localhost", "Connection: close"]
            if headers:
                for k, v in headers.items():
                    hdrs.append(f"{k}: {v}")
            req_data = "\r\n".join(hdrs) + "\r\n\r\n"
            s.sendall(req_data.encode("utf-8"))
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
            header_data, _, body = resp.partition(b"\r\n\r\n")
            first_line = header_data.split(b"\r\n")[0].decode()
            status_code = int(first_line.split()[1])
            return status_code, header_data.decode("latin1"), body.decode("utf-8", errors="replace")

        # Test 1: Missing X-Forwarded-Email -> 403
        st, hdrs, body = request("/")
        assert st == 403, f"Expected 403 for missing email header, got {st}"

        # Test 2: Non-allowlisted email -> 403
        st, hdrs, body = request("/", {"X-Forwarded-Email": "eve@attacker.com", SECRET_HEADER: secret})
        assert st == 403, f"Expected 403 for non-allowlisted email, got {st}"

        # Test 2b: allowlisted email but not via the router (missing / wrong / non-ASCII secret) -> 403
        for bad in (None, "", "f" * 32, secret[:-1], secret + "0", "\u00e9" * 32):
            h = {"X-Forwarded-Email": "alice@example.com"}
            if bad is not None:
                h[SECRET_HEADER] = bad
            st, hdrs, body = request("/", h)
            assert st == 403, f"Expected 403 for secret {bad!r}, got {st}"
        auth = {"X-Forwarded-Email": "alice@example.com", SECRET_HEADER: secret}

        # Test 3: Allowlisted email (case-insensitive) -> 200 OK
        st, hdrs, body = request("/", {"X-Forwarded-Email": "ALICE@EXAMPLE.COM", SECRET_HEADER: secret})
        assert st == 200, f"Expected 200 OK, got {st}"
        assert f"style-src 'sha256-{STYLE_HASH}'" in hdrs, "Missing CSP header with style hash"
        assert "default-src 'none'" in hdrs
        assert "context-normal" in body
        assert "context-xss" in body
        assert "First normal prompt for testing" in body
        assert "running" in body
        # XSS check on dashboard page
        assert "<script>" not in body, "Found unescaped <script> tag in dashboard body!"
        assert "&lt;script&gt;alert(" in body, "XSS payload not properly escaped in dashboard"

        # Test 4: Transcript view for XSS session
        st, hdrs, body = request("/transcript?session=session-xss", auth)
        assert st == 200, f"Expected 200 for transcript, got {st}"
        assert "<script>" not in body, "Found unescaped <script> tag in transcript body!"
        assert "&lt;script&gt;alert(" in body, "XSS prompt not escaped in transcript"
        assert "&lt;script&gt;badTool&lt;/script&gt;" in body, "XSS tool name not escaped in transcript"
        assert "secret output" not in body, "Raw tool output leaked into transcript view!"

        # Test 4b: a transcript in the same project dir but not in the sessions store -> 404
        with open(os.path.join(transcript_dir, "session-private.jsonl"), "w") as f:
            f.write(json.dumps({"type": "user", "message": {"content": "owner's own session"}}) + "\n")
        st, hdrs, body = request("/transcript?session=session-private", auth)
        assert st == 404, f"Expected 404 for session outside the store, got {st}"
        assert "owner's own session" not in body

        # Test 5: curl --unix-socket returns the page with allowlisted header
        curl_out = subprocess.check_output([
            "curl", "-s", "--unix-socket", sock_path,
            "-H", "X-Forwarded-Email: alice@example.com",
            "-H", f"{SECRET_HEADER}: {secret}",
            "http://localhost/"
        ]).decode("utf-8")
        assert "A2A Agent Dashboard" in curl_out, "curl --unix-socket did not return dashboard page"

        # Test 6: POST method -> 405 Method Not Allowed (read-only verification)
        st, hdrs, body = request("/", auth, method="POST")
        assert st == 405, f"Expected 405 for POST, got {st}"

        # Test 7: GET /healthz unauthenticated -> 200 "ok"
        st, hdrs, body = request("/healthz")
        assert st == 200, f"Expected 200 for /healthz unauthenticated, got {st}"
        assert body.strip() == "ok", f"Expected 'ok' for /healthz, got {body!r}"

        # Test 8: Subprocess invocation with python3 -I (verifies sys.path restoration without script dir)
        r = subprocess.run(
            [sys.executable, "-I", os.path.abspath(__file__), "--smoke-check-import"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert r.returncode == 0, f"Failed when launched with python3 -I: {r.stderr}"
        assert "smoke-check-import ok" in r.stdout

        server.shutdown()
        server.server_close()

    print("self-check ok: all assertions passed!", flush=True)


def main():
    harness = require("A2A_HARNESS", HARNESSES)
    cwd = require_dir("A2A_CWD")
    state_dir = require_dir("A2A_STATE_DIR")
    sock = require("A2A_DASH_SOCKET")
    require_private_dir(os.path.dirname(os.path.abspath(sock)))
    allowed_emails = parse_allowed_emails(os.environ.get("A2A_DASH_ALLOWED_EMAILS", ""))
    dash_secret = parse_dash_secret(os.environ.get("A2A_DASH_SECRET", ""))
    session_prefix = os.environ.get("A2A_SESSION_PREFIX", "a2a")

    run_dashboard(
        harness=harness,
        cwd=cwd,
        state_dir=state_dir,
        sock=sock,
        allowed_emails=allowed_emails,
        dash_secret=dash_secret,
        session_prefix=session_prefix,
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--smoke-check-import"]:
        print("smoke-check-import ok", flush=True)
    elif sys.argv[1:] == ["--self-check"]:
        self_check()
    else:
        main()
