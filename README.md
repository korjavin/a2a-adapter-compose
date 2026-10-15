# a2a-adapter-compose

Serve a host user's own `claude` or `codex` CLI as an [A2A](https://github.com/hybroai/a2a-adapter) agent, reachable over HTTPS behind Traefik and one bearer key.

**Read the [threat model](#threat-model) before deploying: whoever holds the key has a shell as the host user.**

## Architecture

```
client --HTTPS--> Traefik --Header(Authorization: Bearer <key>)--> socat :9000
   --> /sock/<harness>.sock (bind mount, read-only) --> a2a-adapter-<harness>@<user> (host systemd unit, checks the same key)
```

Two independent lifecycles:

| Part | What it is | Managed by | Changes via |
|---|---|---|---|
| Host side | `entrypoint.py` wrapper in a venv, one system unit per (user, harness), socket dir `/var/lib/a2a-adapter/<user>/` (`0700`), CLI credentials, the public card URL | Ansible role `a2a_adapter` in devbox-infra (or [manual install](#manual-install-without-the-ansible-role)) | re-run the playbook |
| Ingress | `docker-compose.yml`: a pinned `socat` container (TCP 9000 to the unix socket, no published ports) plus Traefik labels with the `Header()` key gate | Portainer git stack on the `deploy` branch | push to `master`, [webhook](#portainer-git-stack) redeploys |

The agent runs on the host with the user's own installed CLI and login; nothing is containerised except the TCP-to-socket bridge. The bridge needs rootful Docker (it runs as root with only `CAP_DAC_READ_SEARCH` to traverse the private socket dir).

## Config contract

Who owns which setting:

| Setting | Owner |
|---|---|
| `A2A_API_KEY`, `A2A_DOMAIN`, `A2A_HARNESS`, `A2A_SOCKET_DIR`, `TRAEFIK_NETWORK_NAME`, `TRAEFIK_CERTRESOLVER` | Portainer stack environment (see [`.env.example`](.env.example)) |
| user, harness, `public_url`, workspace `cwd`, agent args, `yolo`, CLI credentials, `A2A_API_KEY` (same value as Portainer's) | Ansible vars (or the host env file) |

### Ingress env (Portainer)

| Variable | Required | Meaning |
|---|---|---|
| `A2A_HARNESS` | yes | `claude` or `codex`: which socket to bridge (`<harness>.sock`) |
| `A2A_DOMAIN` | yes | Public hostname. Must equal the host of the instance's `public_url` |
| `A2A_SOCKET_DIR` | yes | Host path of that user's socket dir, e.g. `/var/lib/a2a-adapter/<user>` |
| `A2A_API_KEY` | yes | `openssl rand -hex 32`. Lowercase hex, at least 32 chars, or the container refuses to start (exit 64) and Traefik has no route |
| `TRAEFIK_NETWORK_NAME` | no | External Docker network your Traefik routes over; the name differs per host, check it. Default `traefik_proxy`. How Traefik reads Docker (mounted `docker.sock` or a socket proxy) does not matter |
| `TRAEFIK_CERTRESOLVER` | no | Default `letsencrypt` |

Compose refuses to start if a required variable is unset or empty. One stack serves one (user, harness); for another pair deploy another stack (a different stack name gives a different router name).

### Host env (written by the role to `/etc/a2a-adapter/<user>-<harness>.env`, mode `0600`)

| Variable | Required | Meaning |
|---|---|---|
| `A2A_HARNESS` | yes | `claude` or `codex` |
| `A2A_PUBLIC_URL` | yes | Full `https://` URL put in the agent card (the ingress hostname) |
| `A2A_CWD` | yes | Existing directory the CLI works in |
| `A2A_STATE_DIR` | yes | Existing directory for the session map |
| `A2A_SOCKET` | yes | Socket path. Its directory must be owned by the running user, mode `0700` (checked at startup) |
| `A2A_API_KEY` | yes | The same key as the Portainer `A2A_API_KEY`. Every request must carry `Authorization: Bearer <key>` or gets `401`; the unit refuses to start unless it is lowercase hex, at least 32 chars |
| `A2A_YOLO` | no | Default `true`: skip permissions (claude) / bypass approvals (codex). `false` to disable |
| `A2A_TIMEOUT` | no | Seconds, default `600` |
| `A2A_AGENT_ARGS` | no | Extra CLI args, shell-split; flags the adapter owns are rejected |
| `A2A_NAME`, `A2A_DESCRIPTION`, `A2A_SESSION_PREFIX` | no | Card name/description; session id prefix (default `a2a`) |

Plus `HOME`, `PATH` and the CLI credential (`CLAUDE_CODE_OAUTH_TOKEN`, or an existing `~/.claude` / `~/.codex/auth.json` login).

### Coordinated changes

- **New domain**: the card URL is built at host startup, so update `public_url` in Ansible and re-run, and `A2A_DOMAIN` in Portainer. Both must match.
- **Harness switch** (`claude` to `codex`): change `A2A_HARNESS` in Portainer and make sure the other instance exists on the host. Task stores are separate in-memory stores, so tasks do not migrate. Drain running tasks first.
- **Key rotation**: change `A2A_API_KEY` in the host env (re-run the role, or edit and restart the unit) and in Portainer (redeploy). Requests fail (`401`, or `404` at Traefik) until both match; the ingress healthcheck sends the key too, so the router drops until they do.
- **Upgrading from before the host key check**: redeploy the stack first (its healthcheck now sends the key, which an old host ignores), then add `A2A_API_KEY` to the host env and update `entrypoint.py` (one role run, or env first). An updated `entrypoint.py` without the key in its env refuses to start.

## Portainer git stack

1. Portainer, Stacks, Add stack, **Repository**.
2. Repository URL: this repo. Reference: `refs/heads/deploy`. Compose path: `docker-compose.yml`.
3. Environment variables: the [ingress env](#ingress-env-portainer) above. Generate the key with `openssl rand -hex 32`.
4. Enable the stack webhook (GitOps updates, webhook). Copy the webhook URL.
5. In the GitHub repo add the Actions secret `PORTAINER_REDEPLOY_HOOK` with that URL.

On every push to `master`, `.github/workflows/deploy.yml` force-pushes `master` to the `deploy` branch and POSTs the webhook, which makes Portainer pull and redeploy. The workflow fails loudly if the secret is missing. The stack needs the external Traefik network to exist already.

### Plain HTTP must not redirect

A second router on the `web` entrypoint answers `Host(<A2A_DOMAIN>)` over plain HTTP itself (Traefik `noop@internal`, a 4xx with no `Location`) instead of letting a global web-to-websecure redirect send a `301`. With the redirect, an `http://` client still works, because Python `requests`/`httpx` keep `Authorization` on a same-host upgrade, while its key crosses the network in cleartext on every call. Failing loudly makes the misconfiguration visible. ACME HTTP-01 challenge paths are left alone, other hosts keep their redirect.

This only takes effect if your core Traefik's redirect can be outranked:

- **Entrypoint-level redirect** (`--entrypoints.web.http.redirections.entrypoint.to=websecure`): its generated router has priority `MaxInt-1` by default, and Traefik rejects user router priorities above `MaxInt-1000`, so no label can beat it. Set `--entrypoints.web.http.redirections.entrypoint.priority=1` on the core Traefik (`test/smoke.py` runs that setup). Side effect: any other stack's router on `web` then wins over the redirect for its host, so check none serves real traffic over HTTP by accident.
- **Router-level redirect** (a catch-all router with a `redirectScheme` middleware): works as is unless its priority is `2147483647` or higher.

Until then plain HTTP still `301`s to HTTPS and the key already crossed in cleartext. Clients must be configured with `https://` only.

## Manual install (without the Ansible role)

For a Linux host with systemd, rootful Docker, a Traefik with an HTTPS entrypoint named `websecure`, and the CLI already installed and logged in for the target user. Names below are placeholders; use your own. Run as root.

```bash
U=alice H=claude                     # the host user and harness (claude | codex)
git clone https://github.com/korjavin/a2a-adapter-compose.git /opt/a2a-adapter/src
git -C /opt/a2a-adapter/src checkout <pinned-commit>
uv venv --python 3.12 /opt/a2a-adapter/.venv
uv pip install --python /opt/a2a-adapter/.venv/bin/python -c /opt/a2a-adapter/src/constraints.txt a2a-adapter==0.2.13
install -d -o "$U" -g "$U" -m 0700 /var/lib/a2a-adapter/$U /var/lib/a2a-adapter/$U/state
install -d -m 0700 /etc/a2a-adapter
```

The socket dir's parent (`/var/lib/a2a-adapter`) should be `0755` root. Create `/etc/a2a-adapter/$U-$H.env` (mode `0600`, root) with the host env above; `HOME` and `PATH` must let the unit find the CLI (`$H --version` must work as that user):

```
HOME="/home/alice"
PATH="/home/alice/.local/bin:/usr/local/bin:/usr/bin:/bin"
A2A_HARNESS="claude"
A2A_PUBLIC_URL="https://a2a.example.com/"
A2A_CWD="/srv/work/project"
A2A_STATE_DIR="/var/lib/a2a-adapter/alice/state"
A2A_SOCKET="/var/lib/a2a-adapter/alice/claude.sock"
A2A_API_KEY="..."   # the Portainer A2A_API_KEY
# claude only, if there is no existing ~/.claude login:
# CLAUDE_CODE_OAUTH_TOKEN="..."
```

`/etc/systemd/system/a2a-adapter-claude@.service` (one template per harness; `%i` is the user):

```ini
[Unit]
Description=A2A adapter (claude) for %i
After=network-online.target
Wants=network-online.target

[Service]
User=%i
WorkingDirectory=~
EnvironmentFile=/etc/a2a-adapter/%i-claude.env
ExecStart=/opt/a2a-adapter/.venv/bin/python -I /opt/a2a-adapter/src/entrypoint.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now a2a-adapter-claude@alice
journalctl -u a2a-adapter-claude@alice -n 20     # "Serving claude on unix:..."
```

Then create the Portainer stack as above with `A2A_SOCKET_DIR=/var/lib/a2a-adapter/alice`. `entrypoint.py --self-check` runs the wrapper's offline tests.

## Dashboard host service

A host-side, read-only HTTP service (`dashboard.py`) showing active sessions, running requests, and recent unit errors.

### Dashboard env

| Variable | Required | Meaning |
|---|---|---|
| `A2A_HARNESS` | yes | `claude` or `codex` |
| `A2A_CWD` | yes | Existing directory the CLI works in |
| `A2A_STATE_DIR` | yes | Existing directory for the session map |
| `A2A_DASH_SOCKET` | yes | Socket path for the dashboard, e.g. `/var/lib/a2a-adapter/<user>/dash.sock` in the same `0700` socket dir |
| `A2A_DASH_ALLOWED_EMAILS` | yes | Comma-separated list of allowed emails (case-insensitive). Missing or empty fails closed at startup |
| `A2A_DASH_SECRET` | yes | `openssl rand -hex 32`, the same value as the Portainer stack's `A2A_DASH_SECRET`. Lowercase hex, at least 32 chars, or startup fails closed |
| `A2A_SESSION_PREFIX` | no | Session id prefix (default `a2a`) |
| `A2A_UNIT_NAME` | no | Unit name for journal error inspection (default `a2a-adapter-<harness>@<user>`) |

### Dashboard security & constraints

- **Auth**: The service listens strictly on a unix socket (`A2A_DASH_SOCKET`, no TCP listener) in the user's `0700` private directory. It relies on being reached exclusively through Traefik + forwardAuth (OIDC). It inspects the `X-Auth-Request-Email` header (what oauth2-proxy's `/oauth2/auth` returns, copied in by the dash router's forwardAuth) against `A2A_DASH_ALLOWED_EMAILS` and returns `403 Forbidden` if missing or unlisted. It also requires `X-A2A-Dash-Secret` to equal `A2A_DASH_SECRET` (constant-time compare, `403` otherwise); only the Traefik dash router sets that header, after forwardAuth. Without it any container on the shared Traefik network could call the socat bridge directly with a forged email header.
- **Transcripts are limited to A2A conversations**: `/transcript` serves only session ids present in `<harness>-sessions.json` (`404` otherwise), not every session in the cwd's project dir.
- **XSS & Content Security Policy**: All transcript text and prompts from A2A clients are attacker-influenced; all displayed text is HTML-escaped. The server enforces a strict CSP (`default-src 'none'; style-src 'sha256-...'; frame-ancestors 'none'`).
- **Read-only**: Accepts `GET` requests only; all other HTTP methods return `405 Method Not Allowed`.
- **Health check**: `GET /healthz` returns `200 "ok"` without authentication (for smoke/ops).
- **Transcripts**: Claude Code transcripts are loaded from `~/.claude/projects/<cwd-slug>/<session>.jsonl` with user/assistant text turns and tool-call names (raw tool outputs omitted for privacy/size). For Codex, thread files are managed internally by the Codex CLI, so the dashboard reports "n/a" for transcript files while still listing sessions and running processes.
- **Journal reading**: Recent errors/warnings from `journalctl -u a2a-adapter-<harness>@<user> -p 4 -n 50` are shown only if the service user belongs to `adm` or `systemd-journal` (or root); otherwise "journal not readable" is safely returned without privilege escalation.

### Dashboard systemd unit

`/etc/systemd/system/a2a-dashboard-claude@.service` (mirroring `a2a-adapter-claude@.service`):

```ini
[Unit]
Description=A2A adapter dashboard (claude) for %i
After=network-online.target
Wants=network-online.target

[Service]
User=%i
WorkingDirectory=~
EnvironmentFile=/etc/a2a-adapter/%i-claude.env
ExecStart=/opt/a2a-adapter/.venv/bin/python -I /opt/a2a-adapter/src/dashboard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

(For codex, `/etc/systemd/system/a2a-dashboard-codex@.service` points to `/etc/a2a-adapter/%i-codex.env`.)

Offline verification: `python3 dashboard.py --self-check`.

## Client usage

Do not send an `A2A-Version` header: the `message/send` and `message/stream` method names below are the 0.3 protocol, which is the default when the header is absent; `A2A-Version: 1.0` is rejected with `VersionNotSupportedError`. Only the key gate (`404` without the exact header, `200` with it, for the card and JSON-RPC) is tested, by `test/smoke.py` against a fake adapter. The request bodies here are untested against a live adapter.

Every request, including the agent card, needs the key. Without the exact header Traefik answers `404` (not `401`) so the endpoint does not advertise itself.

```bash
export A2A_URL=https://a2a.example.com
export A2A_API_KEY=...      # the Portainer value

# agent card
curl -fsS -H "Authorization: Bearer $A2A_API_KEY" \
  "$A2A_URL/.well-known/agent-card.json"

# message/send
curl -fsS -X POST "$A2A_URL/" \
  -H "Authorization: Bearer $A2A_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"messageId":"m1","role":"user","parts":[{"kind":"text","text":"List the files here."}]}}}'
```

Streaming uses `message/stream` on the same URL (server-sent events). Reuse the `contextId` from a reply to continue a conversation. A helper for another agent (hermes-style) is just those two calls with the key kept in a secret store:

```bash
a2a() { curl -fsS -X POST "$A2A_URL/" -H "Authorization: Bearer $A2A_API_KEY" \
  -H "Content-Type: application/json" -d "$(jq -n --arg t "$1" \
  '{jsonrpc:"2.0",id:1,method:"message/send",params:{message:{messageId:(now|tostring),role:"user",parts:[{kind:"text",text:$t}]}}}')"; }
```

The key must match exactly: case-sensitive `Bearer`, no extra characters, right host, HTTPS only. **Never configure a client with `http://`**: the key is sent before any server reply, so it is exposed even though the request fails (see [plain HTTP](#plain-http-must-not-redirect)).

## Threat model

- **A leaked key is a remote shell.** With `A2A_YOLO` on (the default) the agent runs arbitrary commands as the host user with no approval step. If that user is in the `docker` group, that is root. Treat the key like an SSH key.
- **There is no sandbox.** The CLI runs directly on the host with the user's files and credentials. The host-side gates are the `0700` socket directory (uvicorn makes the socket itself `0666`) and the adapter's own bearer-key check.
- **The key is not secret from the box.** It sits in the Traefik router-rule label, the container environment (format check and healthcheck) and the root-only host env file, so anyone who can `docker inspect`, use the Portainer UI or read `/etc/a2a-adapter` can read it. Those users are already root-equivalent (accepted). Do not expose a Traefik dashboard/API that would show router rules.
- **Repeated `Authorization` headers**: Traefik's `Header()` matches if any one value matches, so `Bearer wrong` followed by `Bearer <key>` gets in. Accepted: the exact key is still required, it is not a bypass.
- **Neighbour containers**: the socat bridge listens on `:9000` on the shared external Traefik network, so any container attached to it can skip Traefik and call `http://<container>:9000/` directly. The host adapter therefore checks the same bearer key itself (constant-time compare, every path, refuses to start without a valid key): a direct call without the right key gets `401`. (The dashboard closes the same hole with a router-stamped secret header, `A2A_DASH_SECRET`.) A neighbour that sniffs or holds the key is no different from any other key holder.
- **Plaintext hop on the Traefik network (accepted residual risk, owner, 2026-10-16)**: Traefik talks to the socat containers over plain HTTP on the shared Traefik network. The A2A bearer key and the stamped dashboard secret cross that hop and also sit in container labels. Only trusted containers may run on that network: a compromised neighbour with `NET_RAW` could intercept them and replay them.
- **Dashboard identity is the IdP email**: oauth2-proxy here admits any domain (`EMAIL_DOMAINS=*`) and also accepts unverified emails (`INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true`). The email allowlist is safe only because the IdP forbids self-signup and does not let users edit their email. If either changes, switch the allowlist to the OIDC subject (`X-Auth-Request-User`).
- **One static bearer key**, no rate limiting, no per-client identity or audit trail beyond Traefik logs. Rotate by redeploying.
- **Mitigations in place**: key format check fails closed (ingress and host); host re-checks the key; only the one user's socket dir is mounted, read-only; container has no published ports, all capabilities dropped but `CAP_DAC_READ_SEARCH`, read-only rootfs; HTTPS entrypoint only; wrong or missing key gets `404`.
- To reduce risk set `A2A_YOLO=false` (the CLI then needs approvals it cannot get over A2A, so it will be much less useful) and use a dedicated low-privilege host user outside the `docker` group.

## Known limits

- **Task state is in memory** and lost on restart; session maps persist in `A2A_STATE_DIR` but task history does not.
- **Shared workspace**: concurrent conversations, and the owner's own interactive sessions in the same `A2A_CWD`, are not serialised.
- **Timeouts**: `A2A_TIMEOUT` applies per stdout line for streaming claude, but to the whole run for codex.
- **Cancel and timeout kill only the CLI process**, not its grandchildren. Stopping the systemd unit cleans up the whole cgroup.
- One stack serves one (user, harness) pair; the CLIs float to whatever is installed on the host (their version is logged at startup).
- Needs rootful Docker; rootless Docker cannot traverse the socket dir this way.

## Smoke checklist after deploy

1. `systemctl is-active a2a-adapter-<harness>@<user>` is `active` and the socket exists in the socket dir.
2. Portainer: the stack's container is `healthy`. (Unhealthy makes Traefik drop the route, so clients see `404`.)
3. With the key: the agent card returns `200`, and its `url` equals the `public_url`.
4. Without the key and with a wrong key: `404`. Over plain `http://` with the key: a 4xx with no `Location` header, or a `301` if the core Traefik's redirect cannot be outranked (see [plain HTTP](#plain-http-must-not-redirect)).
5. A `message/send` round trip returns a reply.
6. `ss -ltn` on the host shows no new TCP listener for the adapter.
7. `docker inspect` of the container shows no published ports.

`python3 test/smoke.py` runs an automated version of the gate checks against a throwaway Traefik and a fake adapter (needs Docker).

## Optional dashboard ingress

The stack includes an optional `a2a-dashboard` ingress service bridging Traefik to the read-only host dashboard service (`a2a-dashboard-<harness>@<user>.service`, listening on `<harness>-dash.sock` in `A2A_SOCKET_DIR`).

- **OFF by default**: Guarded by `profiles: ["dashboard"]`. In Portainer 2.39 git stacks, stack environment variables are passed directly to Docker Compose, so setting `COMPOSE_PROFILES=dashboard` in the stack environment enables it without needing a second stack or webhook.
- **Config**:
  - `COMPOSE_PROFILES=dashboard`: enables the service.
  - `A2A_DASH_DOMAIN`: public hostname for the dashboard (e.g. `dash.example.com`).
  - `A2A_DASH_FORWARDAUTH_ADDRESS`: optional, the host oauth2-proxy's auth endpoint as Traefik reaches it on the proxy network. Default `http://oauth2-proxy:4180/oauth2/auth`. The proxy must run with `OAUTH2_PROXY_SET_XAUTHREQUEST=true` so it returns `X-Auth-Request-Email`.
  - `TRAEFIK_FORWARDAUTH_MIDDLEWARE` is no longer used (ignored if still set): a shared forwardAuth middleware copies whatever `authResponseHeaders` it was given (commonly `X-Forwarded-Email`, which oauth2-proxy never returns), so the dash router defines its own.
  - `A2A_DASH_SECRET`: `openssl rand -hex 32`, the same value as in the host dashboard env. A Traefik headers middleware on the dash router (after forwardAuth) sends it as `X-A2A-Dash-Secret`; the container refuses to start (exit 64) unless it is lowercase hex, at least 32 chars. Rotate by changing both and redeploying the stack and restarting the dashboard unit.
  - `A2A_DASH_SOCKET_NAME`: optional, basename of the unix socket in `A2A_SOCKET_DIR` (defaults to `<harness>-dash.sock`).
- **Hardening & Auth**:
  - Pinned `alpine/socat`, root with only `CAP_DAC_READ_SEARCH` to traverse the `0700` socket dir, read-only rootfs, no published host ports.
  - OIDC protection via the stack's own forwardAuth middleware (`<stack>-dash-auth`) against the host's oauth2-proxy, `trustForwardHeader=true`, `authResponseHeaders=X-Auth-Request-Email`. Listing the header there makes Traefik drop any client-supplied copy before copying the proxy's value, so it cannot be forged through Traefik. The host service enforces the email allowlist on that header and returns 403 for unauthorized users. It fails closed on ambiguity: exactly one email header and one secret header, the email a single printable-ASCII mailbox (no commas, spaces or control characters), matched as a whole string case-insensitively, with no other normalization and no fallback to `X-Forwarded-Email` or `X-Auth-Request-Preferred-Username`. No login redirect: an unauthenticated request gets the proxy's `401` (sign in at the proxy first).
  - The A2A API bearer key does not grant access to the dashboard, and dashboard OIDC cookies do not grant access to the A2A agent.
  - Plain HTTP requests fail loudly (`noop@internal`, 4xx, no redirect), matching the A2A host router.
  - Container healthcheck probes `GET /healthz` over the unix socket, which returns 200 without auth.

