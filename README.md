# a2a-adapter-compose

Serve a host user's own `claude` or `codex` CLI as an [A2A](https://github.com/hybroai/a2a-adapter) agent, reachable over HTTPS behind Traefik and one bearer key.

**Read the [threat model](#threat-model) before deploying: whoever holds the key has a shell as the host user.**

## Architecture

```
client --HTTPS--> Traefik --Header(Authorization: Bearer <key>)--> socat :9000
   --> /sock/<harness>.sock (bind mount, read-only) --> a2a-adapter-<harness>@<user> (host systemd unit)
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
| user, harness, `public_url`, workspace `cwd`, agent args, `yolo`, CLI credentials | Ansible vars (or the host env file) |

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
| `A2A_YOLO` | no | Default `true`: skip permissions (claude) / bypass approvals (codex). `false` to disable |
| `A2A_TIMEOUT` | no | Seconds, default `600` |
| `A2A_AGENT_ARGS` | no | Extra CLI args, shell-split; flags the adapter owns are rejected |
| `A2A_NAME`, `A2A_DESCRIPTION`, `A2A_SESSION_PREFIX` | no | Card name/description; session id prefix (default `a2a`) |

Plus `HOME`, `PATH` and the CLI credential (`CLAUDE_CODE_OAUTH_TOKEN`, or an existing `~/.claude` / `~/.codex/auth.json` login).

### Coordinated changes

- **New domain**: the card URL is built at host startup, so update `public_url` in Ansible and re-run, and `A2A_DOMAIN` in Portainer. Both must match.
- **Harness switch** (`claude` to `codex`): change `A2A_HARNESS` in Portainer and make sure the other instance exists on the host. Task stores are separate in-memory stores, so tasks do not migrate. Drain running tasks first.
- **Key rotation**: change `A2A_API_KEY` in Portainer and redeploy. The old key stops working as soon as Traefik picks up the new labels.

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
- **There is no sandbox.** The CLI runs directly on the host with the user's files and credentials. The only host-side gate is the `0700` socket directory (uvicorn makes the socket itself `0666`).
- **The key is not secret from the box.** It sits in the Traefik router-rule label and the container environment, so anyone who can `docker inspect` or use the Portainer UI can read it. Those users are already root-equivalent (accepted: the env copy only feeds the fail-closed format check). Do not expose a Traefik dashboard/API that would show router rules.
- **Repeated `Authorization` headers**: Traefik's `Header()` matches if any one value matches, so `Bearer wrong` followed by `Bearer <key>` gets in. Accepted: the exact key is still required, it is not a bypass.
- **One static bearer key**, no rate limiting, no per-client identity or audit trail beyond Traefik logs. Rotate by redeploying.
- **Mitigations in place**: key format check fails closed; only the one user's socket dir is mounted, read-only; container has no published ports, all capabilities dropped but `CAP_DAC_READ_SEARCH`, read-only rootfs; HTTPS entrypoint only; wrong or missing key gets `404`.
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
