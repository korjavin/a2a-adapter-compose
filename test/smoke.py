"""End-to-end check of docker-compose.yml's API-key gate: a real Traefik + the socat ingress + a fake host
adapter on a unix socket in a 0700 uid-1000 dir. Needs docker (rootful / Docker Desktop). Run: python3 test/smoke.py
SMOKE_SLOW=0 skips the 65s long-request case."""

import http.client
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "..", "docker-compose.yml")
RIG = os.path.join(HERE, "compose.test.yml")
NET = "a2a_smoke_proxy"
DOMAIN = "a2a.test"
DASH_DOMAIN = "a2a-dash.test"
KEY = secrets.token_hex(32)
DASH_SECRET = secrets.token_hex(32)
SOCK_DIR = tempfile.mkdtemp(prefix="a2a-smoke-", dir="/tmp")
BASE_ENV = dict(os.environ, A2A_HARNESS="claude", A2A_DOMAIN=DOMAIN, A2A_SOCKET_DIR=SOCK_DIR,
                A2A_API_KEY=KEY, A2A_DASH_SECRET=DASH_SECRET, TRAEFIK_NETWORK_NAME=NET)
failures = []


def sh(*args, env=None, check=True):
    r = subprocess.run(args, env=env or BASE_ENV, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"FAILED: {' '.join(args)}\n{r.stdout}{r.stderr}")
    return r


def ingress(*args, check=True, **env):
    return sh("docker", "compose", "-p", "a2a-smoke", "-f", MAIN, *args, env=dict(BASE_ENV, **env), check=check)


def rig(*args):
    return sh("docker", "compose", "-p", "a2a-smoke-rig", "-f", RIG, *args)


def expect(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


def request(method="GET", path="/.well-known/agent-card.json", auth=None, cookie=None, headers=None,
            body=None, host=DOMAIN, tls=True, timeout=15):
    if tls:
        conn = http.client.HTTPSConnection("127.0.0.1", 18443, timeout=timeout,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=timeout)
    # headers: dict, or a list of (name, value) to send raw duplicates
    req_headers = [("Host", host), *(headers.items() if isinstance(headers, dict) else headers or ())]
    if auth is not None:
        req_headers.append(("Authorization", auth))
    if cookie is not None:
        req_headers.append(("Cookie", cookie))
    if body is not None:
        body = json.dumps(body).encode()
        req_headers += [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in req_headers:
        conn.putheader(k, v)
    conn.endheaders(body)
    resp = conn.getresponse()
    return resp.status, resp.read().decode(errors="replace"), resp.getheader("Location")


def rpc(method, params=None):
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


def wait_for(fn, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


A2A_URL = "http://a2a-smoke-a2a-ingress-1:9000"
DASH_URL = "http://a2a-smoke-a2a-dashboard-1:9000/"


def neighbour(url, *headers, body=None):
    """A container on the shared Traefik network calling a socat bridge directly, skipping Traefik."""
    args = [a for h in headers for a in ("--header", h)]
    if body is not None:
        args += ["--header", "Content-Type: application/json", "--post-data", json.dumps(body)]
    return sh("docker", "run", "--rm", "--network", NET, "--entrypoint", "wget", "alpine/socat:1.8.0.3",
              "-q", "-S", "-O", "-", *args, url, check=False)


def config_checks():
    for var in ("A2A_API_KEY", "A2A_DOMAIN", "A2A_SOCKET_DIR", "A2A_HARNESS"):
        for label, env in (("unset", {k: v for k, v in BASE_ENV.items() if k != var}), ("empty", {**BASE_ENV, var: ""})):
            r = sh("docker", "compose", "-f", MAIN, "config", "-q", env=env, check=False)
            expect(f"config fails with {var} {label}", r.returncode != 0 and var in r.stderr, r.stderr.strip())
    r = sh("docker", "compose", "-f", MAIN, "--env-file", os.path.join(HERE, "..", ".env.example"),
           "config", "-q", env={k: v for k, v in os.environ.items() if not k.startswith(("A2A_", "TRAEFIK_"))},
           check=False)
    expect("config ok with .env.example", r.returncode == 0, r.stderr.strip())


def main():
    config_checks()
    ingress("--profile", "*", "down", "-t", "1", check=False)
    sh("docker", "network", "create", NET, check=False)
    rig("up", "-d")
    expect("fake host serving", wait_for(lambda: "serving" in rig("logs", "fake-host").stdout, 30))
    expect("fake auth serving", wait_for(lambda: "serving" in rig("logs", "fake-auth").stdout, 30))
    good = f"Bearer {KEY}"
    if sys.platform == "linux":  # Docker Desktop's file sharing ignores host permissions
        # the dir really is private: root without capabilities can't traverse it (CAP_DAC_READ_SEARCH lets ingress in)
        r = sh("docker", "run", "--rm", "--user", "0", "--cap-drop", "ALL", "-v", f"{SOCK_DIR}:/sock:ro",
               "--entrypoint", "ls", "alpine/socat:1.8.0.3", "/sock", check=False)
        expect("socket dir denies capless root", r.returncode != 0, r.stdout + r.stderr)

    # fail closed on a key that isn't hex: the container never runs, so Traefik has no router
    ingress("up", "-d", A2A_API_KEY="CHANGE_ME")
    time.sleep(5)
    state = sh("docker", "inspect", "-f", "{{.State.ExitCode}} {{.State.Health.Status}}", "a2a-smoke-a2a-ingress-1",
               check=False).stdout.strip()
    expect("non-hex key: container refuses to run", state.split()[:1] == ["64"] and "healthy" not in state.split(), state)
    expect("non-hex key: 404", request(auth="Bearer CHANGE_ME")[0] == 404)

    ingress("up", "-d")
    expect("router up with the right key", wait_for(lambda: request(auth=good)[0] == 200, 60))
    ports = sh("docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", "a2a-smoke-a2a-ingress-1").stdout.strip()
    expect("ingress publishes no host ports", ports in ("{}", "null"), ports)

    # Dashboard is OFF by default when COMPOSE_PROFILES is unset
    expect("dash off by default: 404", request(path="/", host=DASH_DOMAIN)[0] == 404)
    running_dash = sh("docker", "ps", "--filter", "name=a2a-smoke-a2a-dashboard", "--filter", "status=running", "-q").stdout.strip()
    expect("dash container not running by default", running_dash == "")

    other = secrets.token_hex(32)
    denied = {
        "no Authorization": None,
        "wrong key": f"Bearer {other}",
        "empty Bearer": "Bearer ",
        "lowercase bearer": f"bearer {KEY}",
        "key without scheme": KEY,
        "Basic scheme": f"Basic {KEY}",
        "key + suffix": f"Bearer {KEY}x",
        "truncated key": f"Bearer {KEY[:-1]}",
    }
    for name, auth in denied.items():
        status = request(auth=auth)[0]
        expect(f"agent card, {name}: 404", status == 404, status)
        status = request("POST", "/", auth=auth, body=rpc("message/send"))[0]
        expect(f"JSON-RPC POST /, {name}: 404", status == 404, status)
        status = request("POST", "/", auth=auth, body=rpc("message/stream"))[0]
        expect(f"SSE stream, {name}: 404", status == 404, status)
    expect("right key, other Host: 404", request(auth=good, host="other.test")[0] == 404)
    # the rig's Traefik has a global web->websecure redirect: http:// must fail loudly, not 301 to https
    # (python clients keep Authorization on a same-host http->https redirect and would silently work)
    for path in ("/.well-known/agent-card.json", "/"):
        status, _, location = request(path=path, auth=good, tls=False)
        expect(f"right key over plain HTTP {path}: 4xx, no redirect", 400 <= status < 500 and location is None,
               (status, location))
    status, _, location = request(auth=good, host="other.test", tls=False)
    expect("other host over plain HTTP: still redirected", status in (301, 308) and location, (status, location))

    status, body, _ = request(auth=good)
    expect("agent card with key: 200 JSON", status == 200 and json.loads(body)["url"] == "https://a2a.test/", body)
    status, body, _ = request("POST", "/", auth=good, body=rpc("message/send"))
    expect("JSON-RPC with key: 200", status == 200 and "message/send" in body, body)

    # The host adapter checks the bearer key itself (a2a-tn2): a neighbour container calling the socat bridge
    # directly, skipping Traefik's Header() rule, needs the same key a client sends.
    for name, headers in (("no key", ()), ("wrong key", (f"Authorization: Bearer {other}",)),
                          ("key without scheme", (f"Authorization: {KEY}",))):
        for what, path, body in (("agent card", "/.well-known/agent-card.json", None),
                                 ("JSON-RPC", "/", rpc("message/send"))):
            r = neighbour(A2A_URL + path, *headers, body=body)
            expect(f"a2a, neighbour direct {what}, {name}: 401", r.returncode != 0 and " 401" in r.stderr,
                   (r.returncode, r.stderr.strip()))
    r = neighbour(A2A_URL + "/", f"Authorization: {good}", body=rpc("message/send"))
    expect("a2a, neighbour direct with the right key: 200 (control)", r.returncode == 0 and "message/send" in r.stdout,
           (r.returncode, r.stderr.strip()))

    conn = http.client.HTTPSConnection("127.0.0.1", 18443, timeout=15, context=ssl._create_unverified_context())
    start = time.time()
    conn.request("POST", "/", body=json.dumps(rpc("message/stream")),
                 headers={"Host": DOMAIN, "Authorization": good, "Content-Type": "application/json"})
    resp = conn.getresponse()
    times = [time.time() - start for line in resp if line.startswith(b"data:")]
    expect("SSE streams incrementally", len(times) == 3 and times[0] < 1.5 and times[-1] > 3.5,
           [round(t, 1) for t in times])

    if os.environ.get("SMOKE_SLOW", "1") != "0":
        status, body, _ = request("POST", "/", auth=good, body=rpc("slow", {"seconds": 65}), timeout=90)
        expect("65s request completes", status == 200, (status, body[:200]))

    # Now enable dashboard profile and verify its validation, hardening, and auth matrix
    # No forwardAuth address: the compose default (http://oauth2-proxy:4180/oauth2/auth) hits the rig's fake.
    dash_env = dict(COMPOSE_PROFILES="dashboard", A2A_DASH_DOMAIN=DASH_DOMAIN)
    # Fail-closed checks on required dashboard env vars
    for missing_var, bad in (("A2A_DASH_DOMAIN", ""), ("A2A_DASH_SECRET", ""), ("A2A_DASH_SECRET", "CHANGE_ME"),
                             ("A2A_DASH_SECRET", DASH_SECRET[:31])):
        ingress("up", "-d", **dict(dash_env, **{missing_var: bad}))
        time.sleep(3)
        state = sh("docker", "inspect", "-f", "{{.State.ExitCode}} {{.State.Health.Status}}",
                   "a2a-smoke-a2a-dashboard-1", check=False).stdout.strip()
        expect(f"dash container fails closed with {missing_var}={bad!r}", state.split()[:1] == ["64"], state)

    ingress("up", "-d", **dash_env)
    expect("dash router up and healthy",
           wait_for(lambda: request(path="/", host=DASH_DOMAIN, cookie="dash_auth=owner@example.com")[0] == 200, 60))
    dash_ports = sh("docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", "a2a-smoke-a2a-dashboard-1").stdout.strip()
    expect("dashboard publishes no host ports", dash_ports in ("{}", "null"), dash_ports)

    # Auth matrix:
    # 1. no cookie -> 401/redirect
    status, _, loc = request(path="/", host=DASH_DOMAIN)
    expect("dash, no cookie: 401", status == 401 or (status in (301, 302, 307, 308) and loc), (status, loc))

    # 2. allowlisted cookie -> 200
    status, body, _ = request(path="/", host=DASH_DOMAIN, cookie="dash_auth=owner@example.com")
    expect("dash, allowlisted cookie: 200", status == 200 and "dashboard" in body, (status, body))

    # allowlisted cookie (case-insensitive) -> 200
    status, body, _ = request(path="/", host=DASH_DOMAIN, cookie="dash_auth=OWNER@EXAMPLE.COM")
    expect("dash, allowlisted cookie case-insensitive: 200", status == 200 and "dashboard" in body, (status, body))

    # 3. non-allowlisted cookie -> 403
    status, body, _ = request(path="/", host=DASH_DOMAIN, cookie="dash_auth=intruder@example.com")
    expect("dash, non-allowlisted cookie: 403", status == 403, (status, body))

    # 4. A2A bearer key alone -> denied on the dash host
    status, body, _ = request(path="/", host=DASH_DOMAIN, auth=good)
    expect("dash, A2A bearer key alone: denied (401)", status == 401, (status, body))

    # 5. dash cookie -> 404 on the a2a host
    status, body, _ = request(path="/.well-known/agent-card.json", host=DOMAIN, cookie="dash_auth=owner@example.com")
    expect("dash cookie on a2a host: 404", status == 404, (status, body))

    # Forged email headers (the one dashboard.py reads and the legacy one) cannot bypass forwardAuth or
    # override the email it returns: listing X-Auth-Request-Email in authResponseHeaders makes Traefik drop
    # the client's copy even when the auth server returns none (noemail cookie).
    forged = {"X-Auth-Request-Email": "owner@example.com", "X-Forwarded-Email": "owner@example.com"}
    status, _, _ = request(path="/", host=DASH_DOMAIN, headers=forged)
    expect("dash, forged email headers without cookie: 401", status == 401, status)
    status, _, _ = request(path="/", host=DASH_DOMAIN, cookie="dash_auth=intruder@example.com", headers=forged)
    expect("dash, forged email headers + non-allowlisted cookie: 403", status == 403, status)
    status, _, _ = request(path="/", host=DASH_DOMAIN, cookie="noemail=1", headers=forged)
    expect("dash, forged email headers, auth returns no email: 403", status == 403, status)
    # raw duplicate / mixed-case copies of the header are dropped and overwritten too
    dupes = [("X-Auth-Request-Email", "owner@example.com"), ("x-auth-request-email", "owner@example.com")]
    for cookie, want in ((None, 401), ("dash_auth=intruder@example.com", 403), ("noemail=1", 403)):
        status, _, _ = request(path="/", host=DASH_DOMAIN, cookie=cookie, headers=dupes)
        expect(f"dash, duplicate forged email headers, cookie {cookie}: {want}", status == want, status)
    # an auth response carrying the identity only in old/other headers, or the email twice, is denied
    for cookie in ("legacy=owner@example.com", "dup=owner@example.com"):
        status, _, _ = request(path="/", host=DASH_DOMAIN, cookie=cookie)
        expect(f"dash, auth response {cookie.split('=')[0]}: 403", status == 403, status)

    # A neighbour container on the shared Traefik network skips Traefik and forwardAuth by calling the
    # socat bridge directly with a forged email: denied, it cannot know the router-stamped secret.
    r = neighbour(DASH_URL, "X-Auth-Request-Email: owner@example.com")
    expect("dash, neighbour direct to socat with forged email: 403", r.returncode != 0 and " 403" in r.stderr,
           (r.returncode, r.stderr.strip()))
    r = neighbour(DASH_URL, "X-Auth-Request-Email: owner@example.com", "X-A2A-Dash-Secret: " + secrets.token_hex(32))
    expect("dash, neighbour direct with a guessed secret: 403", r.returncode != 0 and " 403" in r.stderr,
           (r.returncode, r.stderr.strip()))
    # control: the 403s above come from the secret check, not from an unreachable bridge
    r = neighbour(DASH_URL, "X-Auth-Request-Email: owner@example.com", "X-A2A-Dash-Secret: " + DASH_SECRET)
    expect("dash, direct with the router secret: 200 (control)", r.returncode == 0 and "dashboard" in r.stdout,
           (r.returncode, r.stderr.strip()))

    # Plain HTTP on dash host: fails loudly (4xx, no Location redirect)
    status, _, location = request(path="/", host=DASH_DOMAIN, cookie="dash_auth=owner@example.com", tls=False)
    expect("dash over plain HTTP: 4xx, no redirect", 400 <= status < 500 and location is None, (status, location))

    # Internal healthcheck probe endpoint (/healthz) works over unix socket
    status, body, _ = request(path="/healthz", host=DASH_DOMAIN, cookie="dash_auth=owner@example.com")
    expect("dash /healthz: 200 ok", status == 200 and "ok" in body, (status, body))

    # host unit restart: new socket inode in the same dir, ingress untouched
    rig("restart", "fake-host")
    expect("a2a works after host restart, no redeploy", wait_for(lambda: request(auth=good)[0] == 200, 15))
    expect("dash works after host restart, no redeploy",
           wait_for(lambda: request(path="/", host=DASH_DOMAIN, cookie="dash_auth=owner@example.com")[0] == 200, 15))


if __name__ == "__main__":
    try:
        main()
    finally:
        ingress("--profile", "*", "down", "-t", "1", check=False)
        rig("down", "-t", "1")
        sh("docker", "network", "rm", NET, check=False)
    print(f"\n{len(failures)} failure(s)" + (": " + ", ".join(failures) if failures else ""))
    sys.exit(1 if failures else 0)

