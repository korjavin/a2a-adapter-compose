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
KEY = secrets.token_hex(32)
SOCK_DIR = tempfile.mkdtemp(prefix="a2a-smoke-", dir="/tmp")
BASE_ENV = dict(os.environ, A2A_HARNESS="claude", A2A_DOMAIN=DOMAIN, A2A_SOCKET_DIR=SOCK_DIR,
                A2A_API_KEY=KEY, TRAEFIK_NETWORK_NAME=NET)
failures = []


def sh(*args, env=None, check=True):
    r = subprocess.run(args, env=env or BASE_ENV, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"FAILED: {' '.join(args)}\n{r.stdout}{r.stderr}")
    return r


def ingress(*args, **env):
    return sh("docker", "compose", "-p", "a2a-smoke", "-f", MAIN, *args, env=dict(BASE_ENV, **env))


def rig(*args):
    return sh("docker", "compose", "-p", "a2a-smoke-rig", "-f", RIG, *args)


def expect(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


def request(method="GET", path="/.well-known/agent-card.json", auth=None, body=None, host=DOMAIN,
            tls=True, timeout=15):
    if tls:
        conn = http.client.HTTPSConnection("127.0.0.1", 18443, timeout=timeout,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=timeout)
    headers = {"Host": host}
    if auth is not None:
        headers["Authorization"] = auth
    if body is not None:
        body = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
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
    sh("docker", "network", "create", NET, check=False)
    rig("up", "-d")
    expect("fake host serving", wait_for(lambda: "serving" in rig("logs", "fake-host").stdout, 30))
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

    # host unit restart: new socket inode in the same dir, ingress untouched
    rig("restart", "fake-host")
    expect("request works after host restart, no redeploy", wait_for(lambda: request(auth=good)[0] == 200, 15))


if __name__ == "__main__":
    try:
        main()
    finally:
        sh("docker", "compose", "-p", "a2a-smoke", "-f", MAIN, "down", "-t", "1", check=False)
        rig("down", "-t", "1")
        sh("docker", "network", "rm", NET, check=False)
    print(f"\n{len(failures)} failure(s)" + (": " + ", ".join(failures) if failures else ""))
    sys.exit(1 if failures else 0)
