"""Stand-in for the host a2a-adapter: HTTP on a unix socket in a uid-1000 0700 dir, like the ansible role."""

import json
import os
import socketserver
import time
from http.server import BaseHTTPRequestHandler

SOCK_DIR = "/sock"
SOCK = os.path.join(SOCK_DIR, "claude.sock")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # client_address is '' on unix sockets
        pass

    def send_json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/.well-known/agent-card.json":
            return self.send_json({"name": "dummy", "url": "https://a2a.test/"})
        self.send_error(404)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if req["method"] == "message/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(3):
                self.wfile.write(f"data: {json.dumps({'id': req['id'], 'n': i})}\n\n".encode())
                self.wfile.flush()
                time.sleep(2)
            self.close_connection = True
            return
        if req["method"] == "slow":
            time.sleep(req["params"]["seconds"])
        self.send_json({"jsonrpc": "2.0", "id": req["id"], "result": {"method": req["method"]}})


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


DASH_SOCK = os.path.join(SOCK_DIR, "claude-dash.sock")
ALLOWED_EMAILS = {"owner@example.com", "alice@example.com"}


class DashboardHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send_text(self, code, text, content_type="text/plain"):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send_text(200, "ok")

        email = self.headers.get("X-Forwarded-Email", "")
        if not email or email.lower() not in {e.lower() for e in ALLOWED_EMAILS}:
            return self.send_text(403, "forbidden")

        if self.path == "/":
            return self.send_text(200, "<html>dashboard</html>", "text/html")

        self.send_error(404)

    def do_POST(self):
        self.send_error(405)


if __name__ == "__main__":
    import threading

    os.chown(SOCK_DIR, 1000, 1000)
    os.chmod(SOCK_DIR, 0o700)
    os.setgid(1000)
    os.setuid(1000)
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    if os.path.exists(DASH_SOCK):
        os.unlink(DASH_SOCK)
    srv = Server(SOCK, Handler)
    os.chmod(SOCK, 0o666)  # what uvicorn does
    srv_dash = Server(DASH_SOCK, DashboardHandler)
    os.chmod(DASH_SOCK, 0o666)
    t = threading.Thread(target=srv_dash.serve_forever, daemon=True)
    t.start()
    print("serving", SOCK, DASH_SOCK, flush=True)
    srv.serve_forever()
