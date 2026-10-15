"""Fake oauth2-proxy for smoke tests, shaped like the real v7 one (OAUTH2_PROXY_SET_XAUTHREQUEST=true) behind the
dash router's forwardAuth: GET /oauth2/auth on :4180 answers 202 + X-Auth-Request-User/-Email for a session cookie,
401 otherwise. Like the real one it never returns X-Forwarded-Email and ignores client-sent auth headers.
Cookie `noemail=1` (test-only) answers 202 with no email header, to prove Traefik drops a client-supplied copy."""

import http.server
import socketserver
from http.cookies import SimpleCookie


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.split("?")[0] != "/oauth2/auth":
            code, email = 404, None
        else:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            email = cookies["dash_auth"].value if "dash_auth" in cookies else None
            code = 202 if email or "noemail" in cookies else 401
        self.send_response(code)
        if email:
            self.send_header("X-Auth-Request-User", email.split("@")[0])
            self.send_header("X-Auth-Request-Email", email)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    srv = socketserver.TCPServer(("0.0.0.0", 4180), AuthHandler)
    print("fake-auth serving on 4180", flush=True)
    srv.serve_forever()
