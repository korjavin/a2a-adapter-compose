"""Fake forwardAuth service for smoke tests: returns 200 + X-Forwarded-Email for test cookies, 401 otherwise."""

import http.server
import socketserver
from http.cookies import SimpleCookie


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie(cookie_header)
        email = None
        if "dash_auth" in cookies:
            email = cookies["dash_auth"].value
        elif "session" in cookies:
            email = cookies["session"].value

        if email:
            self.send_response(200)
            self.send_header("X-Forwarded-Email", email)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()


if __name__ == "__main__":
    srv = socketserver.TCPServer(("0.0.0.0", 8080), AuthHandler)
    print("fake-auth serving on 8080", flush=True)
    srv.serve_forever()
