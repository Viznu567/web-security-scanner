from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=abc123")
        self.send_header("Set-Cookie", "prefs=dark; HttpOnly; SameSite=Lax")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.end_headers()
        self.wfile.write(b"<h1>Test target</h1>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()