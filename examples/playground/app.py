"""A disposable app for trying Slime's managed-process recovery."""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

started = time.monotonic()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "service": "slime-playground", "status": "healthy",
            "pid": os.getpid(), "uptime_seconds": round(time.monotonic() - started, 1),
        }).encode()
        self.send_response(200 if self.path in ("/", "/health") else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
