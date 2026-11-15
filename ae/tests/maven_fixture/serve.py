#!/usr/bin/env python3
"""Serves a fixture Maven repository directory on 127.0.0.1 with the
Last-Modified dates a test chooses (docs/naeb/adr/0001, "The Maven broker").

    python3 -I serve.py ROOT [AGES] [PORT_FILE]

AGES is JSON: {"<path prefix under ROOT>": <days old>, ...}; the longest
matching prefix wins, everything else is 30 days old. The port is printed
(and written to PORT_FILE). Tests import Repo and read .hits, the paths
asked for.
"""
import email.utils
import http.server
import json
import os
import sys
import threading
import time

DEFAULT_AGE = 30


class Repo:
    def __init__(self, root, ages=None):
        self.root = os.path.realpath(root)
        self.ages = dict(ages or {})
        self.hits = []
        self.lock = threading.Lock()
        repo = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                repo.serve(self, True)

            def do_HEAD(self):
                repo.serve(self, False)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = "http://127.0.0.1:%d/maven2" % self.port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def age_of(self, rel):
        best, age = -1, DEFAULT_AGE
        for prefix, days in self.ages.items():
            if rel.startswith(prefix) and len(prefix) > best:
                best, age = len(prefix), days
        return age

    def serve(self, h, body):
        path = h.path.split("?", 1)[0]
        with self.lock:
            self.hits.append(path)
        if not path.startswith("/maven2/"):
            h.send_error(404)
            return
        rel = path[len("/maven2/"):]
        full = os.path.realpath(os.path.join(self.root, rel))
        if not full.startswith(self.root + os.sep) or not os.path.isfile(full):
            h.send_error(404)
            return
        with open(full, "rb") as f:
            data = f.read()
        stamp = time.time() - self.age_of(rel) * 86400 - 3600
        h.send_response(200)
        h.send_header("Content-Length", str(len(data)))
        h.send_header("Last-Modified", email.utils.formatdate(stamp, usegmt=True))
        h.end_headers()
        if body:
            h.wfile.write(data)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    ages = json.loads(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else {}
    r = Repo(sys.argv[1], ages)
    print(r.port, flush=True)
    if len(sys.argv) > 3:
        with open(sys.argv[3], "w") as f:
            f.write(str(r.port))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        r.close()
