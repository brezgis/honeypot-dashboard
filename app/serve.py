#!/usr/bin/env python3
"""
Simple HTTP server for the Honeypot Dashboard.
Serves on localhost:9999, regenerates dashboard in the background.
"""

import gzip
import hashlib
import http.server
import os
import subprocess
import sys
import threading
import time

# Network + paths overridable via env for containerized deploys. The defaults
# preserve the original on-host behavior (localhost:9999, files beside script).
HOST = os.environ.get("SERVE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SERVE_PORT", "9999"))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("HONEYPOT_DATA_DIR", SCRIPT_DIR)
DASHBOARD_PATH = os.path.join(DATA_DIR, "dashboard.html")
# Bulk page data written by generate.py beside dashboard.html and fetched by it.
DATA_PATH = os.path.join(DATA_DIR, "dashboard-data.json")
# Vendored JS/CSS/fonts (app/static). The page references them with a content
# hash (?v=...), so they're cacheable forever.
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")
STATIC_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
}
STATIC_CACHE = "public, max-age=31536000, immutable"
GENERATE_SCRIPT = os.path.join(SCRIPT_DIR, "generate.py")

# Minimum seconds between regenerations (avoid hammering GeoIP API)
MIN_REGEN_INTERVAL = 30
last_regen = 0
_regen_lock = threading.Lock()
_regen_running = False


def regenerate_sync():
    """Run generate.py synchronously. Called from background thread."""
    global last_regen, _regen_running
    print(f"[*] Regenerating dashboard...")
    try:
        result = subprocess.run(
            [sys.executable, GENERATE_SCRIPT],
            capture_output=True, text=True, timeout=300,
            cwd=SCRIPT_DIR
        )
        if result.returncode != 0:
            print(f"[!] Generate failed: {result.stderr[-500:]}")
        else:
            print(result.stdout.strip()[-500:])
        last_regen = time.time()
    except subprocess.TimeoutExpired:
        print(f"[!] Generate timed out after 300s")
    except Exception as e:
        print(f"[!] Error regenerating: {e}")
    finally:
        with _regen_lock:
            _regen_running = False


def regenerate():
    """Kick off regeneration in background if not already running."""
    global _regen_running
    now = time.time()
    if now - last_regen < MIN_REGEN_INTERVAL:
        return
    with _regen_lock:
        if _regen_running:
            return
        _regen_running = True
    t = threading.Thread(target=regenerate_sync, daemon=True)
    t.start()


# path -> ((st_dev, st_ino, st_mtime_ns, st_size), body, gzipped body, etag).
# generate.py replaces files via rename, so a changed stat key means new content;
# each regeneration is read, transformed and compressed once, not per request.
_file_cache = {}


def _load_cached(path, transform=None):
    """Return (body, gzipped_body, etag) for path, reusing work while unchanged.
    Raises FileNotFoundError if the file doesn't exist."""
    with open(path, "rb") as f:
        st = os.fstat(f.fileno())
        key = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
        cached = _file_cache.get(path)
        if cached and cached[0] == key:
            return cached[1:]
        body = f.read()
    if transform:
        body = transform(body)
    entry = (key, body, gzip.compress(body, 6),
             '"%s"' % hashlib.sha1(body).hexdigest()[:20])
    _file_cache[path] = entry
    return entry[1:]


def _static_path(path):
    """Filesystem path for a /static/<name> URL, or None. Only plain file names
    of known types that exist directly in STATIC_DIR are served."""
    if not path.startswith("/static/"):
        return None
    name = path[len("/static/"):]
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    if os.path.splitext(name)[1] not in STATIC_TYPES:
        return None
    full = os.path.join(STATIC_DIR, name)
    return full if os.path.isfile(full) else None


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SCRIPT_DIR, **kwargs)

    def _accepts_gzip(self):
        enc = self.headers.get("Accept-Encoding", "")
        return any(p.split(";")[0].strip().lower() == "gzip" for p in enc.split(","))

    def _etag_matches(self, etag):
        # Weak comparison: a proxy that compresses (nginx gzip) weakens our
        # strong ETag to W/"..." before the browser echoes it back.
        inm = self.headers.get("If-None-Match", "")
        tags = [t.strip() for t in inm.split(",") if t.strip()]
        return "*" in tags or any((t[2:] if t.startswith("W/") else t) == etag for t in tags)

    def _send_body(self, body, gz, content_type, cache_control, etag=None):
        """Send a 200 (gzip-encoded when the client accepts it), or a 304 when
        an ETag is given and the client already has it."""
        if etag and self._etag_matches(etag):
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", cache_control)
            self.send_header("Vary", "Accept-Encoding")
            self.end_headers()
            return
        use_gzip = gz is not None and self._accepts_gzip()
        payload = gz if use_gzip else body
        self.send_response(200)
        self.send_header("Content-type", content_type)
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", cache_control)
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path == "/dashboard-data.json":
            try:
                body, gz, etag = _load_cached(DATA_PATH)
            except FileNotFoundError:
                self.send_error(404, "Not found")
                return
            # no-cache = always revalidate; the ETag turns the page's 30s
            # auto-refresh into a 304 until the next regeneration.
            self._send_body(body, gz, "application/json; charset=utf-8",
                            "no-cache", etag=etag)
            return
        static = _static_path(path)
        if static:
            body, gz, etag = _load_cached(static)
            ctype = STATIC_TYPES[os.path.splitext(static)[1]]
            # woff2 is already compressed; gzipping it again only costs CPU.
            self._send_body(body, None if ctype == "font/woff2" else gz,
                            ctype, STATIC_CACHE, etag=etag)
            return
        if path in ("/", "/dashboard.html", "/index.html"):
            # Serve whatever HTML we have (even if stale). no-cache + ETag: the
            # page's live-update poll (every 30s) is a 304 until the scheduler
            # writes a new page. (No more <meta refresh>: full reloads blanked
            # the map and reset every scroll position.)
            try:
                body, gz, etag = _load_cached(DASHBOARD_PATH)
                self._send_body(body, gz, "text/html; charset=utf-8", "no-cache", etag=etag)
                return
            except FileNotFoundError:
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                msg = b"<html><body style='background:#0a0a0a;color:#00ff41;font-family:monospace;padding:40px;text-align:center'><h1>Dashboard generating...</h1><p>First run with LLM takes a couple minutes. Refresh shortly.</p><meta http-equiv='refresh' content='15'></body></html>"
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(msg)
                return
        self.send_error(404, "Not found")
        return

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    # Start regeneration in background — don't block the server. In the
    # container the scheduler owns periodic regeneration, so this startup
    # kick is opt-out via SERVE_REGEN_ON_START=0.
    if os.environ.get("SERVE_REGEN_ON_START", "1") != "0":
        regenerate()

    # Threaded: one slow client (or a stalled mobile connection) used to block
    # every other request, since the plain HTTPServer handles one at a time.
    http.server.ThreadingHTTPServer.daemon_threads = True
    server = http.server.ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"\n{'='*60}")
    print(f"  Honeypot Dashboard Server")
    print(f"  http://{HOST}:{PORT}")
    print(f"  Live updates: page polls every 30 seconds")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
