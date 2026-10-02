"""Tests for serve.py: dashboard page + data file routes, gzip, ETag revalidation."""
import gzip
import http.client
import http.server
import threading

import pytest

import serve

PAGE = '<!DOCTYPE html>\n<html><head><title>t</title></head><body>🍯 hi</body></html>'
DATA = '{"markers":{"ip":["1.2.3.4"]},"note":"🍯"}'


@pytest.fixture
def server(tmp_path, monkeypatch):
    (tmp_path / "dashboard.html").write_text(PAGE, encoding="utf-8")
    (tmp_path / "dashboard-data.json").write_text(DATA, encoding="utf-8")
    (tmp_path / "secret.json").write_text("{}")
    monkeypatch.setattr(serve, "DASHBOARD_PATH", str(tmp_path / "dashboard.html"))
    monkeypatch.setattr(serve, "DATA_PATH", str(tmp_path / "dashboard-data.json"))
    monkeypatch.setattr(serve, "SCRIPT_DIR", str(tmp_path))
    monkeypatch.setattr(serve, "_file_cache", {})
    monkeypatch.setattr(serve.DashboardHandler, "log_message", lambda *a: None)
    httpd = http.server.HTTPServer(("127.0.0.1", 0), serve.DashboardHandler)
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    t.start()
    yield tmp_path, httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def _get(port, path, method="GET", **headers):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, headers=headers)
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r, body


def test_data_file_json_identity(server):
    _, port = server
    r, body = _get(port, "/dashboard-data.json?v=abc123")
    assert r.status == 200
    assert r.getheader("Content-Type") == "application/json; charset=utf-8"
    assert r.getheader("Content-Encoding") is None
    assert body.decode("utf-8") == DATA
    assert r.getheader("ETag")
    assert r.getheader("Cache-Control") == "no-cache"
    assert r.getheader("Vary") == "Accept-Encoding"


def test_data_file_gzip(server):
    _, port = server
    r, body = _get(port, "/dashboard-data.json", **{"Accept-Encoding": "br, gzip;q=0.9"})
    assert r.status == 200
    assert r.getheader("Content-Encoding") == "gzip"
    assert int(r.getheader("Content-Length")) == len(body)
    assert gzip.decompress(body).decode("utf-8") == DATA


@pytest.mark.parametrize("weak", [False, True])
def test_data_file_revalidates_with_304(server, weak):
    _, port = server
    r, _ = _get(port, "/dashboard-data.json")
    etag = r.getheader("ETag")
    sent = f"W/{etag}" if weak else etag  # nginx gzip weakens upstream ETags
    r2, body2 = _get(port, "/dashboard-data.json?v=x", **{"If-None-Match": sent})
    assert r2.status == 304 and body2 == b""
    r3, _ = _get(port, "/dashboard-data.json", **{"If-None-Match": '"stale"'})
    assert r3.status == 200


def test_data_file_change_is_picked_up(server):
    tmp_path, port = server
    r, _ = _get(port, "/dashboard-data.json")
    etag = r.getheader("ETag")
    new = tmp_path / "new.json"
    new.write_text('{"v":2}', encoding="utf-8")
    new.replace(tmp_path / "dashboard-data.json")  # atomic rename, as generate.py does
    r2, body2 = _get(port, "/dashboard-data.json", **{"If-None-Match": etag})
    assert r2.status == 200 and body2 == b'{"v":2}'


def test_missing_data_file_404(server):
    tmp_path, port = server
    (tmp_path / "dashboard-data.json").unlink()
    r, _ = _get(port, "/dashboard-data.json")
    assert r.status == 404


@pytest.mark.parametrize("path", ["/", "/dashboard.html", "/index.html", "/?x=1"])
def test_page_served_with_refresh_and_gzip(server, path):
    _, port = server
    r, body = _get(port, path, **{"Accept-Encoding": "gzip"})
    assert r.status == 200
    assert r.getheader("Content-Type") == "text/html; charset=utf-8"
    assert r.getheader("Cache-Control") == "no-cache, no-store, must-revalidate"
    assert r.getheader("Content-Encoding") == "gzip"
    html = gzip.decompress(body).decode("utf-8")
    assert '<head>\n<meta http-equiv="refresh" content="30">' in html
    assert "🍯 hi" in html


def test_page_identity(server):
    _, port = server
    r, body = _get(port, "/")
    assert r.getheader("Content-Encoding") is None
    assert body.decode("utf-8").count('http-equiv="refresh"') == 1


def test_head_has_no_body(server):
    _, port = server
    r, body = _get(port, "/dashboard-data.json", method="HEAD")
    assert r.status == 200 and body == b""
    assert int(r.getheader("Content-Length")) == len(DATA.encode())


@pytest.mark.parametrize("path", ["/secret.json", "/serve.py", "/dashboard-data.json.tmp", "/../x"])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_other_paths_404(server, path, method):
    _, port = server
    r, _ = _get(port, path, method=method)
    assert r.status == 404
