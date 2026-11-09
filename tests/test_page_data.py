"""Tests for the split page: dashboard.html + the dashboard-data.json it fetches."""
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import XSS_PAYLOADS, _make_log_line

import generate


@pytest.fixture(autouse=True)
def _offline(mocker):
    mocker.patch('generate.llm_generate', return_value='')
    mocker.patch('generate._check_ollama_once', return_value=False)
    mocker.patch('generate.load_cache', return_value={})
    mocker.patch('generate.save_cache')
    generate._nickname_cache.clear()
    generate._nickname_counter.clear()


def _decode_markers(c):
    """Python mirror of the page's decodeMarkers()."""
    S = c["strings"]
    out = []
    for i in range(len(c["ip"])):
        flat = c["daily"][i]
        out.append({
            "ip": c["ip"][i], "nickname": c["nick"][i], "lat": c["lat"][i], "lon": c["lon"][i],
            "city": S[c["city"][i]], "country": S[c["country"][i]], "isp": S[c["isp"][i]],
            "creds": [S[k] for k in c["creds"][i]],
            "daily_counts": {c["days"][flat[j]]: flat[j + 1] for j in range(0, len(flat), 2)},
        })
    return out


def _many_attackers_lines(n):
    """n attackers, each logging in successfully and running a distinct command."""
    lines = []
    for i in range(n):
        ip, sid = f"10.1.{i // 250}.{i % 250 + 1}", f"s{i}"
        ts = f"2026-03-0{1 + i % 3}T12:{i % 60:02d}:00.000000Z"
        lines += [
            _make_log_line("cowrie.session.connect", src_ip=ip, session=sid, timestamp=ts),
            _make_log_line("cowrie.login.failed", src_ip=ip, session=sid, timestamp=ts,
                           username="root", password=f"pw{i}"),
            _make_log_line("cowrie.login.success", src_ip=ip, session=sid, timestamp=ts,
                           username="root", password="toor"),
            _make_log_line("cowrie.command.input", src_ip=ip, session=sid, timestamp=ts,
                           input=f"echo marker-{i}"),
        ]
    return lines


def _geo_for(lines):
    geo = {}
    for line in lines:
        ip = json.loads(line)["src_ip"]
        n = sum(map(int, ip.split(".")))
        geo[ip] = {"country": "Netherlands", "countryCode": "NL", "region": "", "city": "Amsterdam",
                   "lat": 52.0 + n / 1000, "lon": 4.0 + n / 1000, "isp": "ISP", "org": ""}
    return geo


def _analyze(lines, geo, tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_text("\n".join(lines))
    return generate.analyze_events(generate.parse_log(str(p)), geo)


class TestCompactMarkers:
    def test_round_trip_matches_original_fields(self, sample_log_lines, mock_geo_cache, tmp_path):
        data = _analyze(sample_log_lines, mock_geo_cache, tmp_path)
        drawable = [m for m in data["markers"] if m.get("daily_counts")]
        assert drawable, "fixture should produce drawable markers"
        decoded = _decode_markers(generate.compact_markers(data["markers"]))
        assert len(decoded) == len(drawable)
        for got, want in zip(decoded, drawable):
            for key in ("ip", "nickname", "city", "country", "isp", "creds", "daily_counts"):
                assert got[key] == want[key], key
            assert got["lat"] == pytest.approx(want["lat"], abs=1e-5)
            assert got["lon"] == pytest.approx(want["lon"], abs=1e-5)

    def test_drops_markers_without_daily_activity_keeps_order(self):
        markers = [
            {"ip": "b", "lat": 1.123456789, "lon": 2.0, "nickname": "nb", "city": "", "country": "X",
             "isp": "I", "creds": ["root:a"], "daily_counts": {"2026-03-02": 3, "2026-03-01": 1}},
            # session-only marker (no daily_counts) — never drawn by the page
            {"ip": "c", "lat": 5, "lon": 5, "count": 0, "country": "X", "isp": "I", "creds": []},
            {"ip": "a", "lat": 3.0, "lon": 4.0, "nickname": "na", "city": "Y", "country": "X",
             "isp": "I", "creds": ["root:a", "root:b"], "daily_counts": {"2026-03-01": 2}},
        ]
        c = generate.compact_markers(markers)
        assert c["ip"] == ["b", "a"]
        assert c["days"] == ["2026-03-01", "2026-03-02"]
        assert c["lat"][0] == 1.12346
        # repeated strings are stored once
        assert c["strings"].count("X") == 1 and c["strings"].count("root:a") == 1
        decoded = _decode_markers(c)
        assert decoded[0]["daily_counts"] == {"2026-03-02": 3, "2026-03-01": 1}
        assert decoded[1]["creds"] == ["root:a", "root:b"]


class TestRenderDashboard:
    def test_bulk_data_not_inlined_and_versioned_url(self, sample_log_lines, mock_geo_cache, tmp_path):
        data = _analyze(sample_log_lines, mock_geo_cache, tmp_path)
        html, data_json = generate.render_dashboard(data)
        payload = json.loads(data_json)
        assert set(payload) == {"markers", "minDay", "timelineLabels", "timelineData", "terminal"}
        assert payload["timelineLabels"] == data["timeline_labels"]
        assert payload["timelineData"] == data["timeline_data"]
        assert payload["minDay"] == "2026-03-01"
        # compact JSON
        assert ", " not in data_json[:200] and "\n" not in data_json
        # the page fetches it with a content hash, and holds none of it inline
        version = hashlib.sha1(data_json.encode()).hexdigest()[:12]
        config = json.loads(re.search(r'<script id="hpd-config" type="application/json">(.*?)</script>', html).group(1))
        assert config["dataUrl"] == f"dashboard-data.json?v={version}"
        assert config["today"] == data["data_today"] and len(config["todayHours"]) == 24
        assert '"daily_counts"' not in html and json.dumps(data["timeline_labels"]) not in html
        assert '"strings"' not in html
        assert generate.generate_html(data) == html

    def test_terminal_split_preserves_all_groups(self, tmp_path, monkeypatch):
        lines = _many_attackers_lines(12)
        data = _analyze(lines, _geo_for(lines), tmp_path)

        monkeypatch.setattr(generate, "TERMINAL_INITIAL_GROUPS", 10_000)
        generate._nickname_cache.clear(); generate._nickname_counter.clear()
        full_html, full_json = generate.render_dashboard(data)
        assert json.loads(full_json)["terminal"] == []

        monkeypatch.setattr(generate, "TERMINAL_INITIAL_GROUPS", 5)
        generate._nickname_cache.clear(); generate._nickname_counter.clear()
        html, data_json = generate.render_dashboard(data)
        rest = json.loads(data_json)["terminal"]

        assert html.count('class="term-ip-group"') == 5
        assert len(rest) == 7 and all(g.startswith('<div class="term-ip-group">') for g in rest)
        # inline groups + deferred groups == the full, all-inline terminal
        term = re.compile(r'id="terminalLog"[^>]*>(.*?)</div>\s*</div>\s*</div>\s*</div>\s*</body>', re.S)
        full_terminal = term.search(full_html).group(1)
        assert term.search(html).group(1) + "".join(rest) == full_terminal
        for i in range(12):
            assert f"echo marker-{i}" in full_terminal

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_marker_creds_escaped_in_data_file(self, payload, mock_geo_cache, tmp_path):
        """Creds shown in map popups come from the data file; they must be escaped."""
        lines = [
            _make_log_line("cowrie.session.connect", src_ip="1.2.3.4"),
            _make_log_line("cowrie.login.failed", src_ip="1.2.3.4", username=payload, password=payload),
        ]
        data = _analyze(lines, mock_geo_cache, tmp_path)
        _html, data_json = generate.render_dashboard(data)
        strings = json.loads(data_json)["markers"]["strings"]
        assert any("&lt;" in s or "&quot;" in s or "&#x27;" in s or "&amp;" in s for s in strings)
        assert not any(payload in s for s in strings)


class TestMainWritesBothFiles:
    def test_main_writes_page_and_data(self, tmp_path, monkeypatch, mock_geo_cache):
        now = datetime.now(timezone.utc) - timedelta(hours=1)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        log = tmp_path / "cowrie.json"
        log.write_text("\n".join([
            _make_log_line("cowrie.session.connect", src_ip="1.2.3.4", timestamp=ts),
            _make_log_line("cowrie.login.failed", src_ip="1.2.3.4", timestamp=ts,
                           username="root", password="admin"),
        ]))
        monkeypatch.setattr(generate, "LOG_PATH", str(log))
        monkeypatch.setattr(generate, "OUTPUT_PATH", str(tmp_path / "dashboard.html"))
        monkeypatch.setattr(generate, "DATA_OUTPUT_PATH", str(tmp_path / generate.DATA_FILENAME))
        monkeypatch.setattr(generate, "load_geo_cache", lambda: dict(mock_geo_cache))
        monkeypatch.setattr(generate, "batch_geoip_lookup", lambda ips, cache: cache)

        generate.main()

        html = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
        data_json = (tmp_path / generate.DATA_FILENAME).read_text(encoding="utf-8")
        version = hashlib.sha1(data_json.encode()).hexdigest()[:12]
        assert f"dashboard-data.json?v={version}" in html
        assert json.loads(data_json)["markers"]["ip"] == ["1.2.3.4"]
        assert not [p for p in os.listdir(tmp_path) if p.endswith(".tmp")]
