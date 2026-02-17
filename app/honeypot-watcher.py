#!/usr/bin/env python3
"""
Watches Cowrie log for successful logins, commands, and file downloads.
Runs on north, reads logs from samovar via SSH.
Sends alerts to Discord via openclaw CLI.
Includes cute nicknames for each IP based on geolocation.
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta

SCRIPT_DIR = "/home/anna/clawd/scripts"
STATE_FILE = os.path.join(SCRIPT_DIR, ".honeypot-watcher-pos")
GEO_CACHE_FILE = os.path.join(SCRIPT_DIR, ".honeypot-geo-cache.json")
REMOTE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
SSH_HOST = "samovar"
DISCORD_TARGET = "1467547146906767360"
CLAWDBOT_BIN = shutil.which("openclaw") or "/home/anna/.nvm/versions/node/v22.22.0/bin/openclaw"

# Nickname generation
COUNTRY_FLAVORS = {
    "NL": ["tulip", "windmill", "gouda", "bike", "stroopwafel", "clog", "dutch"],
    "US": ["eagle", "burger", "yankee", "cowboy", "liberty", "star"],
    "CN": ["dragon", "panda", "jade", "silk", "lantern", "wok"],
    "RU": ["bear", "frost", "cosmo", "steppe", "borscht", "tsar"],
    "BR": ["samba", "toucan", "carnival", "capoeira", "acai"],
    "IN": ["chai", "tiger", "monsoon", "spice", "lotus"],
    "DE": ["pretzel", "stein", "autobahn", "blitz", "strudel"],
    "FR": ["baguette", "crepe", "chateau", "bistro", "monet"],
    "KR": ["kimchi", "hanbok", "kpop", "bibimbap", "seoul"],
    "JP": ["sakura", "ramen", "sensei", "shogun", "bonsai"],
    "GB": ["crumpet", "tea", "fog", "beefeater", "scone"],
    "MY": ["durian", "batik", "satay", "kite", "nasi"],
    "AU": ["kiwi", "outback", "roo", "barbie", "reef"],
    "CA": ["maple", "moose", "poutine", "hockey", "toque"],
    "SE": ["viking", "fjord", "meatball", "abba", "fika"],
    "SG": ["orchid", "merlion", "hawker", "durian", "kaya"],
}
DEFAULT_FLAVORS = ["ghost", "shadow", "phantom", "specter", "wraith", "cipher", "rogue"]

_nickname_cache = {}


def log(msg):
    """Print timestamped log message to stderr (captured by cron redirect)."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", file=sys.stderr)


def load_geo_cache():
    try:
        with open(GEO_CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_geo_cache(cache):
    """Save geo cache atomically (M6 fix)."""
    try:
        tmp = GEO_CACHE_FILE + ".tmp"
        with open(tmp, 'w') as f:
            json.dump(cache, f)
        os.rename(tmp, GEO_CACHE_FILE)
    except Exception as e:
        log(f"Failed to save geo cache: {e}")
        try:
            os.unlink(tmp)
        except Exception:
            pass


MAX_GEO_LOOKUPS_PER_RUN = 10
_geo_lookups_this_run = 0


def lookup_ip(ip, geo_cache):
    """Look up IP geolocation with rate limiting (M1 fix: max 10 per run)."""
    global _geo_lookups_this_run
    if ip in geo_cache:
        # Re-lookup failed entries if we have budget
        cached = geo_cache[ip]
        if cached.get("country") != "Unknown" or cached.get("_retry_after", "") > datetime.now().isoformat():
            return cached
    if _geo_lookups_this_run >= MAX_GEO_LOOKUPS_PER_RUN:
        return geo_cache.get(ip, {"country": "Unknown", "countryCode": "", "city": "", "isp": "Unknown"})
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "honeypot-watcher"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            _geo_lookups_this_run += 1
            if data.get("status") == "success":
                geo_cache[ip] = data
                save_geo_cache(geo_cache)
                return data
            else:
                # Mark failed with retry delay so we don't keep hammering
                geo_cache[ip] = {"country": "Unknown", "countryCode": "", "city": "", "isp": "Unknown",
                                 "_retry_after": (datetime.now() + timedelta(hours=1)).isoformat()}
                save_geo_cache(geo_cache)
    except Exception:
        _geo_lookups_this_run += 1
    return geo_cache.get(ip, {"country": "Unknown", "countryCode": "", "city": "", "isp": "Unknown"})


def get_nickname(ip, geo, creds=None):
    if ip in _nickname_cache:
        return _nickname_cache[ip]

    cc = geo.get("countryCode", "").upper()
    flavors = COUNTRY_FLAVORS.get(cc, DEFAULT_FLAVORS)
    flavor = flavors[hash(ip) % len(flavors)]

    suffix = ""
    if creds:
        cred_str = " ".join(creds).lower()
        if any(w in cred_str for w in ["solana", "sol", "validator", "raydium", "firedancer"]):
            suffix = "_sol"
        elif any(w in cred_str for w in ["root", "admin", "ubuntu"]):
            suffix = "_root"
        elif any(w in cred_str for w in ["postgres", "mysql", "oracle"]):
            suffix = "_db"
        elif any(w in cred_str for w in ["miner", "eth", "bitcoin"]):
            suffix = "_crypto"

    nickname = f"{flavor}{suffix}"
    _nickname_cache[ip] = nickname
    return nickname


def get_last_pos():
    try:
        with open(STATE_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_pos(pos):
    """Save byte position atomically (M6 fix)."""
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, 'w') as f:
            f.write(str(pos))
        os.rename(tmp, STATE_FILE)
    except Exception as e:
        log(f"Failed to save position: {e}")
        try:
            os.unlink(tmp)
        except Exception:
            pass


def ssh_cmd(cmd):
    """Run a command on samovar via SSH. Returns (stdout, ok)."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", SSH_HOST, cmd],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout, result.returncode == 0
    except Exception as e:
        log(f"SSH command failed: {e}")
        return "", False


def get_remote_file_size():
    """Get the byte size of the remote log file. Returns -1 if file doesn't exist."""
    stdout, ok = ssh_cmd(f"wc -c < {REMOTE_LOG} 2>/dev/null || echo -1")
    if not ok:
        return -1
    try:
        return int(stdout.strip())
    except ValueError:
        return -1


def get_remote_content(pos):
    """Read remote log from byte position pos onward. Returns content string."""
    if pos == 0:
        stdout, ok = ssh_cmd(f"cat {REMOTE_LOG}")
    else:
        # tail -c +N is 1-indexed: +1 means from byte 0
        stdout, ok = ssh_cmd(f"tail -c +{pos + 1} {REMOTE_LOG}")
    if not ok:
        return ""
    return stdout


def send_discord(msg):
    try:
        result = subprocess.run(
            [CLAWDBOT_BIN, "message", "send",
             "--channel", "discord",
             "--target", DISCORD_TARGET,
             "--message", msg],
            timeout=30,
            capture_output=True
        )
        if result.returncode != 0:
            log(f"Discord send failed (rc={result.returncode}): {result.stderr.decode()[:200]}")
    except Exception as e:
        log(f"Failed to send to Discord: {e}")


def watch():
    pos = get_last_pos()

    # Get remote file size to detect rotation
    file_size = get_remote_file_size()
    if file_size < 0:
        log("Remote log file not accessible")
        return

    if file_size == 0:
        log("Remote log file is empty")
        save_pos(0)
        return

    # Log rotation detection: if file is smaller than our saved position, it was rotated
    if file_size < pos:
        log(f"Log rotation detected (file size {file_size} < saved pos {pos}), resetting to 0")
        pos = 0

    # Nothing new
    if file_size == pos:
        return

    # Read new content from samovar
    content = get_remote_content(pos)
    if not content:
        log("No content retrieved from remote")
        return

    # H4 fix: use actual remote file size as new position instead of
    # computing from content length (avoids encoding mismatch drift)
    new_pos = file_size

    geo_cache = load_geo_cache()
    ip_creds = {}

    alerts = []
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue

        eid = e.get("eventid", "")
        ip = e.get("src_ip", "")
        ts = e.get("timestamp", "")[:19]

        if eid == "cowrie.login.success":
            u = e.get("username", "")
            p = e.get("password", "")
            ip_creds.setdefault(ip, []).append(f"{u}:{p}")
            geo = lookup_ip(ip, geo_cache)
            nick = get_nickname(ip, geo, ip_creds.get(ip, []))
            city = geo.get("city", "")
            country = geo.get("country", "Unknown")
            loc = f"{city}, {country}" if city else country
            alerts.append(
                f"🚨 **HONEYPOT BREACH** 🚨\n"
                f"🎭 **{nick}** (`{ip}`) from {loc}\n"
                f"Logged in as `{u}:{p}`\n"
                f"Timestamp: {ts}"
            )

        elif eid == "cowrie.command.input":
            cmd = e.get("input", "")
            geo = lookup_ip(ip, geo_cache)
            nick = get_nickname(ip, geo, ip_creds.get(ip, []))
            cmd_display = cmd[:200] + "..." if len(cmd) > 200 else cmd
            alerts.append(f"💀 **{nick}** ran: `{cmd_display}`")

        elif eid == "cowrie.session.file_download":
            url = e.get("url", "")
            geo = lookup_ip(ip, geo_cache)
            nick = get_nickname(ip, geo)
            alerts.append(f"📥 **{nick}** downloading malware: `{url}`")

    # Send in batches of 5 to avoid message size limits
    if alerts:
        log(f"Sending {len(alerts)} alerts")
        for i in range(0, len(alerts), 5):
            batch = alerts[i:i + 5]
            msg = "\n\n".join(batch)
            send_discord(msg)

    save_pos(new_pos)
    log(f"Processed {len(content.splitlines())} lines, {len(alerts)} alerts, pos {pos} -> {new_pos}")


if __name__ == "__main__":
    try:
        watch()
    except Exception as e:
        log(f"Unhandled error: {e}")
        raise
