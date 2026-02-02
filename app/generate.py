#!/usr/bin/env python3
"""
Cowrie Honeypot Dashboard Generator
Parses Cowrie JSON logs, does GeoIP lookups, generates a self-contained HTML dashboard.
"""

import json
import glob
import hashlib
import os
import sys
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
CACHE_PATH = os.path.join(SCRIPT_DIR, "geoip_cache.json")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "dashboard.html")


def parse_log(path):
    """Parse Cowrie JSON log, skipping malformed lines."""
    events = []
    if not os.path.exists(path):
        print(f"[!] Log file not found: {path}")
        return events
    with open(path, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed JSON at line {lineno}")
    return events


def load_geo_cache():
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_geo_cache(cache):
    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)


def batch_geoip_lookup(ips, cache):
    """Lookup IPs via ip-api.com batch endpoint (max 100 per request)."""
    to_lookup = [ip for ip in ips if ip not in cache]
    if not to_lookup:
        return cache

    # Process in batches of 100
    for i in range(0, len(to_lookup), 100):
        batch = to_lookup[i:i+100]
        print(f"[*] GeoIP batch lookup: {len(batch)} IPs...")
        payload = json.dumps([{"query": ip, "fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,query"} for ip in batch]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                results = json.loads(resp.read().decode())
                for r in results:
                    ip = r.get("query", "")
                    if r.get("status") == "success":
                        cache[ip] = {
                            "country": r.get("country", "Unknown"),
                            "countryCode": r.get("countryCode", ""),
                            "region": r.get("regionName", ""),
                            "city": r.get("city", ""),
                            "lat": r.get("lat", 0),
                            "lon": r.get("lon", 0),
                            "isp": r.get("isp", "Unknown"),
                            "org": r.get("org", "")
                        }
                    else:
                        cache[ip] = {
                            "country": "Unknown", "countryCode": "", "region": "",
                            "city": "", "lat": 0, "lon": 0, "isp": "Unknown", "org": ""
                        }
        except (urllib.error.URLError, urllib.error.HTTPError, Exception) as e:
            print(f"[!] Batch GeoIP lookup failed: {e}")
            for ip in batch:
                if ip not in cache:
                    cache[ip] = {
                        "country": "Unknown", "countryCode": "", "region": "",
                        "city": "", "lat": 0, "lon": 0, "isp": "Unknown", "org": ""
                    }
        # Rate limiting: wait between batches
        if i + 100 < len(to_lookup):
            time.sleep(1)

    save_geo_cache(cache)
    return cache


# Country code to flag emoji
def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return "🏴"
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))


# Generate cute nicknames for IPs based on country + what they tried
COUNTRY_FLAVORS = {
    "NL": ["tulip", "windmill", "gouda", "bike", "stroopwafel", "clog", "dutch"],
    "US": ["eagle", "burger", "yankee", "cowboy", "liberty", "star"],
    "CN": ["dragon", "panda", "jade", "silk", "lantern", "wok"],
    "RU": ["bear", "frost", "cosmo", "steppe", "borscht", "tsar"],
    "BR": ["samba", "toucan", "carnival", "capoeira", "acai"],
    "IN": ["chai", "tiger", "monsoon", "spice", "lotus"],
    "DE": ["pretzel", "stein", "autobahn", "blitz", "strudel"],
    "FR": ["baguette", "crepe", "chateau", "bistro", "monet"],
    "KR": ["kimchi", "hanbok", "k-pop", "bibimbap", "seoul"],
    "JP": ["sakura", "ramen", "sensei", "shogun", "bonsai"],
    "GB": ["crumpet", "tea", "fog", "beefeater", "scone"],
    "MY": ["durian", "batik", "satay", "kite", "nasi"],
    "AU": ["kiwi", "outback", "roo", "barbie", "reef"],
    "CA": ["maple", "moose", "poutine", "hockey", "toque"],
    "SE": ["viking", "fjord", "meatball", "abba", "fika"],
}
DEFAULT_FLAVORS = ["ghost", "shadow", "phantom", "specter", "wraith", "cipher", "rogue"]

_nickname_cache = {}
_nickname_counter = Counter()

def generate_nickname(ip, geo, creds_tried=None):
    """Generate a cute nickname for an IP based on country and behavior."""
    if ip in _nickname_cache:
        return _nickname_cache[ip]
    
    cc = geo.get("countryCode", "").upper()
    flavors = COUNTRY_FLAVORS.get(cc, DEFAULT_FLAVORS)
    
    # Pick a flavor word based on IP hash for consistency
    flavor = flavors[hash(ip) % len(flavors)]
    
    # Add a behavior hint from credentials if available
    suffix = ""
    if creds_tried:
        cred_str = " ".join(creds_tried).lower()
        if any(w in cred_str for w in ["solana", "sol", "validator", "raydium", "firedancer"]):
            suffix = "_sol"
        elif any(w in cred_str for w in ["root", "admin", "ubuntu"]):
            suffix = "_root"
        elif any(w in cred_str for w in ["postgres", "mysql", "oracle", "mongo"]):
            suffix = "_db"
        elif any(w in cred_str for w in ["pi", "raspberry"]):
            suffix = "_pi"
        elif any(w in cred_str for w in ["miner", "eth", "bitcoin"]):
            suffix = "_crypto"
    
    # Add a number if we've seen this combo before
    base = f"{flavor}{suffix}"
    _nickname_counter[base] += 1
    if _nickname_counter[base] > 1:
        nickname = f"{base}_{_nickname_counter[base]}"
    else:
        nickname = base
    
    _nickname_cache[ip] = nickname
    return nickname


CACHE_FILE = "/home/dashboard/app/description_cache.json"

def load_cache():
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def analyze_events(events, geo_cache):
    """Extract all stats from parsed events."""
    stats = {
        "total_sessions": 0,
        "total_login_attempts": 0,
        "successful_logins": 0,
        "unique_ips": set(),
        "commands_executed": 0,
        "files_downloaded": 0,
    }

    ip_attempts = Counter()
    ip_first_seen = {}
    ip_last_seen = {}
    ip_creds = defaultdict(list)
    cred_combos = Counter()
    timeline = Counter()  # hourly buckets
    recent_events = []
    successful_sessions = defaultdict(list)  # session -> commands
    session_ips = {}
    session_success = set()

    # Per-day tracking
    EST = timezone(timedelta(hours=-5))

    daily_sessions = Counter()
    daily_login_attempts = Counter()
    daily_successful = Counter()
    daily_ips = defaultdict(set)
    daily_commands = Counter()
    daily_ip_attempts = defaultdict(Counter)  # day -> {ip: count}
    all_timestamps = []

    for e in events:
        eid = e.get("eventid", "")
        ip = e.get("src_ip", "")
        ts = e.get("timestamp", "")
        session = e.get("session", "")

        if ip:
            stats["unique_ips"].add(ip)
        if session and ip:
            session_ips[session] = ip

        # Track timestamp for daily stats
        if ts:
            try:
                dt_est = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(EST)
                day_key = dt_est.strftime("%Y-%m-%d")
                all_timestamps.append(dt_est)
            except (ValueError, AttributeError):
                day_key = None
        else:
            day_key = None

        if eid == "cowrie.session.connect":
            stats["total_sessions"] += 1
            if day_key:
                daily_sessions[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)

        elif eid == "cowrie.login.failed":
            stats["total_login_attempts"] += 1
            ip_attempts[ip] += 1
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts
            u = e.get("username", "")
            p = e.get("password", "")
            combo = f"{u}:{p}"
            ip_creds[ip].append(combo)
            cred_combos[combo] += 1
            if day_key:
                daily_login_attempts[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)
                    daily_ip_attempts[day_key][ip] += 1
            # Timeline bucket
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                bucket = dt.astimezone(timezone(timedelta(hours=-5))).strftime("%Y-%m-%d %H:00 EST")
                timeline[bucket] += 1
            except (ValueError, AttributeError):
                pass
            recent_events.append({"ts": ts, "ip": ip, "action": f"Login attempt: {u}/{p}"})

        elif eid == "cowrie.login.success":
            stats["total_login_attempts"] += 1
            stats["successful_logins"] += 1
            ip_attempts[ip] += 1
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts
            u = e.get("username", "")
            p = e.get("password", "")
            combo = f"{u}:{p}"
            ip_creds[ip].append(combo)
            cred_combos[combo] += 1
            session_success.add(session)
            if day_key:
                daily_login_attempts[day_key] += 1
                daily_successful[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)
                    daily_ip_attempts[day_key][ip] += 1
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                bucket = dt.astimezone(timezone(timedelta(hours=-5))).strftime("%Y-%m-%d %H:00 EST")
                timeline[bucket] += 1
            except (ValueError, AttributeError):
                pass
            recent_events.append({"ts": ts, "ip": ip, "action": f"✅ LOGIN SUCCESS: {u}/{p}"})

        elif eid == "cowrie.command.input":
            stats["commands_executed"] += 1
            cmd = e.get("input", "")
            if session in session_success:
                successful_sessions[session].append({"ts": ts, "cmd": cmd})
            recent_events.append({"ts": ts, "ip": ip, "action": f"Command: {cmd}"})
            if day_key:
                daily_commands[day_key] += 1

        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            stats["files_downloaded"] += 1
            url = e.get("url", e.get("filename", "?"))
            recent_events.append({"ts": ts, "ip": ip, "action": f"File: {url}"})

    stats["unique_ips"] = len(stats["unique_ips"])

    # Sort timeline
    sorted_timeline = sorted(timeline.items())
    timeline_labels = [t[0] for t in sorted_timeline]
    timeline_data = [t[1] for t in sorted_timeline]

    # Top attackers
    top_attackers = []
    for ip, count in ip_attempts.most_common(10):
        geo = geo_cache.get(ip, {})
        nickname = generate_nickname(ip, geo, ip_creds.get(ip, []))
        top_attackers.append({
            "ip": ip,
            "count": count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", ""),
            "cc": geo.get("countryCode", ""),
            "flag": flag_emoji(geo.get("countryCode", "")),
            "isp": geo.get("isp", "Unknown"),
            "nickname": nickname,
        })

    # Top creds
    top_creds = cred_combos.most_common(20)

    # Recent events (last 20)
    recent_events = recent_events[-20:]

    # Map markers
    markers = []
    seen_ips = set()
    for ip, count in ip_attempts.most_common(100):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        geo = geo_cache.get(ip, {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        if lat == 0 and lon == 0:
            continue
        creds_tried = list(set(ip_creds.get(ip, [])))[:10]
        nickname = generate_nickname(ip, geo, ip_creds.get(ip, []))
        markers.append({
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "count": count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", "Unknown"),
            "creds": creds_tried,
            "nickname": nickname,
        })

    # Also add IPs with sessions but no login attempts (just connected)
    for ip in list(set(session_ips.values())):
        if ip not in seen_ips:
            geo = geo_cache.get(ip, {})
            lat = geo.get("lat", 0)
            lon = geo.get("lon", 0)
            if lat != 0 or lon != 0:
                markers.append({
                    "ip": ip, "lat": lat, "lon": lon, "count": 0,
                    "country": geo.get("country", "Unknown"),
                    "isp": geo.get("isp", "Unknown"),
                    "creds": [],
                })

    # Spread out overlapping markers (same lat/lon get fanned out in a circle)
    import math
    coord_counts = Counter((round(m["lat"], 1), round(m["lon"], 1)) for m in markers)
    coord_indices = {}
    for m in markers:
        key = (round(m["lat"], 1), round(m["lon"], 1))
        total = coord_counts[key]
        if total > 1:
            idx = coord_indices.get(key, 0)
            coord_indices[key] = idx + 1
            angle = (2 * math.pi * idx) / total
            spread = 0.04 * min(total, 5)  # very subtle: max 0.2 degrees (~22km)
            m["lat"] += math.sin(angle) * spread
            m["lon"] += math.cos(angle) * spread

    # Successful sessions with commands
    success_data = []
    for sid, cmds in successful_sessions.items():
        ip = session_ips.get(sid, "?")
        success_data.append({"session": sid, "ip": ip, "commands": cmds})
    # Sort by first command timestamp, most recent first
    success_data.sort(key=lambda s: s["commands"][0]["ts"] if s["commands"] else "", reverse=True)

    # Build daily breakdown
    today_est = datetime.now(EST).strftime("%Y-%m-%d")
    all_days = sorted(set(
        list(daily_sessions.keys()) + list(daily_login_attempts.keys()) +
        list(daily_commands.keys())
    ), reverse=True)

    daily_breakdown = []
    for day in all_days[:30]:
        # Find top attacker IP for this day
        top_ip = ""
        top_nick = ""
        if daily_ip_attempts[day]:
            top_ip = daily_ip_attempts[day].most_common(1)[0][0]
            geo = geo_cache.get(top_ip, {})
            top_nick = generate_nickname(top_ip, geo, ip_creds.get(top_ip, []))
        daily_breakdown.append({
            "date": day,
            "sessions": daily_sessions.get(day, 0),
            "login_attempts": daily_login_attempts.get(day, 0),
            "successful": daily_successful.get(day, 0),
            "unique_ips": len(daily_ips.get(day, set())),
            "commands": daily_commands.get(day, 0),
            "top_attacker_ip": top_ip,
            "top_attacker_nick": top_nick,
        })

    # Today's stats
    today_stats = {
        "sessions": daily_sessions.get(today_est, 0),
        "login_attempts": daily_login_attempts.get(today_est, 0),
        "successful_logins": daily_successful.get(today_est, 0),
        "unique_ips": len(daily_ips.get(today_est, set())),
        "commands": daily_commands.get(today_est, 0),
    }

    # Days active and attacks per day
    if all_timestamps:
        first_event = min(all_timestamps)
        days_active = max(1, (datetime.now(EST) - first_event).days + 1)
    else:
        days_active = 0
    attacks_per_day = round(stats["total_login_attempts"] / max(1, days_active), 1)
    d = max(1, days_active)
    averages = {
        "sessions_per_day": round(stats["total_sessions"] / d, 1),
        "logins_per_day": attacks_per_day,
        "successful_per_day": round(stats["successful_logins"] / d, 1),
        "ips_per_day": round(stats["unique_ips"] / d, 1),
        "commands_per_day": round(stats["commands_executed"] / d, 1),
        "success_rate": round(stats["successful_logins"] / max(1, stats["total_login_attempts"]) * 100, 1),
    }

    return {
        "stats": stats,
        "today_stats": today_stats,
        "days_active": days_active,
        "attacks_per_day": attacks_per_day,
        "averages": averages,
        "daily_breakdown": daily_breakdown,
        "top_attackers": top_attackers,
        "top_creds": top_creds,
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
        "recent_events": recent_events,
        "markers": markers,
        "successful_sessions": success_data,
        "geo_cache": geo_cache,
        "ip_creds": dict(ip_creds),
        "ip_first_seen": ip_first_seen,
        "ip_last_seen": ip_last_seen,
        "generated": datetime.now(EST).strftime("%Y-%m-%d %H:%M:%S EST"),
    }


def llm_generate(prompt, model="qwen3:4b", temperature=0.5, max_tokens=30):
    """Call Ollama to generate text using raw mode (no chat template). Falls back to empty string on failure."""
    try:
        payload = json.dumps({"model": model, "prompt": prompt, "stream": False, "raw": True, "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": 512, "stop": ["\n"]}}).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read()).get("response", "").strip()
    except Exception as e:
        print(f"[!] LLM generation failed: {e}")
        return ""


def generate_greatest_hits(data):
    """Generate attacker stories for the top attackers, with LLM + caching."""
    hits = []
    geo_cache = data.get("geo_cache", {})
    ip_creds = data.get("ip_creds", {})
    desc_cache = load_cache()

    for attacker in data["top_attackers"][:6]:
        nick = attacker["nickname"]
        ip = attacker["ip"]
        count = attacker["count"]
        country = attacker.get("country", "Unknown")
        city = attacker.get("city", "")
        isp = attacker.get("isp", "Unknown")

        # Gather their commands
        cmds = []
        for s in data.get("successful_sessions", []):
            if s["ip"] == ip:
                cmds.extend([c["cmd"] for c in s["commands"]])

        creds = ip_creds.get(ip, [])
        creds_str = ", ".join(creds[:5]) if creds else "none captured"

        # Check cache first
        cmd_hash = hashlib.md5(str(sorted(set(cmds))).encode()).hexdigest()[:8] if cmds else "nocmds"
        cache_key = f"gh_{ip}_{cmd_hash}"
        
        if cache_key in desc_cache:
            story = desc_cache[cache_key]
        elif cmds:
            # Try LLM with qwen3:4b
            # Extract just the key command names, not the full args
            import re
            key_cmds = set()
            for cmd in cmds[:10]:
                # Get the base command names
                for part in re.split(r'[;|&]', cmd):
                    part = part.strip()
                    base = part.split()[0] if part.split() else ""
                    base = base.split("/")[-1]  # strip paths
                    if base and base not in ("export", "echo", "2", "head", "cut", "awk", "sed", "grep", "tr"):
                        key_cmds.add(base)
            cmd_list = ", ".join(sorted(key_cmds)[:8])
            prompt = f"""SSH honeypot attacker summary. Explain what they did and WHY it matters. Be technical and specific.

Attacker: 249 attempts, 84 commands. Ran: cat, dmidecode, free, lscpu, lspci, nproc, uname. From: Netherlands, DigitalOcean.
→ Persistent scanner from a cloud VPS. Full hardware audit (CPU, GPU, RAM, PCI devices) — profiling this box for cryptomining potential. 249 attempts shows automated tooling.

Attacker: 12 attempts, 3 commands. Ran: wget, chmod, bash. From: China, Alibaba Cloud.
→ Smash-and-grab: downloaded a remote script and executed it immediately. Likely deploying a cryptominer or botnet agent. No recon, straight to payload delivery.

Attacker: 75 attempts, 0 commands. Credentials tried: ubuntu:temponly, slurm:111111, servidor:111111. From: Germany, Hetzner.
→ Pure credential brute-forcer. 75 attempts with service-specific passwords (slurm = HPC clusters, servidor = Portuguese for server). Scanning for misconfigured compute nodes.

Attacker: {count} attempts, {len(cmds)} commands. Ran: {cmd_list}. Creds: {creds_str}. From: {country}, {isp}.
→"""
            story = llm_generate(prompt, temperature=0.7, max_tokens=60)
            if not story or any(story.lower().startswith(p) for p in ["here", "i can", "we ", "okay", "the attacker", "this command", "this is", "let me", "it looks", "the user"]):
                story = classify_commands_fast(cmds)
            if not story:
                story = "Got in, poked around, ran some commands."
            desc_cache[cache_key] = story
        else:
            # Generate a more informative description even without commands
            cred_list = creds[:8]
            cred_types = []
            for c in cred_list:
                if "/" in c:
                    u = c.split("/")[0]
                    if u in ("root", "admin", "administrator"): cred_types.append("admin")
                    elif u in ("ubuntu", "debian", "centos"): cred_types.append("linux-default")
                    elif u in ("solana", "sol", "validator"): cred_types.append("crypto")
                    elif u in ("oracle", "postgres", "mysql", "redis"): cred_types.append("database")
                    elif u in ("git", "deploy", "jenkins", "docker"): cred_types.append("devops")
            cred_types = list(set(cred_types))
            type_str = ", ".join(cred_types[:3]) if cred_types else "mixed"
            story = f"Brute-force scanner ({type_str} credentials). {count} attempts with combos like {creds_str}. Never breached."
            desc_cache[cache_key] = story
        if story:
            # Clean up LLM artifacts
            for prefix in [f"Nickname: {nick}", f"{nick}:", f'"{nick}"', f"**{nick}**"]:
                if story.lower().startswith(prefix.lower()):
                    story = story[len(prefix):].lstrip(" -:,")
            # Kill "Or:" alternatives — just keep the first sentence
            if " Or:" in story or " Or," in story:
                story = story.split(" Or:")[0].split(" Or,")[0].strip()
            # Strip quotes and take first sentence if multiple
            story = story.strip('"').strip()
            sentences = story.split('. ')
            if len(sentences) > 2:
                story = '. '.join(sentences[:2]) + '.'
            if len(story) > 200:
                story = story[:197].rsplit(" ", 1)[0] + "..."
        if not story:
            story = f"Knocked {count} times from {country}. {'Got in and ran recon.' if cmds else 'Never made it past the door.'}"

        # Time range (convert UTC to EST)
        first = data.get("ip_first_seen", {}).get(ip, "")
        last = data.get("ip_last_seen", {}).get(ip, "")
        if first and last:
            try:
                f_utc = datetime.fromisoformat(first.replace("Z", "+00:00")[:26])
                l_utc = datetime.fromisoformat(last.replace("Z", "+00:00")[:26])
                f_est = f_utc - timedelta(hours=5)
                l_est = l_utc - timedelta(hours=5)
                f_short = f_est.strftime("%H:%M")
                l_short = l_est.strftime("%H:%M")
                f_date = f_est.strftime("%Y-%m-%d")
                l_date = l_est.strftime("%Y-%m-%d")
            except:
                f_short = first[11:16]
                l_short = last[11:16]
                f_date = first[:10]
                l_date = last[:10]
            if f_date == l_date:
                time_range = f"{f_short}–{l_short}"
            else:
                time_range = f"{f_date[5:]} {f_short} – {l_date[5:]} {l_short}"
        else:
            time_range = ""

        hits.append({
            "nick": nick,
            "ip": ip,
            "count": count,
            "flag": attacker.get("flag", "🏴"),
            "story": story,
            "cmds": len(cmds),
            "time_range": time_range,
        })

    save_cache(desc_cache)
    return hits


def classify_commands_fast(cmds):
    """Quick pattern-match for common attacker behaviors. Returns a varied explanation."""
    import random
    cmd_str = " ".join(cmds).lower()
    if not cmds:
        return random.choice([
            "Logged in, looked around, got bored, left.",
            "Opened the door, peeked inside, closed it again.",
            "Connected and immediately lost interest.",
        ])
    
    # Long commands still match patterns
    # (removed LLM deferral)
    pass
    
    patterns = [
        (["uname", "/proc/cpuinfo", "nproc"], [
            "Fingerprinting the system — checking OS, CPU, and hardware specs.",
            "Casing the joint: pulled system info to see what they're working with.",
            "Standard recon script — uname, CPU count, the usual checklist.",
            "Ran the attacker's equivalent of kicking the tires.",
            "Checking under the hood — OS version, architecture, processor count.",
            "First thing they did? See if the hardware's worth compromising.",
            "Automated fingerprinting — this box got sized up in seconds.",
            "The digital equivalent of reading the label before opening the package.",
        ]),
        (["wget http", "curl http", "chmod +x", "./"], [
            "Downloaded and attempted to execute a remote payload.",
            "Pulled a binary from the internet and tried to run it. Classic.",
            "Fetch, chmod, execute — the attacker speedrun trifecta.",
            "Tried to download and run something nasty from a remote server.",
        ]),
        (["cat /etc/passwd", "cat /etc/shadow"], [
            "Went straight for the credential files.",
            "Trying to harvest usernames and password hashes.",
            "Raiding /etc/passwd — hunting for accounts to crack.",
        ]),
        (["crontab", "systemctl", "/etc/init.d"], [
            "Attempting to set up persistence via scheduled tasks.",
            "Trying to plant a backdoor that survives reboot.",
            "Looking for ways to make their access permanent.",
        ]),
        (["history", ".bash_history"], [
            "Snooping through command history for credentials or clues.",
            "Reading the previous tenant's diary — checking bash history.",
        ]),
        (["ifconfig", "ip addr", "hostname"], [
            "Network recon — mapping the local network layout.",
            "Checking what network this box sits on.",
        ]),
        (["iptables", "firewall"], [
            "Poking at firewall rules.",
            "Trying to mess with the network security config.",
        ]),
        (["find /", "locate"], [
            "Searching the filesystem for interesting files.",
            "Rummaging through directories looking for loot.",
        ]),
        (["ssh ", "scp "], [
            "Attempting to pivot to other machines on the network.",
            "Trying to use this box as a springboard to reach other hosts.",
        ]),
    ]
    
    for keywords, explanations in patterns:
        if any(kw in cmd_str for kw in keywords):
            return random.choice(explanations)
    
    if len(cmds) <= 2 and all(len(c) < 30 for c in cmds):
        return random.choice([
            "Quick recon — peeked around and left.",
            "Brief visit. Ran a command or two and bounced.",
            "In and out in seconds. Just checking if anyone's home.",
        ])
    
    return None  # Complex enough to warrant LLM

def generate_command_explanations(data):
    """Generate explanations for commands in successful sessions. Uses fast pattern matching
    for common behaviors, LLM only for genuinely interesting/complex sessions."""
    explained = []
    llm_count = 0
    MAX_LLM_CALLS = 8  # Cap LLM calls to keep generation fast on CPU
    
    seen_ips = {}  # ip -> count, to vary descriptions for repeat visitors
    for s in data.get("successful_sessions", []):
        geo = data.get("geo_cache", {}).get(s["ip"], {})
        ip_creds_map = data.get("ip_creds", {})
        nick = generate_nickname(s["ip"], geo, ip_creds_map.get(s["ip"], []))
        cmds = [c["cmd"] for c in s["commands"]]
        if not cmds:
            continue
        
        # Track how many times we've seen this IP
        seen_ips[s["ip"]] = seen_ips.get(s["ip"], 0) + 1

        # Use fast pattern matching only - LLM too slow/unreliable on CPU
        explanation = classify_commands_fast(cmds)
        if explanation is None:
            explanation = "Got in, ran some commands, left."

        explained.append({
            "nick": nick,
            "ip": s["ip"],
            "commands": s["commands"],
            "explanation": explanation,
        })

    return explained


def generate_html(data):
    stats = data["stats"]
    today = data["today_stats"]
    geo_cache = data.get("geo_cache", {})
    ip_creds = data.get("ip_creds", {})
    markers_json = json.dumps(data["markers"])
    top_creds_labels = json.dumps([c[0] for c in data["top_creds"][:15]])
    top_creds_data = json.dumps([c[1] for c in data["top_creds"][:15]])
    timeline_labels = json.dumps(data["timeline_labels"])
    timeline_data = json.dumps(data["timeline_data"])

    # Generate LLM-powered content
    print("[*] Generating greatest hits (LLM)...")
    greatest_hits = generate_greatest_hits(data)
    greatest_hits_html = ""
    for hit in greatest_hits:
        greatest_hits_html += f"""
        <div class="hit-card">
            <div class="hit-nick" onclick="flyToAttacker('{hit['nick']}')">{hit['flag']} {hit['nick']}</div>
            <div class="hit-stat">{hit['count']} attempts{' · ' + str(hit['cmds']) + ' commands' if hit['cmds'] else ''}</div>
            <div class="hit-story">{hit['story']}</div>
            <div style="color:#555;font-size:0.75em;margin-top:4px;">⏰ {hit['time_range']}</div>
        </div>"""
    if not greatest_hits_html:
        greatest_hits_html = '<div style="color:#666;">No attackers to profile yet.</div>'

    print("[*] Generating command explanations (LLM)...")
    explained_sessions = generate_command_explanations(data)

    # Build leaderboard rows
    leaderboard_rows = ""
    for i, a in enumerate(data["top_attackers"], 1):
        city_or_country = a['city'] if a['city'] else a['country']
        leaderboard_rows += f"""
        <tr>
            <td><span class="nick-link" onclick="flyToAttacker(&quot;{a['nickname']}&quot;)">{a['nickname']}</span><br><span style="color:#666;font-size:0.8em">{a['ip']}</span></td>
            <td>{a['flag']} {city_or_country}</td>
            <td class="hide-mobile">{a['isp']}</td>
            <td class="glow">{a['count']}</td>
        </tr>"""

    # Recent activity
    activity_rows = ""
    for ev in reversed(data["recent_events"]):
        try:
            dt_ev = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
            ts_short = dt_ev.astimezone(timezone(timedelta(hours=-5))).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            ts_short = ev["ts"][:19].replace("T", " ") if ev["ts"] else "?"
        action_class = "success-text" if "SUCCESS" in ev["action"] else ""
        geo = geo_cache.get(ev['ip'], {})
        nick = generate_nickname(ev['ip'], geo, ip_creds.get(ev['ip'], []))
        activity_rows += f"""
        <div class="activity-row">
            <span class="ts">{ts_short}</span>
            <span class="nick-link" onclick="flyToAttacker(&quot;{nick}&quot;)">{nick}</span>
            <span class="ip">{ev['ip']}</span>
            <span class="action {action_class}">{ev['action']}</span>
        </div>"""

    # Successful sessions terminal (with LLM explanations)
    terminal_content = ""
    if explained_sessions:
        for s in explained_sessions:
            geo = geo_cache.get(s["ip"], {})
            nick = s["nick"]
            city = geo.get("city", "")
            country = geo.get("country", "Unknown")
            loc = f"{city}, {country}" if city else country
            first_ts_raw = s["commands"][0]["ts"] if s["commands"] else ""
            if first_ts_raw:
                try:
                    utc_dt = datetime.fromisoformat(first_ts_raw.replace("Z", "+00:00")[:26])
                    est_dt = utc_dt - timedelta(hours=5)
                    first_ts = est_dt.strftime("%Y-%m-%d %H:%M") + " EST"
                except:
                    first_ts = first_ts_raw[:16].replace("T", " ")
            else:
                first_ts = ""
            terminal_content += f'<div class="term-header">🎭 <span class="nick-link" onclick="flyToAttacker(&quot;{nick}&quot;)">{nick}</span> ({s["ip"]}) — {loc} <span style="color:#555;font-size:0.85em">· {first_ts}</span></div>\n'
            terminal_content += f'<div class="term-line" style="color:#ff9944;font-style:italic;">💡 {s["explanation"]}</div>\n'
            for cmd in s["commands"]:
                terminal_content += f'<div class="term-line"><span class="term-prompt">{nick}@honeypot:~$ </span>{cmd["cmd"]}</div>\n'
    elif data["successful_sessions"]:
        for s in data["successful_sessions"]:
            geo = geo_cache.get(s["ip"], {})
            nick = generate_nickname(s["ip"], geo, ip_creds.get(s["ip"], []))
            city = geo.get("city", "")
            country = geo.get("country", "Unknown")
            loc = f"{city}, {country}" if city else country
            terminal_content += f'<div class="term-header">🎭 <span class="nick-link" onclick="flyToAttacker(&quot;{nick}&quot;)">{nick}</span> ({s["ip"]}) — {loc}</div>\n'
            for cmd in s["commands"]:
                ts_short = cmd["ts"][:19].replace("T", " ") if cmd["ts"] else ""
                terminal_content += f'<div class="term-line"><span class="term-prompt">{nick}@honeypot:~$ </span>{cmd["cmd"]}</div>\n'
    else:
        terminal_content = '<div class="term-line" style="color:#666;">No successful logins captured yet. The bots are still trying...</div>'

    # Daily breakdown rows
    daily_rows = ""
    for d in data["daily_breakdown"]:
        attacker_cell = f'<span class="nick-link" onclick="flyToAttacker(&quot;{d["top_attacker_nick"]}&quot;)">{d["top_attacker_nick"]}</span> <span style="color:#555">({d["top_attacker_ip"]})</span>' if d["top_attacker_ip"] else '<span style="color:#555">—</span>'
        daily_rows += f"""
        <tr>
            <td class="glow">{d['date']}</td>
            <td>{d['sessions']}</td>
            <td class="hide-mobile">{d['login_attempts']}</td>
            <td>{d['successful']}</td>
            <td>{d['unique_ips']}</td>
            <td class="hide-mobile">{d['commands']}</td>
            <td class="hide-mobile">{attacker_cell}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Honeypot Dashboard</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@400;700;900&display=swap');

  @keyframes pulse-ring {{
    0% {{ transform: scale(1); opacity: 0.8; }}
    50% {{ transform: scale(1.8); opacity: 0; }}
    100% {{ transform: scale(1); opacity: 0; }}
  }}
  @keyframes pulse-dot {{
    0% {{ opacity: 0.6; box-shadow: 0 0 4px #ff0000; }}
    50% {{ opacity: 1.0; box-shadow: 0 0 12px #ff4444, 0 0 24px #ff000066; }}
    100% {{ opacity: 0.6; box-shadow: 0 0 4px #ff0000; }}
  }}
  .pulse-marker {{
    position: relative;
    will-change: transform;
  }}
  .pulse-marker .dot {{
    width: 100%;
    height: 100%;
    background: radial-gradient(circle, #ff4444 0%, #cc0000 70%);
    border-radius: 50%;
    animation: pulse-dot 2s ease-in-out infinite;
  }}
  .pulse-marker .ring {{
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    border: 2px solid #ff4444;
    border-radius: 50%;
    animation: pulse-ring 2s ease-out infinite;
    pointer-events: none;
  }}
  .leaflet-zoom-anim .leaflet-marker-icon {{
    transition: transform 0.25s cubic-bezier(0,0,0.25,1) !important;
  }}
  .leaflet-pan-anim .leaflet-marker-icon {{
    transition: transform 0.25s linear !important;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0a0a0a;
    color: #00ff41;
    font-family: 'JetBrains Mono', monospace;
    overflow-x: hidden;
  }}

  .scanline {{
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.03) 2px, rgba(0,255,65,0.03) 4px);
    pointer-events: none; z-index: 9999;
  }}

  header {{
    background: linear-gradient(180deg, #0d1117 0%, #0a0a0a 100%);
    border-bottom: 1px solid #00ff41;
    padding: 20px 30px;
    text-align: center;
  }}
  header h1 {{
    font-family: 'Orbitron', sans-serif;
    font-size: 2.2em;
    color: #00ff41;
    text-shadow: 0 0 20px rgba(0,255,65,0.5), 0 0 40px rgba(0,255,65,0.2);
    letter-spacing: 3px;
  }}
  header .subtitle {{
    color: #555;
    font-size: 0.85em;
    margin-top: 5px;
  }}

  .stats-bar {{
    display: flex;
    justify-content: center;
    gap: 30px;
    padding: 20px;
    background: #0d1117;
    border-bottom: 1px solid #1a3a1a;
    flex-wrap: wrap;
  }}
  .stat {{
    text-align: center;
    min-width: 120px;
  }}
  .stat .value {{
    font-family: 'Orbitron', sans-serif;
    font-size: 2em;
    color: #00ff41;
    text-shadow: 0 0 10px rgba(0,255,65,0.4);
  }}
  .stat .label {{
    font-size: 0.75em;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
  }}

  .alltime-bar {{
    background: transparent;
    display: flex;
    justify-content: center;
    gap: 20px;
    padding: 12px 20px;
    background: #080c10;
    border-bottom: 1px solid #1a3a1a;
    flex-wrap: wrap;
  }}
  .alltime-stat {{
    text-align: center;
    min-width: 90px;
  }}
  .alltime-value {{
    font-family: 'Orbitron', sans-serif;
    font-size: 1.2em;
    color: #00aa30;
    text-shadow: 0 0 6px rgba(0,170,48,0.3);
  }}
  .alltime-label {{
    font-size: 0.65em;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 3px;
  }}

  .container {{
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
  }}

  .grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
  }}
  .grid.full {{ grid-template-columns: 1fr; }}

  .panel {{
    background: #0d1117;
    border: 1px solid #1a3a1a;
    border-radius: 8px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }}
  .panel::before {{
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 2px;
    background: linear-gradient(90deg, transparent, #00ff41, transparent);
  }}
  .panel h2 {{
    font-family: 'Orbitron', sans-serif;
    font-size: 1.1em;
    color: #00ff41;
    margin-bottom: 15px;
    text-transform: uppercase;
    letter-spacing: 2px;
  }}

  #map {{
    height: 400px;
    min-height: 400px;
    border-radius: 6px;
    border: 1px solid #1a3a1a;
    background: #0a0a0a;
    z-index: 1;
    position: relative;
  }}
  .leaflet-container {{
    background: #0a0a0a !important;
  }}
  #map .leaflet-tile-pane {{
    z-index: 1;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
  }}
  th, td {{
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid #1a2a1a;
    font-size: 0.85em;
  }}
  th {{
    color: #00aa30;
    text-transform: uppercase;
    font-size: 0.75em;
    letter-spacing: 1px;
  }}
  td {{ color: #aaa; }}
  .glow {{ color: #00ff41; font-weight: bold; text-shadow: 0 0 5px rgba(0,255,65,0.3); }}

  .activity-feed {{
    height: 350px;
    max-height: 350px;
    overflow-y: auto;
    font-size: 0.82em;
    flex: 1;
  }}
  .greatest-hits {{
    max-height: 500px;
    overflow-y: auto;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }}
  .hit-card {{
    background: #111a11;
    border: 1px solid #1a3a1a;
    border-radius: 6px;
    padding: 12px;
  }}
  .hit-card .hit-nick {{
    color: #ff4444;
    font-weight: bold;
    font-size: 1.1em;
    cursor: pointer;
  }}
  .hit-card .hit-nick:hover {{
    text-shadow: 0 0 8px rgba(255,68,68,0.5);
  }}
  .hit-card .hit-stat {{
    color: #00ff41;
    font-family: 'Orbitron', sans-serif;
    font-size: 0.85em;
    margin: 4px 0;
  }}
  .hit-card .hit-story {{
    color: #aaa;
    font-size: 0.85em;
    margin-top: 6px;
    line-height: 1.4;
  }}
  .activity-feed::-webkit-scrollbar {{ width: 6px; }}
  .activity-feed::-webkit-scrollbar-track {{ background: #0a0a0a; }}
  .activity-feed::-webkit-scrollbar-thumb {{ background: #1a3a1a; border-radius: 3px; }}

  .activity-row {{
    padding: 6px 10px;
    border-bottom: 1px solid #111;
    display: flex;
    gap: 12px;
    align-items: baseline;
  }}
  .activity-row:hover {{ background: #111a11; }}
  .activity-row .ts {{ color: #444; min-width: 150px; font-size: 0.9em; }}
  .activity-row .ip {{ color: #ff6b6b; min-width: 130px; }}
  .activity-row .action {{ color: #aaa; flex: 1; min-width: 0; max-height: 80px; overflow-y: auto; overflow-x: hidden; word-break: break-all; white-space: pre-wrap; }}
  .activity-row .action::-webkit-scrollbar {{ width: 4px; }}
  .activity-row .action::-webkit-scrollbar-track {{ background: #0a0a0a; }}
  .activity-row .action::-webkit-scrollbar-thumb {{ background: #1a3a1a; border-radius: 3px; }}
  .success-text {{ color: #00ff41 !important; font-weight: bold; }}
  .nick-link {{
    color: #ff4444;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .nick-link:hover {{
    color: #ff6666;
    text-decoration: underline;
    text-shadow: 0 0 8px rgba(255,68,68,0.5);
  }}

  .terminal {{
    background: #000;
    border: 1px solid #1a3a1a;
    border-radius: 6px;
    padding: 15px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85em;
    max-height: 350px;
    overflow-y: auto;
  }}
  .term-header {{
    color: #ff6b6b;
    font-weight: bold;
    margin: 10px 0 5px 0;
    border-bottom: 1px solid #222;
    padding-bottom: 3px;
  }}
  .term-line {{ color: #00ff41; margin: 2px 0; }}
  .term-prompt {{ color: #ff6b6b; }}

  .leaflet-popup-content-wrapper {{
    background: #0d1117 !important;
    color: #00ff41 !important;
    border: 1px solid #00ff41 !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
  }}
  .leaflet-popup-tip {{ background: #0d1117 !important; }}
  .leaflet-popup-content {{ font-size: 0.85em; }}
  .popup-ip {{ color: #ff6b6b; font-weight: bold; font-size: 1.1em; }}
  .popup-label {{ color: #666; }}

  .footer {{
    text-align: center;
    padding: 20px;
    color: #333;
    font-size: 0.8em;
  }}

  canvas {{ max-height: 300px; }}

  @media (max-width: 900px) {{
    .grid {{ grid-template-columns: 1fr; }}
    .stats-bar {{ gap: 15px; }}
  }}
  @media (max-width: 600px) {{
    header h1 {{ font-size: 1.1em; letter-spacing: 1px; }}
    header .subtitle {{ font-size: 0.65em; word-break: break-word; }}
    .container {{ padding: 8px; }}
    .panel {{ padding: 10px; overflow: visible; }}
    .panel h2 {{ font-size: 0.85em; letter-spacing: 1px; }}

    /* Stats: 2x2 grid instead of horizontal row */
    .stats-bar {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 10px 8px; }}
    .stat {{ min-width: unset; }}
    .stat .value {{ font-size: 1.3em; }}
    .stat .label {{ font-size: 0.55em; }}
    .alltime-bar {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; padding: 8px; }}
    .alltime-stat {{ min-width: unset; }}
    .alltime-value {{ font-size: 0.95em; }}
    .alltime-label {{ font-size: 0.5em; }}

    /* Activity feed: stack ts/ip/action vertically */
    .activity-row {{ flex-wrap: wrap; gap: 2px; padding: 8px 6px; }}
    .activity-row .ts {{ min-width: unset; font-size: 0.7em; width: 100%; }}
    .activity-row .ip {{ min-width: unset; font-size: 0.8em; }}
    .activity-row .action {{ font-size: 0.75em; width: 100%; max-height: 60px; }}

    /* Tables: hide less important columns on mobile */
    table {{ width: 100%; table-layout: fixed; }}
    th, td {{ padding: 6px 4px; font-size: 0.75em; word-break: break-word; white-space: normal; }}
    .hide-mobile {{ display: none !important; }}
    table {{ font-size: 0.85em; }}
    table td, table th {{ padding: 8px 6px; }}

    .terminal {{ font-size: 0.7em; padding: 8px; }}
    .greatest-hits {{ grid-template-columns: 1fr; }}
    #map {{ height: 280px; }}
    canvas {{ max-height: 200px; }}

    /* Fix Leaflet touch zoom marker drift */
    .leaflet-marker-icon {{ transition: none !important; }}
  }}
</style>
</head>
<body>

<div class="scanline"></div>

<header>
  <h1>🍯 HONEYPOT DASHBOARD</h1>
  <div class="subtitle">COWRIE SSH HONEYPOT // LIVE ATTACKER INTELLIGENCE // Generated: {data['generated']}</div>
</header>

<div class="stats-bar">
  <div class="stat"><div class="value">{today['sessions']}</div><div class="label">Sessions Today</div></div>
  <div class="stat"><div class="value">{today['login_attempts']}</div><div class="label">Login Attempts Today</div></div>
  <div class="stat"><div class="value">{today['successful_logins']}</div><div class="label">Successful Logins Today</div></div>
  <div class="stat"><div class="value">{today['unique_ips']}</div><div class="label">Unique IPs Today</div></div>
  <div class="stat"><div class="value">{today['commands']}</div><div class="label">Commands Today</div></div>
</div>


<div class="container">

  <div class="grid full">
    <div class="panel" style="overflow:visible;">
      <h2>🌍 Attack Origins</h2>
      <div id="map"></div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>🏆 Top Attackers</h2>
      <div style="max-height:350px; overflow-y:auto;">
        <table>
          <tr><th>Attacker</th><th>Origin</th><th class="hide-mobile">ISP</th><th>Attempts</th></tr>
          {leaderboard_rows}
        </table>
      </div>
    </div>
    <div class="panel">
      <h2>📡 Recent Activity</h2>
      <div class="activity-feed">
        {activity_rows}
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>🎬 Greatest Hits</h2>
      <div class="greatest-hits">
        {greatest_hits_html}
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>🔑 Top Credentials</h2>
      <canvas id="credsChart"></canvas>
    </div>
    <div class="panel">
      <h2>📈 Attack Timeline</h2>
      <canvas id="timelineChart"></canvas>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>📊 Daily Breakdown</h2>
      <div style="overflow-x:auto; max-height:500px; overflow-y:auto;">
        <table>
          <tr><th>Date</th><th>Sessions</th><th class="hide-mobile">Login Attempts</th><th>Successful</th><th>Unique IPs</th><th class="hide-mobile">Commands</th><th class="hide-mobile">Top Attacker</th></tr>
          {daily_rows}
        </table>
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>📊 All-Time Stats</h2>
      <div style="overflow-x:auto;">
        <table>
          <tr><th>Metric</th><th>Total</th><th>Avg / Day</th></tr>
          <tr><td>Sessions</td><td class="glow">{stats['total_sessions']}</td><td>{data['averages']['sessions_per_day']}</td></tr>
          <tr><td>Login Attempts</td><td class="glow">{stats['total_login_attempts']}</td><td>{data['averages']['logins_per_day']}</td></tr>
          <tr><td>Successful Logins</td><td class="glow">{stats['successful_logins']}</td><td>{data['averages']['successful_per_day']}</td></tr>
          <tr><td>Unique IPs</td><td class="glow">{stats['unique_ips']}</td><td>{data['averages']['ips_per_day']}</td></tr>
          <tr><td>Commands Executed</td><td class="glow">{stats['commands_executed']}</td><td>{data['averages']['commands_per_day']}</td></tr>
          <tr><td>Days Active</td><td class="glow" colspan="2">{data['days_active']}</td></tr>
          <tr><td>Success Rate</td><td class="glow" colspan="2">{data['averages']['success_rate']}%</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>💀 Successful Logins — What They Did</h2>
      <div class="terminal" style="max-height:400px; overflow-y:auto;">
        {terminal_content}
      </div>
    </div>
  </div>

</div>

<div class="footer">
  HONEYPOT DASHBOARD v1.0 // Data from Cowrie SSH Honeypot // {data['generated']}
</div>

<script>
  // Map
  var map = L.map('map', {{
    center: [20, 0],
    zoom: 2,
    zoomControl: true,
    attributionControl: false,
    maxBounds: [[-85, -180], [85, 180]],
    maxBoundsViscosity: 1.0,
    minZoom: 2
  }});

  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    maxZoom: 18
  }}).addTo(map);

  // Fix tile loading on mobile — recalculate container size after render
  setTimeout(function() {{ map.invalidateSize(true); }}, 100);
  setTimeout(function() {{ map.invalidateSize(true); }}, 300);
  setTimeout(function() {{ map.invalidateSize(true); }}, 1000);
  setTimeout(function() {{ map.invalidateSize(true); }}, 2000);
  window.addEventListener('resize', function() {{ map.invalidateSize(true); }});
  document.addEventListener('visibilitychange', function() {{ if (!document.hidden) map.invalidateSize(true); }});

  var markerLookup = {{}};
  var pulseMarkers = [];
  var markers = {markers_json};
  markers.forEach(function(m) {{
    var baseRadius = Math.max(6, Math.min(22, m.count * 2));
    var phase = Math.random() * Math.PI * 2;

    // Outer ring (pulse effect)
    var ring = L.circleMarker([m.lat, m.lon], {{
      radius: baseRadius * 1.8,
      fillColor: '#ff4444',
      fillOpacity: 0,
      color: '#ff4444',
      weight: 2,
      opacity: 0.4
    }}).addTo(map);

    // Inner dot
    var dot = L.circleMarker([m.lat, m.lon], {{
      radius: baseRadius,
      fillColor: '#ff4444',
      fillOpacity: 0.7,
      color: '#ff6666',
      weight: 2,
      opacity: 0.9
    }}).addTo(map);

    pulseMarkers.push({{ ring: ring, dot: dot, baseRadius: baseRadius, phase: phase }});

    var credsHtml = m.creds.length > 0
      ? '<br><span class="popup-label">Creds tried:</span><br>' + m.creds.map(function(c) {{ return '&nbsp;&nbsp;' + c; }}).join('<br>')
      : '';

    dot.bindPopup(
      '<span style="color:#ff4444;font-weight:bold;font-size:14px">' + (m.nickname || '?') + '</span><br>' +
      '<span class="popup-ip">' + m.ip + '</span><br>' +
      '<span class="popup-label">Location:</span> ' + (m.city ? m.city + ', ' : '') + m.country + '<br>' +
      '<span class="popup-label">ISP:</span> ' + m.isp + '<br>' +
      '<span class="popup-label">Attempts:</span> <strong>' + m.count + '</strong>' +
      credsHtml
    );

    if (m.nickname) markerLookup[m.nickname] = dot;
    markerLookup[m.ip] = dot;
  }});

  // Animate pulse via JS — no CSS, so no drift
  function animatePulse() {{
    var t = Date.now() / 1000;
    pulseMarkers.forEach(function(pm) {{
      var cycle = (Math.sin(t * 2 + pm.phase) + 1) / 2; // 0..1
      pm.ring.setRadius(pm.baseRadius * (1.4 + cycle * 0.8));
      pm.ring.setStyle({{ opacity: 0.6 - cycle * 0.5, weight: 2 - cycle }});
      pm.dot.setStyle({{ fillOpacity: 0.5 + cycle * 0.3 }});
    }});
    requestAnimationFrame(animatePulse);
  }}
  animatePulse();

  window.flyToAttacker = function(nickname) {{
    var mapEl = document.getElementById('map');
    if (mapEl) {{ mapEl.scrollIntoView({{ behavior: 'smooth', block: 'center' }}); }}
    var m = markerLookup[nickname];
    if (m) {{
      setTimeout(function() {{
        map.flyTo(m.getLatLng(), 6, {{duration: 0.8}});
        setTimeout(function() {{ m.openPopup(); }}, 900);
      }}, 400);
    }}
  }};

  // Credentials chart
  new Chart(document.getElementById('credsChart'), {{
    type: 'bar',
    data: {{
      labels: {top_creds_labels},
      datasets: [{{
        label: 'Attempts',
        data: {top_creds_data},
        backgroundColor: 'rgba(0, 255, 65, 0.6)',
        borderColor: '#00ff41',
        borderWidth: 1,
      }}]
    }},
    options: {{
      indexAxis: 'y',
      responsive: true,
      plugins: {{
        legend: {{ display: false }},
      }},
      scales: {{
        x: {{
          ticks: {{ color: '#666' }},
          grid: {{ color: '#1a2a1a' }},
        }},
        y: {{
          ticks: {{ color: '#00ff41', font: {{ family: 'JetBrains Mono', size: 11 }} }},
          grid: {{ display: false }},
        }}
      }}
    }}
  }});

  // Timeline chart
  new Chart(document.getElementById('timelineChart'), {{
    type: 'line',
    data: {{
      labels: {timeline_labels},
      datasets: [{{
        label: 'Attempts',
        data: {timeline_data},
        borderColor: '#00ff41',
        backgroundColor: 'rgba(0, 255, 65, 0.1)',
        fill: true,
        tension: 0.3,
        pointBackgroundColor: '#00ff41',
        pointRadius: 4,
      }}]
    }},
    options: {{
      responsive: true,
      plugins: {{
        legend: {{ display: false }},
      }},
      scales: {{
        x: {{
          ticks: {{ color: '#666', maxRotation: 45, maxTicksLimit: 6, callback: function(val, idx, ticks) {{ var label = this.getLabelForValue(val); var parts = label.split(' '); return parts[0].slice(5) + ' ' + parts[1]; }} }},
          grid: {{ color: '#1a2a1a' }},
        }},
        y: {{
          beginAtZero: true,
          ticks: {{ color: '#666' }},
          grid: {{ color: '#1a2a1a' }},
        }}
      }}
    }}
  }});
</script>

</body>
</html>"""
    return html


def main():
    print("[*] Parsing Cowrie log...")
    # Read current + rotated logs
    rotated = sorted(f for f in glob.glob(LOG_PATH + "*") if f != LOG_PATH)
    log_files = rotated + [LOG_PATH]  # rotated first, current last
    seen = set()
    events = []
    for lf in log_files:
        if lf not in seen:
            seen.add(lf)
            events.extend(parse_log(lf))
    print(f"[*] Loaded {len(events)} events")

    if not events:
        print("[!] No events found. Generating empty dashboard.")

    # Collect unique IPs
    all_ips = set()
    for e in events:
        ip = e.get("src_ip")
        if ip:
            all_ips.add(ip)
    print(f"[*] Found {len(all_ips)} unique IPs")

    # GeoIP
    geo_cache = load_geo_cache()
    geo_cache = batch_geoip_lookup(all_ips, geo_cache)

    # Analyze
    data = analyze_events(events, geo_cache)

    # Generate HTML
    html = generate_html(data)
    with open(OUTPUT_PATH, "w") as f:
        f.write(html)
    print(f"[✓] Dashboard written to {OUTPUT_PATH}")
    print(f"    Sessions: {data['stats']['total_sessions']} | Logins: {data['stats']['total_login_attempts']} | "
          f"Success: {data['stats']['successful_logins']} | IPs: {data['stats']['unique_ips']}")


if __name__ == "__main__":
    main()
