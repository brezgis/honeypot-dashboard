#!/usr/bin/env python3
"""
Persistent Analytics Store for Cowrie Honeypot Dashboard
Incrementally processes cowrie JSON logs and maintains aggregated analytics.

Fixes applied (2026-02-06):
- C3: Atomic writes (temp file + os.rename) for analytics.json
- H1: 30-day retention pruning for sessions, credentials, IPs, commands
- H2: File-size-based log rotation detection (replaces fragile line counting)
- H3: Atomic writes for geoip_cache.json
"""

import json
import os
import sys
import tempfile
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone, timedelta

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
ANALYTICS_PATH = os.path.join(SCRIPT_DIR, "analytics.json")
GEOIP_CACHE_PATH = os.path.join(SCRIPT_DIR, "geoip_cache.json")

# Retention: prune data older than this
RETENTION_DAYS = 30


def atomic_json_write(filepath, data, indent=2):
    """Write JSON atomically using temp file + os.rename."""
    dirpath = os.path.dirname(filepath)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dirpath, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent)
        os.rename(tmp_path, filepath)
    except Exception as e:
        print(f"[!] Atomic write failed for {filepath}: {e}")
        # Clean up temp file if rename failed
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return False
    return True


def load_geoip_cache():
    """Load existing GeoIP cache."""
    if os.path.exists(GEOIP_CACHE_PATH):
        try:
            with open(GEOIP_CACHE_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_geoip_cache(cache):
    """Save GeoIP cache atomically (H3 fix)."""
    if not atomic_json_write(GEOIP_CACHE_PATH, cache):
        print("[!] Failed to save GeoIP cache")


def batch_geoip_lookup(ips, cache):
    """Lookup IPs via ip-api.com batch endpoint (max 100 per request)."""
    to_lookup = [ip for ip in ips if ip not in cache]
    if not to_lookup:
        return cache

    print(f"[*] Looking up GeoIP for {len(to_lookup)} new IPs...")
    
    # Process in batches of 100 (API limit)
    for i in range(0, len(to_lookup), 100):
        batch = to_lookup[i:i+100]
        print(f"[*] Processing batch {i//100 + 1}: {len(batch)} IPs")
        
        payload = json.dumps([{
            "query": ip, 
            "fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,query"
        } for ip in batch]).encode()
        
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
                            "org": r.get("org", "Unknown")
                        }
                    else:
                        # Mark failed lookups so we don't retry them immediately
                        cache[ip] = {
                            "country": "Unknown",
                            "countryCode": "",
                            "region": "",
                            "city": "",
                            "lat": 0,
                            "lon": 0,
                            "isp": "Unknown",
                            "org": "Unknown"
                        }
        except Exception as e:
            print(f"[!] GeoIP lookup failed: {e}")
            
        # Rate limiting: wait 4 seconds between batches (15 requests per minute limit)
        if i + 100 < len(to_lookup):
            time.sleep(4)
    
    return cache


def load_analytics():
    """Load existing analytics data."""
    if os.path.exists(ANALYTICS_PATH):
        try:
            with open(ANALYTICS_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Failed to load analytics: {e}")
    
    # Return default structure
    return {
        "commands": {},
        "credentials": {},
        "ips": {},
        "sessions": {},
        "daily_summary": {},
        "meta": {
            "last_byte_offset": 0,
            "last_file_size": 0,
            "total_events_processed": 0,
            "last_updated": None
        }
    }


def save_analytics(analytics):
    """Save analytics data atomically (C3 fix)."""
    analytics["meta"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    if atomic_json_write(ANALYTICS_PATH, analytics):
        print(f"[*] Analytics saved to {ANALYTICS_PATH}")
        return True
    else:
        print(f"[!] Failed to save analytics")
        return False


def prune_old_data(analytics):
    """Remove data older than RETENTION_DAYS (H1 fix)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
    pruned_counts = {"sessions": 0, "credentials": 0, "commands": 0, "ips": 0, "daily_summary": 0}

    # Prune sessions
    old_sessions = [sid for sid, s in analytics.get("sessions", {}).items()
                    if s.get("start_time", "") and s["start_time"] < cutoff]
    for sid in old_sessions:
        del analytics["sessions"][sid]
        pruned_counts["sessions"] += 1

    # Prune credentials by last_seen
    old_creds = [c for c, v in analytics.get("credentials", {}).items()
                 if v.get("last_seen", "") and v["last_seen"] < cutoff]
    for c in old_creds:
        del analytics["credentials"][c]
        pruned_counts["credentials"] += 1

    # Prune commands by last_seen
    old_cmds = [c for c, v in analytics.get("commands", {}).items()
                if v.get("last_seen", "") and v["last_seen"] < cutoff]
    for c in old_cmds:
        del analytics["commands"][c]
        pruned_counts["commands"] += 1

    # Prune IPs by last_seen
    old_ips = [ip for ip, v in analytics.get("ips", {}).items()
               if v.get("last_seen", "") and v["last_seen"] < cutoff]
    for ip in old_ips:
        del analytics["ips"][ip]
        pruned_counts["ips"] += 1

    # Prune daily summaries older than retention
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%d")
    old_days = [d for d in analytics.get("daily_summary", {}) if d < cutoff_date]
    for d in old_days:
        del analytics["daily_summary"][d]
        pruned_counts["daily_summary"] += 1

    total_pruned = sum(pruned_counts.values())
    if total_pruned > 0:
        print(f"[*] Pruned {total_pruned} old entries: {pruned_counts}")

    return analytics


def process_new_events():
    """Process new events from the cowrie log using byte offsets (H2 fix)."""
    if not os.path.exists(LOG_PATH):
        print(f"[!] Log file not found: {LOG_PATH}")
        return
    
    # Load existing data
    analytics = load_analytics()
    geoip_cache = load_geoip_cache()

    # Migrate from old line-based tracking to byte offsets
    if "last_processed_line" in analytics.get("meta", {}):
        print("[*] Migrating from line-based to byte-offset tracking")
        analytics["meta"].pop("last_processed_line", None)
        # Start fresh from beginning on migration
        analytics["meta"]["last_byte_offset"] = 0
        analytics["meta"]["last_file_size"] = 0

    last_offset = analytics["meta"].get("last_byte_offset", 0)
    last_file_size = analytics["meta"].get("last_file_size", 0)
    
    # Get current file size
    try:
        current_size = os.path.getsize(LOG_PATH)
    except OSError as e:
        print(f"[!] Cannot stat log file: {e}")
        return

    # Log rotation detection: file smaller than last known size (H2 fix)
    if current_size < last_file_size:
        print(f"[*] Log rotation detected (size {current_size} < last {last_file_size}), resetting offset")
        last_offset = 0

    # Nothing new
    if current_size <= last_offset:
        print(f"[*] No new data (file size {current_size}, offset {last_offset})")
        # Still prune and save
        analytics = prune_old_data(analytics)
        save_analytics(analytics)
        return

    events_processed = 0
    new_ips = set()

    print(f"[*] Processing events from byte offset {last_offset} (file size: {current_size})")

    try:
        with open(LOG_PATH, "r") as f:
            f.seek(last_offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    process_event(event, analytics, new_ips)
                    events_processed += 1

                    if events_processed % 1000 == 0:
                        print(f"[*] Processed {events_processed} events...")

                except json.JSONDecodeError:
                    # First line after seek may be partial — skip gracefully
                    if events_processed == 0 and last_offset > 0:
                        continue
                    print(f"[!] Skipping malformed JSON line")
                    continue
    except IOError as e:
        print(f"[!] Failed to read log file: {e}")
        return

    # Update byte offset to actual file size (not computed from content)
    analytics["meta"]["last_byte_offset"] = current_size
    analytics["meta"]["last_file_size"] = current_size
    analytics["meta"]["total_events_processed"] += events_processed
    
    # Perform GeoIP lookups for new IPs
    if new_ips:
        geoip_cache = batch_geoip_lookup(list(new_ips), geoip_cache)
        save_geoip_cache(geoip_cache)
        
        # Update IP analytics with geo data
        for ip in new_ips:
            if ip in analytics["ips"] and ip in geoip_cache:
                geo = geoip_cache[ip]
                analytics["ips"][ip].update({
                    "country": geo["country"],
                    "city": geo["city"],
                    "isp": geo["isp"]
                })
    
    # Generate daily summary
    generate_daily_summaries(analytics)
    
    # Prune old data (H1 fix)
    analytics = prune_old_data(analytics)

    # Save results atomically (C3 fix)
    save_analytics(analytics)
    print(f"[*] Processed {events_processed} new events, {len(new_ips)} new IPs")


def process_event(event, analytics, new_ips):
    """Process a single cowrie event."""
    eventid = event.get("eventid", "")
    timestamp = event.get("timestamp", "")
    src_ip = event.get("src_ip", "")
    session = event.get("session", "")
    
    if not timestamp:
        return
        
    # Track new IPs for GeoIP lookup
    if src_ip and src_ip not in analytics["ips"]:
        new_ips.add(src_ip)
        analytics["ips"][src_ip] = {
            "country": "Unknown",
            "city": "Unknown", 
            "isp": "Unknown",
            "first_seen": timestamp,
            "last_seen": timestamp,
            "total_attempts": 0,
            "successful_logins": 0,
            "commands_run": 0
        }
    
    # Update IP last_seen
    if src_ip and src_ip in analytics["ips"]:
        analytics["ips"][src_ip]["last_seen"] = timestamp
        analytics["ips"][src_ip]["total_attempts"] += 1
    
    # Process different event types
    if eventid == "cowrie.session.connect":
        if session not in analytics["sessions"]:
            analytics["sessions"][session] = {
                "ip": src_ip,
                "start_time": timestamp,
                "end_time": None,
                "commands": [],
                "credentials_tried": [],
                "got_in": False
            }
    
    elif eventid == "cowrie.session.closed":
        if session in analytics["sessions"]:
            analytics["sessions"][session]["end_time"] = timestamp
    
    elif eventid in ["cowrie.login.failed", "cowrie.login.success"]:
        username = event.get("username", "")
        password = event.get("password", "")
        credential = f"{username}:{password}"
        success = eventid == "cowrie.login.success"
        
        if credential not in analytics["credentials"]:
            analytics["credentials"][credential] = {
                "count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "success": success
            }
        
        analytics["credentials"][credential]["count"] += 1
        analytics["credentials"][credential]["last_seen"] = timestamp
        if success:
            analytics["credentials"][credential]["success"] = True
        
        if session in analytics["sessions"]:
            analytics["sessions"][session]["credentials_tried"].append({
                "credential": credential,
                "timestamp": timestamp,
                "success": success
            })
            if success:
                analytics["sessions"][session]["got_in"] = True
                if src_ip in analytics["ips"]:
                    analytics["ips"][src_ip]["successful_logins"] += 1
    
    elif eventid == "cowrie.command.input":
        command = event.get("input", "").strip()
        if command:
            if command not in analytics["commands"]:
                analytics["commands"][command] = {
                    "count": 0,
                    "first_seen": timestamp,
                    "last_seen": timestamp
                }
            
            analytics["commands"][command]["count"] += 1
            analytics["commands"][command]["last_seen"] = timestamp
            
            if session in analytics["sessions"]:
                analytics["sessions"][session]["commands"].append({
                    "command": command,
                    "timestamp": timestamp
                })
            
            if src_ip in analytics["ips"]:
                analytics["ips"][src_ip]["commands_run"] += 1


def generate_daily_summaries(analytics):
    """Generate daily summary statistics."""
    daily_data = defaultdict(lambda: {
        "total_sessions": 0,
        "login_attempts": 0,
        "successful": 0,
        "unique_ips": set(),
        "unique_commands": set(),
        "credentials": defaultdict(int),
        "ips": defaultdict(int)
    })
    
    for session_id, session in analytics["sessions"].items():
        if not session["start_time"]:
            continue
            
        try:
            date = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00")).date().isoformat()
        except (ValueError, TypeError):
            continue
            
        day = daily_data[date]
        day["total_sessions"] += 1
        
        if session["ip"]:
            day["unique_ips"].add(session["ip"])
            day["ips"][session["ip"]] += 1
        
        for cred_attempt in session["credentials_tried"]:
            day["login_attempts"] += 1
            day["credentials"][cred_attempt["credential"]] += 1
            if cred_attempt["success"]:
                day["successful"] += 1
        
        for cmd in session["commands"]:
            day["unique_commands"].add(cmd["command"])
    
    for date, data in daily_data.items():
        top_credential = max(data["credentials"].items(), key=lambda x: x[1]) if data["credentials"] else ("", 0)
        top_ip = max(data["ips"].items(), key=lambda x: x[1]) if data["ips"] else ("", 0)
        
        analytics["daily_summary"][date] = {
            "total_sessions": data["total_sessions"],
            "login_attempts": data["login_attempts"],
            "successful": data["successful"],
            "unique_ips": len(data["unique_ips"]),
            "unique_commands": len(data["unique_commands"]),
            "top_credential": top_credential[0],
            "top_ip": top_ip[0]
        }


def main():
    """Main processing function."""
    print(f"[*] Starting analytics processing at {datetime.now()}")
    process_new_events()
    print(f"[*] Analytics processing completed")


if __name__ == "__main__":
    main()
