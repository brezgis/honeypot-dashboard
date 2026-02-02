#!/usr/bin/env python3
"""
Persistent Analytics Store for Cowrie Honeypot Dashboard
Incrementally processes cowrie JSON logs and maintains aggregated analytics.
"""

import json
import os
import sys
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
    """Save GeoIP cache."""
    try:
        with open(GEOIP_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except IOError as e:
        print(f"[!] Failed to save GeoIP cache: {e}")


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
            "last_processed_line": 0,
            "total_events_processed": 0,
            "last_updated": None
        }
    }


def save_analytics(analytics):
    """Save analytics data."""
    analytics["meta"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(ANALYTICS_PATH, "w") as f:
            json.dump(analytics, f, indent=2)
        print(f"[*] Analytics saved to {ANALYTICS_PATH}")
    except IOError as e:
        print(f"[!] Failed to save analytics: {e}")
        return False
    return True


def process_new_events():
    """Process new events from the cowrie log."""
    if not os.path.exists(LOG_PATH):
        print(f"[!] Log file not found: {LOG_PATH}")
        return
    
    # Load existing data
    analytics = load_analytics()
    geoip_cache = load_geoip_cache()
    
    last_processed = analytics["meta"]["last_processed_line"]
    events_processed = 0
    new_ips = set()
    
    print(f"[*] Processing events from line {last_processed + 1}")
    
    try:
        with open(LOG_PATH, "r") as f:
            # Skip already processed lines
            for i in range(last_processed):
                f.readline()
            
            current_line = last_processed
            for line in f:
                current_line += 1
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    process_event(event, analytics, new_ips)
                    events_processed += 1
                    
                    # Update progress every 1000 events
                    if events_processed % 1000 == 0:
                        print(f"[*] Processed {events_processed} events...")
                        
                except json.JSONDecodeError:
                    print(f"[!] Skipping malformed JSON at line {current_line}")
                    continue
            
            analytics["meta"]["last_processed_line"] = current_line
            analytics["meta"]["total_events_processed"] += events_processed
    
    except IOError as e:
        print(f"[!] Failed to read log file: {e}")
        return
    
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
    
    # Save results
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
        # Track session start
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
        # Track session end
        if session in analytics["sessions"]:
            analytics["sessions"][session]["end_time"] = timestamp
    
    elif eventid in ["cowrie.login.failed", "cowrie.login.success"]:
        # Track credentials
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
        
        # Track in session
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
        # Track commands
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
            
            # Track in session
            if session in analytics["sessions"]:
                analytics["sessions"][session]["commands"].append({
                    "command": command,
                    "timestamp": timestamp
                })
            
            # Update IP command count
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
    
    # Process sessions for daily summaries
    for session_id, session in analytics["sessions"].items():
        if not session["start_time"]:
            continue
            
        try:
            date = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00")).date().isoformat()
        except:
            continue
            
        day = daily_data[date]
        day["total_sessions"] += 1
        
        if session["ip"]:
            day["unique_ips"].add(session["ip"])
            day["ips"][session["ip"]] += 1
        
        # Count login attempts and successes
        for cred_attempt in session["credentials_tried"]:
            day["login_attempts"] += 1
            day["credentials"][cred_attempt["credential"]] += 1
            if cred_attempt["success"]:
                day["successful"] += 1
        
        # Count unique commands
        for cmd in session["commands"]:
            day["unique_commands"].add(cmd["command"])
    
    # Convert to final format
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