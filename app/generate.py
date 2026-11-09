#!/usr/bin/env python3
"""
Cowrie Honeypot Dashboard Generator
Parses Cowrie JSON logs, does GeoIP lookups, generates a self-contained HTML dashboard.

Fixes applied (2026-02-06):
- H3: Atomic writes (temp+rename) for geoip_cache.json and description_cache.json
- L5: Moved imports (math, random, re) to top of file
- L7: Bare except → specific exception types in load_cache()
- M5: Seed random with IP hash for deterministic command explanations

Fixes applied (2026-03-24) - Pike:
- H1/H3: Shared desc_cache between generate_greatest_hits and generate_attacker_narratives
         (single load + single save per generate_html run, no partial-write race)
- H2: Removed dead classify_commands_fast function (~80 lines, never called)
- M1: Consolidated inline _bad_starts lists into module-level _BAD_PREFIXES
"""

import glob
import gzip
import hashlib
import json
import math
import os
import random
import re
import sys
import tempfile
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone, timedelta
from html import escape as h
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("America/New_York")

def strip_markdown(text):
    """Strip markdown formatting from LLM output before inserting into HTML."""
    if not text:
        return text
    # Remove headers (### Header -> Header)
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    # Remove bold/italic markers
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'__(.+?)__', r'\1', text)
    text = re.sub(r'_(.+?)_', r'\1', text)
    # Remove inline code backticks
    text = re.sub(r'`(.+?)`', r'\1', text)
    # Remove code blocks
    text = re.sub(r'```[\s\S]*?```', '', text)
    # Remove horizontal rules
    text = re.sub(r'^---+$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\*\*\*+$', '', text, flags=re.MULTILINE)
    # Remove bullet points
    text = re.sub(r'^\s*[-*+]\s+', '', text, flags=re.MULTILINE)
    # Remove numbered lists prefix
    text = re.sub(r'^\s*\d+\.\s+', '', text, flags=re.MULTILINE)
    # Collapse multiple newlines/whitespace
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    # Final safety: remove any remaining markdown artifacts
    text = text.replace('**', '').replace('__', '').replace('`', '')
    # Remove any leftover # at start of text
    text = re.sub(r'^#+\s*', '', text)
    return text.strip()


# Meta-phrase patterns that indicate bad LLM output
_BAD_PREFIXES = [
    "based on the", "here is the", "here is a", "here's the", "here's a",
    "as an ai", "i'll analyze", "i will analyze", "let me analyze",
    "the following", "this is a", "this is the", "i can see",
    "looking at the", "analyzing the", "the attacker profile",
    "attacker profile:", "summary:", "analysis:",
    "(do not include", "arrow-chain summary",
    "attacker:", "attacker profile", "the attacker",
    # Inline bad-starts from generate_greatest_hits / generate_attacker_narratives (M1 fix)
    "here", "i can", "we ", "okay",
    "this command", "it looks", "the user", "based on",
    "sure",
]


def validate_llm_output(text, max_chars=300):
    """Check if LLM output is good quality. Returns (is_valid, reason)."""
    if not text:
        return False, "empty"
    text_lower = text.lower().strip()
    for prefix in _BAD_PREFIXES:
        if text_lower.startswith(prefix):
            return False, f"meta-prefix: {prefix}"
    if len(text) > max_chars:
        return False, f"too long ({len(text)} chars)"
    # Check for any residual markdown
    if re.search(r'^#{1,6}\s', text, re.MULTILINE):
        return False, "contains markdown headers"
    if '**' in text:
        return False, "contains bold markdown"
    if '`' in text:
        return False, "contains backtick markdown"
    # Reject descriptions that just restate stats (attempt counts, session counts)
    if re.match(r'^\d[\d,]*\s+(attempts?|sessions?|commands?)', text_lower):
        return False, "just restates stats"
    # Reject descriptions that are just country/ISP metadata
    if re.match(r'^(attacker:?\s+)?(from\s+)?[A-Z][a-z]+[,\s]', text) and len(text) < 80:
        # Check if it's mostly proper nouns and metadata (no action verbs)
        action_words = ["brute", "scan", "target", "credential", "dump", "download",
                        "execute", "deploy", "persist", "recon", "fingerprint", "probe",
                        "exploit", "attack", "compromise", "harvest", "spray", "stuff",
                        "audit", "profile", "pivot", "shell", "payload", "miner", "botnet"]
        if not any(w in text_lower for w in action_words):
            return False, "just metadata, no attack description"
    return True, "ok"


# === Prompt Routing System ===
# Prompt variants tested against real sessions, routed by attacker archetype.

PROMPT_SOPHISTICATED = (
    "You are a security analyst writing one-liner descriptions for a honeypot dashboard.\n"
    "Technically precise, dry wit. The humor comes from what attackers actually do.\n\n"
    "Rules:\n"
    "- One sentence, under 200 characters\n"
    "- No markdown, no backticks, no bullet points\n"
    "- Don\'t start with \"The attacker\" or \"An attacker\"\n"
    "- Don\'t restate metadata (country, IP, ISP)\n"
    "- Don\'t say \"honeypot\"\n"
    "- Lead with the most interesting technical action\n"
    "- ONLY describe actions listed in the profile \u2014 do NOT invent additional actions\n\n"
    "Examples:\n"
    "- \"Chattr\'d .ssh, injected the mdrfckr key, changed root password, inventoried the hardware \u2014 methodical takeover in one session.\"\n"
    "- \"Wrote uname -a to a shell script, chmod 777\'d it, and executed it \u2014 could\'ve just typed it, but cargo-cult habits die hard.\"\n"
    "- \"SSH key injection followed by chattr lockdown and hardware census \u2014 this one runs a tight ship for a script kiddie.\"\n\n"
    "Describe this attacker in one sentence:\n"
    "{profile}"
)

PROMPT_RECON = (
    "You are a security analyst writing one-liner descriptions for a honeypot dashboard.\n"
    "Technically precise, dry wit.\n\n"
    "Rules:\n"
    "- One sentence, under 200 characters\n"
    "- No markdown, no backticks\n"
    "- Don\'t start with \"The attacker\"\n"
    "- Don\'t restate metadata (country, IP, ISP)\n"
    "- Don\'t say \"honeypot\"\n"
    "- Highlight the repetition or futility\n\n"
    "Examples:\n"
    "- \"3,951 sessions of the exact same uname command with Solana creds \u2014 dedication to monotony.\"\n"
    "- \"Showed up with validator credentials, ran uname four times, left \u2014 window-shopping for crypto nodes.\"\n"
    "- \"172 attempts, 4 logins; massive fingerprinting script with custom separators \u2014 likely probing for honeypot signatures.\"\n"
    "- \"Ran uname eight times with default credentials, proving they prefer repetition over reading the manual.\"\n\n"
    "Describe this attacker in one sentence:\n"
    "{profile}"
)

PROMPT_BOMBER = (
    "You write terse, deadpan one-liners for a security dashboard.\n"
    "Let the absurdity of the facts speak for itself.\n\n"
    "Rules:\n"
    "- One sentence, under 200 characters\n"
    "- No markdown, no backticks\n"
    "- Don\'t start with \"The attacker\" or \"An attacker\"\n"
    "- Don\'t restate metadata (country, IP, ISP)\n"
    "- Don\'t say \"honeypot\"\n"
    "- State the single most telling fact. Deadpan.\n"
    "- Mention the most absurd passwords by name.\n\n"
    "Examples:\n"
    "- \"Thirty thousand root attempts with French names as passwords, breached twice, said ok, and left.\"\n"
    "- \"18,583 root attempts, never got in \u2014 not even once.\"\n"
    "- \"13k root tries, one succeeded. Echoed \'ok\' then exited. Passwords: jetaime, slipknot1, monster1.\"\n\n"
    "Describe this attacker in one sentence:\n"
    "{profile}"
)

PROMPT_DRIVEBY = (
    "Write a brief, dismissive one-liner for a security dashboard.\n\n"
    "Rules:\n"
    "- One sentence, under 150 characters\n"
    "- No markdown, no backticks\n"
    "- Don\'t start with \"The attacker\"\n"
    "- Don\'t say \"honeypot\"\n"
    "- Be terse. These aren\'t interesting.\n\n"
    "Examples:\n"
    "- \"Ubuntu:ubuntu, in, no commands, left.\"\n"
    "- \"Tried root:12345, failed, moved on.\"\n"
    "- \"admin:admin, logged in, did nothing, and left.\"\n\n"
    "Describe this attacker in one sentence:\n"
    "{profile}"
)

PROMPT_PERSISTENT = (
    "You are a security analyst writing one-liner descriptions for a honeypot dashboard.\n"
    "Dry wit, technically precise. Focus on the persistence angle.\n\n"
    "Rules:\n"
    "- One sentence, under 200 characters\n"
    "- No markdown, no backticks\n"
    "- Don\'t start with \"The attacker\" or \"An attacker\"\n"
    "- Don\'t restate metadata\n"
    "- Don\'t say \"honeypot\"\n"
    "- Highlight the repetition or patience\n\n"
    "Examples:\n"
    "- \"18 sessions with sequential passwords (123, 1234, 12345...) \u2014 like a determined toddler with a dictionary.\"\n"
    "- \"Ran HONEYPOT_TEST_12345 across seven sessions \u2014 turns out the answer was yes.\"\n"
    "- \"153 sessions of whoami and ssh -V with passwords counting up from 123 \u2014 either testing infrastructure or deeply committed to boredom.\"\n\n"
    "Describe this attacker in one sentence:\n"
    "{profile}"
)

_CATEGORY_PROMPTS = {
    'sophisticated': PROMPT_SOPHISTICATED,
    'recon': PROMPT_RECON,
    'bomber': PROMPT_BOMBER,
    'persistent': PROMPT_PERSISTENT,
    'driveby': PROMPT_DRIVEBY,
}

RECON_KEYWORDS = {
    'uname', '/proc/cpu', '/proc/mem', 'lscpu', 'nproc', 'hostname',
    'whoami', 'id', 'free', 'df', 'uptime', '/etc/os-release',
    '/bin/./uname',
}


def _is_mostly_recon(commands):
    """Check if >60% of commands are recon-type."""
    if not commands:
        return False
    recon_count = sum(1 for cmd in commands
                      if any(kw in cmd.lower() for kw in RECON_KEYWORDS))
    return recon_count / len(commands) > 0.6


def classify_attacker(attempt_count, session_count, command_count, unique_commands,
                      has_ssh_key, has_payload, interestingness_score):
    """Classify attacker into routing category.
    Returns: 'sophisticated', 'recon', 'bomber', 'persistent', 'driveby'"""
    if has_ssh_key or has_payload:
        return 'sophisticated'
    if interestingness_score > 20:
        return 'sophisticated'
    if command_count > 0 and _is_mostly_recon(unique_commands):
        return 'recon'
    if attempt_count > 1000 and command_count < 3:
        return 'bomber'
    if session_count > 5 and attempt_count < 5000:
        return 'persistent'
    if attempt_count < 100 and session_count <= 2:
        return 'driveby'
    return 'bomber'


def _category_fallback(category, profile_data):
    """Category-appropriate fallback when LLM fails."""
    if category == 'sophisticated':
        actions = profile_data.get('key_actions', 'recon and exploitation')
        return "Gained access and ran %s \u2014 hands-on-keyboard operator." % actions
    elif category == 'recon':
        logins = profile_data.get('login_count', 'multiple')
        return "Logged in %s times, ran the same fingerprinting commands, left." % logins
    elif category == 'bomber':
        count = profile_data.get('attempt_count', 'thousands of')
        passwords = profile_data.get('notable_passwords', '')
        if passwords:
            return "%s login attempts with passwords like %s \u2014 never got anywhere." % (count, passwords)
        return "%s login attempts, brute-forcing with a dictionary \u2014 no luck." % count
    elif category == 'persistent':
        sessions = profile_data.get('session_count', 'multiple')
        return "Kept coming back across %s sessions \u2014 persistence without payoff." % sessions
    elif category == 'driveby':
        cred = profile_data.get('top_cred', 'default creds')
        got_in = profile_data.get('got_in', False)
        if got_in:
            return "%s, in, nothing, gone." % cred
        return "Tried %s, failed, moved on." % cred
    return "Attempted access without notable activity."


_FALLBACK_PATTERNS = [
    re.compile(p) for p in (
        r"— hands-on-keyboard operator\.$",
        r"^Logged in \S+ times, ran the same fingerprinting commands, left\.$",
        r" login attempts with passwords like .* — never got anywhere\.$",
        r" login attempts, brute-forcing with a dictionary — no luck\.$",
        r"^Kept coming back across \S+ sessions — persistence without payoff\.$",
        r", in, nothing, gone\.$",
        r"^Attempted access without notable activity\.$",
    )
]


def _looks_like_fallback(text):
    """True for text produced by _category_fallback (not by the LLM)."""
    return any(p.search(text) for p in _FALLBACK_PATTERNS)


def _llm_usable():
    """Whether an LLM call could succeed right now. During main()'s first,
    LLM-off pass this records that the LLM pass is needed."""
    global _llm_pending
    if not LLM_ENABLED:
        _llm_pending += 1
        return False
    return bool(_check_ollama_once())


def build_profile_text(ip, attempt_count, ip_sessions, all_cmds, creds):
    """Build natural-language profile summary for the LLM prompt.
    Curated to give the model the right material for each category."""
    login_count = len(ip_sessions)
    parts = ["%d attempts" % attempt_count]
    if login_count > 0:
        parts.append("%d login%s" % (login_count, 's' if login_count != 1 else ''))
    profile = ", ".join(parts) + ". "

    if all_cmds:
        unique = list(dict.fromkeys(all_cmds))
        cmd_samples = [cmd[:120] for cmd in unique[:8]]
        profile += "Commands: " + " | ".join(cmd_samples) + ". "

        cmd_str = " ".join(all_cmds).lower()
        if "authorized_keys" in cmd_str or "ssh-keygen" in cmd_str:
            profile += "SSH key injection detected. "
        if "chattr" in cmd_str:
            profile += "Used chattr for file locking. "
        if "mdrfckr" in cmd_str:
            profile += "Injected mdrfckr SSH key. "
        if re.search(r'passwd\b', cmd_str):
            profile += "Changed root password. "
        if "wget" in cmd_str or "curl" in cmd_str:
            profile += "Downloaded remote payload. "
        if re.search(r'chmod\s+(777|\+x)', cmd_str):
            profile += "Made files executable. "
        if "hosts.deny" in cmd_str:
            profile += "Cleared hosts.deny. "
        if any(x in cmd_str for x in ["xmrig", "minerd", "cpuminer"]):
            profile += "Deployed cryptominer. "
    elif login_count > 0:
        profile += "Got in but ran no commands. "

    # Notable passwords
    if creds:
        unique_creds = list(set(creds))
        exotic = [c for c in unique_creds if c not in BORING_CREDS]
        if exotic:
            passwords = []
            for c in exotic[:5]:
                sep = ":" if ":" in c else "/"
                passwords.append(c.split(sep)[-1])
            if passwords:
                profile += "Notable passwords: " + ", ".join(passwords) + ". "

        pw_list = []
        for c in creds[:20]:
            sep = ":" if ":" in c else "/"
            pw_list.append(c.split(sep)[-1])
        seq = [p for p in pw_list if p in ("123", "1234", "12345", "123456", "1234567", "12345678")]
        if len(seq) >= 3:
            profile += "Sequential passwords (123, 1234, 12345...). "

        cred_str_lower = " ".join(creds).lower()
        if any(w in cred_str_lower for w in ["solana", "validator", "raydium", "firedancer", "snarkos"]):
            profile += "Using crypto/Solana credentials. "

    if all_cmds and len(set(all_cmds)) == 1 and "echo" in all_cmds[0].lower():
        profile += "Only command: echo ok. "

    return profile.strip()


# Paths & endpoints — overridable via env for containerized deploys. The
# defaults preserve the original on-host behavior exactly (data files alongside
# the script, Cowrie logs at their fixed path, Ollama on localhost).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("HONEYPOT_DATA_DIR", SCRIPT_DIR)
LOG_PATH = os.environ.get("COWRIE_LOG_PATH", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
os.makedirs(DATA_DIR, exist_ok=True)
CACHE_PATH = os.path.join(DATA_DIR, "geoip_cache.json")
OUTPUT_PATH = os.path.join(DATA_DIR, "dashboard.html")
CACHE_FILE = os.path.join(DATA_DIR, "description_cache.json")

# Max attacker IPs plotted on the map. The map filters per-day client-side, so
# this only bounds page size; set well above the ~5–6k unique IPs in a 60-day
# window so recent days (newer, lower-volume IPs) aren't dropped off the map.
MAX_MAP_MARKERS = int(os.environ.get("MAX_MAP_MARKERS", "10000"))

# The bulk page data (map markers, hourly timeline, the bulk of the "Successful
# Logins" terminal) is written to a separate JSON file beside dashboard.html and
# fetched by the page, instead of being inlined. serve.py serves it (gzipped,
# with an ETag), so the 30s auto-refresh mostly revalidates it with a 304.
DATA_FILENAME = "dashboard-data.json"
DATA_OUTPUT_PATH = os.path.join(DATA_DIR, DATA_FILENAME)

# Attacker groups in the "Successful Logins" terminal rendered into the HTML up
# front; the panel is a 400px scroll box, so this comfortably over-fills it. The
# remaining groups ship (pre-rendered) in the data file and are appended as the
# panel is scrolled toward the bottom.
TERMINAL_INITIAL_GROUPS = int(os.environ.get("TERMINAL_INITIAL_GROUPS", "30"))

# Map marker coordinates are rounded to this many decimals in the data file
# (5 decimals ~ 1 m; markers are drawn with a >= 6px radius).
MARKER_COORD_DECIMALS = 5


def atomic_json_write(filepath, data, indent=2):
    """Write JSON atomically using temp file + os.rename (H3 fix)."""
    dirpath = os.path.dirname(filepath)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dirpath, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent)
        os.rename(tmp_path, filepath)
    except Exception as e:
        print(f"[!] Atomic write failed for {filepath}: {e}")
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return False
    return True


def annotate_command(cmd):
    """Layer 1: Dictionary lookup for command annotations. Returns short technical note or None."""
    cmd_stripped = cmd.strip()
    cmd_lower = cmd_stripped.lower()
    
    # Exact/prefix matches first
    annotations = {
        "uname -a": "OS/kernel identification",
        "uname": "OS identification",
        "cat /etc/passwd": "user enumeration",
        "cat /etc/shadow": "password hash extraction",
        "cat /proc/cpuinfo": "CPU profiling",
        "cat /proc/meminfo": "memory profiling",
        "cat /proc/version": "kernel version check",
        "free -m": "RAM check",
        "free -h": "RAM check",
        "free": "RAM check",
        "df -h": "disk space check",
        "df": "disk space check",
        "lscpu": "CPU architecture scan",
        "nproc": "core count check",
        "dmidecode": "hardware inventory",
        "lspci": "PCI device enumeration",
        "lsblk": "block device enumeration",
        "lsusb": "USB device scan",
        "ifconfig": "network mapping",
        "ip addr": "network mapping",
        "ip a": "network mapping",
        "ip route": "routing table check",
        "hostname": "hostname discovery",
        "hostname -I": "IP address discovery",
        "whoami": "privilege check",
        "id": "privilege check",
        "w": "logged-in users check",
        "who": "logged-in users check",
        "last": "login history check",
        "uptime": "uptime check",
        "ps aux": "process enumeration",
        "ps -ef": "process enumeration",
        "top": "process monitoring",
        "netstat -tulpn": "open ports scan",
        "ss -tulpn": "open ports scan",
        "mount": "mounted filesystem check",
        "dmesg": "kernel message dump",
        "env": "environment variable dump",
        "printenv": "environment variable dump",
        "history": "history snooping",
        "cat ~/.bash_history": "history snooping",
        "cat /root/.bash_history": "history snooping",
    }
    
    if cmd_lower in annotations:
        return annotations[cmd_lower]
    
    patterns = [
        (r'export\s+HISTFILE\s*=\s*/dev/null', "anti-forensics: disable history"),
        (r'unset\s+HISTFILE', "anti-forensics: disable history"),
        (r'export\s+HISTSIZE\s*=\s*0', "anti-forensics: disable history"),
        (r'HISTORY.*=/dev/null', "anti-forensics: disable history"),
        (r'/bin/\./\w+', "obfuscated system check"),
        (r'cat\s+/etc/passwd', "user enumeration"),
        (r'cat\s+/etc/shadow', "password hash extraction"),
        (r'cat\s+/proc/cpuinfo', "CPU profiling"),
        (r'wget\s+https?://', "payload download from C2"),
        (r'curl\s+https?://', "payload download"),
        (r'curl\s+-[sOo]', "payload download"),
        (r'tftp\s+', "payload download via TFTP"),
        (r'chmod\s+\+x', "make executable"),
        (r'chmod\s+[0-7]*7[0-7]*\s+', "make executable (world)"),
        (r'^\.\/', "execute payload"),
        (r'/tmp/\w+', "execute from /tmp"),
        (r'crontab', "persistence setup"),
        (r'/etc/cron', "persistence setup"),
        (r'iptables', "firewall tampering"),
        (r'ufw\s+', "firewall tampering"),
        (r'systemctl', "service manipulation"),
        (r'service\s+', "service manipulation"),
        (r'rm\s+-rf\s+/', "destructive wipe attempt"),
        (r'rm\s+.*\.log', "log cleanup"),
        (r'pkill|killall|kill\s+-9', "process termination"),
        (r'useradd|adduser', "create backdoor account"),
        (r'passwd\s+', "password change attempt"),
        (r'ssh-keygen|authorized_keys', "SSH key persistence"),
        (r'nc\s+-[le]|ncat|netcat', "reverse shell / listener"),
        (r'/dev/tcp/', "bash reverse shell"),
        (r'base64\s+-d|base64\s+--decode', "decode obfuscated payload"),
        (r'python.*-c.*import', "Python one-liner execution"),
        (r'perl\s+-e', "Perl one-liner execution"),
        (r'xmrig|minerd|ccminer|cpuminer', "cryptominer deployment"),
        (r'\.bash_history', "history snooping"),
        (r'history', "history snooping"),
        (r'dd\s+if=', "disk operation"),
        (r'echo\s+.*>\s*/etc/', "system file modification"),
        (r'echo\s+.*>>\s*/etc/', "system file append"),
        (r'apt\s+install|yum\s+install|pip\s+install', "package installation"),
        (r'docker\s+', "container manipulation"),
        (r'chattr\s+', "file attribute tampering"),
    ]
    
    for pattern, note in patterns:
        if re.search(pattern, cmd_lower):
            return note
    
    return None

# The only event types the dashboard reads. Cowrie logs ~6 events per session
# (version, kex, closed, ...); skipping the rest before json.loads roughly
# halves parse time. A line is only skipped when none of these byte strings
# appear anywhere in it, so the eventid check after parsing still decides.
RELEVANT_EVENT_MARKERS = (b"cowrie.session.connect", b"cowrie.login.",
                          b"cowrie.command.input", b"cowrie.session.file_")


def iter_log(path, relevant_only=False):
    """Yield events from a Cowrie JSON log, skipping malformed lines. Handles
    .gz files (detected by magic bytes, not extension)."""
    if not os.path.exists(path):
        print(f"[!] Log file not found: {path}")
        return
    is_gzip = False
    try:
        with open(path, "rb") as f:
            is_gzip = f.read(2) == b'\x1f\x8b'
    except Exception:
        pass
    opener = gzip.open if is_gzip else open
    loads = json.loads
    markers = RELEVANT_EVENT_MARKERS
    bad = 0
    try:
        with opener(path, "rb") as f:
            for line in f:
                if relevant_only and not any(m in line for m in markers):
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    event = loads(line)
                except ValueError:  # JSONDecodeError, or undecodable bytes
                    bad += 1
                    continue
                if isinstance(event, dict):
                    yield event
    except Exception as e:
        print(f"[!] Error reading {path}: {e}")
    if bad:
        print(f"[!] Skipped {bad} malformed JSON line(s) in {path}")


def parse_log(path):
    """Parse a whole Cowrie JSON log into a list of events."""
    return list(iter_log(path))


def load_geo_cache():
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                cache = json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
        # Prune entries older than 30 days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        pruned = {}
        for k, v in cache.items():
            if isinstance(v, dict) and "_cached_at" in v:
                if v["_cached_at"] > cutoff:
                    pruned[k] = v
            else:
                pruned[k] = v
        if len(pruned) < len(cache):
            print(f"[*] Pruned {len(cache) - len(pruned)} stale geoip cache entries")
        return pruned
    return {}


def save_geo_cache(cache):
    """Save geo cache atomically (H3 fix)."""
    now = datetime.now(timezone.utc).isoformat()
    for k, v in cache.items():
        if isinstance(v, dict) and "_cached_at" not in v:
            v["_cached_at"] = now
    atomic_json_write(CACHE_PATH, cache)


def batch_geoip_lookup(ips, cache):
    """Lookup IPs via ip-api.com batch endpoint (max 100 per request)."""
    to_lookup = [ip for ip in ips if ip not in cache or (isinstance(cache.get(ip), dict) and cache[ip].get("country") == "Unknown")]
    if not to_lookup:
        return cache

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
        if i + 100 < len(to_lookup):
            time.sleep(1)

    save_geo_cache(cache)
    return cache


def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return "\U0001f3f4"
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))


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
    "VN": ["pho", "lotus", "mekong", "bamboo", "dragonfruit"],
    "ID": ["komodo", "batik", "rendang", "volcano", "garuda"],
    "TR": ["sultan", "bazaar", "kebab", "bosphorus", "anatolia"],
    "IR": ["saffron", "persia", "cyrus", "rosewater", "pistachio"],
    "UA": ["cossack", "sunflower", "steppe", "trident", "varenyk"],
    "PL": ["pierogi", "bison", "amber", "falcon", "zubr"],
    "RO": ["dracula", "carpath", "mamaliga", "danube", "lynx"],
    "ES": ["flamenco", "siesta", "paella", "matador", "rioja"],
    "IT": ["pasta", "vespa", "espresso", "gondola", "ciao"],
    "MX": ["taco", "lucha", "agave", "cactus", "mariachi"],
    "AR": ["tango", "pampas", "gaucho", "mate", "asado"],
    "ZA": ["springbok", "savanna", "braai", "kudu", "rooibos"],
    "EG": ["sphinx", "nile", "pharaoh", "scarab", "papyrus"],
    "SG": ["merlion", "orchid", "kopi", "durian", "hawker"],
    "TH": ["padthai", "elephant", "muay", "mango", "tuktuk"],
    "PH": ["jeepney", "adobo", "tarsier", "bayan", "halohalo"],
    "TW": ["boba", "taipei", "oolong", "ximen", "betel"],
    "HK": ["dimsum", "harbor", "junk", "neon", "peak"],
    "AE": ["dune", "falcon", "oasis", "souk", "dhow"],
    "SA": ["oryx", "date", "oasis", "najd", "frankincense"],
    "NG": ["jollof", "afrobeat", "naija", "delta", "nok"],
    "PK": ["indus", "markhor", "minar", "truck", "chinar"],
    "BD": ["delta", "jute", "rickshaw", "ilish", "sundarban"],
    "VE": ["arepa", "orinoco", "angel", "llanero", "harpy"],
}
DEFAULT_FLAVORS = ["ghost", "shadow", "phantom", "specter", "wraith", "cipher",
                   "rogue", "nomad", "drifter", "void", "echo", "static", "husk"]

# Adjective pool — paired with a country-flavored noun so nicknames draw from a
# large, characterful namespace (far fewer collisions than the old single word).
NICKNAME_ADJECTIVES = [
    "rusty", "silent", "feral", "grumpy", "sneaky", "brazen", "weary", "manic",
    "stoic", "jittery", "crimson", "obsidian", "vapor", "glitchy", "midnight",
    "rabid", "listless", "clandestine", "baroque", "derelict", "frantic", "sullen",
    "arctic", "molten", "spectral", "unhinged", "velvet", "ashen", "wired", "rogue",
    "cryptic", "drowsy", "savage", "placid", "gnarled", "hollow", "brisk", "murky",
    "zealous", "aloof", "lurking", "restless", "venomous", "wily", "scrappy",
    "ironclad", "nocturnal", "haywire",
]

BORING_CREDS = {
    "root:root", "admin:admin", "admin:password", "admin:123456", "root:123456",
    "user:user", "test:test", "admin:admin123", "root:password", "admin:1234",
    "root:1234", "root:admin", "guest:guest", "admin:12345", "root:12345",
    "root:toor", "admin:admin1", "root:root123", "admin:default", "root:default",
    "ubuntu:ubuntu", "user:password", "test:123456", "admin:1q2w3e4r", "root:1q2w3e4r",
    "support:support", "user:123456", "pi:raspberry", "admin:pass", "root:pass",
    "admin:123", "root:123", "test:test123", "root:1234567890", "admin:1234567890",
}

_nickname_cache = {}
_nickname_counter = Counter()
# ip -> (kind, raw value) explaining where the nickname's signature came from,
# e.g. ("password", "jetaime") or ("command", "wget http://x/bins.sh").
_nickname_source = {}


def _ip_hash(ip):
    """Stable per-IP hash. Uses md5 rather than the builtin hash() (which is
    salted per process), so an attacker keeps the same nickname across runs."""
    return int(hashlib.md5(ip.encode("utf-8")).hexdigest(), 16)


# --- Nickname signatures ------------------------------------------------------
# A nickname is <country-noun>_<signature>, where the signature is the most
# distinctive thing the attacker did: a known malware/IOC marker, the payload
# they downloaded, an unusual program or echo marker they ran, or failing all
# that the rarest password they tried. Attackers with nothing distinctive get
# <adjective>_<noun>. (The old scheme appended _root/_sol to ~95% of names.)

# Substrings that identify a known toolkit/botnet; checked against commands.
IOC_KEYWORDS = [
    "mdrfckr", "xmrig", "kinsing", "kdevtmpfsi", "c3pool", "supportxmr", "nanopool",
    "redtail", "mirai", "gafgyt", "tsunami", "dota", "perlbot", "kaiten", "muhstik",
    "sysrv", "outlaw", "teamtnt", "watchdogs", "rondodox",
]

# Programs every bot runs — never distinctive enough to name someone after.
GENERIC_PROGRAMS = {
    "uname", "cat", "echo", "cd", "ls", "whoami", "id", "free", "df", "nproc", "lscpu",
    "ps", "top", "w", "who", "uptime", "hostname", "export", "unset", "history", "grep",
    "head", "tail", "awk", "sed", "sh", "bash", "env", "ifconfig", "ip", "netstat",
    "mount", "wc", "rm", "chmod", "chown", "mkdir", "cp", "mv", "touch", "pwd", "exit",
    "logout", "sleep", "printf", "test", "true", "false", "set", "sudo", "su", "which",
    "type", "command", "crontab", "kill", "pkill", "killall", "lspci", "lsblk", "ss",
    "last", "dmesg", "printenv", "passwd", "tr", "cut", "sort", "uniq", "xargs", "find",
    "wget", "curl", "tftp", "ftpget", "nohup", "enable", "system", "shell", "linuxshell",
    "busybox", "if", "then", "else", "fi", "for", "do", "done", "while", "chattr",
    "lsattr", "ulimit", "dd", "base64", "perl", "python", "python3", "nc", "scp", "ssh",
    "tar", "gzip", "unzip", "apt", "yum", "systemctl", "service", "openssl", "md5sum",
    "sha256sum", "stat", "file", "readlink", "basename", "dirname", "date", "locale",
    "getconf", "arch", "lsb_release", "dmidecode", "screen", "tmux", "init", "reboot",
}

# Passwords/usernames too common to be anyone's signature.
COMMON_PASSWORDS = {
    "root", "admin", "password", "passwd", "pass", "test", "user", "guest", "ubuntu",
    "debian", "centos", "oracle", "postgres", "mysql", "default", "changeme", "toor",
    "raspberry", "admin123", "root123", "password1", "password123", "qwerty", "qwerty123",
    "abc123", "abcd1234", "1q2w3e4r", "1qaz2wsx", "qwe123", "letmein", "welcome",
    "master", "secret", "support", "service", "system", "server", "linux", "login",
    "administrator", "p@ssw0rd", "passw0rd", "pssw0rd", "adminadmin", "rootroot",
    "testtest", "test123", "user123", "1234qwer", "qwer1234", "asdf", "asdfgh",
    "zxcvbn", "iloveyou", "monkey", "dragon", "sunshine", "princess", "football",
    "baseball", "superman", "shadow", "michael", "solana", "validator", "sol",
    "git", "ftp", "www", "web", "dev", "deploy", "pi", "hadoop", "nagios", "tomcat",
    "jenkins", "minecraft", "steam", "docker", "ansible", "vagrant", "elastic",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s;|&'\"`)]+", re.I)
_PROG_RE = re.compile(r"^[a-z][a-z0-9._-]{1,24}$")
_ECHO_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{3,30}$")


# The page is public; attacker passwords are often crude. Never name anyone this.
_BLOCKED_SIG_PARTS = ("fuck", "shit", "cunt", "nigg", "fag", "bitch", "whore", "rape",
                      "dick", "cock", "pussy", "slut", "porn", "nazi", "hitler", "kill")


def _slug(value, maxlen=12):
    """Lowercase [a-z0-9] slug for use in a nickname, or None if unusable."""
    s = _SLUG_RE.sub("", (value or "").lower())
    if any(w in s for w in _BLOCKED_SIG_PARTS):
        return None
    s = s[:maxlen]
    if len(s) < 3 or s.isdigit():
        return None
    return s


def _command_signature(cmds):
    """(slug, source command) for the most distinctive thing in a command list."""
    lowered = [c.lower() for c in cmds]
    for kw in IOC_KEYWORDS:
        for raw, low in zip(cmds, lowered):
            if kw in low:
                return kw, raw
    for raw in cmds:
        for url in _URL_RE.findall(raw):
            name = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            name = re.sub(r"\.(sh|bin|py|pl|elf|tar|gz|tgz|zip|txt)$", "", name, flags=re.I)
            if "." in name or ":" in name:   # bare host/IP, not a file
                continue
            s = _slug(name)
            if s:
                return s, raw
    for raw in cmds:
        for part in re.split(r"[;&|\n]+", raw):
            words = part.strip().split()
            if not words:
                continue
            prog = words[0].rsplit("/", 1)[-1].lower()
            if prog == "echo" and len(words) > 1:
                arg = words[-1].strip("'\"")
                s = _slug(arg) if _ECHO_WORD_RE.match(arg) and arg.lower() not in ("ok", "test", "hello") else None
                if s:
                    return s, raw
            elif _PROG_RE.match(prog) and prog not in GENERIC_PROGRAMS:
                s = _slug(prog)
                if s and s not in COMMON_PASSWORDS:
                    return s, raw
    return None, None


def _credential_signature(creds, password_ips):
    """(slug, kind, raw) for the rarest unusual password an IP tried (ties go to
    the earliest tried), else an unusual username. password_ips maps slug ->
    number of IPs that tried it; counts are bucketed (log2) so a name doesn't
    flip every time another bot tries the same word."""
    best = None
    for order, (u, p) in enumerate(creds[:200]):
        s = _slug(p)
        if not s or len(s) < 4 or s in COMMON_PASSWORDS or p.lower() == u.lower():
            continue
        rank = (password_ips.get(s, 1).bit_length(), order)
        if best is None or rank < best[0]:
            best = (rank, s, p)
    if best:
        return best[1], "password", best[2]
    for u, _p in creds[:200]:
        s = _slug(u)
        if s and s not in COMMON_PASSWORDS:
            return s, "username", u
    return None, None, None


def _nickname_parts(ip, geo):
    cc = (geo or {}).get("countryCode", "").upper()
    nouns = COUNTRY_FLAVORS.get(cc, DEFAULT_FLAVORS)
    hv = _ip_hash(ip)
    return NICKNAME_ADJECTIVES[(hv >> 16) % len(NICKNAME_ADJECTIVES)], nouns[hv % len(nouns)], hv


def _claim_nickname(ip, adj, noun, hv, sig):
    """Pick the first free name among increasingly specific candidates. IPs are
    claimed oldest-first, so a newcomer never renames an established attacker."""
    tail = ip.split(":")[-1].split(".")[-1] or str(hv % 1000)
    if sig:
        candidates = [f"{noun}_{sig}", f"{adj}_{noun}_{sig}", f"{adj}_{noun}_{sig}_{tail}"]
    else:
        candidates = [f"{adj}_{noun}", f"{adj}_{noun}_{tail}"]
    for name in candidates:
        if _nickname_counter[name] == 0:
            break
    else:
        name = f"{candidates[-1]}_{hv % 10007}"
    _nickname_counter[name] += 1
    _nickname_cache[ip] = name
    return name


def assign_nicknames(ip_order, geo_cache, ip_creds_raw, ip_cmds):
    """Name every IP in one deterministic pass (ip_order: oldest first).

    ip_creds_raw: ip -> [(username, password), ...] unique, in first-tried order.
    ip_cmds: ip -> [command, ...] run after a successful login, in order.
    """
    password_ips = Counter()
    for creds in ip_creds_raw.values():
        password_ips.update({s for _u, p in creds[:200] if (s := _slug(p))})
    for ip in ip_order:
        if ip in _nickname_cache:
            continue
        sig, source = _command_signature(ip_cmds.get(ip, ()))
        if sig:
            _nickname_source[ip] = ("command", source)
        else:
            sig, kind, raw = _credential_signature(ip_creds_raw.get(ip, ()), password_ips)
            if sig:
                _nickname_source[ip] = (kind, raw)
        adj, noun, hv = _nickname_parts(ip, geo_cache.get(ip, {}))
        _claim_nickname(ip, adj, noun, hv, sig)


def generate_nickname(ip, geo, creds_tried=None):
    """The IP's nickname (see assign_nicknames). An IP that wasn't part of the
    batch assignment is named on the spot from its credentials (a list of
    "user:pass" strings)."""
    if ip in _nickname_cache:
        return _nickname_cache[ip]
    pairs = [tuple(c.split(":", 1)) if ":" in c else (c, "") for c in (creds_tried or [])]
    sig, kind, raw = _credential_signature(pairs, {})
    if sig:
        _nickname_source[ip] = (kind, raw)
    adj, noun, hv = _nickname_parts(ip, geo)
    return _claim_nickname(ip, adj, noun, hv, sig)


def nickname_source_text(ip):
    """Human-readable 'why this name' line, raw (escape before rendering)."""
    kind, raw = _nickname_source.get(ip, (None, None))
    if not kind:
        return ""
    raw = raw if len(raw) <= 80 else raw[:77] + "..."
    return f"{kind}: {raw}"


def load_cache():
    """Load description cache. Good descriptions are permanent — no expiry."""
    try:
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return {}
    return cache

def _cache_get(cache, key):
    """Get value from cache, handling both old (string) and new (dict with text) formats."""
    v = cache.get(key)
    if v is None:
        return None
    if isinstance(v, dict):
        text = v.get("text", v.get("story", ""))
    else:
        text = v
    # Always strip markdown from cached values on read
    return strip_markdown(text) if text else text

def save_cache(cache):
    """Save description cache atomically (H3 fix)."""
    now = datetime.now(timezone.utc).isoformat()
    out = {}
    for k, v in cache.items():
        if isinstance(v, str):
            out[k] = {"text": v, "_cached_at": now}
        elif isinstance(v, dict) and "_cached_at" not in v:
            v["_cached_at"] = now
            out[k] = v
        else:
            out[k] = v
    atomic_json_write(CACHE_FILE, out)


# --- Timestamps ---------------------------------------------------------------
# Every event needs its local day, hourly bucket and hour. New York's UTC offset
# is always a whole number of hours, so all of that is a function of the UTC
# hour: parse each distinct "YYYY-MM-DDTHH" once instead of every event.
_hour_info_cache = {}


def _ts_info(ts):
    """(day_key, timeline_bucket, local_hour) for a Cowrie timestamp, or None."""
    if not ts:
        return None
    if len(ts) >= 20 and ts[-1] == "Z" and ts[10] == "T":
        key = ts[:13]
        info = _hour_info_cache.get(key)
        if info is None:
            try:
                dt = datetime.strptime(key, "%Y-%m-%dT%H").replace(tzinfo=timezone.utc)
                datetime.fromisoformat(ts[:-1])  # validate the rest of the string
            except (ValueError, TypeError):
                return None
            info = _local_hour_info(dt)
            _hour_info_cache[key] = info
        return info
    try:  # non-UTC offset or unusual format: slow path
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return _local_hour_info(dt)


def _local_hour_info(dt):
    lt = dt.astimezone(LOCAL_TZ)
    return (lt.strftime("%Y-%m-%d"), lt.strftime("%Y-%m-%d %H:00 ") + lt.strftime("%Z"), lt.hour)


def _utc_key(dt):
    """Sortable string matching the first 19 chars of a Cowrie 'Z' timestamp."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def analyze_events(events, geo_cache, now=None, geo_lookup=None):
    """Extract all stats from parsed events, in a single streaming pass (events
    may be any iterable, e.g. a generator over the log files).

    geo_lookup(ips, cache) -> cache, if given, runs after the pass with every IP
    seen, so GeoIP enrichment needs no second read of the logs."""
    now_local = (now or datetime.now(timezone.utc)).astimezone(LOCAL_TZ)
    cutoff_24h = _utc_key(now_local - timedelta(hours=24))
    today_est = now_local.strftime("%Y-%m-%d")

    stats = {
        "total_sessions": 0,
        "total_login_attempts": 0,
        "successful_logins": 0,
        "unique_ips": set(),
        "commands_executed": 0,
        "files_downloaded": 0,
    }
    last_24h = {"sessions": 0, "login_attempts": 0, "successful_logins": 0,
                "unique_ips": set(), "commands": 0}

    ip_attempts = Counter()
    ip_first_seen = {}
    ip_last_seen = {}
    ip_first_any = {}            # first event of any kind (nickname claim order)
    ip_creds_raw = defaultdict(dict)   # ip -> {(u, p): None}, insertion-ordered
    ip_success = set()
    cred_combos = Counter()      # (u, p) -> count
    timeline = Counter()
    # Only the last 100 feed items are ever shown; keep raw tuples, format later.
    recent_raw = deque(maxlen=100)
    successful_sessions = defaultdict(list)
    session_ips = {}
    session_success = set()
    session_creds = {}

    hourly_attempts = Counter()
    daily_sessions = Counter()
    daily_login_attempts = Counter()
    daily_successful = Counter()
    daily_ips = defaultdict(set)
    daily_commands = Counter()
    daily_ip_attempts = defaultdict(Counter)
    first_ts = None              # earliest event timestamp (for days_active)

    for e in events:
        eid = e.get("eventid", "")
        ip = e.get("src_ip", "")
        ts = e.get("timestamp", "")
        session = e.get("session", "")

        if ip:
            stats["unique_ips"].add(ip)
            if ip not in ip_first_any:
                ip_first_any[ip] = ts
        if session and ip:
            session_ips[session] = ip

        info = _ts_info(ts)
        day_key = info[0] if info else None
        if day_key and (first_ts is None or ts < first_ts):
            first_ts = ts
        recent24 = bool(ts) and ts[:19] >= cutoff_24h

        if eid == "cowrie.session.connect":
            stats["total_sessions"] += 1
            if day_key:
                daily_sessions[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)
            if recent24:
                last_24h["sessions"] += 1
                if ip:
                    last_24h["unique_ips"].add(ip)

        elif eid == "cowrie.login.failed" or eid == "cowrie.login.success":
            ok = eid == "cowrie.login.success"
            stats["total_login_attempts"] += 1
            ip_attempts[ip] += 1
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts
            u = e.get("username", "")
            p = e.get("password", "")
            pair = (u, p)
            ip_creds_raw[ip][pair] = None
            cred_combos[pair] += 1
            if ok:
                stats["successful_logins"] += 1
                session_success.add(session)
                session_creds[session] = pair
                ip_success.add(ip)
            if day_key:
                daily_login_attempts[day_key] += 1
                if ok:
                    daily_successful[day_key] += 1
                if ip:
                    daily_ips[day_key].add(ip)
                    daily_ip_attempts[day_key][ip] += 1
            if info:
                timeline[info[1]] += 1
                hourly_attempts[info[2]] += 1
            if recent24:
                last_24h["login_attempts"] += 1
                if ok:
                    last_24h["successful_logins"] += 1
                if ip:
                    last_24h["unique_ips"].add(ip)
            if ok:
                recent_raw.append((ts, ip, "success", u, p))
            elif e.get("type", "") and not p:
                recent_raw.append((ts, ip, "key", u, e.get("type", "")))
            else:
                recent_raw.append((ts, ip, "login", u, p))

        elif eid == "cowrie.command.input":
            stats["commands_executed"] += 1
            cmd = e.get("input", "")
            if session in session_success:
                successful_sessions[session].append({"ts": ts, "cmd": cmd})
            recent_raw.append((ts, ip, "cmd", cmd, None))
            if day_key:
                daily_commands[day_key] += 1
            if recent24:
                last_24h["commands"] += 1

        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            stats["files_downloaded"] += 1
            url = e.get("url", e.get("filename", "?"))
            recent_raw.append((ts, ip, "file", url, None))

    if geo_lookup:
        geo_cache = geo_lookup(stats["unique_ips"], geo_cache)
    stats["unique_ips"] = len(stats["unique_ips"])
    last_24h["unique_ips"] = len(last_24h["unique_ips"])

    # Escape each distinct credential once; everything rendered uses the
    # escaped "user:pass" form.
    _esc = {}

    def esc_combo(pair):
        s = _esc.get(pair)
        if s is None:
            s = _esc[pair] = f"{h(pair[0])}:{h(pair[1])}"
        return s

    ip_creds_pairs = {ip: list(d) for ip, d in ip_creds_raw.items()}
    ip_creds = {ip: [esc_combo(c) for c in pairs] for ip, pairs in ip_creds_pairs.items()}

    # Name everyone up front, oldest first, so names are stable run to run.
    ip_cmds = defaultdict(list)
    for sid, cmds in successful_sessions.items():
        ip_cmds[session_ips.get(sid, "?")].extend(c["cmd"] for c in cmds)
    assign_nicknames(sorted(ip_first_any, key=lambda i: (ip_first_any[i], i)),
                     geo_cache, ip_creds_pairs, ip_cmds)

    sorted_timeline = sorted(timeline.items())
    timeline_labels = [t[0] for t in sorted_timeline]
    timeline_data = [t[1] for t in sorted_timeline]

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

    top_creds = [(esc_combo(pair), n) for pair, n in cred_combos.most_common(20)]

    # Format the last 100 feed items, then group consecutive same-IP same-type.
    raw_recent = []
    for ts, ip, kind, a, b in recent_raw:
        if kind == "success":
            action = f"✅ LOGIN SUCCESS: {h(a)}/{h(b)}"
        elif kind == "key":
            action = f"🔑 Key auth: {h(a)} ({h(b)})"
        elif kind == "login":
            action = f"Login attempt: {h(a)}/{h(b)}"
        elif kind == "cmd":
            action = f"Command: {h(a)}"
        else:
            action = f"File: {h(a)}"
        raw_recent.append({"ts": ts, "ip": ip, "action": action})
    grouped_recent = []
    for ev in raw_recent:
        action_type = ev["action"].split(":")[0]
        grp_key = (ev["ip"], action_type)
        if grouped_recent and grouped_recent[-1]["_group_key"] == grp_key:
            grouped_recent[-1]["count"] += 1
            grouped_recent[-1]["last_ts"] = ev["ts"]
        else:
            grouped_recent.append({**ev, "_group_key": grp_key, "count": 1,
                                   "first_ts": ev["ts"], "last_ts": ev["ts"]})
    recent_events = grouped_recent[-20:]

    # Per-IP daily counts, built once (not a scan of every day per IP).
    ip_daily = defaultdict(dict)
    for day_k in sorted(daily_ip_attempts):
        for ip, n in daily_ip_attempts[day_k].items():
            ip_daily[ip][day_k] = n

    markers = []
    seen_ips = set()
    # Plot every geolocated attacker, not just the top-500 by total attempts.
    # That old cap biased the map toward long-lived high-volume IPs, so recent
    # weeks — dominated by newer, lower-volume attackers — rendered sparse or
    # empty. MAX_MAP_MARKERS is just a generous safety bound on page size.
    for ip, count in ip_attempts.most_common(MAX_MAP_MARKERS):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        geo = geo_cache.get(ip, {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        if lat == 0 and lon == 0:
            continue
        markers.append({
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "count": count,
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", "Unknown"),
            # First 10 distinct, in the order tried (deterministic: the old
            # list(set(...)) reshuffled every run and churned the data file).
            "creds": ip_creds.get(ip, [])[:10],
            "nickname": _nickname_cache.get(ip, ""),
            "first_seen": ip_first_seen.get(ip, ""),
            "last_seen": ip_last_seen.get(ip, ""),
            "daily_counts": ip_daily.get(ip, {}),
            "got_in": ip in ip_success,
            "named_for": nickname_source_text(ip),
        })

    for ip in sorted(set(session_ips.values())):
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

    coord_counts = Counter((round(m["lat"], 1), round(m["lon"], 1)) for m in markers)
    coord_indices = {}
    for m in markers:
        key = (round(m["lat"], 1), round(m["lon"], 1))
        total = coord_counts[key]
        if total > 1:
            idx = coord_indices.get(key, 0)
            coord_indices[key] = idx + 1
            angle = (2 * math.pi * idx) / total
            spread = 0.04 * min(total, 5)
            m["lat"] += math.sin(angle) * spread
            m["lon"] += math.cos(angle) * spread

    success_data = []
    for sid, cmds in successful_sessions.items():
        ip = session_ips.get(sid, "?")
        pair = session_creds.get(sid)
        creds = f"{h(pair[0])}/{h(pair[1])}" if pair else "unknown"
        success_data.append({"session": sid, "ip": ip, "commands": cmds, "creds": creds})
    success_data.sort(key=lambda s: s["commands"][0]["ts"] if s["commands"] else "", reverse=True)

    all_days = sorted(set(
        list(daily_sessions.keys()) + list(daily_login_attempts.keys()) +
        list(daily_commands.keys())
    ), reverse=True)

    daily_breakdown = []
    for day in all_days:
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

    today_stats = {
        "sessions": daily_sessions.get(today_est, 0),
        "login_attempts": daily_login_attempts.get(today_est, 0),
        "successful_logins": daily_successful.get(today_est, 0),
        "unique_ips": len(daily_ips.get(today_est, set())),
        "commands": daily_commands.get(today_est, 0),
    }

    first_event = None
    if first_ts:
        try:
            first_event = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    if first_event:
        days_active = max(1, (now_local - first_event).days + 1)
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

    # Compute fun all-time stats
    unique_countries = set()
    for ip_key in ip_attempts:
        geo = geo_cache.get(ip_key, {})
        cc = geo.get("country", "Unknown")
        if cc != "Unknown":
            unique_countries.add(cc)

    busiest_day = max(daily_login_attempts.items(), key=lambda x: x[1]) if daily_login_attempts else ("", 0)
    peak_hour = max(hourly_attempts.items(), key=lambda x: x[1])[0] if hourly_attempts else 0
    peak_hour_str = f"{peak_hour:02d}:00–{(peak_hour+1)%24:02d}:00"

    # Compute peak day for each metric
    def _peak(daily_counter):
        if not daily_counter:
            return (0, "—")
        day, val = max(daily_counter.items(), key=lambda x: x[1])
        try:
            dt = datetime.strptime(day, "%Y-%m-%d")
            short = dt.strftime("%b %-d")
        except (ValueError, AttributeError):
            short = day[5:]
        return (val, short)

    peak_sessions = _peak(daily_sessions)
    peak_logins = _peak(daily_login_attempts)
    peak_successful = _peak(daily_successful)
    peak_commands = _peak(daily_commands)
    # Peak unique IPs per day
    daily_unique_ip_counts = {day: len(ips) for day, ips in daily_ips.items()}
    peak_ips = _peak(daily_unique_ip_counts)

    # Peak daily success rate
    daily_success_rates = {}
    for day in daily_login_attempts:
        attempts = daily_login_attempts[day]
        if attempts > 0:
            rate = daily_successful.get(day, 0) / attempts * 100
            daily_success_rates[day] = round(rate, 1)
    if daily_success_rates:
        peak_sr_day = max(daily_success_rates, key=daily_success_rates.get)
        peak_sr_val = daily_success_rates[peak_sr_day]
        try:
            dt = datetime.strptime(peak_sr_day, "%Y-%m-%d")
            peak_sr_short = dt.strftime("%b %-d")
        except (ValueError, AttributeError):
            peak_sr_short = peak_sr_day[5:]
        peak_success_rate = (peak_sr_val, peak_sr_short)
    else:
        peak_success_rate = (0, "—")

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
        "data_today": today_est,
        "recent_events": recent_events,
        "markers": markers,
        "successful_sessions": success_data,
        "geo_cache": geo_cache,
        "ip_creds": ip_creds,
        "ip_first_seen": ip_first_seen,
        "ip_last_seen": ip_last_seen,
        "unique_countries": len(unique_countries),
        "busiest_day": busiest_day,
        "peak_hour": peak_hour_str,
        "last_24h": last_24h,
        "peak_sessions": peak_sessions,
        "peak_logins": peak_logins,
        "peak_successful": peak_successful,
        "peak_commands": peak_commands,
        "peak_ips": peak_ips,
        "peak_success_rate": peak_success_rate,
        "generated": now_local.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "generated_epoch": int(now_local.timestamp()),
    }


def ollama_healthy():
    """Quick check if Ollama is responding."""
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags", method="GET")
        resp = urllib.request.urlopen(req, timeout=2)
        return resp.status == 200
    except Exception:
        return False


_ollama_is_healthy = None

def _check_ollama_once():
    global _ollama_is_healthy
    if _ollama_is_healthy is None:
        _ollama_is_healthy = ollama_healthy()
        if not _ollama_is_healthy:
            print("[!] Ollama not responding, skipping LLM descriptions this run")
    return _ollama_is_healthy


# main() renders twice: first with the LLM off (cached descriptions + instant
# template fallbacks) so a fresh page is written within seconds, then — only if
# something actually needed the LLM — again with it on. CPU inference can take
# minutes; it should never hold the dashboard back.
LLM_ENABLED = True
_llm_pending = 0


def llm_generate(prompt, model="qwen3.5:9b", temperature=0.5, max_tokens=30):
    """Call Ollama to generate text using raw mode. Falls back to empty string on failure."""
    global _llm_pending
    if not LLM_ENABLED:
        _llm_pending += 1
        return ""
    if not _check_ollama_once():
        return ""
    try:
        payload = json.dumps({"model": model, "prompt": prompt, "stream": False, "think": False, "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": 512, "stop": ["\n"]}}).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=300)  # 5min for CPU inference
        return json.loads(resp.read()).get("response", "").strip()
    except Exception as e:
        print(f"[!] LLM generation failed: {e}")
        return ""


def compute_interestingness(ip, attempt_count, data):
    """Score an attacker's interestingness for greatest hits ranking.
    Prioritizes command diversity and sophistication over raw volume."""
    score = 0.0

    # Base score from attempts (log scale, diminishing returns)
    score += min(math.log2(max(attempt_count, 1) + 1) * 2, 15)

    # Find sessions for this IP
    ip_sessions = [s for s in data.get("successful_sessions", []) if s["ip"] == ip]
    all_cmds = []
    for s in ip_sessions:
        all_cmds.extend([c["cmd"] for c in s["commands"]])

    # Big bonus for having commands at all
    if all_cmds:
        score += 20

    # Bonus for command count and diversity
    unique_cmds = set(all_cmds)
    score += min(len(unique_cmds) * 3, 30)
    score += min(len(all_cmds) * 0.5, 10)

    # Bonus for multiple sessions
    if len(ip_sessions) > 1:
        score += min(len(ip_sessions) * 2, 10)

    # Bonus for sophisticated attack patterns
    cmd_str = " ".join(all_cmds).lower()
    sophisticated_patterns = [
        ("authorized_keys", 15, "SSH key injection"),
        ("ssh-keygen", 12, "SSH key generation"),
        ("chattr", 10, "file attribute tampering"),
        ("crontab", 10, "persistence via cron"),
        ("/etc/cron", 10, "persistence via cron"),
        ("wget", 8, "payload download"),
        ("curl", 8, "payload download"),
        ("base64", 10, "obfuscated payload"),
        ("nc -", 12, "reverse shell"),
        ("/dev/tcp/", 12, "bash reverse shell"),
        ("iptables", 8, "firewall tampering"),
        ("useradd", 10, "backdoor account"),
        ("xmrig", 10, "cryptominer"),
        ("docker", 8, "container manipulation"),
        ("dmidecode", 5, "hardware profiling"),
        ("lspci", 5, "hardware profiling"),
    ]
    for pattern, bonus, _ in sophisticated_patterns:
        if pattern in cmd_str:
            score += bonus

    # Penalty for generic-only credentials
    creds = data.get("ip_creds", {}).get(ip, [])
    if creds and not all_cmds:
        boring_count = sum(1 for c in creds if c in BORING_CREDS)
        if boring_count == len(creds):
            score -= 5  # All boring creds, no commands = not interesting

    return score


def generate_greatest_hits(data, desc_cache=None):
    """Generate attacker stories using prompt routing system.
    Each attacker is classified and gets a category-specific prompt.
    H1/H3 fix: accepts shared desc_cache from caller; if None, loads own copy."""
    hits = []
    geo_cache = data.get("geo_cache", {})
    ip_creds = data.get("ip_creds", {})
    _owns_cache = desc_cache is None
    if _owns_cache:
        desc_cache = load_cache()

    scored_attackers = []
    for attacker in data["top_attackers"]:
        score = compute_interestingness(attacker["ip"], attacker["count"], data)
        scored_attackers.append((score, attacker))
    scored_attackers.sort(key=lambda x: x[0], reverse=True)
    ranked_attackers = [a for _, a in scored_attackers[:6]]

    for attacker in ranked_attackers:
        nick = attacker["nickname"]
        ip = attacker["ip"]
        count = attacker["count"]
        country = attacker.get("country", "Unknown")

        ip_sessions = [s for s in data.get("successful_sessions", []) if s["ip"] == ip]
        all_cmds = []
        for s in ip_sessions:
            all_cmds.extend([c["cmd"] for c in s["commands"]])

        creds = ip_creds.get(ip, [])
        unique_cmds = list(set(all_cmds))

        # Detect attack patterns
        cmd_str_lower = " ".join(all_cmds).lower() if all_cmds else ""
        has_ssh_key = "authorized_keys" in cmd_str_lower or "ssh-keygen" in cmd_str_lower
        has_payload = bool(re.search(r'(wget|curl)\s+https?://', cmd_str_lower)) or \
                      ("chmod" in cmd_str_lower and ("777" in cmd_str_lower or "+x" in cmd_str_lower))
        int_score = compute_interestingness(ip, count, data)

        total_sessions = max(len(ip_sessions), 1)
        first_seen = data.get("ip_first_seen", {}).get(ip, "")
        last_seen = data.get("ip_last_seen", {}).get(ip, "")

        category = classify_attacker(
            attempt_count=count,
            session_count=total_sessions,
            command_count=len(all_cmds),
            unique_commands=unique_cmds,
            has_ssh_key=has_ssh_key,
            has_payload=has_payload,
            interestingness_score=int_score
        )
        print(f"[*] {nick} ({ip}): category={category}, attempts={count}, cmds={len(all_cmds)}, score={int_score:.1f}")

        # Cache check — good descriptions are permanent
        cmd_hash = hashlib.md5(str(sorted(set(all_cmds))).encode()).hexdigest()[:8] if all_cmds else "nocmds"
        cache_key = f"gh_{ip}_{cmd_hash}"

        cached_story = _cache_get(desc_cache, cache_key) if cache_key in desc_cache else None
        story = None

        if cached_story:
            is_valid, _reason = validate_llm_output(cached_story, max_chars=200)
            if is_valid and _looks_like_fallback(cached_story):
                # Older versions cached template fallbacks as if they were LLM
                # output, making them permanent. Keep showing one until the LLM
                # can replace it.
                is_valid, _reason = (not _llm_usable()), "cached fallback"
            if is_valid and '**' not in cached_story and not any(
                cached_story.lower().startswith(p) for p in ["attacker:", "the attacker", "based on"]
            ):
                story = cached_story
                print(f"    Using cached description (valid)")
            else:
                print(f"    Cached description failed validation ({_reason}), regenerating")
                del desc_cache[cache_key]

        if story is None:
            profile_text = build_profile_text(ip, count, ip_sessions, all_cmds, creds)
            prompt_template = _CATEGORY_PROMPTS.get(category, PROMPT_BOMBER)
            prompt = prompt_template.replace("{profile}", profile_text)

            print(f"    Generating with {category} prompt...")
            raw = llm_generate(prompt, temperature=0.6, max_tokens=60)
            story = strip_markdown(raw)
            story = re.sub(r'^[\u2192\u279c>]+\s*', '', story).strip()

            # Quality gate — _bad_starts now consolidated into _BAD_PREFIXES (M1 fix)
            is_valid, reason = validate_llm_output(story, max_chars=200)
            if not is_valid:
                print(f"    First attempt failed ({reason}), retrying...")
                raw = llm_generate(prompt, temperature=0.4, max_tokens=60)
                story = strip_markdown(raw)
                story = re.sub(r'^[\u2192\u279c>]+\s*', '', story).strip()
                is_valid, reason = validate_llm_output(story, max_chars=200)

            if not is_valid:
                print(f"    LLM failed twice, using {category} fallback")
                exotic_pws = [c for c in set(creds) if c not in BORING_CREDS]
                pw_samples = []
                for c in exotic_pws[:3]:
                    sep = ":" if ":" in c else "/"
                    pw_samples.append(c.split(sep)[-1])

                fallback_data = {
                    'attempt_count': count,
                    'session_count': total_sessions,
                    'login_count': len(ip_sessions),
                    'key_actions': ', '.join(unique_cmds[:5]) if unique_cmds else 'recon',
                    'notable_passwords': ', '.join(pw_samples) if pw_samples else '',
                    'top_cred': creds[0] if creds else 'default creds',
                    'got_in': len(ip_sessions) > 0,
                }
                story = _category_fallback(category, fallback_data)

            elif story:
                # Only real LLM output is cached; fallbacks are recomputed each
                # run so they get replaced once the LLM is reachable.
                desc_cache[cache_key] = story
                print(f"    Cached: {story[:80]}...")

        # Final cleanup
        if story:
            for prefix in [f"Nickname: {nick}", f"{nick}:", f'"{nick}"', f"**{nick}**"]:
                if story.lower().startswith(prefix.lower()):
                    story = story[len(prefix):].lstrip(" -:,")
            if " Or:" in story or " Or," in story:
                story = story.split(" Or:")[0].split(" Or,")[0].strip()
            story = story.strip('"').strip()
            if len(story) > 200:
                story = story[:197].rsplit(" ", 1)[0] + "..."

        if not story:
            if all_cmds:
                story = f"Gained access and executed {len(all_cmds)} commands."
            else:
                story = f"Attempted {count} logins without gaining access."

        # Time range
        time_range = ""
        if first_seen and last_seen:
            try:
                f_utc = datetime.fromisoformat(first_seen.replace("Z", "+00:00")[:26]).replace(tzinfo=timezone.utc)
                l_utc = datetime.fromisoformat(last_seen.replace("Z", "+00:00")[:26]).replace(tzinfo=timezone.utc)
                f_local = f_utc.astimezone(ZoneInfo("America/New_York"))
                l_local = l_utc.astimezone(ZoneInfo("America/New_York"))
                f_short = f_local.strftime("%H:%M")
                l_short = l_local.strftime("%H:%M")
                f_date = f_local.strftime("%Y-%m-%d")
                l_date = l_local.strftime("%Y-%m-%d")
                if f_date == l_date:
                    time_range = f"{f_short}\u2013{l_short}"
                else:
                    time_range = f"{f_date[5:]} {f_short} \u2013 {l_date[5:]} {l_short}"
            except (ValueError, TypeError):
                time_range = ""

        hits.append({
            "nick": nick,
            "ip": ip,
            "count": count,
            "flag": attacker.get("flag", "\U0001f3f4"),
            "story": story,
            "cmds": len(all_cmds),
            "sessions": len(ip_sessions),
            "time_range": time_range,
        })

    if _owns_cache:
        save_cache(desc_cache)
    return hits


# H2 fix: classify_commands_fast removed — dead code, superseded by the
# classify_attacker + _CATEGORY_PROMPTS prompt routing system (Bea review 2026-03-22).


def generate_attacker_narratives(data, desc_cache=None):
    """Generate ONE narrative per attacker IP, grouping all sessions and deduplicating commands.
    H1/H3 fix: accepts shared desc_cache from caller; if None, loads own copy."""
    geo_cache = data.get("geo_cache", {})
    ip_creds_map = data.get("ip_creds", {})
    _owns_cache = desc_cache is None
    if _owns_cache:
        desc_cache = load_cache()

    # Group successful sessions by IP
    ip_sessions = defaultdict(list)
    for s in data.get("successful_sessions", []):
        ip_sessions[s["ip"]].append(s)

    if not ip_sessions:
        return []

    results = []
    llm_calls = 0
    MAX_LLM_CALLS = 10

    for ip, sessions in ip_sessions.items():
        geo = geo_cache.get(ip, {})
        nick = generate_nickname(ip, geo, ip_creds_map.get(ip, []))
        country = geo.get("country", "Unknown")
        city = geo.get("city", "")
        isp = geo.get("isp", "Unknown")
        loc = f"{city}, {country}" if city else country

        # Collect ALL commands across all sessions, preserving order of first appearance
        all_cmds_ordered = []
        cmd_counts = Counter()
        seen_cmds = set()
        all_creds = set()
        first_ts = None
        last_ts = None

        for s in sessions:
            if s.get("creds"):
                all_creds.add(s["creds"])
            for c in s["commands"]:
                cmd = c["cmd"]
                cmd_counts[cmd] += 1
                if cmd not in seen_cmds:
                    seen_cmds.add(cmd)
                    all_cmds_ordered.append(cmd)
                # Track time range
                ts = c.get("ts", "")
                if ts:
                    if first_ts is None or ts < first_ts:
                        first_ts = ts
                    if last_ts is None or ts > last_ts:
                        last_ts = ts

        total_cmd_executions = sum(cmd_counts.values())
        unique_cmd_count = len(all_cmds_ordered)
        creds_str = ", ".join(sorted(all_creds)[:3]) or "unknown"

        # Build cache key from IP + sorted unique commands
        cmd_hash = hashlib.md5(str(sorted(seen_cmds)).encode()).hexdigest()[:8]
        cache_key = f"atk_{ip}_{cmd_hash}"

        cached = _cache_get(desc_cache, cache_key)
        if cached:
            is_valid, _reason = validate_llm_output(cached, max_chars=350)
            if is_valid and '**' not in cached:
                narrative = cached
            else:
                print(f"[*] Cached narrative for {cache_key} failed validation, regenerating")
                narrative = None
                if cache_key in desc_cache:
                    del desc_cache[cache_key]
        else:
            narrative = None
        if narrative is None:
            cacheable = True  # False when the LLM was wanted but didn't deliver
            # Build the narrative
            # For simple cases (all same command), use a template
            if unique_cmd_count == 0:
                narrative = f"Logged in across {len(sessions)} sessions but ran no commands."
            elif unique_cmd_count == 1 and any(
                k in all_cmds_ordered[0].lower() for k in ["uname", "/bin/./uname"]
            ):
                narrative = f"Ran uname {total_cmd_executions}x across {len(sessions)} sessions — automated OS fingerprinting."
            elif unique_cmd_count <= 3 and total_cmd_executions == unique_cmd_count:
                # Few unique commands, each run once — use annotations
                steps = []
                for cmd in all_cmds_ordered:
                    ann = annotate_command(cmd)
                    if ann:
                        steps.append(ann)
                    else:
                        # Use the command basename
                        base = cmd.strip().split()[0].split("/")[-1] if cmd.strip() else "?"
                        steps.append(base)
                narrative = " → ".join(steps)
            elif unique_cmd_count <= 6:
                # Moderate complexity — build arrow chain from annotations
                steps = []
                for cmd in all_cmds_ordered:
                    ann = annotate_command(cmd)
                    if ann and ann not in steps:
                        steps.append(ann)
                    elif not ann:
                        base = cmd.strip().split()[0].split("/")[-1] if cmd.strip() else "?"
                        if base not in steps:
                            steps.append(base)
                # Add repetition note if significant
                repeated = [(cmd, cnt) for cmd, cnt in cmd_counts.items() if cnt > 2]
                narrative = " → ".join(steps)
                if repeated:
                    top_repeated = max(repeated, key=lambda x: x[1])
                    # Guard against empty/whitespace command strings: "".split()
                    # is [] and [0] would raise IndexError (production crash:
                    # [FATAL] list index out of range). Fall back to "?".
                    top_cmd = top_repeated[0].strip()
                    ann = annotate_command(top_repeated[0]) or (
                        top_cmd.split()[0].split("/")[-1] if top_cmd else "?"
                    )
                    narrative += f" (repeated {ann} {top_repeated[1]}x)"
            else:
                # Complex command set — use LLM
                if llm_calls < MAX_LLM_CALLS:
                    llm_calls += 1
                    # Build deduplicated command summary for prompt
                    cmd_summary_parts = []
                    for cmd in all_cmds_ordered[:15]:
                        count = cmd_counts[cmd]
                        if count > 1:
                            cmd_summary_parts.append(f"{cmd}  (x{count})")
                        else:
                            cmd_summary_parts.append(cmd)
                    # Sanitize: truncate long commands and strip control characters
                    cmd_summary_parts = [
                        re.sub(r"[\x00-\x1f\x7f-\x9f]", "", part[:100])
                        for part in cmd_summary_parts
                    ]
                    cmd_block = "\n".join(cmd_summary_parts)

                    prompt = (
                        "Summarize this SSH honeypot attacker's behavior as a short arrow-chain narrative. "
                        "Use → to connect steps. Be specific and technical. No preamble, no quotes.\n\n"
                        "Example: OS fingerprint via uname → full hardware audit (lscpu, dmidecode, free) → "
                        "enumerated PCI devices → profiling for cryptomining potential\n\n"
                        "Example: wget payload from C2 → chmod +x → executed binary → attempted persistence via crontab\n\n"
                        f"Attacker: {nick} from {loc} ({isp})\n"
                        f"Sessions: {len(sessions)}, Total commands: {total_cmd_executions}, "
                        f"Unique commands: {unique_cmd_count}\n"
                        f"Credentials: {creds_str}\n"
                        f"Commands (deduplicated, in order):\n{cmd_block}\n\n"
                        "Arrow-chain summary:"
                    )
                    narrative = llm_generate(prompt, temperature=0.5, max_tokens=80)
                    narrative = strip_markdown(narrative)
                    # Strip leading arrow from prompt format
                    narrative = re.sub(r'^[\u2192\u2192]\s*', '', narrative).strip()

                    # Validate — inline bad-starts consolidated into _BAD_PREFIXES (M1 fix)
                    is_valid, reason = validate_llm_output(narrative)
                    if not is_valid or len(narrative) < 10:
                        narrative = None

                if not narrative:
                    # Fallback: build from annotations. Not cached, so the LLM
                    # gets another go next run.
                    cacheable = False
                    steps = []
                    for cmd in all_cmds_ordered[:10]:
                        ann = annotate_command(cmd)
                        if ann and ann not in steps:
                            steps.append(ann)
                    narrative = " → ".join(steps) if steps else f"Ran {unique_cmd_count} unique commands across {len(sessions)} sessions."

            # Clean up
            narrative = narrative.strip('"').strip()
            if len(narrative) > 300:
                narrative = narrative[:297].rsplit(" ", 1)[0] + "..."

            if cacheable:
                desc_cache[cache_key] = {
                    "text": narrative,
                    "_cached_at": datetime.now(timezone.utc).isoformat()
                }

        # Build the display commands: deduplicated with counts
        display_cmds = []
        for cmd in all_cmds_ordered:
            count = cmd_counts[cmd]
            display_cmds.append({"cmd": cmd, "count": count})

        results.append({
            "ip": ip,
            "nick": nick,
            "loc": loc,
            "sessions": len(sessions),
            "total_cmds": total_cmd_executions,
            "unique_cmds": unique_cmd_count,
            "creds": creds_str,
            "narrative": narrative,
            "display_cmds": display_cmds,
            "first_ts": first_ts,
            "last_ts": last_ts,
        })

    if _owns_cache:
        save_cache(desc_cache)
    return results





def _epoch_minutes(ts):
    try:
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() // 60)
    except (ValueError, AttributeError, TypeError):
        return 0


def compact_markers(markers):
    """Columnar, string-deduplicated encoding of the map markers for the data file.

    Keeps exactly what the page's map code reads, in the original order.
    Markers with no per-day activity are dropped: the map only ever draws a
    marker on a day it has attempts, so those could never appear. Every string
    is HTML-escaped here — the page inserts them as markup. The page's
    decodeMarkers() rebuilds one record per marker.

    Columns: ip, nick, lat, lon, city/country/isp/why (string-table indexes),
    creds (list of indexes), daily (flat [day index, count, ...]), n (total
    attempts), ok (1 if the IP ever logged in), last (last attempt, epoch
    minutes).
    """
    strings, string_idx = [], {}

    def sidx(value):
        value = h(value or "")
        if value not in string_idx:
            string_idx[value] = len(strings)
            strings.append(value)
        return string_idx[value]

    drawable = [m for m in markers if m.get("daily_counts")]
    days = sorted({d for m in drawable for d in m["daily_counts"]})
    day_idx = {d: i for i, d in enumerate(days)}
    cols = {k: [] for k in ("ip", "nick", "lat", "lon", "city", "country", "isp", "creds",
                            "daily", "n", "ok", "why", "last")}
    for m in drawable:
        cols["ip"].append(h(m["ip"]))
        cols["nick"].append(h(m.get("nickname", "")))
        cols["lat"].append(round(m["lat"], MARKER_COORD_DECIMALS))
        cols["lon"].append(round(m["lon"], MARKER_COORD_DECIMALS))
        cols["city"].append(sidx(m.get("city", "")))
        cols["country"].append(sidx(m.get("country")))
        cols["isp"].append(sidx(m.get("isp")))
        # creds are already escaped "user:pass" strings — don't double-escape
        cred_ids = []
        for c in m.get("creds", []):
            if c not in string_idx:
                string_idx[c] = len(strings)
                strings.append(c)
            cred_ids.append(string_idx[c])
        cols["creds"].append(cred_ids)
        flat = []
        for day, count in sorted(m["daily_counts"].items()):
            flat += [day_idx[day], count]
        cols["daily"].append(flat)
        cols["n"].append(m.get("count", 0))
        cols["ok"].append(1 if m.get("got_in") else 0)
        cols["why"].append(sidx(m.get("named_for", "")))
        cols["last"].append(_epoch_minutes(m.get("last_seen", "")))
    return {"days": days, "strings": strings, **cols}


def build_page_data(data, terminal_rest=()):
    """The bulk data the page fetches from DATA_FILENAME (see static/app.js)."""
    markers = compact_markers(data["markers"])
    # Earliest day with data bounds the day pager.
    candidates = list(markers["days"][:1]) + [d["date"] for d in data["daily_breakdown"] if d.get("date")]
    return {
        "markers": markers,
        "minDay": min(candidates) if candidates else None,
        "timelineLabels": data["timeline_labels"],
        "timelineData": data["timeline_data"],
        "terminal": list(terminal_rest),
    }


def generate_html(data):
    """Render the dashboard page only (see render_dashboard for page + data file)."""
    return render_dashboard(data)[0]


STATIC_DIR = os.path.join(SCRIPT_DIR, "static")
_static_versions = {}


def static_url(name):
    """Relative URL for a file in app/static, versioned by content hash so
    serve.py can let browsers cache it forever."""
    v = _static_versions.get(name)
    if v is None:
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as f:
                v = hashlib.sha1(f.read()).hexdigest()[:10]
        except OSError:
            v = "0"
        _static_versions[name] = v
    return f"static/{name}?v={v}"


PAGE_CSS = """
@font-face { font-family: 'JetBrains Mono'; font-weight: 100 800; font-display: swap;
  src: url(__FONT_MONO__) format('woff2'); }
@font-face { font-family: 'Orbitron'; font-weight: 400 900; font-display: swap;
  src: url(__FONT_DISPLAY__) format('woff2'); }

:root {
  --bg: #0a0a0a; --panel: #0d1117; --line: #1a3a1a; --line-soft: #1a2a1a;
  --green: #00ff41; --green-dim: #00aa30; --red: #ff4444; --red-soft: #ff6b6b;
  --amber: #ffb000; --text: #aaa; --muted: #666; --faint: #444;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html { overflow-x: hidden; max-width: 100vw; }
body {
  background: var(--bg); color: var(--green);
  font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  overflow-x: hidden; max-width: 100vw; -webkit-text-size-adjust: 100%;
}
.scanline {
  position: fixed; inset: 0; pointer-events: none; z-index: 9999;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.03) 2px, rgba(0,255,65,0.03) 4px);
  transform: translateZ(0);  /* own layer: never repainted on scroll */
}

header {
  background: linear-gradient(180deg, #0d1117 0%, #0a0a0a 100%);
  border-bottom: 1px solid var(--green);
  padding: 20px 30px; text-align: center; position: relative;
}
header h1 {
  font-family: 'Orbitron', sans-serif; font-size: 2.2em; color: var(--green);
  text-shadow: 0 0 20px rgba(0,255,65,0.5), 0 0 40px rgba(0,255,65,0.2);
  letter-spacing: 3px;
}
.status {
  position: absolute; right: 20px; top: 50%; transform: translateY(-50%);
  color: #555; font-size: 0.75em; display: flex; align-items: center; gap: 6px;
}
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green);
  box-shadow: 0 0 6px var(--green); animation: blink 2.4s ease-in-out infinite; }
.status.offline .live-dot { background: #555; box-shadow: none; animation: none; }
@keyframes blink { 50% { opacity: 0.35; } }

.stats-bar {
  display: flex; justify-content: center; gap: 30px; padding: 20px;
  background: var(--panel); border-bottom: 1px solid var(--line); flex-wrap: wrap;
}
.stat { text-align: center; min-width: 120px; }
.stat .value { font-family: 'Orbitron', sans-serif; font-size: 2em; color: var(--green);
  text-shadow: 0 0 10px rgba(0,255,65,0.4); font-variant-numeric: tabular-nums; }
.stat .label { font-size: 0.75em; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

.container { max-width: 1400px; margin: 0 auto; padding: 20px; width: 100%; overflow-x: hidden; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; max-width: 100%; }
.grid.full { grid-template-columns: 1fr; }
.panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 20px;
  position: relative; overflow: hidden; display: flex; flex-direction: column;
  min-height: 0; min-width: 0; width: 100%; max-width: 100%;
}
.panel::before {
  content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
  background: linear-gradient(90deg, transparent, var(--green), transparent);
}
.panel h2 {
  font-family: 'Orbitron', sans-serif; font-size: 1.1em; color: var(--green);
  margin-bottom: 15px; text-transform: uppercase; letter-spacing: 2px;
}
.panel-head { display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; margin-bottom: 15px; }
.panel-head h2 { margin-bottom: 0; }
.panel-sub { color: #555; font-size: 0.75em; }
.scroll { overflow-y: auto; }
.scroll::-webkit-scrollbar { width: 6px; }
.scroll::-webkit-scrollbar-track { background: var(--bg); }
.scroll::-webkit-scrollbar-thumb { background: var(--line); border-radius: 3px; }

/* --- map --- */
.pager { display: flex; align-items: center; gap: 10px; }
.pager button {
  background: none; border: 1px solid #333; color: #888; font-size: 1.2em; cursor: pointer;
  padding: 4px 10px; border-radius: 4px; font-family: inherit;
}
.pager button:hover:not(:disabled) { border-color: var(--green-dim); color: var(--green); }
.pager button:disabled { opacity: 0.3; cursor: default; }
#dayLabel { color: #888; font-size: 0.85em; min-width: 170px; text-align: center; }
.legend { color: var(--muted); font-size: 0.75em; display: flex; gap: 14px; align-items: center; }
.legend i { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 5px; vertical-align: -1px; }
.legend .k-tried { background: var(--red); }
.legend .k-in { background: var(--amber); }
.legend .k-live { border: 2px solid var(--red); background: none; }
.map-wrap { position: relative; }
#map {
  height: 440px; border-radius: 6px; border: 1px solid var(--line);
  background: var(--bg); z-index: 1;
}
.leaflet-container { background: var(--bg) !important; font-family: inherit; }
.leaflet-control-attribution { background: rgba(10,10,10,0.75) !important; color: #6b7280 !important; font-size: 10px; }
.leaflet-control-attribution a { color: #9ca3af !important; }
.leaflet-bar a { background: var(--panel) !important; color: var(--green) !important; border-color: var(--line) !important; }
.map-note {
  position: absolute; left: 50%; top: 12px; transform: translateX(-50%); z-index: 500;
  background: rgba(13,17,23,0.92); border: 1px solid var(--line); color: var(--text);
  padding: 6px 12px; border-radius: 4px; font-size: 0.8em; pointer-events: none;
  transition: opacity 0.3s; max-width: 90%; text-align: center;
}
.map-note[hidden] { display: block; opacity: 0; }
.hp-pulse { animation: hp-pulse 2s ease-out infinite; transform-box: fill-box; transform-origin: center; }
@keyframes hp-pulse { from { transform: scale(0.7); opacity: 0.9; } to { transform: scale(2.4); opacity: 0; } }
.hp-select { animation: hp-select 1.2s ease-in-out infinite alternate; }
@keyframes hp-select { from { stroke-opacity: 1; } to { stroke-opacity: 0.35; } }
.leaflet-popup-content-wrapper {
  background: var(--panel) !important; color: var(--green) !important;
  border: 1px solid var(--green) !important; border-radius: 6px !important;
}
.leaflet-popup-tip { background: var(--panel) !important; }
.leaflet-popup-content { font-size: 0.85em; line-height: 1.5; margin: 12px 16px; }
.leaflet-container a.leaflet-popup-close-button { color: var(--muted); }
.pop-nick { color: var(--red); font-weight: bold; font-size: 1.15em; }
.pop-why { color: var(--muted); font-size: 0.85em; word-break: break-all; }
.pop-ip { color: var(--red-soft); font-weight: bold; margin: 4px 0; }
.pop .l { color: var(--muted); }
.pop-in { color: var(--amber); font-weight: bold; }
.pop-creds { color: var(--text); max-height: 120px; overflow-y: auto; word-break: break-all; }

/* --- tables / feeds --- */
table { width: 100%; border-collapse: collapse; }
td { overflow-wrap: anywhere; }
td.glow, td.num { white-space: nowrap; overflow-wrap: normal; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--line-soft); font-size: 0.85em; }
th { color: var(--green-dim); text-transform: uppercase; font-size: 0.75em; letter-spacing: 1px; }
td { color: var(--text); }
.glow { color: var(--green); font-weight: bold; text-shadow: 0 0 5px rgba(0,255,65,0.3); }
.day-link { cursor: pointer; }
.day-link:hover { text-decoration: underline; }
.dim { color: #555; }
.small { font-size: 0.8em; }

.activity-feed { height: 350px; font-size: 0.82em; }
.activity-row { padding: 6px 10px; border-bottom: 1px solid #111; display: flex; gap: 12px; align-items: baseline; }
.activity-row:hover { background: #111a11; }
.activity-row .ts { color: var(--faint); min-width: 150px; font-size: 0.9em; }
.activity-row .ip { color: var(--red-soft); min-width: 130px; }
.activity-row .action { color: var(--text); flex: 1; min-width: 0; max-height: 80px; overflow-y: auto;
  overflow-x: hidden; word-break: break-all; white-space: pre-wrap; }
.count-badge { background: #ff6b35; color: #000; padding: 1px 6px; border-radius: 8px; font-size: 0.8em; font-weight: bold; }
.success-text { color: var(--green) !important; font-weight: bold; }
.nick-link { color: var(--red); font-weight: bold; cursor: pointer; }
.nick-link:hover { color: #ff6666; text-decoration: underline; text-shadow: 0 0 8px rgba(255,68,68,0.5); }

.greatest-hits { max-height: 520px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.hit-card { background: #111a11; border: 1px solid var(--line); border-radius: 6px; padding: 12px; }
.hit-card .hit-nick { color: var(--red); font-weight: bold; font-size: 1.1em; cursor: pointer; }
.hit-card .hit-nick:hover { text-shadow: 0 0 8px rgba(255,68,68,0.5); }
.hit-card .hit-why { color: #555; font-size: 0.72em; word-break: break-all; }
.hit-card .hit-stat { color: var(--green); font-family: 'Orbitron', sans-serif; font-size: 0.85em; margin: 4px 0; }
.hit-card .hit-story { color: var(--text); font-size: 0.85em; margin-top: 6px; line-height: 1.4; }
.hit-card .hit-time { color: #555; font-size: 0.75em; margin-top: 4px; }

/* --- charts --- */
.bars { display: grid; gap: 5px; font-size: 0.78em; }
.bar-row { display: grid; grid-template-columns: minmax(0, 15em) 1fr 4.5em; gap: 10px; align-items: center; }
.bar-label { color: var(--green); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-track { height: 14px; background: #0f1a0f; border-radius: 2px; overflow: hidden; }
.bar-fill { display: block; height: 100%; background: rgba(0,255,65,0.6); border-right: 1px solid var(--green); }
.bar-val { color: var(--muted); text-align: right; font-variant-numeric: tabular-nums; }
#timelineDayLabel { color: #888; font-size: 0.75em; margin-bottom: 10px; }
.timeline svg { width: 100%; height: auto; display: block; }
.timeline .bar { fill: rgba(0,255,65,0.55); }
.timeline .bar:hover { fill: var(--green); }
.timeline .bar.now { fill: var(--amber); }
.timeline .grid-line { stroke: var(--line-soft); stroke-width: 1; }
.timeline text { fill: var(--muted); font-size: 10px; font-family: inherit; }

/* --- successful logins terminal --- */
.terminal {
  background: #000; border: 1px solid var(--line); border-radius: 6px; padding: 15px;
  font-size: 0.85em; max-height: 420px; overflow-x: hidden;
  word-break: break-all; white-space: pre-wrap; max-width: 100%;
}
.term-line { color: var(--green); margin: 2px 0; }
.term-ip-group { margin-bottom: 16px; border-bottom: 1px solid var(--line); padding-bottom: 12px; }
.term-ip-header { color: var(--red-soft); font-weight: bold; font-size: 1.05em; margin-bottom: 8px; padding-bottom: 4px; }
.session-block { margin: 4px 0 4px 12px; padding: 4px 12px; border-left: 2px solid var(--line); }
.session-meta { color: #555; font-size: 0.8em; margin-bottom: 4px; }
.session-narrative { color: #ff8c00; font-size: 0.85em; font-style: italic; line-height: 1.4; }
.session-cmds { color: var(--green); font-size: 0.82em; margin-top: 4px; line-height: 1.5; }
.session-cmds .cmd-line { margin: 2px 0; overflow-wrap: break-word; word-break: break-all; white-space: pre-wrap; }
.session-cmds .cmd-prompt { color: #888; }
.cmd-count { color: var(--muted); }
.cmd-annotation { display: block; color: #0a8; font-style: italic; font-size: 0.82em; opacity: 0.8; margin-left: 18px; margin-bottom: 2px; }

@media (max-width: 900px) {
  .grid { grid-template-columns: 1fr; }
  .stats-bar { gap: 15px; }
  .status { position: static; transform: none; justify-content: center; margin-top: 6px; }
}
@media (max-width: 600px) {
  header { padding: 14px 10px; }
  header h1 { font-size: 1.1em; letter-spacing: 1px; }
  .container { padding: 6px; }
  .grid { gap: 10px; margin-bottom: 10px; }
  .panel { padding: 10px; }
  .panel h2 { font-size: 0.85em; letter-spacing: 1px; }
  .stats-bar { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 10px 8px; }
  .stat { min-width: unset; }
  .stat .value { font-size: 1.3em; }
  .stat .label { font-size: 0.55em; }
  .activity-row { flex-wrap: wrap; gap: 2px; padding: 8px 6px; }
  .activity-row .ts { min-width: unset; font-size: 0.7em; width: 100%; }
  .activity-row .ip { min-width: unset; font-size: 0.8em; }
  .activity-row .action { font-size: 0.75em; width: 100%; max-height: 60px; }
  .hide-mobile { display: none !important; }
  table { font-size: 0.85em; }
  table td, table th { padding: 8px 6px; }
  .terminal { font-size: 0.7em; padding: 8px; }
  .greatest-hits { grid-template-columns: 1fr; }
  #map { height: 300px; }
  #dayLabel { min-width: 120px; }
  .legend { display: none; }
  .bar-row { grid-template-columns: minmax(0, 10em) 1fr 3.5em; }
}
@media (prefers-reduced-motion: reduce) {
  .hp-pulse, .hp-select, .live-dot { animation: none; }
}
"""


def _nick_html(ip, nick, cls="nick-link", inner=None):
    """A clickable attacker name (app.js flies the map to data-ip)."""
    why = nickname_source_text(ip)
    title = f' title="named for {h(why)}"' if why else ""
    return f'<span class="{cls}" data-ip="{h(ip)}"{title}>{inner if inner is not None else h(nick)}</span>'


def _fmt_local(ts, fmt):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(LOCAL_TZ).strftime(fmt)
    except (ValueError, AttributeError, TypeError):
        return ""


def render_dashboard(data):
    """Render the dashboard. Returns (html, data_json): the page and the contents
    of DATA_FILENAME, which must be written beside it."""
    stats = data["stats"]
    today = data["today_stats"]
    last_24h = data.get("last_24h", {})
    peak_sessions = data.get("peak_sessions", (0, "—"))
    peak_logins = data.get("peak_logins", (0, "—"))
    peak_successful = data.get("peak_successful", (0, "—"))
    peak_commands = data.get("peak_commands", (0, "—"))
    peak_ips = data.get("peak_ips", (0, "—"))
    peak_success_rate = data.get("peak_success_rate", (0, "—"))
    geo_cache = data.get("geo_cache", {})
    ip_creds = data.get("ip_creds", {})

    # H1/H3 fix: load cache once, share between both LLM generation passes, save once at end
    print("[*] Loading description cache...")
    shared_desc_cache = load_cache()

    print("[*] Generating greatest hits (LLM)...")
    greatest_hits = generate_greatest_hits(data, desc_cache=shared_desc_cache)
    greatest_hits_html = ""
    for hit in greatest_hits:
        why = nickname_source_text(hit["ip"])
        parts = [f"{hit['count']:,} attempts"]
        if hit.get("sessions"):
            parts.append(f"{hit['sessions']} sessions")
        if hit["cmds"]:
            parts.append(f"{hit['cmds']} cmds")
        greatest_hits_html += (
            f'<div class="hit-card">'
            f'<div class="hit-nick" data-ip="{h(hit["ip"])}">{hit["flag"]} {h(hit["nick"])}</div>'
            + (f'<div class="hit-why">named for {h(why)}</div>' if why else "")
            + f'<div class="hit-stat">{" · ".join(parts)}</div>'
            f'<div class="hit-story">{h(hit["story"])}</div>'
            + (f'<div class="hit-time">⏰ {h(hit["time_range"])}</div>' if hit.get("time_range") else "")
            + '</div>'
        )
    if not greatest_hits_html:
        greatest_hits_html = '<div class="dim">No attackers to profile yet.</div>'

    print("[*] Generating attacker narratives...")
    attacker_narratives = generate_attacker_narratives(data, desc_cache=shared_desc_cache)

    # Save merged cache once after both passes complete
    save_cache(shared_desc_cache)

    leaderboard_rows = ""
    for a in data["top_attackers"]:
        city_or_country = h(a['city']) if a['city'] else h(a['country'])
        leaderboard_rows += (
            f'<tr><td>{_nick_html(a["ip"], a["nickname"])}<br><span class="dim small">{h(a["ip"])}</span></td>'
            f'<td>{a["flag"]} {city_or_country}</td>'
            f'<td class="hide-mobile">{h(a["isp"])}</td>'
            f'<td class="glow">{a["count"]:,}</td></tr>'
        )

    activity_rows = ""
    prev_ip = None
    for ev in reversed(data["recent_events"]):
        ts_short = _fmt_local(ev["ts"], "%Y-%m-%d %H:%M:%S") or (ev["ts"] or "?")[:19].replace("T", " ")
        count = ev.get("count", 1)
        if count > 1:
            first_ts, last_ts = ev.get("first_ts", ""), ev.get("last_ts", "")
            if _fmt_local(first_ts, "%F") == _fmt_local(last_ts, "%F"):
                rng = f"{_fmt_local(first_ts, '%H:%M')} – {_fmt_local(last_ts, '%H:%M')}"
            else:
                rng = f"{_fmt_local(first_ts, '%m-%d %H:%M')} – {_fmt_local(last_ts, '%m-%d %H:%M')}"
            if rng.strip(" –"):
                ts_short = rng
        count_badge = f'<span class="count-badge">{count}×</span> ' if count > 1 else ""
        action_class = "success-text" if "SUCCESS" in ev["action"] else ""
        geo = geo_cache.get(ev['ip'], {})
        nick = generate_nickname(ev['ip'], geo, ip_creds.get(ev['ip'], []))
        show_ip = h(ev["ip"]) if ev["ip"] != prev_ip else "↑"
        prev_ip = ev["ip"]
        # Action already html-escaped at creation time — no double-escape
        activity_rows += (
            f'<div class="activity-row"><span class="ts">{ts_short}</span>'
            f'{_nick_html(ev["ip"], nick)}<span class="ip">{show_ip}</span>'
            f'<span class="action {action_class}">{count_badge}{ev["action"]}</span></div>'
        )
    if not activity_rows:
        activity_rows = '<div class="dim">Quiet so far.</div>'

    terminal_content = ""
    terminal_rest = []
    if attacker_narratives:
        # One self-contained HTML chunk per attacker group. The first
        # TERMINAL_INITIAL_GROUPS go into the page; the rest go into the data
        # file and are appended on scroll (same markup, just later).
        terminal_groups = []
        for atk in attacker_narratives:
            session_word = "session" if atk["sessions"] == 1 else "sessions"
            cmd_word = "cmd" if atk["total_cmds"] == 1 else "cmds"
            g = (
                f'<div class="term-ip-group"><div class="term-ip-header">'
                f'{_nick_html(atk["ip"], atk["nick"], inner="\U0001f3ad " + h(atk["nick"]))} ({h(atk["ip"])}) '
                f'— {h(atk["loc"])} · {atk["sessions"]} {session_word} '
                f'· {atk["total_cmds"]} {cmd_word}</div><div class="session-block">'
            )
            time_parts = []
            if atk.get("first_ts"):
                time_parts.append(_fmt_local(atk["first_ts"], "%Y-%m-%d %H:%M %Z")
                                  or h(atk["first_ts"][:16].replace("T", " ")))
            if atk.get("creds"):
                time_parts.append(f'as {atk["creds"]}')  # already escaped
            meta = " · ".join(time_parts)
            if meta:
                g += f'<div class="session-meta">{meta}</div>'
            g += f'<div class="session-narrative">{h(atk["narrative"])}</div>'
            if atk.get("display_cmds"):
                g += '<div class="session-cmds">'
                for dc in atk["display_cmds"]:
                    count_badge = f' <span class="cmd-count">×{dc["count"]}</span>' if dc["count"] > 1 else ""
                    annotation = annotate_command(dc["cmd"])
                    note_html = f'<div class="cmd-annotation">↳ {annotation}</div>' if annotation else ""
                    g += f'<div class="cmd-line"><span class="cmd-prompt">$</span> {h(dc["cmd"])}{count_badge}</div>{note_html}'
                g += '</div>'
            g += '</div></div>'
            terminal_groups.append(g)
        initial = max(0, TERMINAL_INITIAL_GROUPS)
        terminal_content = "".join(terminal_groups[:initial])
        terminal_rest = terminal_groups[initial:]
    else:
        terminal_content = '<div class="term-line dim">No successful logins captured yet. The bots are still trying...</div>'

    daily_rows = ""
    for d in data["daily_breakdown"]:
        attacker_cell = (f'{_nick_html(d["top_attacker_ip"], d["top_attacker_nick"])} '
                         f'<span class="dim">({h(d["top_attacker_ip"])})</span>'
                         if d["top_attacker_ip"] else '<span class="dim">—</span>')
        daily_rows += (
            f'<tr><td class="glow day-link" data-day="{h(d["date"])}" title="Show this day on the map">{h(d["date"])}</td>'
            f'<td>{d["sessions"]:,}</td><td class="hide-mobile">{d["login_attempts"]:,}</td>'
            f'<td>{d["successful"]:,}</td><td>{d["unique_ips"]:,}</td>'
            f'<td class="hide-mobile">{d["commands"]:,}</td><td class="hide-mobile">{attacker_cell}</td></tr>'
        )

    creds = data["top_creds"][:15]
    cred_max = max((c[1] for c in creds), default=1) or 1
    creds_html = "".join(
        f'<div class="bar-row"><span class="bar-label" title="{label}">{label}</span>'
        f'<span class="bar-track"><span class="bar-fill" style="width:{max(0.5, n / cred_max * 100):.1f}%"></span></span>'
        f'<span class="bar-val">{n:,}</span></div>'
        for label, n in creds   # labels are already escaped
    ) or '<div class="dim">No login attempts yet.</div>'

    # Today's hourly counts, so the timeline draws before the data file arrives.
    today_key = data.get("data_today", "")
    today_hours = [0] * 24
    for label, n in zip(data["timeline_labels"], data["timeline_data"]):
        if label[:10] == today_key:
            try:
                today_hours[int(label[11:13])] += n
            except ValueError:
                pass

    sr_24h = round(last_24h.get('successful_logins', 0) / max(1, last_24h.get('login_attempts', 1)) * 100, 1)
    avg = data['averages']
    alltime_rows = (
        f"<tr><td>Sessions</td><td class=\"glow\">{stats['total_sessions']:,}</td><td>{avg['sessions_per_day']:,}</td><td>{last_24h.get('sessions', 0):,}</td><td>{peak_sessions[0]:,} ({peak_sessions[1]})</td></tr>"
        f"<tr><td>Login Attempts</td><td class=\"glow\">{stats['total_login_attempts']:,}</td><td>{avg['logins_per_day']:,}</td><td>{last_24h.get('login_attempts', 0):,}</td><td>{peak_logins[0]:,} ({peak_logins[1]})</td></tr>"
        f"<tr><td>Successful Logins</td><td class=\"glow\">{stats['successful_logins']:,}</td><td>{avg['successful_per_day']:,}</td><td>{last_24h.get('successful_logins', 0):,}</td><td>{peak_successful[0]:,} ({peak_successful[1]})</td></tr>"
        f"<tr><td>Unique IPs</td><td class=\"glow\">{stats['unique_ips']:,}</td><td>{avg['ips_per_day']:,}</td><td>{last_24h.get('unique_ips', 0):,}</td><td>{peak_ips[0]:,} ({peak_ips[1]})</td></tr>"
        f"<tr><td>Commands Executed</td><td class=\"glow\">{stats['commands_executed']:,}</td><td>{avg['commands_per_day']:,}</td><td>{last_24h.get('commands', 0):,}</td><td>{peak_commands[0]:,} ({peak_commands[1]})</td></tr>"
        f"<tr><td>Days Active</td><td class=\"glow\" colspan=\"4\">{data['days_active']}</td></tr>"
        f"<tr><td>Success Rate</td><td class=\"glow\">{avg['success_rate']}%</td><td>{avg['success_rate']}%</td><td>{sr_24h}%</td><td>{peak_success_rate[0]}% ({peak_success_rate[1]})</td></tr>"
    )

    got_in = len({s["ip"] for s in data.get("successful_sessions", [])})

    # Compact JSON (no whitespace, raw UTF-8). The page requests it with a
    # content-hash query so a regenerated file is never confused with a cached
    # older one; serve.py ignores the query string.
    data_json = json.dumps(build_page_data(data, terminal_rest),
                           separators=(",", ":"), ensure_ascii=False)
    data_version = hashlib.sha1(data_json.encode("utf-8")).hexdigest()[:12]
    data_url = f"{DATA_FILENAME}?v={data_version}"

    body = f"""<div class="stats-bar" id="statsBar" data-live>
  <div class="stat"><div class="value">{today['sessions']:,}</div><div class="label">Sessions Today</div></div>
  <div class="stat"><div class="value">{today['login_attempts']:,}</div><div class="label">Login Attempts Today</div></div>
  <div class="stat"><div class="value">{today['successful_logins']:,}</div><div class="label">Successful Logins Today</div></div>
  <div class="stat"><div class="value">{today['unique_ips']:,}</div><div class="label">Unique IPs Today</div></div>
  <div class="stat"><div class="value">{today['commands']:,}</div><div class="label">Commands Today</div></div>
</div>

<div class="container">

  <div class="grid full">
    <div class="panel">
      <div class="panel-head">
        <h2>\U0001f30d Attack Origins</h2>
        <div class="legend"><span><i class="k-tried"></i>tried</span><span><i class="k-in"></i>got in</span><span><i class="k-live"></i>active now</span></div>
        <div class="pager">
          <button type="button" id="dayPrev" aria-label="Previous day">&larr;</button>
          <span id="dayLabel"></span>
          <button type="button" id="dayNext" aria-label="Next day">&rarr;</button>
        </div>
      </div>
      <div class="map-wrap">
        <div id="map"></div>
        <div id="mapNote" class="map-note">loading attackers…</div>
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>\U0001f3c6 Top Attackers</h2>
      <div class="scroll" id="leaderboard" data-live style="max-height:350px">
        <table>
          <thead><tr><th>Attacker</th><th>Origin</th><th class="hide-mobile">ISP</th><th>Attempts</th></tr></thead>
          <tbody>{leaderboard_rows}</tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <h2>\U0001f4e1 Recent Activity</h2>
      <div class="activity-feed scroll" id="activityFeed" data-live>{activity_rows}</div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>\U0001f3ac Greatest Hits</h2>
      <div class="greatest-hits scroll" id="greatestHits" data-live>{greatest_hits_html}</div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <h2>\U0001f511 Top Credentials</h2>
      <div class="bars" id="credsChart" data-live>{creds_html}</div>
    </div>
    <div class="panel">
      <h2 style="margin-bottom:0;">\U0001f4c8 Attack Timeline</h2>
      <div id="timelineDayLabel"></div>
      <div class="timeline" id="timeline"></div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>\U0001f4ca Daily Breakdown</h2>
      <div class="scroll" id="dailyBreakdown" data-live style="overflow-x:auto; max-height:400px;">
        <table>
          <thead><tr><th>Date</th><th>Sessions</th><th class="hide-mobile">Login Attempts</th><th>Successful</th><th>Unique IPs</th><th class="hide-mobile">Commands</th><th class="hide-mobile">Top Attacker</th></tr></thead>
          <tbody>{daily_rows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <h2>\U0001f4ca All-Time Stats</h2>
      <div id="alltimeStats" data-live style="overflow-x:auto;">
        <table>
          <thead><tr><th>Metric</th><th>Total</th><th>Avg / Day</th><th>Last 24h</th><th>Peak Day</th></tr></thead>
          <tbody>{alltime_rows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="grid full">
    <div class="panel">
      <div class="panel-head">
        <h2>\U0001f480 Successful Logins</h2>
        <span class="panel-sub" id="loginsCount" data-live>{got_in:,} attacker{'' if got_in == 1 else 's'} got in</span>
      </div>
      <div class="terminal scroll" id="terminalLog" data-live="terminal">{terminal_content}</div>
    </div>
  </div>

</div>"""

    # Build identity for live updates: changes whenever anything visible does.
    version = hashlib.sha1((body + data_version).encode("utf-8")).hexdigest()[:12]
    config = json.dumps({
        "version": version,
        "dataUrl": data_url,
        "today": today_key,
        "todayHours": today_hours,
        "generated": data.get("generated_epoch") or int(time.time()),
    }, separators=(",", ":")).replace("</", "<\\/")
    css = (PAGE_CSS.replace("__FONT_MONO__", static_url("jetbrains-mono.woff2"))
                   .replace("__FONT_DISPLAY__", static_url("orbitron.woff2")))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Honeypot Dashboard</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍯</text></svg>">
<script id="hpd-config" type="application/json">{config}</script>
<script>
  // Start downloading the bulk data immediately, in parallel with everything else.
  window.hpdData = fetch(JSON.parse(document.getElementById('hpd-config').textContent).dataUrl)
    .then(function(r) {{ if (!r.ok) throw new Error('dashboard data: HTTP ' + r.status); return r.json(); }});
  window.hpdData.catch(function() {{}});  // reported where it is consumed
</script>
<link rel="preload" href="{static_url('jetbrains-mono.woff2')}" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="{static_url('orbitron.woff2')}" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="{static_url('leaflet.css')}">
<script defer src="{static_url('leaflet.js')}"></script>
<script defer src="{static_url('app.js')}"></script>
<style>{css}</style>
</head>
<body>
<div class="scanline"></div>
<header>
  <h1>\U0001f36f HONEYPOT DASHBOARD</h1>
  <div class="status" id="liveStatus" title="Updates in place every 30 seconds"><span class="live-dot"></span><span id="updatedAgo">updated {h(data['generated'][11:16])}</span></div>
</header>
{body}
</body>
</html>"""
    return html, data_json


WINDOW_DAYS = 60


def iter_window_events(log_files, cutoff):
    """Relevant events newer than cutoff from all log files, deduplicated on
    (session, timestamp, eventid), first occurrence wins. Streams: the full
    multi-month history is never held in memory. Fills counts in `stats`."""
    cutoff_key = _utc_key(cutoff)
    seen = set()
    stats = iter_window_events.stats = {"files": 0, "skipped_files": 0, "events": 0,
                                        "old": 0, "dup": 0}
    for lf in log_files:
        # A rotated file last written before the cutoff can't hold anything
        # in the window — don't even open it. (The live log is always read.)
        if lf != LOG_PATH:
            try:
                if os.path.getmtime(lf) < cutoff.timestamp():
                    stats["skipped_files"] += 1
                    continue
            except OSError:
                continue
        stats["files"] += 1
        for e in iter_log(lf, relevant_only=True):
            ts = e.get("timestamp", "")
            # Missing/malformed timestamps count as old and are dropped.
            if not isinstance(ts, str) or _ts_info(ts) is None or ts[:19] <= cutoff_key:
                stats["old"] += 1
                continue
            # hash() of the key, not the key: same dedup at a fraction of the
            # memory (a 64-bit collision across ~1M events is ~1e-7 likely).
            key = hash((e.get("session", ""), ts, e.get("eventid", "")))
            if key in seen:
                stats["dup"] += 1
                continue
            seen.add(key)
            stats["events"] += 1
            yield e


def write_outputs(html, data_json):
    # Data file first, then the page that references it, each atomically, so a
    # freshly served page never points at a data file older than itself.
    for path, content in ((DATA_OUTPUT_PATH, data_json), (OUTPUT_PATH, html)):
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
        os.rename(tmp_path, path)


def main():
    global LLM_ENABLED, _llm_pending
    t0 = time.monotonic()
    print("[*] Parsing Cowrie log...")
    rotated = sorted(f for f in glob.glob(LOG_PATH + "*")
                     if f != LOG_PATH and not f.endswith(".tmp"))
    log_files = list(dict.fromkeys(rotated + [LOG_PATH]))

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=WINDOW_DAYS)
    geo_cache = load_geo_cache()

    def geo_lookup(ips, cache):
        print(f"[*] Found {len(ips)} unique IPs")
        return batch_geoip_lookup(ips, cache)

    data = analyze_events(iter_window_events(log_files, cutoff), geo_cache, now=now,
                          geo_lookup=geo_lookup)
    st = iter_window_events.stats
    print(f"[*] {st['events']} events in the last {WINDOW_DAYS} days from {st['files']} files "
          f"(skipped {st['skipped_files']} old files, {st['old']} old events, {st['dup']} duplicates) "
          f"in {time.monotonic() - t0:.1f}s")

    # Pass 1: no LLM — cached descriptions and instant fallbacks.
    LLM_ENABLED, _llm_pending = False, 0
    write_outputs(*render_dashboard(data))
    print(f"[\u2713] Dashboard written to {OUTPUT_PATH} (+ {DATA_FILENAME}) in {time.monotonic() - t0:.1f}s")
    print(f"    Sessions: {data['stats']['total_sessions']} | Logins: {data['stats']['total_login_attempts']} | "
          f"Success: {data['stats']['successful_logins']} | IPs: {data['stats']['unique_ips']}")

    # Pass 2: fill in what needed the LLM, if it's up.
    LLM_ENABLED = True
    if _llm_pending and _check_ollama_once():
        print(f"[*] {_llm_pending} description(s) need the LLM; generating...")
        write_outputs(*render_dashboard(data))
        print(f"[\u2713] Dashboard updated with LLM descriptions in {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"[FATAL] {e}")
        traceback.print_exc()
        sys.exit(1)
