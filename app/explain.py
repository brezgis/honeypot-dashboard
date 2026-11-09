"""Plain-English explanations of attacker commands.

explain(cmd) returns a short line like
    "unlocks ~/.ssh → plants an SSH key (mdrfckr botnet) → locks the key file"
or None if nothing recognisable happens.

Most attacker "commands" are chains (`a; b && c | d`) or whole shell scripts,
so instead of labelling a command by its first word, every behaviour rule is
searched across the full text and the hits are listed in the order they occur.
Known campaigns (recognisable by a fingerprint string) are named first.

Rules were written against 60 days of real samovar traffic (27.8k distinct
commands); tests/test_explain.py pins the important ones.
"""
import re
from functools import lru_cache

MAX_STEPS = 4

# (fingerprint regex, campaign name). Checked against the whole command.
CAMPAIGNS = [
    (r"mdrfckr", "mdrfckr SSH-key botnet"),
    (r"lockr\s+-ia\s+\.ssh", "mdrfckr SSH-key botnet"),
    (r"/tmp/(secure|auth)\.sh", "rival-cleanup dropper"),
    (r"D877F783D5D3EF8C|TelegramDesktop/tdata", "Telegram session stealer"),
    (r"===SHELL_BEHAVIOR===|xxxxxx", "sandbox-detection script"),
    (r"check_[0-9a-f]{32}|^\(\d+\*\d+\+\d+", "honeypot-detection probe"),
    (r"/home/cowrie|/opt/cowrie|/srv/cowrie|\bkippo\b", "honeypot hunter"),
    # Naming xmrig alone isn't enough: recon scripts grep for rival miners.
    (r"xmrig\S*\s+(-o|--url|-c)\b|--donate-level|(c3pool|supportxmr|nanopool|moneroocean)\.\w|stratum\+(tcp|ssl)://", "Monero miner"),
    (r"\bkinsing\b|kdevtmpfsi", "Kinsing miner"),
    (r"\bredtail\b", "RedTail miner"),
    (r"\bmirai\b|\bgafgyt\b|\bmozi\b", "Mirai-family IoT botnet"),
]

# (regex, label). Order only matters for ties at the same position.
_RULES = [
    # --- ssh key persistence / lockout
    (r"chattr\s+-[a-z]*i[a-z]*\s+\S*\.ssh", "unlocks ~/.ssh"),
    (r"lockr\s+-ia", "unlocks ~/.ssh"),
    (r"rm\s+-rf\s+\S*\.ssh\b", "wipes existing SSH keys"),
    (r"(echo|printf)\s.*ssh-(rsa|ed25519|dss)\s.*>>?\s*\S*authorized_keys|>>?\s*\S*authorized_keys", "plants its own SSH key"),
    (r"chmod\s+-R\s+go=\s+\S*\.ssh", "locks down ~/.ssh"),
    (r"chattr\s+\+[a-z]*i", "makes files undeletable (chattr +i)"),
    (r"ssh-keygen", "generates SSH keys"),
    # --- credentials / accounts
    (r"^\s*Enter new UNIX password|^\s*Retype new", "types blindly into a password prompt"),
    (r"(^|[;&|(]\s*)passwd(\s|$)|\|\s*passwd\b|chpasswd", "changes the root password"),
    (r"useradd|adduser", "creates a backdoor account"),
    (r"cat\s+/etc/shadow", "reads password hashes"),
    (r"cat\s+/etc/passwd", "lists user accounts"),
    # --- rivals / cleanup / anti-forensics
    (r"pkill|killall|kill\s+-9", "kills competing processes"),
    (r"grep\s.*(\[Mm\]|[Mm])iner", "checks for a rival miner"),
    (r"(>|echo\s*>)\s*/etc/hosts\.deny", "clears the IP blocklist (hosts.deny)"),
    (r"(HISTFILE|HISTSIZE)\s*=|unset\s+HISTFILE|history\s+-c", "disables shell history"),
    (r"rm\s+(-\w+\s+)*\S*(/var/log|\.log\b|\.bash_history)", "deletes logs"),
    (r"iptables|ufw\s|nft\s", "changes the firewall"),
    # --- payloads
    (r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data|aws_v2", "asks the cloud metadata service for credentials"),
    (r"(wget|curl|tftp|ftpget)\b[^;|&]*?(https?|ftp)://", "downloads a payload"),
    (r"\b(wget|curl)\b", "fetches something from the internet"),
    (r"\bscp\b", "copies files over SSH"),
    (r"base64\s+(-d|--decode)", "decodes a hidden payload"),
    (r"/dev/shm/\.", "stages a hidden file in RAM (/dev/shm)"),
    (r"chmod\s+(\+x|[0-7]*7[0-7]*)\s+'?\S*/\.", "makes a hidden file executable"),
    (r"chmod\s+(\+x|[0-7]*[1357])\b", "makes a file executable"),
    (r"(^|[;&|\s(])\./[\w.-]+|sh\s+\S+\.sh\b|bash\s+\S+\.sh\b", "runs it"),
    (r"nohup|setsid|disown|&\s*$", "runs it in the background"),
    (r"crontab\s+-l", "checks scheduled jobs"),
    (r"crontab\s+(?!-l)|/etc/cron", "adds a cron job (persistence)"),
    (r"systemctl\s+(enable|start)|/etc/systemd/system/", "installs a service (persistence)"),
    (r"/etc/rc\.local|\.bashrc|\.profile", "edits startup scripts (persistence)"),
    (r"(ba)?sh\s+-i\b.*(/dev/tcp/|>&)|0>&1|\bnc\s+-[a-z]*e\b|ncat\s.*-e\b|socat\s.*exec", "opens a reverse shell"),
    (r"exec\s+\d+<>/dev/tcp/", "downloads over a raw socket (no curl/wget needed)"),
    (r"python3?\s+-c|perl\s+-e", "runs an inline script"),
    # --- targeted hunting
    (r"locate\s+D877F783D5D3EF8C|TelegramDesktop", "hunts for Telegram session files"),
    (r"ttyGSM|ttyUSB|/var/spool/sms|smsd", "looks for SMS modems"),
    (r"^\s*/ip\s|/system\s+resource|mikrotik", "tries MikroTik router commands"),
    (r"mnemonic|seed phrase|AKIA|BEGIN (RSA|OPENSSH|EC) PRIVATE", "searches files for secrets (seed phrases, API keys)"),
    (r"\.ethereum|\.bitcoin|wallet\.dat|keystore|\.electrum|solana|id\.json", "looks for crypto wallets"),
    (r"\.aws/credentials|\.docker/config|\.kube/config|\.env\b", "looks for cloud credentials"),
    (r"docker\s+(ps|run|images)", "checks for Docker"),
    (r"nvidia-smi|lspci.*(vga|nvidia|3d)", "checks for a GPU"),
    # --- honeypot / sandbox detection
    (r"/home/cowrie|/opt/cowrie|/srv/cowrie|\bkippo\b", "looks for honeypot software (Cowrie)"),
    (r"\$\(\(\s*\d+\s*[-+*/]\s*\d+|^\(\d+\s*[-+*/]\s*\d+", "tests if the shell really does arithmetic"),
    (r"check_[0-9a-f]{32}_small_pid|\$\$", "checks its own process ID"),
    (r"check_[0-9a-f]{32}", "echoes random tokens to spot a fake shell"),
    (r"/proc/net/tcp6?\b.*0016|/proc/net/tcp", "checks what's listening on port 22"),
    (r"readlink\s+/proc/|/proc/\$\w+/(status|exe)", "inspects its own process"),
    (r"/tmp/\.hp[0-9a-f]+_", "tests if files it writes really persist"),
    (r"/proc/1/comm|/\.dockerenv|/proc/1/cgroup", "checks if it's inside a container"),
    (r"/proc/net/arp", "lists neighbouring machines"),
    (r"command\s+-v\s+busybox|^\s*busybox\s*$", "checks for BusyBox (IoT device?)"),
    (r"/root/lbu\.list|/etc/alpine-release", "checks for Alpine Linux"),
    (r"stat\s+-c\s+%a", "checks folder permissions"),
    (r"/dev/urandom", "reads random bytes (shell check)"),
    (r"cat\s+/bin/\w+|ls\s+-l\w*\s+/bin/", "inspects system binaries for tampering"),
    (r"echo\s+-e\s+['\"]?\\x", "echoes hex-encoded text (shell check)"),
    (r"^\s*echo\s+['\"]?[A-Za-z][\w-]{2,}['\"]?\s*$", "echoes a marker to confirm the login works"),
    # --- environment probing
    (r"echo\s+Hi\s*\|\s*cat\s+-n|echo\s+(ok|test|\$\?)\b|printf\s+'?%s", "checks the shell actually works"),
    (r"printf\s+['\"]#!/bin/(ba)?sh|>\s*filter\b", "tests if it can write and run scripts"),
    (r"dd\s+bs=\d+\s+count=", "reads raw bytes (honeypot check)"),
    (r"/proc/cpuinfo|lscpu|nproc|grep\s+-c\s+\^?processor", "counts CPU cores"),
    (r"free\s+(-\w+)?|/proc/meminfo", "checks RAM"),
    (r"\bdf\b|lsblk|/sys/block", "checks disk space"),
    (r"uname\s+-m|\barch\b|getconf\s+LONG_BIT", "checks CPU architecture"),
    (r"\buname\b|/proc/version|/etc/(os|lsb|alpine|redhat|debian)[-_]?(release|version)|hostnamectl", "identifies the OS"),
    (r"ssh\s+-V|sshd\s+-V", "checks the SSH version"),
    (r"/proc/loadavg", "checks system load"),
    (r"\bmount\b", "lists mounted filesystems"),
    (r"^\s*ls\s+-\w*\s+/\s*$|^\s*pwd\s*$", "looks around the filesystem"),
    (r"machine-id|dmidecode|/sys/class/dmi|product_(name|serial)", "fingerprints the hardware"),
    (r"\bwhoami\b|(^|[;&|\s])id(\s|$)", "checks its privileges"),
    (r"(^|[;&|\s])(w|who|last|lastlog)(\s|$)|last_output", "checks who else logs in"),
    (r"\btop\b|\bps\b", "lists running processes"),
    (r"ifconfig|\bip\s+(a|addr|route|link)\b|netstat|\bss\s+-", "maps the network"),
    (r"ls\s+-lh\s+\$\(which\s+ls\)|which\s+ls", "checks for tampered binaries"),
    (r"\bhostname\b", "reads the hostname"),
    (r"\buptime\b", "checks uptime"),
    (r"\benv\b|printenv", "dumps environment variables"),
    (r"\bhistory\b|\.bash_history", "reads shell history"),
]

# One-line descriptions for the Campaigns tile.
CAMPAIGN_INFO = {
    "mdrfckr SSH-key botnet": "Swaps root's SSH keys for its own (signed \u201cmdrfckr\u201d) and locks the folder so you can't undo it.",
    "rival-cleanup dropper": "Kills other malware (secure.sh, auth.sh) and clears the IP blocklist before moving in.",
    "Telegram session stealer": "Hunts for Telegram Desktop session files to hijack accounts, and checks for SMS modems.",
    "honeypot-detection probe": "Fires arithmetic and process-ID checks a fake shell might get wrong. Thousands of commands from a handful of IPs.",
    "sandbox-detection script": "Writes and runs a tiny script to see whether the box is real and lets it execute things.",
    "Monero miner": "Installs a cryptominer plus a cron job to keep it running.",
    "Kinsing miner": "Container-hunting cryptominer that kills rivals and digs in.",
    "RedTail miner": "Cryptominer spread through SSH brute force and web exploits.",
    "Mirai-family IoT botnet": "Recruits routers and cameras for DDoS attacks.",
    "honeypot hunter": "Looks for Cowrie's own install folders. (It is, in fact, talking to Cowrie.)",
}

_CAMPAIGNS = [(re.compile(p, re.I), name) for p, name in CAMPAIGNS]
_COMPILED = [(re.compile(p, re.I | re.M), label) for p, label in _RULES]
# Noise that would otherwise trip rules (`2>/dev/null` contains "dev").
_NOISE = re.compile(r"\s*\d?\s*>\s*/dev/null(\s*2>&1)?|\s*2>&1")


@lru_cache(maxsize=65536)
def campaign(cmd):
    """Name of a known campaign this command belongs to, or None."""
    for rx, name in _CAMPAIGNS:
        if rx.search(cmd):
            return name
    return None


# When the key label is present, the listed vaguer ones add nothing.
_SUPPRESS = {
    "downloads a payload": {"fetches something from the internet"},
    "asks the cloud metadata service for credentials": {"downloads a payload", "fetches something from the internet"},
    "echoes random tokens to spot a fake shell": {"echoes a marker to confirm the login works"},
    "makes a hidden file executable": {"makes a file executable"},
    "checks for Alpine Linux": {"identifies the OS"},
    "checks for a rival miner": {"lists running processes"},
}


def steps(cmd):
    """Behaviour labels found in cmd, in order of appearance, deduplicated."""
    return list(_steps(cmd or ""))


@lru_cache(maxsize=65536)
def _steps(cmd):
    text = _NOISE.sub("", cmd or "")
    hits = []
    for order, (rx, label) in enumerate(_COMPILED):
        m = rx.search(text)
        if m:
            hits.append((m.start(), order, label))
    found = {label for _p, _o, label in hits}
    drop = set().union(*(_SUPPRESS.get(label, set()) for label in found))
    out = []
    for _pos, _order, label in sorted(hits):
        if label not in out and label not in drop:
            out.append(label)
    return tuple(out)


def explain(cmd, max_steps=MAX_STEPS):
    """One-line explanation, or None. Campaign first, then up to max_steps steps."""
    found = steps(cmd)
    name = campaign(cmd)
    if not found and not name:
        return None
    shown = found[:max_steps]
    line = " → ".join(shown)
    if len(found) > max_steps:
        line += f" (+{len(found) - max_steps} more)"
    if name:
        return f"[{name}] {line}" if line else f"[{name}]"
    return line
