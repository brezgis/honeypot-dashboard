#!/usr/bin/env bash
# honeypot-watchdog.sh — email an alert (via Resend) when the honeypot or its
# dashboard stops working. Run from cron on the honeypot host, e.g.:
#   */15 * * * * root /usr/local/bin/honeypot-watchdog.sh
#
# Config in /etc/honeypot-watchdog.env (chmod 600):
#   RESEND_API_KEY=re_...
#   ALERT_FROM=Honeypot Watchdog <honeypot@mail.example.com>
#   ALERT_TO=you@example.com
#   DASHBOARD_URL=https://your-domain.example.com/   # optional, linked in alerts
#
# Behavior: alerts once on an OK->FAIL transition, reminds at most every
# REMIND_EVERY seconds while still broken, and sends one note on FAIL->OK.
# Run with --test to send a one-off test email and exit.
set -o pipefail

ENV_FILE="${HONEYPOT_WATCHDOG_ENV:-/etc/honeypot-watchdog.env}"
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

COWRIE_LOG="${COWRIE_LOG:-/home/cowrie/cowrie/var/log/cowrie/cowrie.json}"
DASHBOARD_HTML="${DASHBOARD_HTML:-/opt/honeypot-dashboard/data/dashboard.html}"
REDIRECT_PORT="${REDIRECT_PORT:-2223}"
DASHBOARD_MAX_AGE="${DASHBOARD_MAX_AGE:-1800}"   # dashboard.html must be < 30 min old
REMIND_EVERY="${REMIND_EVERY:-43200}"            # re-alert at most every 12h while broken
STALL_LIMIT="${STALL_LIMIT:-3}"                  # consecutive low-growth checks before alarm
FROM="${ALERT_FROM:-Honeypot Watchdog <honeypot@mail.example.com>}"
TO="${ALERT_TO:-}"
DASHBOARD_URL="${DASHBOARD_URL:-https://your-domain.example.com/}"

send() {  # $1=subject  $2=text-body
  if [ -z "${RESEND_API_KEY:-}" ] || [ -z "$TO" ]; then
    echo "watchdog: RESEND_API_KEY or ALERT_TO unset; cannot email" >&2; return 1
  fi
  local payload
  payload=$(FROM="$FROM" TO="$TO" SUBJECT="$1" BODY="$2" python3 -c '
import json, os
print(json.dumps({"from": os.environ["FROM"], "to": os.environ["TO"],
                  "subject": os.environ["SUBJECT"], "text": os.environ["BODY"]}))')
  curl -s -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer $RESEND_API_KEY" -H "Content-Type: application/json" \
    -d "$payload" >/dev/null
}

if [ "${1:-}" = "--test" ]; then
  if [ -z "${RESEND_API_KEY:-}" ] || [ -z "$TO" ]; then
    echo "RESEND_API_KEY or ALERT_TO unset in $ENV_FILE" >&2; exit 1
  fi
  payload=$(FROM="$FROM" TO="$TO" \
    SUBJECT="🐝 Honeypot watchdog test" \
    BODY="Test email from the honeypot watchdog on $(hostname) at $(date -u)." \
    python3 -c 'import json, os; print(json.dumps({"from": os.environ["FROM"], "to": os.environ["TO"], "subject": os.environ["SUBJECT"], "text": os.environ["BODY"]}))')
  echo "Resend response:"
  curl -s -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer $RESEND_API_KEY" -H "Content-Type: application/json" \
    -d "$payload"
  echo
  exit 0
fi

STATE_DIR="${WATCHDOG_STATE_DIR:-/var/lib/honeypot-watchdog}"
mkdir -p "$STATE_DIR"
STATE_FILE="$STATE_DIR/status"; ALERT_STAMP="$STATE_DIR/last_alert"
SIZE_FILE="$STATE_DIR/cowrie_size"; STALL_FILE="$STATE_DIR/cowrie_stalls"

now=$(date +%s)
problems=""
add() { problems="${problems}\n • $1"; }

# 1) Port-22 -> Cowrie redirect present? (the failure mode this watchdog exists for)
if ! iptables -t nat -S PREROUTING 2>/dev/null | grep -q -- "--dport 22 -j REDIRECT --to-ports ${REDIRECT_PORT}"; then
  add "iptables REDIRECT :22 -> :${REDIRECT_PORT} is MISSING — the honeypot is not receiving port-22 traffic."
fi

# 2) Dashboard container up + dashboard.html fresh?
if ! docker ps --filter name=honeypot-dashboard --filter status=running -q 2>/dev/null | grep -q .; then
  add "the honeypot-dashboard container is NOT running."
elif [ -f "$DASHBOARD_HTML" ]; then
  age=$(( now - $(stat -c %Y "$DASHBOARD_HTML" 2>/dev/null || echo "$now") ))
  [ "$age" -gt "$DASHBOARD_MAX_AGE" ] && add "dashboard.html hasn't regenerated in $((age/60)) min — the scheduler may be stuck."
else
  add "dashboard.html is missing ($DASHBOARD_HTML)."
fi

# 3) Cowrie log still growing? (size delta vs last run; tolerate daily rotation)
cur_size=$(stat -c %s "$COWRIE_LOG" 2>/dev/null || echo 0)
prev_size=$(cat "$SIZE_FILE" 2>/dev/null || echo 0)
echo "$cur_size" > "$SIZE_FILE"
if [ "$prev_size" -gt 0 ] && [ "$cur_size" -ge "$prev_size" ]; then
  if [ $(( cur_size - prev_size )) -lt 200 ]; then
    stalls=$(( $(cat "$STALL_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$stalls" > "$STALL_FILE"
    [ "$stalls" -ge "$STALL_LIMIT" ] && add "Cowrie log barely grew over the last $STALL_LIMIT checks — capture may be dead (Cowrie down?)."
  else
    echo 0 > "$STALL_FILE"
  fi
else
  echo 0 > "$STALL_FILE"   # rotated or first run
fi

# --- decide + notify ---
prev_status=$(cat "$STATE_FILE" 2>/dev/null || echo OK)
last_alert=$(cat "$ALERT_STAMP" 2>/dev/null || echo 0)

if [ -n "$problems" ]; then
  echo FAIL > "$STATE_FILE"
  if [ "$prev_status" = OK ] || [ $(( now - last_alert )) -ge "$REMIND_EVERY" ]; then
    body="$(printf 'The honeypot watchdog detected a problem on %s:\n%b\n\nChecked (UTC): %s\nDashboard: %s' "$(hostname)" "$problems" "$(date -u)" "$DASHBOARD_URL")"
    send "🚨 Honeypot problem detected" "$body" && echo "$now" > "$ALERT_STAMP"
  fi
else
  echo OK > "$STATE_FILE"
  if [ "$prev_status" = FAIL ]; then
    send "✅ Honeypot recovered" "$(printf 'All honeypot checks are passing again as of %s (UTC).' "$(date -u)")"
    : > "$ALERT_STAMP"
  fi
fi
