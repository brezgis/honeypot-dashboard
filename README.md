# Honeypot Dashboard

A Cowrie SSH honeypot disguised as a Solana validator node, with a live web dashboard showing real-time attacker activity.

**Dashboard:** https://samovar-honeypot.duckdns.org (HTTP basic auth required)

## Architecture

```
Internet → Port 22 (iptables NAT → 2223) → Cowrie honeypot
                                                ↓
                                            JSON logs
                                                ↓
                              generate.py (parse + describe + render)
                                                ↓
                                          dashboard.html
                                                ↓
                                    serve.py ← nginx reverse proxy
                                                ↓
                                          HTTPS (Let's Encrypt)
```

Cowrie captures SSH login attempts and shell interactions. Every 5 minutes, `generate.py` parses the logs and regenerates the dashboard HTML. The result is served by a lightweight Python HTTP server behind nginx with TLS.

## The Bait

The honeypot is themed as a **Solana validator node** to attract crypto-targeting attackers:

- Fake Solana wallet with seed phrases in `.env`
- Planted credentials in `.bash_history`
- Realistic validator configuration files
- Enticing directory structure that rewards exploration

## Session Descriptions

Attacker sessions get human-readable descriptions via a 3-layer system:

1. **Command annotations** — Dictionary lookup for known commands (instant)
2. **Pattern matching** — Regex-based descriptions for common attack patterns
3. **Cached LLM** — qwen3:4b via Ollama generates descriptions for novel sessions, cached in `description_cache.json`

This keeps regeneration fast (most sessions hit cache) while still handling new attack patterns intelligently.

## File Structure

```
/home/dashboard/
├── README.md
└── app/
    ├── generate.py            # Log parser + dashboard generator
    ├── serve.py               # HTTP server (behind nginx)
    ├── analytics.py           # Analytics and statistics
    ├── dashboard.html          # Generated dashboard (output)
    ├── description_cache.json  # LLM description cache
    └── geoip_cache.json        # GeoIP lookup cache
```

## Regeneration

The dashboard auto-regenerates every 5 minutes via cron.

To regenerate manually:
```bash
cd /home/dashboard/app && python3 generate.py
```

## Tech Stack

- **Honeypot:** Cowrie (SSH/Telnet)
- **Dashboard:** Python (generate.py + serve.py)
- **LLM:** Ollama with qwen3:4b (CPU inference, no GPU)
- **Web:** nginx, Let's Encrypt (certbot)
- **Infrastructure:** Hetzner VPS, 32GB RAM, Ubuntu

## Connectivity

- **Reverse tunnel:** autossh maintains a persistent tunnel back to north (home server) on port 2224
- **SSH access:** Port 2222 (root, key-only)
- **Dashboard also available:** http://<YOUR_SERVER_IP>:8080
