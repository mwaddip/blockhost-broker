# Email Server Design — Broker Server

**Date**: 2026-02-27
**Server**: 95.179.128.177 (Debian 13 trixie)
**Purpose**: Receive-only mail server for odol.cash and blockhost.io with webmail access

## Requirements

- Inbound email only (outbound port 25 blocked by VPS provider)
- Two domains: odol.cash, blockhost.io
- Handful of named accounts (< 10), manually managed
- Webmail access via Roundcube
- Spam filtering with Junk folder + whitelist-from-webmail workflow
- All packages from Debian apt (no third-party repos)

## Components

| Component | Package | Version | Role | Listens |
|-----------|---------|---------|------|---------|
| Postfix | `postfix` | 3.10.5 | SMTP inbound | 0.0.0.0:25 (STARTTLS) |
| Rspamd | `rspamd` | 3.12.1 | Spam filter (milter) | 127.0.0.1:11332 (milter), 127.0.0.1:11334 (web UI) |
| Dovecot | `dovecot-imapd`, `dovecot-sieve` | 2.4.1 | IMAP + Sieve filtering | 127.0.0.1:143 |
| Roundcube | `roundcube`, `roundcube-plugins` | 1.6.13 | Webmail (PHP) | via nginx (mail.odol.cash:443) |
| PHP-FPM | `php-fpm` | 8.4 | PHP runtime for Roundcube | unix socket |

## Architecture

### Mail flow

```
Internet:25 → UFW → Postfix
                       ↓
                    Rspamd (milter, scores message)
                       ↓
              ┌────────┼────────────┐
              ↓        ↓            ↓
           score<6   score 6-12   score>12
           (clean)   (suspicious)  (spam)
              ↓        ↓            ↓
           Deliver   Deliver     Reject at SMTP
              ↓        ↓         (never stored)
           Inbox    Junk folder
              ↑        ↑
              └────────┘
                   ↑
            Dovecot (IMAP, reads Maildir)
                   ↑
            Roundcube (webmail, mail.odol.cash)
```

### Spam pipeline

1. **Greylisting** (Rspamd): Temporarily rejects first delivery attempt from unknown sender/IP/recipient triples. Legitimate servers retry after a few minutes; spambots don't.
2. **Scoring** (Rspamd): Each message gets a spam score based on headers, content, DNSBL, fuzzy hashes, etc.
3. **Thresholds**:
   - Score < 6: Deliver to Inbox
   - Score 6-12: Deliver with `X-Spamd-Result` header → Dovecot Sieve files to Junk
   - Score > 12: Reject at SMTP level (no backscatter)
4. **Learning** (Roundcube `markasjunk` plugin):
   - Move Junk → Inbox: POST to Rspamd `/learnham` (whitelist sender)
   - Move Inbox → Junk: POST to Rspamd `/learnspam` (blacklist sender)

### Virtual mailbox setup

- Virtual mailbox domains: `odol.cash`, `blockhost.io`
- System user `vmail` (uid/gid 5000) owns all mail
- Maildir storage: `/var/mail/vhosts/<domain>/<user>/`
- Account map: `/etc/postfix/vmailbox` (flat file, postmap hash)
- Passwords: Dovecot `passwd-file` at `/etc/dovecot/users` (doveadm pw -s BLF-CRYPT)

Adding an account:
```bash
# 1. Add to Postfix virtual mailbox map
echo "user@odol.cash odol.cash/user/" >> /etc/postfix/vmailbox
postmap /etc/postfix/vmailbox

# 2. Add to Dovecot password file
doveadm pw -s BLF-CRYPT  # generates password hash
echo "user@odol.cash:{BLF-CRYPT}$hash:::::" >> /etc/dovecot/users
```

### TLS

- Postfix STARTTLS on port 25: uses Let's Encrypt certs for odol.cash (already exists)
- Roundcube: nginx reverse proxy on `mail.odol.cash` with Let's Encrypt (certbot)
- Dovecot IMAP: localhost only, no TLS needed (Roundcube connects via 127.0.0.1)

### DNS

Current MX records (`10 odol.cash.` / `10 blockhost.io.`) point to the server's own A record — this already works for receiving mail. No DNS changes strictly required.

Optional cleanup:
- Add `A` record: `mail.odol.cash` → 95.179.128.177 (for webmail URL + explicit mail host)
- Change MX to: `10 mail.odol.cash.` (cleaner, explicit)
- Same for blockhost.io if desired

### Firewall

Add to UFW:
```bash
sudo ufw allow 25/tcp comment 'SMTP inbound'
```

IMAP (143) stays localhost-only. Roundcube served via nginx (443 already open).

### Nginx

New server block for `mail.odol.cash`:
- Proxy PHP to php-fpm unix socket
- Roundcube document root: `/var/lib/roundcube/public_html` (Debian package default)
- Optional: `/rspamd` location proxied to 127.0.0.1:11334 with basic auth

### Rspamd web UI

Proxied through nginx at `mail.odol.cash/rspamd/` behind HTTP basic auth. Shows spam stats, message history, and allows manual training.

## Packages (all from Debian 13 apt)

```bash
apt install postfix dovecot-imapd dovecot-sieve dovecot-managesieved \
    rspamd roundcube roundcube-plugins php-fpm
```

## What this design does NOT include

- Outbound email (port 25 blocked by VPS provider)
- SPF/DKIM/DMARC (not needed for receive-only)
- Database backend (flat files sufficient for < 10 accounts)
- ClamAV antivirus (heavy, Rspamd catches most threats)
- POP3 (IMAP only)
- Self-service account creation (manual only)
