# supervision.sh

Bash monitoring script designed to run via cron. Checks TCP ports, mail services, and HTTPS sites, logs all results with timestamps, and sends a single aggregated email alert when any check fails.

## What it checks

- **TCP ports** 80, 443 on `ns8-leader.example.com` (basic reachability via netcat)
- **SMTP** ports 25 (plain), 587 (STARTTLS), 465 (implicit TLS) — banner check via netcat/openssl
- **IMAP** port 143 (STARTTLS) and 993 (implicit TLS) — greeting check via netcat/openssl
- **HTTP status** (expects 200 after following redirects) on `app1.example.com` and `app2.example.com`
- **TLS certificate** — alerts only when the certificate has already expired (log always shows days remaining)

## Email alerts

Alert emails are sent via the local mail server of a **NethServer 8** instance. NethServer 8 exposes an unauthenticated, unencrypted SMTP relay on `localhost:10587` for local applications — this script is designed specifically for that setup.

## Requirements

- `bash` ≥ 4
- `nc` (netcat)
- `curl`
- `openssl`
- `timeout` (GNU coreutils)

## Installation

```bash
sudo cp supervision.sh /usr/local/bin/supervision.sh
sudo chmod 750 /usr/local/bin/supervision.sh
sudo touch /var/log/supervision.log
sudo chmod 640 /var/log/supervision.log
```

## Configuration

Edit the variables at the top of the script:

| Variable | Default | Description |
|---|---|---|
| `HOST_INFRA` | `ns8-leader.example.com` | Host for all service checks |
| `PORTS` | `(80 443)` | TCP ports probed with netcat (basic reachability) |
| `SITES` | `(app1.example.com ...)` | HTTPS sites to check |
| `LOG_FILE` | `/var/log/supervision.log` | Log output path |
| `TIMEOUT` | `10` | Connection timeout in seconds |
| `MAIL_RELAY` | `localhost` | SMTP relay host |
| `MAIL_PORT` | `10587` | SMTP relay port (no auth, no TLS) |
| `MAIL_FROM` | `supervision@example.com` | Sender address |
| `MAIL_TO` | `(admin@example.com ...)` | Recipient list (one per line in array) |

## Log format

```
[2026-06-19 09:35:04] [INFO] === Supervision run started ===
[2026-06-19 09:35:04] [OK  ] PORT 80 on ns8-leader.example.com is reachable
[2026-06-19 09:35:14] [OK  ] SMTP 25 on ns8-leader.example.com is responding
[2026-06-19 09:35:17] [OK  ] SMTP 465 on ns8-leader.example.com is responding
[2026-06-19 09:35:26] [OK  ] IMAP 993 on ns8-leader.example.com is responding
[2026-06-19 09:35:36] [OK  ] HTTP app1.example.com returned 200
[2026-06-19 09:35:36] [OK  ] CERT app1.example.com valid for 61 more days (expires: Aug 19 13:40:48 2026 GMT)
[2026-06-19 09:35:37] [INFO] Alert email sent to: admin@example.com
[2026-06-19 09:35:37] [INFO] === Supervision run finished ===
```

## Cron setup

Run as root (to write to `/var/log`). Add to root's crontab with `sudo crontab -e`:

```cron
*/15 * * * * /usr/local/bin/supervision.sh
```

## Manual test

```bash
# Syntax check
bash -n /usr/local/bin/supervision.sh

# Run once and inspect the log
sudo /usr/local/bin/supervision.sh && tail -30 /var/log/supervision.log
```

## Log rotation

Add `/etc/logrotate.d/supervision`:

```
/var/log/supervision.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
```
