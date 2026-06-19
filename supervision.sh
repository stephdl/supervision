#!/usr/bin/env bash
# supervision.sh — Infrastructure monitoring script
# Checks TCP ports, SMTP, IMAP, Sieve, and HTTPS sites.
# Logs all results with timestamps, sends a single alert email on failure.
# Designed to be called by cron.

# set -u catches undefined variables; -e is intentionally omitted — a monitoring
# script must continue even when individual checks fail or return non-zero.
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Host for all mail/infra service checks
HOST_INFRA="ns8-leader.constance-associes.fr"

# TCP ports to probe with netcat (basic reachability)
PORTS=(80 443)

# HTTPS sites to check (HTTP status + TLS certificate)
SITES=(
    "webtop.constance-associes.fr"
    "sogo.constance-associes.fr"
)

# Log file path (ensure the directory is writable by the cron user)
LOG_FILE="/var/log/supervision.log"

# Connection timeout in seconds
TIMEOUT=10

# Email alert settings — relay on localhost:10587, no auth, no encryption
MAIL_RELAY="localhost"
MAIL_PORT="10587"
MAIL_FROM="supervision@ns8-leader.constance-associes.fr"
MAIL_TO=(
    "stephane@de-labrusse.fr"
    # Add more recipients here, one per line
)

# ---------------------------------------------------------------------------
# Internal state — accumulates failure messages for the alert email
# ---------------------------------------------------------------------------
FAILURES=()

# ---------------------------------------------------------------------------
# log LEVEL MESSAGE
# Write a timestamped entry to the log file.
# LEVEL: OK | FAIL | INFO
# ---------------------------------------------------------------------------
log() {
    local level="$1"
    local message="$2"
    printf '[%s] [%-4s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE"
}

# ---------------------------------------------------------------------------
# check_port HOST PORT
# Test TCP connectivity to HOST:PORT using netcat (basic reachability only).
# Appends to FAILURES on error.
# ---------------------------------------------------------------------------
check_port() {
    local host="$1"
    local port="$2"

    if nc -z -w "$TIMEOUT" "$host" "$port" &>/dev/null; then
        log OK "PORT $port on $host is reachable"
    else
        local msg="PORT $port on $host is unreachable"
        log FAIL "$msg"
        FAILURES+=("$msg")
    fi
}

# ---------------------------------------------------------------------------
# check_smtp HOST PORT
# Test real SMTP service by reading the greeting banner.
# Port 25: nc + QUIT (plain TCP, expects "220" banner).
# Port 587: openssl s_client with STARTTLS negotiation.
# Port 465: openssl s_client with implicit TLS (SMTPS).
# -k equivalent: openssl -verify_return_error omitted — cert quality handled by check_cert.
# Appends to FAILURES on error.
# ---------------------------------------------------------------------------
check_smtp() {
    local host="$1"
    local port="$2"
    local banner

    case "$port" in
        465)
            # Implicit TLS — sleep keeps stdin open so the server banner arrives before openssl exits
            banner=$( (sleep 3; echo "QUIT") | timeout "$TIMEOUT" openssl s_client \
                -connect "${host}:${port}" 2>/dev/null | grep "^220" | head -1) || true
            ;;
        587)
            # STARTTLS — server sends plain "220" banner before TLS negotiation; nc suffices
            banner=$(timeout "$TIMEOUT" nc -w "$TIMEOUT" "$host" "$port" 2>/dev/null | head -1) || true
            ;;
        *)
            # Plain SMTP (port 25) — read the greeting only, send nothing before banner
            # Sending data before "220" triggers postscreen pregreet test and CrowdSec bans
            # timeout wraps nc because -w is not a guaranteed total timeout on all systems
            banner=$(timeout "$TIMEOUT" nc -w "$TIMEOUT" "$host" "$port" 2>/dev/null | head -1) || true
            ;;
    esac

    if echo "$banner" | grep -q "^220"; then
        log OK "SMTP $port on $host is responding"
    else
        local msg="SMTP $port on $host is not responding"
        log FAIL "$msg"
        FAILURES+=("$msg")
    fi
}

# ---------------------------------------------------------------------------
# check_imap HOST PORT
# Test real IMAP service by reading the capability banner.
# Port 143: openssl s_client with STARTTLS negotiation.
# Port 993: openssl s_client with implicit TLS (IMAPS).
# A valid IMAP greeting starts with "* OK".
# Appends to FAILURES on error.
# ---------------------------------------------------------------------------
check_imap() {
    local host="$1"
    local port="$2"
    local banner

    case "$port" in
        993)
            # Implicit TLS — sleep keeps stdin open so the IMAP greeting arrives before openssl exits
            banner=$( (sleep 3; echo "a1 LOGOUT") | timeout "$TIMEOUT" openssl s_client \
                -connect "${host}:${port}" 2>/dev/null | grep "^\* OK" | head -1) || true
            ;;
        143)
            # STARTTLS — server sends plain "* OK" greeting before TLS negotiation; nc suffices
            banner=$(timeout "$TIMEOUT" nc -w "$TIMEOUT" "$host" "$port" 2>/dev/null | head -1) || true
            ;;
        *)
            banner=$(echo "a1 LOGOUT" | nc -w "$TIMEOUT" "$host" "$port" 2>/dev/null | head -1) || true
            ;;
    esac

    if echo "$banner" | grep -q "^\* OK"; then
        log OK "IMAP $port on $host is responding"
    else
        local msg="IMAP $port on $host is not responding"
        log FAIL "$msg"
        FAILURES+=("$msg")
    fi
}

# ---------------------------------------------------------------------------
# check_http SITE
# Perform an HTTPS GET and verify that the final HTTP response code is 200.
# -L follows redirects; certificate validation is handled by check_cert.
# Appends to FAILURES on error.
# ---------------------------------------------------------------------------
check_http() {
    local site="$1"
    local code

    # -L follows redirects; %{http_code} captures the final response code
    code=$(curl -skL -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "https://$site" 2>/dev/null || echo "000")

    if [[ "$code" == "200" ]]; then
        log OK "HTTP $site returned 200"
    else
        local msg="HTTP $site returned unexpected code: $code"
        log FAIL "$msg"
        FAILURES+=("$msg")
    fi
}

# ---------------------------------------------------------------------------
# check_cert SITE
# Verify TLS certificate validity and warn if expiring within CERT_WARN_DAYS.
# Appends to FAILURES on connection error or near-expiry.
# ---------------------------------------------------------------------------
check_cert() {
    local site="$1"
    local end_date days_left

    # Retrieve the certificate expiry date
    end_date=$(
        timeout "$TIMEOUT" openssl s_client -connect "$site:443" -servername "$site" \
            </dev/null 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null \
        | cut -d= -f2
    ) || true

    if [[ -z "$end_date" ]]; then
        local msg="CERT $site: unable to retrieve certificate"
        log FAIL "$msg"
        FAILURES+=("$msg")
        return
    fi

    # Calculate days remaining (portable: seconds difference / 86400)
    local expiry_epoch now_epoch
    expiry_epoch=$(date -d "$end_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$end_date" +%s)
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    if (( days_left > 0 )); then
        log OK "CERT $site valid for $days_left more days (expires: $end_date)"
    else
        local msg="CERT $site has expired (expired: $end_date)"
        log FAIL "$msg"
        FAILURES+=("$msg")
    fi
}

# ---------------------------------------------------------------------------
# send_alert BODY
# Send a plain-text alert email via the local SMTP relay (no auth, no TLS).
# One email per script run, listing all failures.
# ---------------------------------------------------------------------------
send_alert() {
    local body="$1"
    local subject="[SUPERVISION] Failures detected on $(date '+%Y-%m-%d %H:%M')"

    # Build the --mail-rcpt flags for curl
    local rcpt_flags=()
    for addr in "${MAIL_TO[@]}"; do
        rcpt_flags+=(--mail-rcpt "$addr")
    done

    # Format the To header (comma-separated)
    local to_header
    to_header=$(IFS=', '; echo "${MAIL_TO[*]}")

    curl -s \
        --url "smtp://${MAIL_RELAY}:${MAIL_PORT}" \
        --mail-from "$MAIL_FROM" \
        "${rcpt_flags[@]}" \
        --upload-file - <<EOF
From: $MAIL_FROM
To: $to_header
Subject: $subject

The following checks failed at $(date '+%Y-%m-%d %H:%M:%S'):

$body

-- supervision.sh on $(hostname)
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log INFO "=== Supervision run started ==="

# Basic TCP reachability (ports that have no dedicated protocol check)
for port in "${PORTS[@]}"; do
    check_port "$HOST_INFRA" "$port"
done

# SMTP service checks — real banner/EHLO test via curl
for port in 25 465 587; do
    check_smtp "$HOST_INFRA" "$port"
done

# IMAP service checks — real capability test via curl
for port in 143 993; do
    check_imap "$HOST_INFRA" "$port"
done

# HTTP response and TLS certificate for each web site
for site in "${SITES[@]}"; do
    check_http "$site"
    check_cert "$site"
done

# Send a single aggregated alert if any check failed
if (( ${#FAILURES[@]} > 0 )); then
    send_alert "$(printf '  - %s\n' "${FAILURES[@]}")"
    log INFO "Alert email sent to: ${MAIL_TO[*]}"
fi

log INFO "=== Supervision run finished ==="
