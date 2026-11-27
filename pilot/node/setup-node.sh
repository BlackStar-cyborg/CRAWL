#!/usr/bin/env bash
# setup-node.sh (v2) - configure an Ubuntu 24.04 VPS as a CRAWL node. Safe to re-run.
#
# Run ON THE NODE, as your normal user with sudo:
#   sudo bash setup-node.sh                                         # HTTP only, bare IP
#   sudo DOMAIN=example.ch CERT_EMAIL=you@uzh.ch bash setup-node.sh # + domain + HTTPS
#
# Variables (all optional):
#   DOMAIN       also serve this name and get a Let's Encrypt certificate for it.
#                Its DNS A record must already point at this server, and port 80 must be
#                open in the provider firewall (Let's Encrypt checks over HTTP).
#   CERT_EMAIL   e-mail for Let's Encrypt expiry notices (required with DOMAIN)
#   CERT         now (default) or later: with "later", the domain is configured for HTTP but
#                no certificate is requested yet. Use it to deploy the tokens BEFORE the
#                certificate announces the domain in Certificate Transparency logs, then
#                re-run without CERT=later.
#   TLS_ON_IP    reject (default): HTTPS connections that do not ask for DOMAIN (e.g. scanners
#                that connect to the bare IP) are refused during the handshake, so the
#                certificate does not reveal the domain name to IP-range scanners.
#                cert: serve the domain certificate to them anyway.
#   HC_URL       heartbeat URL (e.g. healthchecks.io), pinged while the log is growing
#
# What it sets up:
#   nginx  ->  /var/log/crawl/requests.json.log      one JSON object per request, incl. all
#                                                    headers in arrival order (njs)
#              /var/log/crawl/requests.combined.log  the same requests in Apache "combined"
#              /var/log/crawl/acme.json.log          Let's Encrypt validation requests only
#   web root /var/www/crawl, owned by you, so deploy-site.sh can rsync without sudo
#   logrotate (daily, compressed, never deleted), UTC + NTP, SSH key-only, ufw 22/80/443
#   with DOMAIN: certificate (renewed automatically), issue/renewal times in
#                /var/log/crawl/cert-issued.txt
#
# Every run first backs up /etc/nginx to /root/nginx-backup-<time> and restores it
# if the new configuration does not pass "nginx -t".

set -euo pipefail

DOMAIN="${DOMAIN:-}"
CERT_EMAIL="${CERT_EMAIL:-}"
TLS_ON_IP="${TLS_ON_IP:-reject}"
CERT="${CERT:-now}"
HC_URL="${HC_URL:-}"
LOG_DIR=/var/log/crawl
WEB_ROOT=/var/www/crawl
ADMIN_USER="${SUDO_USER:-root}"
JS_SO=/usr/lib/nginx/modules/ngx_http_js_module.so
JS_LOAD_CONF=/etc/nginx/modules-enabled/60-crawl-http-js.conf
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/root/nginx-backup-$STAMP"

die() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run with sudo"
if [ -n "$DOMAIN" ]; then
  [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$ ]] || die "DOMAIN looks wrong: $DOMAIN"
  [[ "$CERT_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "DOMAIN is set: CERT_EMAIL (valid e-mail) is required"
fi
[[ "$TLS_ON_IP" =~ ^(reject|cert)$ ]] || die "TLS_ON_IP must be reject or cert"
[[ "$CERT" =~ ^(now|later)$ ]] || die "CERT must be now or later"
[ "$ADMIN_USER" != root ] || echo "WARNING: run via sudo from your normal user, so the web root gets the right owner."
. /etc/os-release
[ "${ID:-}" = ubuntu ] || echo "WARNING: written for Ubuntu 24.04, this is ${PRETTY_NAME:-unknown}."

echo "== Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq nginx ufw unattended-upgrades rsync curl jq certbot openssl
if apt-get install -yq libnginx-mod-http-js; then :; else
  echo "WARNING: libnginx-mod-http-js not installable - logging without the header list."
fi

echo "== Time: UTC, NTP on"
timedatectl set-timezone UTC
timedatectl set-ntp true

echo "== Automatic security updates"
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "== SSH: key-only login (only if a key is installed, so you can't lock yourself out)"
AUTH_KEYS="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
if [ -s "$AUTH_KEYS" ]; then
  cat > /etc/ssh/sshd_config.d/10-crawl.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
  sshd -t && systemctl reload ssh
else
  echo "WARNING: no key in $AUTH_KEYS - password login left ON. Add a key and re-run."
fi

echo "== Firewall (ufw): SSH, HTTP, HTTPS only"
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable

echo "== Directories"
mkdir -p "$LOG_DIR"
chown root:adm "$LOG_DIR"
chmod 0750 "$LOG_DIR"
[ "$ADMIN_USER" = root ] || usermod -aG adm "$ADMIN_USER"
mkdir -p "$WEB_ROOT/.well-known/acme-challenge"
if [ ! -e "$WEB_ROOT/index.html" ]; then
  printf '<!doctype html>\n<html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>\n' \
    > "$WEB_ROOT/index.html"
fi
[ "$ADMIN_USER" = root ] || chown -R "$ADMIN_USER": "$WEB_ROOT"
chmod 0755 "$WEB_ROOT"

echo "== Backing up /etc/nginx to $BACKUP"
cp -a /etc/nginx "$BACKUP"
restore_and_die() {
  echo "Restoring the previous nginx configuration from $BACKUP" >&2
  rsync -a --delete "$BACKUP/" /etc/nginx/
  nginx -t && systemctl restart nginx || true
  die "$1"
}

# ---------------------------------------------------------------------------------------
# nginx configuration
# ---------------------------------------------------------------------------------------
NJS=0
if [ -f "$JS_SO" ]; then
  NJS=1
  # Ubuntu's package normally enables the module itself in modules-enabled. Load it ourselves
  # only if nothing else does - loading it twice makes nginx refuse to start.
  rm -f "$JS_LOAD_CONF"
  if ! grep -Eqs '^[[:space:]]*load_module[[:space:]].*ngx_http_js_module' /etc/nginx/modules-enabled/*.conf; then
    echo "load_module $JS_SO;" > "$JS_LOAD_CONF"
  fi
fi

write_log_conf() {   # $1 = 1: with header list (njs), 0: without
  mkdir -p /etc/nginx/njs
  {
    echo "# CRAWL request log format. Field names as in playground/nginx/nginx.conf, plus TLS fields."
    echo "# bytes_sent is the body size (\$body_bytes_sent), as in the playground."
    if [ "$1" = 1 ]; then
      cat <<'EOF'
js_path   /etc/nginx/njs/;
js_import crawlheaders from crawl-headers.js;
js_set    $crawl_raw_headers crawlheaders.raw;
EOF
    fi
    cat <<'EOF'
log_format crawl_json escape=json
    '{'
      '"ts":"$time_iso8601","msec":"$msec","request_id":"$request_id",'
      '"client_ip":"$remote_addr","client_port":"$remote_port",'
      '"server_ip":"$server_addr","server_port":"$server_port","scheme":"$scheme",'
      '"host":"$host","http_host":"$http_host",'
      '"method":"$request_method","uri":"$request_uri","protocol":"$server_protocol","raw_request":"$request",'
      '"status":"$status","bytes_sent":"$body_bytes_sent","request_length":"$request_length",'
      '"request_time":"$request_time","connection":"$connection","connection_requests":"$connection_requests",'
      '"user_agent":"$http_user_agent","referer":"$http_referer","accept":"$http_accept",'
      '"accept_language":"$http_accept_language","accept_encoding":"$http_accept_encoding",'
      '"x_forwarded_for":"$http_x_forwarded_for",'
      '"ssl_protocol":"$ssl_protocol","ssl_cipher":"$ssl_cipher","ssl_server_name":"$ssl_server_name",'
EOF
    if [ "$1" = 1 ]; then
      echo "      '\"headers\":\"\$crawl_raw_headers\"'"
    else
      echo "      '\"headers\":\"\"'"
    fi
    echo "    '}';"
  } > /etc/nginx/conf.d/00-crawl-log.conf
}

mkdir -p /etc/nginx/njs
cat > /etc/nginx/njs/crawl-headers.js <<'EOF'
// All request headers as [[name, value], ...] in the order the client sent them
// (header order is a client fingerprint). Used by /etc/nginx/conf.d/00-crawl-log.conf.
function raw(r) {
    try { return JSON.stringify(r.rawHeadersIn); } catch (e) { return "[]"; }
}
export default { raw };
EOF

mkdir -p /etc/nginx/snippets
cat > /etc/nginx/snippets/crawl-site.conf <<'EOF'
# Shared by every CRAWL server block (bare IP, domain, HTTP, HTTPS): same content, same logs.
# The "host", "scheme" and "ssl_server_name" log fields tell the channels apart.
root /var/www/crawl;
index index.html;
server_tokens off;   # "Server: nginx" without version - an experimental variable, change deliberately

access_log /var/log/crawl/requests.json.log     crawl_json;
access_log /var/log/crawl/requests.combined.log combined;
error_log  /var/log/crawl/error.log warn;

# Server level only: an add_header inside a location would silently drop these two.
add_header Referrer-Policy "same-origin" always;   # browsers send no Referer to other sites
add_header Cache-Control "no-store" always;        # every re-fetch reaches the log

# Let's Encrypt validation: own log, so it does not show up as crawler traffic
location ^~ /.well-known/acme-challenge/ {
    access_log /var/log/crawl/acme.json.log crawl_json;
    default_type text/plain;
    try_files $uri =404;
}

location / {
    try_files $uri $uri/ =404;
}

# Token URLs: real and guessed /docs/* URLs get the same landing page (status 200), so the
# response does not reveal which tokens exist, and a resolver has a reason to keep browsing.
location /docs/ {
    try_files $uri /decoy.html;
}
EOF

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
have_cert() { [ -n "$DOMAIN" ] && [ -s "$CERT_DIR/fullchain.pem" ] && [ -s "$CERT_DIR/privkey.pem" ]; }

write_site_conf() {
  local f=/etc/nginx/sites-available/crawl
  cat > "$f" <<'EOF'
# CRAWL node - generated by pilot/node/setup-node.sh; re-run the script instead of editing.

# Bare IP and unknown Host headers (most scanners land here)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    include snippets/crawl-site.conf;
}
EOF
  if [ -n "$DOMAIN" ]; then
    cat >> "$f" <<'EOF'

# The domain over HTTP (no redirect to HTTPS: both stay observable)
server {
    listen 80;
    listen [::]:80;
    server_name __DOMAIN__;
    include snippets/crawl-site.conf;
}
EOF
  fi
  if have_cert; then
    cat >> "$f" <<'EOF'

# The domain over HTTPS
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name __DOMAIN__;
    ssl_certificate     /etc/letsencrypt/live/__DOMAIN__/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/__DOMAIN__/privkey.pem;
    include snippets/crawl-site.conf;
}
EOF
    if [ "$TLS_ON_IP" = reject ]; then
      cat >> "$f" <<'EOF'

# HTTPS to the bare IP / other names: refuse the handshake, do not hand out the certificate
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOF
    fi
  fi
  sed -i "s/__DOMAIN__/$DOMAIN/g" "$f"
  rm -f /etc/nginx/sites-enabled/default
  ln -sf "$f" /etc/nginx/sites-enabled/crawl
}

apply_nginx() {
  write_log_conf "$NJS"
  write_site_conf
  if nginx -t 2>/tmp/crawl-nginx-test.txt; then :;
  elif [ "$NJS" = 1 ]; then
    cat /tmp/crawl-nginx-test.txt
    echo "WARNING: config with njs failed - retrying without the header list."
    NJS=0
    rm -f "$JS_LOAD_CONF"
    write_log_conf 0
    nginx -t 2>/tmp/crawl-nginx-test.txt || { cat /tmp/crawl-nginx-test.txt; restore_and_die "nginx -t failed"; }
  else
    cat /tmp/crawl-nginx-test.txt
    restore_and_die "nginx -t failed"
  fi
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx || restore_and_die "nginx did not start"
}

echo "== nginx configuration"
apply_nginx

# ---------------------------------------------------------------------------------------
# TLS certificate
# ---------------------------------------------------------------------------------------
CERT_NOTE="no DOMAIN set: HTTP only"
if [ -n "$DOMAIN" ]; then
  # Runs after every automatic renewal (certbot.timer): reload nginx and record the time.
  # Each renewal is a new Certificate Transparency entry, i.e. a new discovery event.
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/crawl-reload-and-record.sh <<'EOF'
#!/bin/sh
systemctl reload nginx
{
  echo "Certificate for ${RENEWED_DOMAINS:-?} renewed at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  openssl x509 -in "$RENEWED_LINEAGE/cert.pem" -noout -serial -startdate -enddate -fingerprint -sha256
} >> /var/log/crawl/cert-issued.txt
EOF
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/crawl-reload-and-record.sh
  if have_cert; then
    CERT_NOTE="existing certificate for $DOMAIN kept (certbot renews it automatically)"
  elif [ "$CERT" = later ]; then
    CERT_NOTE="CERT=later: $DOMAIN served over HTTP only, no certificate requested yet"
  else
    echo "== TLS certificate for $DOMAIN"
    echo "   Note: issuing publishes $DOMAIN in Certificate Transparency logs (a discovery channel)."
    CB=(certbot certonly --webroot -w "$WEB_ROOT" -d "$DOMAIN" --cert-name "$DOMAIN"
        --non-interactive --agree-tos -m "$CERT_EMAIL" --no-eff-email)
    # Dry run against the staging CA first: checks DNS + port 80 without using up real rate limits.
    # (The staging certificate can appear in test CT logs too, so its time is recorded as well.)
    echo "Staging dry run for $DOMAIN at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG_DIR/cert-issued.txt"
    if ! "${CB[@]}" --dry-run; then
      CERT_NOTE="FAILED: dry run did not validate. Check that $DOMAIN's A record points here and port 80 is open in the provider firewall, then re-run. HTTP works meanwhile."
    elif ! "${CB[@]}"; then
      CERT_NOTE="FAILED: issuance failed after a successful dry run - see /var/log/letsencrypt/letsencrypt.log"
    else
      {
        echo "Certificate for $DOMAIN issued at $(date -u +%Y-%m-%dT%H:%M:%SZ) (CT log entry follows within minutes)"
        openssl x509 -in "$CERT_DIR/cert.pem" -noout -serial -startdate -enddate -fingerprint -sha256
      } | tee -a "$LOG_DIR/cert-issued.txt"
      apply_nginx
      CERT_NOTE="certificate issued, HTTPS on"
    fi
  fi
fi

echo "== Log rotation: daily, compressed, kept ~10 years"
cat > /etc/logrotate.d/crawl <<'EOF'
/var/log/crawl/*.log {
    daily
    rotate 3650
    dateext
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1 || nginx -s reopen
    endscript
}
EOF
logrotate -d /etc/logrotate.d/crawl >/dev/null 2>&1 || echo "WARNING: logrotate -d reported a problem"

if [ -n "$HC_URL" ]; then
  echo "== Heartbeat: ping every 30 min while the request log is being written"
  cat > /etc/cron.d/crawl-heartbeat <<EOF
*/30 * * * * root find $LOG_DIR/requests.json.log -mmin -120 | grep -q . && curl -fsS -m 10 "$HC_URL" > /dev/null
EOF
elif [ -f /etc/cron.d/crawl-heartbeat ]; then
  sed -i 's#/access\.json\.log#/requests.json.log#' /etc/cron.d/crawl-heartbeat   # v1 used the old log name
fi

echo "== Self-test"
sleep 1
curl -s -o /dev/null -A "crawl-setup-selftest" http://127.0.0.1/robots.txt || true
sleep 1
LAST="$(tail -n 1 "$LOG_DIR/requests.json.log" 2>/dev/null || true)"
if echo "$LAST" | jq -e '.user_agent == "crawl-setup-selftest"' >/dev/null 2>&1; then
  HDRS="$(echo "$LAST" | jq -r '.headers')"
  if [ "$NJS" = 1 ] && echo "$HDRS" | jq -e 'length > 0' >/dev/null 2>&1; then
    SELFTEST="OK - JSON log written, header list: $HDRS"
  else
    SELFTEST="OK - JSON log written, but WITHOUT header list"
  fi
else
  SELFTEST="FAILED - no self-test line in $LOG_DIR/requests.json.log"
fi

echo
echo "==================================================================="
echo " nginx:    $(nginx -v 2>&1 | sed 's/^nginx version: //')   njs header logging: $([ "$NJS" = 1 ] && echo on || echo off)"
echo " TLS:      $CERT_NOTE"
echo " Logs:     $LOG_DIR/requests.json.log (+ .combined.log, acme.json.log)"
echo " Self-test: $SELFTEST"
echo " Backup:   $BACKUP"
echo "==================================================================="
echo "The self-test request (127.0.0.1, user agent crawl-setup-selftest) is in the log - it is ours."
echo "If you were just added to group adm: log out and back in once to read $LOG_DIR."
