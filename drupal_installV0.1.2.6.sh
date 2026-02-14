#!/usr/bin/env bash
set -Eeuo pipefail
TS="$(date +%Y%m%d_%H%M%S)"
# TS is used for temporary filenames (avoid "unbound variable" under set -u).

# ------------------------------------------------------------
# Drupal 11.3.3 install v0.1.2
# Ubuntu 24.04 (noble) + Nginx + PHP-FPM + MariaDB + Composer
#
# Key design:
# - System components installed as root
# - Drupal codebase + drush install executed as www-data via:
#     su - www-data -s /bin/bash -c "..."
# - NO ACL logic
# - Fix "theme/style missing": prepare /var/www ownership/permissions before composer create-project
# - Fix "composer diagnose pubkeys FAIL": force COMPOSER_HOME for www-data + download keys + persist for login shells
# ------------------------------------------------------------

VERSION="0.1.2"
DRUPAL_VERSION="11.3.3"

APP_USER="${APP_USER:-www-data}"
APP_GROUP="${APP_GROUP:-www-data}"

TARGET_DIR="${TARGET_DIR:-/var/www/drupal}"
COMPOSER_HOME_DIR="/var/www/.composer"
COMPOSER_PUBKEYS_OK=0

WEB_ROOT="${WEB_ROOT:-$TARGET_DIR/web}"

DB_NAME="${DB_NAME:-drupal_db}"
DB_USER="${DB_USER:-drupal_user}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"

NGINX_SITE_CONF="${NGINX_SITE_CONF:-/etc/nginx/sites-available/drupal.conf}"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/drupal.conf"

CREDS_DIR="/var/lib/drupal-tools/credentials"
CREDS_FILE="${CREDS_DIR}/drupal_${DB_NAME}.env"

LOG_DIR="/var/log/drupal-tools"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/drupal_installV${VERSION}_${DRUPAL_VERSION}_$(date +%Y%m%d_%H%M%S).log"

# ---- colors (terminal only) ----
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi

log()   { echo "[${C_DIM}$(date '+%Y-%m-%d %H:%M:%S')${C_RESET}] $*"; }
info()  { log "${C_CYAN}$*${C_RESET}"; }
ok()    { log "${C_GREEN}[OK]${C_RESET} $*"; }
warn()  { log "${C_YELLOW}[WARN]${C_RESET} $*"; }
fail()  { log "${C_RED}[FAIL]${C_RESET} $*"; }
fatal() { log "${C_RED}[FATAL]${C_RESET} $*"; exit 1; }

on_err() {
  local ec=$?
  fatal "Script failed (exit=${ec}). See log: ${LOG_FILE}"
}
trap on_err ERR

# log everything to file (including command output)
exec > >(tee -a "$LOG_FILE") 2>&1

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fatal "Please run as root (use: sudo -E bash $0)"
  fi
}

detect_site_uri() {
  if [[ -n "${SITE_URI:-}" ]]; then
    echo "$SITE_URI"
    return
  fi
  local ip
  ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print $1; exit}')"
  [[ -z "$ip" ]] && ip="127.0.0.1"
  echo "http://${ip}"
}

apt_install() {
  local pkgs=("$@")
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

ensure_service_active() {
  local svc="$1"
  systemctl enable --now "$svc" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$svc"; then
    ok "Service active: ${svc}"
  else
    fatal "Service not active: ${svc}"
  fi
}

write_nginx_site() {
  local server_name="$1"
  install -d -m 0755 -o root -g root /etc/nginx/sites-available /etc/nginx/sites-enabled

  cat > "$NGINX_SITE_CONF" <<EOT
server {
  listen 80;
  server_name ${server_name};

  root ${WEB_ROOT};
  index index.php index.html;

  location = /_baseline.php { root /var/www; include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php8.3-fpm.sock; }

  location / {
    try_files \$uri /index.php?\$query_string;
  }

  location ~ \\.php\$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;
  }

  location ~* \\.(css|js|jpg|jpeg|png|gif|ico|svg|woff2?)\$ {
    expires 30d;
    add_header Cache-Control "public, max-age=2592000";
    try_files \$uri @rewrite;
  }

  location @rewrite {
    rewrite ^ /index.php?\$query_string;
  }

  location ~ /\\. {
    deny all;
  }
}
EOT

  ln -sf "$NGINX_SITE_CONF" "$NGINX_SITE_LINK"
  nginx -t
  systemctl reload nginx
  ok "Wrote: ${NGINX_SITE_CONF}"
}

ensure_composer() {
  log "==> BASELINE: ensuring Composer binary at /usr/local/bin/composer"
  # Ensure www-data home exists to avoid 'su: cannot change directory' warnings.
  install -d -m 0755 -o root -g root /var/www

  if command -v composer >/dev/null 2>&1; then
    ok "Composer binary present: $(command -v composer)"
  else
    info "Installing Composer..."
    curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php
    local expected actual
    expected="$(curl -fsSL https://composer.github.io/installer.sig)"
    actual="$(php -r "echo hash_file('sha384','/tmp/composer-setup.php');")"
    if [[ -z "${expected}" || "${expected}" != "${actual}" ]]; then
      rm -f /tmp/composer-setup.php
      fail "Composer installer signature mismatch (expected=${expected}, actual=${actual})."
      return 1
    fi
    php /tmp/composer-setup.php --quiet --install-dir=/usr/local/bin --filename=composer
    rm -f /tmp/composer-setup.php
    ok "Composer installed to: /usr/local/bin/composer"
  fi

  # Verify Composer as application user (avoid root prompts/warnings).
  local ver
  ver="$(su - "${APP_USER}" -s /bin/bash -c "env HOME=/var/www COMPOSER_HOME='${COMPOSER_HOME_DIR}' composer --version 2>/dev/null" || true)"
  if [[ -n "${ver}" ]]; then
    ok "Composer (as ${APP_USER}): ${ver}"
  else
    warn "Composer version check under ${APP_USER} did not produce output (will continue)."
  fi
}

prepare_www_permissions() {
  log "==> BASELINE: preparing /var/www ownership & COMPOSER_HOME for ${APP_USER}"
  # Create base directories (safe if already exist).
  install -d -m 0755 -o root -g root /var/www
  install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" /var/www/html
  install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${TARGET_DIR}"
  install -d -m 0755 -o "${APP_USER}" -g "${APP_GROUP}" "${COMPOSER_HOME_DIR}"

  # Ownership fixes to avoid theme/style permission issues.
  chown "${APP_USER}:${APP_GROUP}" /var/www || true
  chown -R "${APP_USER}:${APP_GROUP}" "${COMPOSER_HOME_DIR}" "${TARGET_DIR}" /var/www/html 2>/dev/null || true
  chmod 0755 /var/www /var/www/html "${TARGET_DIR}" "${COMPOSER_HOME_DIR}" || true
}

init_composer_keys_wwwdata() {
  log "==> BASELINE: initializing Composer pubkeys for ${APP_USER} (COMPOSER_HOME forced: ${COMPOSER_HOME_DIR})"
  COMPOSER_PUBKEYS_OK=0

  # Run diagnose (ignore failures), then parse pubkey lines.
  local diag
  diag="$(su - "${APP_USER}" -s /bin/bash -c "env HOME=/var/www COMPOSER_HOME='${COMPOSER_HOME_DIR}' composer diagnose --no-interaction 2>&1 || true")"
  if echo "${diag}" | grep -q "Checking pubkeys: OK"; then
    COMPOSER_PUBKEYS_OK=1
    ok "Composer pubkeys: OK"
    return 0
  fi

  warn "Composer pubkeys missing; downloading keys into ${COMPOSER_HOME_DIR}"
  su - "${APP_USER}" -s /bin/bash -c "set -e;
    export HOME=/var/www;
    export COMPOSER_HOME='${COMPOSER_HOME_DIR}';
    umask 022;
    curl -fsSL https://composer.github.io/snapshots.pub -o '${COMPOSER_HOME_DIR}/keys.dev.pub';
    curl -fsSL https://composer.github.io/releases.pub -o '${COMPOSER_HOME_DIR}/keys.tags.pub';
    chmod 0644 '${COMPOSER_HOME_DIR}/keys.dev.pub' '${COMPOSER_HOME_DIR}/keys.tags.pub';
  " || true

  diag="$(su - "${APP_USER}" -s /bin/bash -c "env HOME=/var/www COMPOSER_HOME='${COMPOSER_HOME_DIR}' composer diagnose --no-interaction 2>&1 || true")"
  if echo "${diag}" | grep -q "Checking pubkeys: OK"; then
    COMPOSER_PUBKEYS_OK=1
    ok "Composer pubkeys: OK (verified)"
  else
    fail "Composer pubkeys: FAIL"
    echo "${diag}" | grep -E "^Checking pubkeys:|^Missing pubkey|^Run composer self-update" | sed 's/^/[composer] /' || true
    warn "Fix (interactive): sudo su - ${APP_USER} -s /bin/bash"
    warn "Then run:"
    warn "  export COMPOSER_HOME=${COMPOSER_HOME_DIR}"
    warn "  curl -fsSL https://composer.github.io/snapshots.pub -o ${COMPOSER_HOME_DIR}/keys.dev.pub"
    warn "  curl -fsSL https://composer.github.io/releases.pub -o ${COMPOSER_HOME_DIR}/keys.tags.pub"
  fi
}

load_or_generate_credentials() {
  install -d -m 0700 -o root -g root "$CREDS_DIR"

  if [[ -f "$CREDS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CREDS_FILE"
    ok "Loaded saved credentials: ${CREDS_FILE}"
    return
  fi

  DB_PASS="$(openssl rand -hex 16)"
  ADMIN_PASS="$(openssl rand -hex 12)"

  cat > "$CREDS_FILE" <<EOC
# root-only credentials (generated by drupal_installV${VERSION}.sh)
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
ADMIN_USER=admin
ADMIN_PASS=${ADMIN_PASS}
EOC
  chmod 0600 "$CREDS_FILE"
  ok "Credentials written to: ${CREDS_FILE} (root-only)"
}

ensure_db_user_and_db() {
  log "==> INSTALL: ensuring DB + user exist (idempotent)"
  mariadb -e "
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';

ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';

GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';

FLUSH PRIVILEGES;
"
}

backup_partial_drupal_dir_if_needed() {
  if [[ -d "$TARGET_DIR" ]]; then
    if [[ -f "$TARGET_DIR/composer.json" && -d "$TARGET_DIR/web" && -d "$TARGET_DIR/vendor" ]]; then
      return
    fi
    local ts dest
    ts="$(date +%Y%m%d_%H%M%S)"
    dest="${TARGET_DIR}.broken_${ts}"
    warn "Directory ${TARGET_DIR} exists but looks incomplete; moving to ${dest}"
    mv "$TARGET_DIR" "$dest"
  fi
}

create_drupal_project_as_wwwdata() {
  info "==> INSTALL: creating Drupal project via Composer as ${APP_USER}"
  backup_partial_drupal_dir_if_needed

  install -d -m 0755 -o "$APP_USER" -g "$APP_GROUP" "$(dirname "$TARGET_DIR")"
  install -d -m 0755 -o "$APP_USER" -g "$APP_GROUP" "$TARGET_DIR"

  if [[ -f "$TARGET_DIR/composer.json" && -d "$TARGET_DIR/web" ]]; then
    ok "Drupal project already present; skipping create-project."
    return
  fi

  local cmd="
    set -e
    export COMPOSER_HOME=/var/www/.composer
    cd \"$(dirname "$TARGET_DIR")\"
    rm -rf \"$(basename "$TARGET_DIR")\"/*
    composer -n create-project drupal/recommended-project \"$(basename "$TARGET_DIR")\" ${DRUPAL_VERSION}
  "
  su - "$APP_USER" -s /bin/bash -c "$cmd"
  ok "Drupal codebase created at: ${TARGET_DIR}"
}

ensure_drush_as_wwwdata() {
  info "==> INSTALL: ensuring Drush exists (per-project)"
  if [[ -x "$TARGET_DIR/vendor/bin/drush" ]]; then
    ok "Drush already installed: $($TARGET_DIR/vendor/bin/drush --version 2>/dev/null || true)"
    return
  fi
  local cmd="
    set -e
    export COMPOSER_HOME=/var/www/.composer
    cd \"$TARGET_DIR\"
    composer -n require drush/drush
  "
  su - "$APP_USER" -s /bin/bash -c "$cmd"
  ok "Drush installed."
}

detect_existing_site() {
  [[ -f "$WEB_ROOT/sites/default/settings.php" ]] || return 1
  local cmd="
    set -e
    cd \"$TARGET_DIR\"
    ./vendor/bin/drush -q --uri=\"$SITE_URI\" status >/dev/null
  "
  su - "$APP_USER" -s /bin/bash -c "$cmd" >/dev/null 2>&1
}

install_drupal_minimal_as_wwwdata() {
  info "==> INSTALL: running drush site:install (minimal) as ${APP_USER}"

  local db_url="mysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
  local cmd="
    set -e
    cd \"$TARGET_DIR\"
    ./vendor/bin/drush -y --uri=\"$SITE_URI\" site:install minimal \
      --db-url='${db_url}' \
      --account-name=admin \
      --account-pass='${ADMIN_PASS}' \
      --site-name='Drupal'
  "
  su - "$APP_USER" -s /bin/bash -c "$cmd"
  ok "Drupal installation complete."
}

drush_status_report() {
  info "==> STATUS: Drush status (with --uri=${SITE_URI})"
  local cmd="
    set -e
    cd \"$TARGET_DIR\"
    ./vendor/bin/drush --uri=\"$SITE_URI\" status | sed 's/^/[drush] /'
  "
  if su - "$APP_USER" -s /bin/bash -c "$cmd"; then
    ok "Drush status OK."
  else
    warn "Drush status failed."
  fi
}

drush_one_time_login() {
  local cmd="
    set -e
    cd \"$TARGET_DIR\"
    ./vendor/bin/drush --uri=\"$SITE_URI\" uli
  "
  su - "$APP_USER" -s /bin/bash -c "$cmd" 2>/dev/null || true
}

write_baseline_endpoint() {
  cat > /var/www/_baseline.php <<'PHP'
<?php
header('Content-Type: text/plain; charset=utf-8');
echo "OK\n";
echo "time=" . date('c') . "\n";
PHP
  chown "$APP_USER:$APP_GROUP" /var/www/_baseline.php
  chmod 0644 /var/www/_baseline.php
}

main() {
  require_root

  info "=== Drupal ${DRUPAL_VERSION} install v${VERSION} ==="
  info "Log file: ${LOG_FILE}"

  SITE_URI="$(detect_site_uri)"
  info "Site URI: ${SITE_URI}"
  info "Target dir: ${TARGET_DIR}"

  info "==> BASELINE: base packages"
  apt_install ca-certificates curl unzip git gnupg lsb-release software-properties-common jq openssl

  info "==> BASELINE: installing PHP 8.3 + extensions"
  apt_install php8.3-fpm php8.3-cli php8.3-common php8.3-mysql php8.3-xml php8.3-gd php8.3-curl php8.3-mbstring php8.3-zip php8.3-intl php8.3-opcache php8.3-bcmath php-apcu
  ensure_service_active php8.3-fpm
  ok "PHP ready: $(php -v | head -n 1)"

  info "==> BASELINE: installing MariaDB"
  apt_install mariadb-server mariadb-client
  ensure_service_active mariadb

  ensure_composer

  prepare_www_permissions
  init_composer_keys_wwwdata

  info "==> BASELINE: installing Nginx"
  apt_install nginx
  ensure_service_active nginx

  write_baseline_endpoint

  local host_ip
  host_ip="$(echo "$SITE_URI" | sed -E 's#^https?://##')"
  write_nginx_site "${host_ip} localhost"
  ok "Baseline endpoint: ${SITE_URI}/_baseline.php"
  ok "Nginx site config: ${NGINX_SITE_CONF}"

  info "==> INSTALL: preflight checks"
  load_or_generate_credentials

  ensure_db_user_and_db

  create_drupal_project_as_wwwdata
  ensure_drush_as_wwwdata

  if detect_existing_site; then
    warn "Existing Drupal site detected (settings.php + drush bootstrap OK). Will not reinstall."
    ADMIN_PASS="(unknown; reset via Drush if needed)"
  else
    install_drupal_minimal_as_wwwdata
  fi

  drush_status_report

  local uli
  uli="$(drush_one_time_login || true)"

  log ""
  info "========== INSTALL SUMMARY =========="
  ok "Open: ${SITE_URI}"
  ok "Login URL: ${SITE_URI}/user/login"
  ok "Admin user: admin"
  ok "Admin password: ${ADMIN_PASS}"
  [[ -n "${uli:-}" ]] && ok "One-time login (drush uli): ${uli}"
  ok "Nginx site config: ${NGINX_SITE_CONF}"
  ok "Credentials file (root-only): ${CREDS_FILE}"
  ok "Log file: ${LOG_FILE}"
  info "===================================="
  ok "Done."
  log "Tip: to enter ${APP_USER} interactive shell, run: sudo su - ${APP_USER} -s /bin/bash"
  # Composer key status (pubkey verification)
  if [[ "${COMPOSER_PUBKEYS_OK:-0}" -eq 1 ]]; then
    ok "Composer pubkeys: OK."
  else
    fail "Composer pubkeys: FAIL (signature verification keys missing)."
    warn "Fix: sudo su - ${APP_USER} -s /bin/bash -c 'export COMPOSER_HOME=${COMPOSER_HOME_DIR}; composer self-update --update-keys'"
    warn "Verify: sudo su - ${APP_USER} -s /bin/bash -c 'export COMPOSER_HOME=${COMPOSER_HOME_DIR}; composer diagnose | sed -n \"1,25p\"'"
  fi
}

main "$@"
