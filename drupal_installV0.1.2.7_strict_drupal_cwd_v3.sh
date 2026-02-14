#!/usr/bin/env bash
set -Eeuo pipefail

# drupal_installV0.1.sh
# Drupal 11.3.3 all-in-one installer for Ubuntu 24.04 (root installs system components,
# www-data installs Drupal codebase + drush + site install).
#
# Key principles (per your要求):
# - System components: root
# - Drupal 拉取/安装: www-data (or set APP_USER, but default is www-data)
# - No ACL logic
# - Fix ownership/permissions for /var/www + /var/www/drupal + /var/www/.composer
# - Force COMPOSER_HOME and initialize www-data pubkeys (composer diagnose should pass)

########################################
# Config (override via env vars)
########################################
DRUPAL_VERSION="${DRUPAL_VERSION:-11.3.3}"
DRUPAL_DIR="${DRUPAL_DIR:-/var/www/drupal}"
WEB_ROOT="${WEB_ROOT:-${DRUPAL_DIR}/web}"

SCRIPT_VERSION="${SCRIPT_VERSION:-V0.1.2.7}"
SCRIPT_ID="drupal_install${SCRIPT_VERSION}"

APP_USER="${APP_USER:-www-data}"
DRUPAL_DIR="/var/www/drupal"

COMPOSER_BIN="${COMPOSER_BIN:-/usr/local/bin/composer}"
COMPOSER_HOME_DIR="${COMPOSER_HOME_DIR:-/var/www/.config/composer}"

DB_NAME="${DB_NAME:-drupal_db}"
DB_USER="${DB_USER:-drupal_user}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"

ALLOW_REINSTALL="${ALLOW_REINSTALL:-0}"  # 1 => always run site:install
SITE_URI="${SITE_URI:-}"                 # e.g. http://192.168.64.12

NGINX_SITE_CONF="${NGINX_SITE_CONF:-/etc/nginx/sites-available/drupal.conf}"
NGINX_SITE_ENABLED="${NGINX_SITE_ENABLED:-/etc/nginx/sites-enabled/drupal.conf}"

STATE_DIR="${STATE_DIR:-/var/lib/drupal-tools}"
CREDS_DIR="${CREDS_DIR:-${STATE_DIR}/credentials}"
CREDS_FILE="${CREDS_FILE:-${CREDS_DIR}/drupal_${DB_NAME}.env}"

LOG_DIR="${LOG_DIR:-/var/log/drupal-tools}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/${SCRIPT_ID}_${DRUPAL_VERSION}_$(date +%Y%m%d_%H%M%S).log}"

########################################
# Colors (terminal only)
########################################
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_MAG=$'\033[35m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAG=""
fi

########################################
# Logging helpers
########################################
_ts(){ date '+%Y-%m-%d %H:%M:%S'; }
_log_plain(){ printf '[%s] %s\n' "$(_ts)" "$1" >>"$LOG_FILE"; }
_log(){
  local color="$1"; shift
  local msg="$*"
  local line="[$(_ts)] ${msg}"
  printf '%s%s%s\n' "$color" "$line" "$C_RESET"
  _log_plain "$msg"
}
step(){ _log "$C_MAG" "==> $*"; }
info(){ _log "$C_BLUE" "$*"; }
ok(){ _log "$C_GREEN" "[OK] $*"; }
warn(){ _log "$C_YELLOW" "[WARN] $*"; }
err(){ _log "$C_RED" "[FATAL] $*"; }

die(){ err "$*"; exit 1; }

# Alias used by some blocks
fail(){ die "$@"; }

# Run a command as APP_USER using a *login shell* (su -), so CWD becomes /var/www for www-data.
# For Drupal-related composer operations, also cd into ${DRUPAL_DIR} if it exists.
# Ensure fixed Drupal project root exists and is writable by ${APP_USER}
ensure_drupal_root() {
  install -d -m 02775 -o "${APP_USER}" -g "${APP_USER}" "/var/www"
  install -d -m 02775 -o "${APP_USER}" -g "${APP_USER}" "${DRUPAL_DIR}"
}

# Run a command as APP_USER using a *login shell* (su -), always cd into /var/www/drupal.
# This is the "strict" mode you requested: any Drupal-related composer/drush runs from ${DRUPAL_DIR}.
as_app_user_drupal() {
  local cmd="$*"
  ensure_drupal_root
  su - "${APP_USER}" -s /bin/bash -c "cd \"${DRUPAL_DIR}\" && ${cmd}"
}

# Run explicitly in /var/www (for global composer ops like pubkeys/diagnose).
as_app_user_www() {
  local cmd="$*"
  install -d -m 02775 -o "${APP_USER}" -g "${APP_USER}" "/var/www"
  su - "${APP_USER}" -s /bin/bash -c "cd \"/var/www\" && ${cmd}"
}

########################################
# Shell / error handling
########################################
on_err(){
  local ec=$?
  err "Script failed (exit=$ec). See log: $LOG_FILE"
}
trap on_err ERR

########################################
# Preconditions
########################################
if [[ $EUID -ne 0 ]]; then
  die "Please run as root: sudo -E bash $0"
fi

mkdir -p "$LOG_DIR" || true
touch "$LOG_FILE" || true
chmod 0600 "$LOG_FILE" || true

_log "$C_BOLD" "=== Drupal ${DRUPAL_VERSION} install ${SCRIPT_VERSION} ==="
info "Log file: $LOG_FILE"

########################################
# Auto-detect SITE_URI
########################################
if [[ -z "${SITE_URI}" ]]; then
  HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "$HOST_IP" ]]; then
    SITE_URI="http://${HOST_IP}"
  else
    SITE_URI="http://localhost"
  fi
fi

########################################
# Utilities
########################################
apt_install(){
  local pkgs=("$@");
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
}
service_active(){ systemctl is-active --quiet "$1"; }

########################################
# 1) Base packages
########################################
step "BASELINE: base packages"
apt_install ca-certificates curl unzip git gnupg lsb-release software-properties-common jq openssl

########################################
# 2) PHP 8.3 + extensions
########################################
step "BASELINE: installing PHP 8.3 + extensions"
apt_install php8.3-fpm php8.3-cli php8.3-common php8.3-mysql php8.3-xml php8.3-gd php8.3-curl php8.3-mbstring php8.3-zip php8.3-intl php8.3-opcache php8.3-bcmath php-apcu
systemctl enable --now php8.3-fpm
service_active php8.3-fpm && ok "Service active: php8.3-fpm"

# Light tuning (idempotent)
PHP_FPM_INI=/etc/php/8.3/fpm/php.ini
PHP_CLI_INI=/etc/php/8.3/cli/php.ini
sed -i 's/^;\?cgi\.fix_pathinfo\s*=\s*.*/cgi.fix_pathinfo=0/' "$PHP_FPM_INI" || true
sed -i 's/^;\?memory_limit\s*=\s*.*/memory_limit=512M/' "$PHP_FPM_INI" || true
sed -i 's/^;\?upload_max_filesize\s*=\s*.*/upload_max_filesize=64M/' "$PHP_FPM_INI" || true
sed -i 's/^;\?post_max_size\s*=\s*.*/post_max_size=64M/' "$PHP_FPM_INI" || true
sed -i 's/^;\?max_execution_time\s*=\s*.*/max_execution_time=120/' "$PHP_FPM_INI" || true
sed -i 's/^;\?memory_limit\s*=\s*.*/memory_limit=512M/' "$PHP_CLI_INI" || true
systemctl reload php8.3-fpm || true
ok "PHP ready: $(php -v | head -n 1)"

########################################
# 3) MariaDB
########################################
step "BASELINE: installing MariaDB"
apt_install mariadb-server mariadb-client
systemctl enable --now mariadb
service_active mariadb && ok "Service active: mariadb"

########################################
# 4) Composer (root installs binary; www-data uses it)
########################################
step "BASELINE: ensuring Composer binary at ${COMPOSER_BIN}"
if [[ ! -x "$COMPOSER_BIN" ]]; then
  tmpdir="$(mktemp -d)"
  ( cd "$tmpdir" \
    && curl -fsSL https://getcomposer.org/installer -o composer-setup.php \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
  )
  rm -rf "$tmpdir"
  ok "Installed Composer: $(COMPOSER_ALLOW_SUPERUSER=1 $COMPOSER_BIN --version 2>/dev/null | head -n 1)"
else
  ok "Composer already present: $(COMPOSER_ALLOW_SUPERUSER=1 $COMPOSER_BIN --version 2>/dev/null | head -n 1)"
fi

########################################
# 5) Ownership/permissions for /var/www + COMPOSER_HOME
########################################
step "BASELINE: preparing /var/www ownership & COMPOSER_HOME for ${APP_USER}"
# Ensure directories exist
install -d -m 0755 -o www-data -g www-data /var/www
install -d -m 0755 -o www-data -g www-data "$COMPOSER_HOME_DIR"
chown -R www-data:www-data "$COMPOSER_HOME_DIR"

# Also include /var/www and /var/www/drupal (as you requested)
chown www-data:www-data /var/www || true
if [[ -d /var/www/drupal ]]; then
  chown -R www-data:www-data /var/www/drupal || true
fi

# Optional: ensure www-data can enter /var/www
chmod 0755 /var/www || true

########################################
# 6) www-data composer keys initialization (no ACL)
########################################
step "BASELINE: initializing Composer pubkeys for ${APP_USER} (COMPOSER_HOME=${COMPOSER_HOME_DIR})"

# Ensure XDG-style composer home exists (Composer 2 uses ~/.config/composer by default)
install -d -m 02775 -o "${APP_USER}" -g "${APP_USER}" /var/www
install -d -m 0755 -o "${APP_USER}" -g "${APP_USER}" "$(dirname "${COMPOSER_HOME_DIR}")"
install -d -m 0755 -o "${APP_USER}" -g "${APP_USER}" "${COMPOSER_HOME_DIR}"

# Backward compatible path (some setups still expect ~/.composer)
if [[ ! -e /var/www/.composer ]]; then
  ln -s ".config/composer" /var/www/.composer || true
fi

DEV_KEY="${COMPOSER_HOME_DIR}/keys.dev.pub"
TAGS_KEY="${COMPOSER_HOME_DIR}/keys.tags.pub"

# Download keys directly (avoid running composer as root / prompts)
if as_app_user_www "export COMPOSER_HOME=\"${COMPOSER_HOME_DIR}\"; umask 022; mkdir -p \"${COMPOSER_HOME_DIR}\"; curl -fsSL https://composer.github.io/snapshots.pub -o \"${COMPOSER_HOME_DIR}/keys.dev.pub\"; curl -fsSL https://composer.github.io/releases.pub  -o \"${COMPOSER_HOME_DIR}/keys.tags.pub\"; chmod 0644 \"${COMPOSER_HOME_DIR}/keys.dev.pub\" \"${COMPOSER_HOME_DIR}/keys.tags.pub\""; then
  ok "Composer pubkey files downloaded."
else
  warn "Could not download Composer pubkeys (network/TLS/DNS)."
fi

# Per-file visual check
if [[ -s "${TAGS_KEY}" ]]; then ok "keys.tags.pub: present"; else fail "keys.tags.pub: MISSING"; fi
if [[ -s "${DEV_KEY}"  ]]; then ok "keys.dev.pub : present"; else fail "keys.dev.pub : MISSING"; fi

# Verify with composer diagnose (best-effort; do not hard-fail install)
# NOTE: composer diagnose may fail if it cannot spawn subprocesses (e.g., git check).
# We treat this as non-fatal because pubkey files were already validated above.
SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

COMPOSER_DIAG=""
DIAG_EC=0

# Temporarily silence ERR trap & stop inheriting it into subshells/command substitutions
_OLD_ERR_TRAP="$(trap -p ERR || true)"
trap - ERR
set +E

if COMPOSER_DIAG="$(
  as_app_user "env -i HOME=\"/var/www\" PATH=\"${SAFE_PATH}\" COMPOSER_HOME=\"${COMPOSER_HOME_DIR}\" COMPOSER_CACHE_DIR=\"/var/www/.cache/composer\" ${COMPOSER_BIN} diagnose --no-ansi"
)"; then
  DIAG_EC=0
else
  DIAG_EC=$?
fi

# Restore shell error trap behavior
set -E
eval "${_OLD_ERR_TRAP}" 2>/dev/null || true

if [[ $DIAG_EC -ne 0 ]]; then
  warn "composer diagnose failed (exit=${DIAG_EC}). Continuing because pubkey files exist."
  warn "$(printf "%s\n" "${COMPOSER_DIAG}" | sed -n '1,30p' | sed 's/^/[composer] /')"
  warn "Common causes:"
  warn "  - git not found in PATH for ${APP_USER} (check: sudo -u ${APP_USER} -H command -v git)"
  warn "  - PHP CLI disables proc_open/shell_exec (check: php -i | grep -i disable_functions)"
else
  # Composer prints "OK" on a separate line after "Checking pubkeys:"
  PUBBLOCK="$(printf "%s\n" "${COMPOSER_DIAG}" | awk '
    /^Checking pubkeys:/{in=1; print; next}
    in && /^Checking /{exit}
    in{print}
  ' | head -n 12)"
  if printf "%s\n" "${PUBBLOCK}" | grep -Eq '^[[:space:]]*OK[[:space:]]*$'; then
    ok "Composer pubkeys: PASS ✅"
  else
    warn "Composer pubkeys: diagnose did not report OK (format change or partial output)."
    warn "$(printf "%s\n" "${PUBBLOCK}" | sed 's/^/[composer] /')"
    warn "Note: key files are present; continuing."
  fi
fi

fi

step "BASELINE: installing Nginx"

apt_install nginx
systemctl enable --now nginx
service_active nginx && ok "Service active: nginx"

# Baseline endpoint (works before Drupal exists)
cat > /var/www/_baseline.php <<'PHP'
<?php
header('Content-Type: text/plain; charset=utf-8');
echo "baseline_ok\n";
PHP
chown www-data:www-data /var/www/_baseline.php || true
chmod 0644 /var/www/_baseline.php || true

# Nginx site config
cat > "$NGINX_SITE_CONF" <<NGINX
server {
    listen 80;
    server_name _;

    root ${WEB_ROOT};
    index index.php index.html;

    location = /_baseline.php {
        root /var/www;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location / {
        try_files \$uri /index.php\$is_args\$args;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location ~* \.(?:css|js|jpg|jpeg|gif|png|svg|ico|webp|woff2?|ttf|eot)\$ {
        expires 7d;
        access_log off;
        add_header Cache-Control "public";
        try_files \$uri /index.php\$is_args\$args;
    }

    location ~* \.(?:txt|md)\$ {
        deny all;
    }
}
NGINX

ln -sf "$NGINX_SITE_CONF" "$NGINX_SITE_ENABLED"
rm -f /etc/nginx/sites-enabled/default || true
nginx -t
systemctl reload nginx
ok "Nginx ready."
info "Baseline endpoint: ${SITE_URI}/_baseline.php"
info "Nginx site config: ${NGINX_SITE_CONF}"

########################################
# 8) Credentials (resume-friendly)
########################################
step "INSTALL: preflight checks"
install -d -m 0700 -o root -g root "$CREDS_DIR"

DB_PASS=""
ADMIN_PASS=""
if [[ -f "$CREDS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CREDS_FILE"
  ok "Loaded saved credentials: $CREDS_FILE"
else
  DB_PASS="$(openssl rand -hex 16)"
  ADMIN_PASS="$(openssl rand -hex 12)"
  cat > "$CREDS_FILE" <<ENV
DB_NAME='${DB_NAME}'
DB_USER='${DB_USER}'
DB_PASS='${DB_PASS}'
DB_HOST='${DB_HOST}'
DB_PORT='${DB_PORT}'
SITE_URI='${SITE_URI}'
ADMIN_USER='admin'
ADMIN_PASS='${ADMIN_PASS}'
DRUPAL_DIR='${DRUPAL_DIR}'
DRUPAL_VERSION='${DRUPAL_VERSION}'
COMPOSER_HOME_DIR='${COMPOSER_HOME_DIR}'
ENV
  chmod 0600 "$CREDS_FILE"
  chown root:root "$CREDS_FILE"
  ok "Generated DB_PASS + ADMIN_PASS (saved for resume)."
  info "Credentials written to: $CREDS_FILE (root-only)"
fi

# Make sure vars exist (when sourced)
DB_PASS="${DB_PASS:-}"; ADMIN_PASS="${ADMIN_PASS:-}"

########################################
# 9) Ensure DB + user exist (idempotent)
########################################
step "INSTALL: ensuring DB + user exist (idempotent)"
# Note: use mariadb CLI as root (unix_socket auth)
mariadb -e "
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
" >/dev/null
ok "DB ready: ${DB_NAME} (user: ${DB_USER}@${DB_HOST}:${DB_PORT})"

########################################
# 10) Create Drupal codebase (www-data)
########################################
step "INSTALL: Drupal codebase"

# If directory exists but doesn't look like a composer-created Drupal project, decide what to do:
# - complete project => skip
# - empty directory  => reuse for create-project
# - non-empty junk   => move aside
NEED_CREATE_PROJECT=1
if [[ -d "${DRUPAL_DIR}" ]]; then
  if [[ -f "${WEB_ROOT}/sites/default/default.settings.php" && -f "${WEB_ROOT}/core/lib/Drupal.php" && -f "${DRUPAL_DIR}/composer.json" ]]; then
    ok "Drupal codebase detected; skipping create-project."
    NEED_CREATE_PROJECT=0
  else
    if [[ -z "$(ls -A "${DRUPAL_DIR}" 2>/dev/null || true)" ]]; then
      warn "Directory ${DRUPAL_DIR} exists and is empty; will use it for create-project."
      NEED_CREATE_PROJECT=1
    else
      TS_NOW="$(date +%Y%m%d_%H%M%S)"
      BACKUP_DIR="${DRUPAL_DIR}.broken_${TS_NOW}"
      warn "Directory ${DRUPAL_DIR} exists but looks incomplete. Moving it to: ${BACKUP_DIR}"
      mv "${DRUPAL_DIR}" "${BACKUP_DIR}"
      NEED_CREATE_PROJECT=1
    fi
  fi
fi

if [[ "${NEED_CREATE_PROJECT}" -eq 1 ]]; then
  # Ensure /var/www and target dir exist and are writable by www-data BEFORE create-project
  chown -R "${APP_USER}:${APP_USER}" /var/www || true
  install -d -m 02775 -o "${APP_USER}" -g "${APP_USER}" "${DRUPAL_DIR}"

  step "INSTALL: creating Drupal project via Composer as ${APP_USER}"
  # Run inside /var/www/drupal and use '.' so we keep the fixed root directory.
  as_app_user_drupal "export COMPOSER_HOME=\'${COMPOSER_HOME_DIR}\'; ${COMPOSER_BIN} create-project -n drupal/recommended-project:'${DRUPAL_VERSION}' ."
  chown -R www-data:www-data "$DRUPAL_DIR" || true
  ok "Drupal codebase created at: ${DRUPAL_DIR}"
fi

########################################
# 11) Ensure Drush exists (per-project)
########################################
step "INSTALL: ensuring Drush exists (per-project)"
if [[ -x "${DRUPAL_DIR}/vendor/bin/drush" ]]; then
  ok "Drush already installed: $(as_app_user_drupal "./vendor/bin/drush --version" | head -n 1)"
else
  as_app_user_drupal "export COMPOSER_HOME=\'${COMPOSER_HOME_DIR}\'; ${COMPOSER_BIN} require -n drush/drush"
  ok "Drush installed: $(as_app_user_drupal "./vendor/bin/drush --version" | head -n 1)"
fi

########################################
# 12) Site install (minimal) if needed
########################################
# Ensure sites/default/files exists and is writable by www-data
install -d -m 0775 -o www-data -g www-data "${WEB_ROOT}/sites/default/files"
chown -R www-data:www-data "${WEB_ROOT}/sites/default" || true

INSTALLED=0
if [[ -f "${WEB_ROOT}/sites/default/settings.php" ]]; then
  if as_app_user_drupal "./vendor/bin/drush status --format=json --uri='${SITE_URI}'" >/tmp/drush_status.json 2>/dev/null; then
    if jq -r '.bootstrap // ""' /tmp/drush_status.json 2>/dev/null | grep -qi 'successful'; then
      INSTALLED=1
    fi
  fi
fi

if [[ "$ALLOW_REINSTALL" == "1" ]]; then
  warn "ALLOW_REINSTALL=1 set; will run site:install even if already installed."
  INSTALLED=0
fi

if [[ "$INSTALLED" == "1" ]]; then
  ok "Existing Drupal site detected; will not reinstall."
else
  step "INSTALL: running drush site:install (minimal) as ${APP_USER}"
  as_app_user_drupal "./vendor/bin/drush -y site:install minimal \
    --db-url='mysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}' \
    --account-name=admin \
    --account-pass='${ADMIN_PASS}' \
    --site-name='Drupal' \
    --uri='${SITE_URI}'"
  ok "Drupal installation complete."
fi

########################################
# 13) Status report & final outputs
########################################
step "STATUS: Drush status (with --uri=${SITE_URI})"
if as_app_user_drupal "./vendor/bin/drush status --uri='${SITE_URI}'" 2>/dev/null | sed 's/^/[drush] /' | while IFS= read -r line; do info "$line"; done; then
  ok "Drush status OK."
else
  warn "Could not run drush status (bootstrap may have failed)."
fi

# One-time login URL (drush uli)
ULI=""
ULI="$(as_app_user_drupal "./vendor/bin/drush uli --uri='${SITE_URI}'" 2>/dev/null || true)"

# Admin password: if site already existed but creds file has ADMIN_PASS, show it.
ADMIN_PASS_OUT="${ADMIN_PASS:-}"
if [[ -z "$ADMIN_PASS_OUT" && -f "$CREDS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CREDS_FILE" || true
  ADMIN_PASS_OUT="${ADMIN_PASS:-}"
fi

info ""
_log "$C_BOLD" "========== INSTALL SUMMARY =========="
info "Open: ${SITE_URI}"
info "Login URL: ${SITE_URI}/user/login"
info "Admin user: admin"
if [[ -n "$ADMIN_PASS_OUT" ]]; then
  info "Admin password: ${ADMIN_PASS_OUT}"
else
  warn "Admin password: (unknown; check ${CREDS_FILE} if created by this script, or reset via drush)."
fi
if [[ -n "$ULI" ]]; then
  info "One-time login (drush uli): ${ULI}"
fi
info "Nginx site config: ${NGINX_SITE_CONF}"
info "Credentials file (root-only): ${CREDS_FILE}"
info "Log file: ${LOG_FILE}"
_log "$C_BOLD" "===================================="

ok "Done."

# Helpful tip for interactive usage
info "Tip: to enter ${APP_USER} interactive shell, run: sudo su - ${APP_USER} -s /bin/bash"
