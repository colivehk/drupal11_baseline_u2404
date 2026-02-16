#!/usr/bin/env bash
set -Eeuo pipefail

# drupal_installV7.5.6.sh
# Drupal 11.3.3 all-in-one installer for Ubuntu 24.04 (root installs system components,
# OPS_USER installs Drupal codebase + drush + site install (default ubuntu).
#
# Key principles (per your要求):
# - System components: root
# - Drupal codebase ops (composer/drush): OPS_USER (default ubuntu)
# - Web runtime writes: WEB_USER (default www-data) only for sites/default/files
# - Shared group + setgid prevents permission fights
# - Optional ACL support (installs 'acl' package) to avoid group-refresh Permission denied on drush cr
# - No whole-site chown to www-data
# - COMPOSER_HOME/Cache default to /home/<OPS_USER>

########################################
# Config (override via env vars)
########################################
DRUPAL_VERSION="${DRUPAL_VERSION:-11.3.3}"
DRUPAL_DIR="/var/www/drupal"
WEB_ROOT="${WEB_ROOT:-${DRUPAL_DIR}/web}"

SCRIPT_VERSION="${SCRIPT_VERSION:-V7.5.6}"
SCRIPT_FLAVOR="${SCRIPT_FLAVOR:-collab_perms}"
SCRIPT_ID="drupal_install${SCRIPT_VERSION}_${SCRIPT_FLAVOR}"

# Absolute path of this script (used in MAINTENANCE.md examples)
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"

# Back-compat: APP_USER is treated as WEB_USER (web runtime).
APP_USER="${APP_USER:-www-data}"

# Collaboration / ownership model (V7.5.3):
# - CODE_OWNER owns the codebase directory (edit/read)
# - WEB_USER is the web runtime user; ONLY sites/default/files must be writable by it
# - OPS_USER runs composer/drush for installs & maintenance (default = CODE_OWNER)
# - COLLAB_GROUP is the shared group so ubuntu + www-data can both maintain files
COLLAB_GROUP="${COLLAB_GROUP:-drupal}"
CODE_OWNER="${CODE_OWNER:-ubuntu}"
WEB_USER="${WEB_USER:-${APP_USER}}"
OPS_USER="${OPS_USER:-${CODE_OWNER}}"
OPS_HOME="$(getent passwd "${OPS_USER}" | awk -F: '{print $6}' || true)"
if [[ -z "${OPS_HOME}" ]]; then OPS_HOME="/home/${OPS_USER}"; fi

COMPOSER_BIN="${COMPOSER_BIN:-/usr/local/bin/composer}"
COMPOSER_HOME_DIR="${COMPOSER_HOME_DIR:-${OPS_HOME}/.config/composer}"
COMPOSER_CACHE_DIR="${COMPOSER_CACHE_DIR:-${OPS_HOME}/.cache/composer}"

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
# CLI args
########################################
FIX_PERMS_ONLY=0
ENABLE_ACL=0

print_help(){
  cat <<'EOF'
Usage:
  sudo -E bash drupal_installV7.5.6.sh [--fix-perms] [--acl]

Options:
  --fix-perms   Only normalize ownership/permissions on existing paths (no apt, no install, no mkdir)
  --acl         Apply ACL on sites/default/files for OPS_USER (prevents group-not-refreshed Permission denied on drush cr)
  --no-acl      Disable ACL application (default)
  -h, --help    Show this help

Notes:
  - Root is required.
  - Default model: CODE_OWNER=ubuntu, OPS_USER=ubuntu, WEB_USER=www-data (APP_USER works), COLLAB_GROUP=drupal
  - Full install mode installs 'acl' package so setfacl/getfacl are available (ACL is only applied when you pass --acl)
  - Override via env vars: CODE_OWNER=..., OPS_USER=..., WEB_USER=..., COLLAB_GROUP=... (or set APP_USER instead of WEB_USER)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fix-perms)
      FIX_PERMS_ONLY=1
      shift
      ;;
    --acl)
      ENABLE_ACL=1
      shift
      ;;
    --no-acl)
      ENABLE_ACL=0
      shift
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      print_help >&2
      exit 2
      ;;
  esac
done

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

# Run a command as OPS_USER using a *login shell* (su -), so HOME and env are correct.
# OPS_USER is used for composer/drush (install & maintenance).
# WEB_USER is the runtime user; ONLY sites/default/files must be writable by WEB_USER.
# Ensure collaboration group exists and CODE_OWNER/OPS_USER/WEB_USER are members.
ensure_collab_group() {
  if ! getent group "${COLLAB_GROUP}" >/dev/null 2>&1; then
    groupadd "${COLLAB_GROUP}"
    ok "Created group: ${COLLAB_GROUP}"
  fi

  # Add relevant users to the shared group (ignore missing users).
  for u in "${CODE_OWNER}" "${OPS_USER}" "${WEB_USER}"; do
    if id -u "${u}" >/dev/null 2>&1; then
      usermod -aG "${COLLAB_GROUP}" "${u}" || true
    else
      warn "User '${u}' does not exist; skip group membership."
    fi
  done
}

# Ensure fixed Drupal project root exists and matches the collab ownership model.
ensure_drupal_root() {
  ensure_collab_group

  # Base /var/www stays root-owned; subdirs are owned as needed.
  install -d -m 0755 -o root -g root "/var/www"

  # Codebase root: CODE_OWNER + COLLAB_GROUP, setgid for group inheritance
  install -d -m 02775 -o "${CODE_OWNER}" -g "${COLLAB_GROUP}" "${DRUPAL_DIR}"

  # Composer runtime dirs for OPS_USER (who runs composer/drush)
  install -d -m 02775 -o "${OPS_USER}" -g "${COLLAB_GROUP}" "${OPS_HOME}/.config"
  install -d -m 02775 -o "${OPS_USER}" -g "${COLLAB_GROUP}" "${COMPOSER_HOME_DIR}"
  install -d -m 02775 -o "${OPS_USER}" -g "${COLLAB_GROUP}" "${OPS_HOME}/.cache"
  install -d -m 02775 -o "${OPS_USER}" -g "${COLLAB_GROUP}" "${COMPOSER_CACHE_DIR}"
}

# Normalize ownership/permissions so ubuntu + www-data can both maintain the site without chmod/chown fights.
# - Codebase: CODE_OWNER:COLLAB_GROUP with group-writable bits
# - Runtime files/: WEB_USER:COLLAB_GROUP with group-writable bits
normalize_permissions() {
  ensure_drupal_root

  # Codebase (preserve exec bits; just ensure group is writable and dirs are setgid)
  chown -R "${CODE_OWNER}:${COLLAB_GROUP}" "${DRUPAL_DIR}" || true
  find "${DRUPAL_DIR}" -type d -exec chmod 2775 {} \; 2>/dev/null || true
  find "${DRUPAL_DIR}" -type f -exec chmod g+rw {} \; 2>/dev/null || true

  # Runtime files dir (only if WEB_ROOT exists; do not create a new codebase in --fix-perms mode)
  if [[ -d "${WEB_ROOT}" ]]; then
    install -d -m 02775 -o "${WEB_USER}" -g "${COLLAB_GROUP}" "${WEB_ROOT}/sites/default/files"
    chown -R "${WEB_USER}:${COLLAB_GROUP}" "${WEB_ROOT}/sites/default/files" || true
    find "${WEB_ROOT}/sites/default/files" -type d -exec chmod 2775 {} \; 2>/dev/null || true
    find "${WEB_ROOT}/sites/default/files" -type f -exec chmod g+rw {} \; 2>/dev/null || true
  else
    warn "WEB_ROOT not found (${WEB_ROOT}); skipping sites/default/files permission fix."
  fi

  # Composer cache/home
  chown -R "${OPS_USER}:${COLLAB_GROUP}" "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" 2>/dev/null || true
  find "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" -type d -exec chmod 2775 {} \; 2>/dev/null || true
  find "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" -type f -exec chmod g+rw {} \; 2>/dev/null || true

  if [[ "${ENABLE_ACL}" == "1" ]]; then
    apply_acl_runtime_files
  fi
}

# "Pure" permissions normalization: do NOT create any new directories.
# Only adjusts ownership/permissions on paths that already exist.
normalize_permissions_pure() {
  ensure_collab_group

  # Codebase
  if [[ -d "${DRUPAL_DIR}" ]]; then
    chown -R "${CODE_OWNER}:${COLLAB_GROUP}" "${DRUPAL_DIR}" || true
    find "${DRUPAL_DIR}" -type d -exec chmod 2775 {} \; 2>/dev/null || true
    find "${DRUPAL_DIR}" -type f -exec chmod g+rw {} \; 2>/dev/null || true
  else
    warn "DRUPAL_DIR not found (${DRUPAL_DIR}); skipping codebase permission fix."
  fi

  # Runtime files directory (do NOT create)
  local files_dir="${WEB_ROOT}/sites/default/files"
  if [[ -d "${files_dir}" ]]; then
    chown -R "${WEB_USER}:${COLLAB_GROUP}" "${files_dir}" || true
    find "${files_dir}" -type d -exec chmod 2775 {} \; 2>/dev/null || true
    find "${files_dir}" -type f -exec chmod g+rw {} \; 2>/dev/null || true
  else
    warn "Runtime dir not found (${files_dir}); skipping sites/default/files permission fix."
  fi

  # Composer home/cache (do NOT create)
  for d in "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}"; do
    if [[ -d "${d}" ]]; then
      chown -R "${OPS_USER}:${COLLAB_GROUP}" "${d}" 2>/dev/null || true
      find "${d}" -type d -exec chmod 2775 {} \; 2>/dev/null || true
      find "${d}" -type f -exec chmod g+rw {} \; 2>/dev/null || true
    else
      warn "Composer dir not found (${d}); skipping."
    fi
  done


  if [[ "${ENABLE_ACL}" == "1" ]]; then
    apply_acl_runtime_files
  fi
}

########################################
# Optional ACL support (prevents group-not-refreshed Permission denied on drush cr)
########################################
acl_available() {
  command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1
}

apply_acl_runtime_files() {
  local files_dir="${WEB_ROOT}/sites/default/files"
  if [[ ! -d "${files_dir}" ]]; then
    warn "Runtime dir not found (${files_dir}); skipping ACL."
    return 0
  fi
  if ! acl_available; then
    warn "ACL tools not found (setfacl/getfacl). Install package: apt-get install -y acl"
    return 0
  fi

  # Grant OPS_USER stable rwX on runtime files, regardless of group membership refresh.
  # Keep WEB_USER + COLLAB_GROUP entries too (idempotent).
  setfacl -R -m "u:${OPS_USER}:rwX" -m "u:${WEB_USER}:rwX" -m "g:${COLLAB_GROUP}:rwX" "${files_dir}" 2>/dev/null || true
  setfacl -R -d -m "u:${OPS_USER}:rwX" -m "u:${WEB_USER}:rwX" -m "g:${COLLAB_GROUP}:rwX" "${files_dir}" 2>/dev/null || true
  ok "ACL applied on runtime dir: ${files_dir} (OPS_USER=${OPS_USER})"
}

# Run command as APP_USER inside ${DRUPAL_DIR}, passing arguments safely (avoids quote/escape bugs).

# Run a command as APP_USER using a *login shell* (su -), always cd into /var/www/drupal.
# Hard mode: single CWD, and COMPOSER_HOME is always absolute (no stray quote directories like "'").
as_app_user_drupal() {
  local cmd="$*"
  ensure_drupal_root
  # Pass values as positional args to avoid quoting bugs in cmd string
  su -s /bin/bash - "${OPS_USER}" -c '
    export COMPOSER_HOME="$1"
    export COMPOSER_CACHE_DIR="$2"
    cd "$3" || exit 1
    bash -c "$4"
  ' bash "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" "${DRUPAL_DIR}" "${cmd}"
}

# Alias: even "global" composer ops run from ${DRUPAL_DIR} in hard mode.
as_app_user_www() {
  as_app_user_drupal "$@"
}


########################################
# Maintenance guide (written to DRUPAL_DIR/MAINTENANCE.md)
########################################
write_maintenance_doc() {
  local out="${DRUPAL_DIR}/MAINTENANCE.md"
  if [[ ! -d "${DRUPAL_DIR}" ]]; then
    warn "DRUPAL_DIR not found (${DRUPAL_DIR}); skip writing MAINTENANCE.md"
    return 0
  fi

  cat > "${out}" <<EOF
# Drupal Maintenance Quick Guide (generated by ${SCRIPT_ID})

This VM uses a **3-user model** to avoid permission fights:

- **root**: system packages + services (apt, nginx/php/mariadb configs, systemctl)
- **${CODE_OWNER}**: human operator (SSH login, edit code, upload files, run composer/drush)
- **${WEB_USER}**: web runtime (php-fpm/nginx). Only needs **write** access to \`sites/default/files\`.

## Golden rules

1) **Code ownership**
- Code (modules/themes/vendor) should be owned by **${CODE_OWNER}:${COLLAB_GROUP}**
- Directories should be \`2775\` (setgid) so new files inherit group \`${COLLAB_GROUP}\`.

2) **Runtime writes**
- \`${WEB_ROOT}/sites/default/files\` must be owned by **${WEB_USER}:${COLLAB_GROUP}**
- Directories: \`2775\`, files: \`664\` (group writable)

3) **Optional ACL (recommended)**
- If you see \`Failed to unlink ... Permission denied\` on \`drush cr\`, enable ACL:
  - Run: \`sudo -E bash "${SCRIPT_PATH}" --fix-perms --acl\`
- ACL avoids issues when your current SSH session has not refreshed group membership.

4) **Composer keys (pubkeys)**
- Composer pubkeys live under the user running composer: \`${COMPOSER_HOME_DIR}\`
- In this model, composer is run as **${OPS_USER}**, so pubkeys belong to **${OPS_USER}**.

## Daily commands (run as ${CODE_OWNER})

### Composer (install/upgrade modules)
\`\`\`bash
cd ${DRUPAL_DIR}
composer require drupal/XXX
composer update drupal/XXX
\`\`\`

### Drush
\`\`\`bash
cd ${DRUPAL_DIR}
./vendor/bin/drush --uri=${SITE_URI} cr
./vendor/bin/drush --uri=${SITE_URI} updb -y
./vendor/bin/drush --uri=${SITE_URI} cim -y
./vendor/bin/drush --uri=${SITE_URI} cex -y
\`\`\`

## Deploying a custom module (tar.gz) via SSH upload

Recommended workflow (no sudo):

1) Upload \`my_module.tar.gz\` to \`${OPS_HOME}\`
2) Extract into modules/custom:
\`\`\`bash
cd ${DRUPAL_DIR}
tar -xzf ${OPS_HOME}/my_module.tar.gz -C web/modules/custom
\`\`\`
3) Rebuild caches:
\`\`\`bash
cd ${DRUPAL_DIR}
./vendor/bin/drush --uri=${SITE_URI} cr
\`\`\`

## When you see Permission denied (unlink css/js) on cache rebuild

That usually means \`sites/default/files\` ownership was polluted.

Fix it (root):
\`\`\`bash
sudo chown -R ${WEB_USER}:${COLLAB_GROUP} ${WEB_ROOT}/sites/default/files
sudo find ${WEB_ROOT}/sites/default/files -type d -exec chmod 2775 {} \;
sudo find ${WEB_ROOT}/sites/default/files -type f -exec chmod 0664 {} \;
\`\`\`

Or run this script in pure fix mode:
\`\`\`bash
sudo -E bash "${SCRIPT_PATH}" --fix-perms
\`\`\`

## System services (root only)
\`\`\`bash
sudo systemctl restart php8.3-fpm nginx mariadb
sudo nginx -t
\`\`\`
EOF

  chown "${CODE_OWNER}:${COLLAB_GROUP}" "${out}" 2>/dev/null || true
  chmod 0664 "${out}" 2>/dev/null || true
  ok "Wrote maintenance guide: ${out}"
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

# In --fix-perms mode, avoid creating new directories for logging.
# Always log under /tmp (which already exists).
if [[ "${FIX_PERMS_ONLY}" == "1" ]]; then
  LOG_DIR="/tmp"
  LOG_FILE="${LOG_DIR}/${SCRIPT_ID}_${DRUPAL_VERSION}_fixperms_$(date +%Y%m%d_%H%M%S).log"
fi

mkdir -p "$LOG_DIR" || true
touch "$LOG_FILE" || true
chmod 0600 "$LOG_FILE" || true

_log "$C_BOLD" "=== Drupal ${DRUPAL_VERSION} install ${SCRIPT_VERSION} (collab perms, ops=ubuntu, web=www-data) ==="
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
# Mode: fix permissions only
########################################
if [[ "${FIX_PERMS_ONLY}" == "1" ]]; then
  step "FIX-PERMS(PURE): normalize permissions only (no install, no directory creation)"
  normalize_permissions_pure
  ok "Permissions normalized."
  write_maintenance_doc
  info "CODE_OWNER=${CODE_OWNER}"
  info "WEB_USER=${WEB_USER} (runtime)"; info "OPS_USER=${OPS_USER} (composer/drush ops)"
  info "COLLAB_GROUP=${COLLAB_GROUP}"
  info "DRUPAL_DIR=${DRUPAL_DIR}"
  info "WEB_ROOT=${WEB_ROOT}"
  info "Tip: cache rebuild can be run as OPS_USER (recommended) or WEB_USER:"
  info "  sudo -u ${OPS_USER} -E ${DRUPAL_DIR}/vendor/bin/drush cr"
  info "  sudo -u ${WEB_USER} -E ${DRUPAL_DIR}/vendor/bin/drush cr"
  ok "Done (--fix-perms)."
  exit 0
fi

########################################
# Utilities
########################################
apt_install(){
  local pkgs=("$@");
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
}

# Install the first available package from a list (optional feature)
apt_install_first_available(){
  local label="$1"; shift
  local pkg
  for pkg in "$@"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then
      step "BASELINE: install optional package (${label}): ${pkg}"
      apt_install "$pkg"
      ok "Optional package installed (${label}): ${pkg}"
      return 0
    fi
  done
  warn "Optional package not found for ${label}: tried [$*]"
  return 0
}

service_active(){ systemctl is-active --quiet "$1"; }

########################################
# 1) Base packages
########################################
step "BASELINE: base packages"
apt_install ca-certificates curl unzip git gnupg lsb-release software-properties-common jq openssl acl

########################################
# 2) PHP 8.3 + extensions
########################################
step "BASELINE: installing PHP 8.3 + extensions"
apt_install php8.3-fpm php8.3-cli php8.3-common php8.3-mysql php8.3-xml php8.3-gd php8.3-curl php8.3-mbstring php8.3-zip php8.3-intl php8.3-opcache php8.3-bcmath php-apcu
systemctl enable --now php8.3-fpm
service_active php8.3-fpm && ok "Service active: php8.3-fpm"

# Optional extensions: ImageMagick (Imagick) + UploadProgress
# These are best-effort: if the exact package name differs on your distro mirror, we warn and continue.
apt_install_first_available "imagick" php8.3-imagick php-imagick
apt_install_first_available "imagemagick-binary" imagemagick
apt_install_first_available "uploadprogress" php8.3-uploadprogress php-uploadprogress

# Enable modules if present (no-op if not installed)
phpenmod imagick 2>/dev/null || true
phpenmod uploadprogress 2>/dev/null || true
systemctl reload php8.3-fpm || true

# Quick verification
php -m | grep -qi '^imagick$' && ok "PHP ext enabled: imagick" || warn "PHP ext missing: imagick (optional)"
php -m | grep -qi '^uploadprogress$' && ok "PHP ext enabled: uploadprogress" || warn "PHP ext missing: uploadprogress (optional)"

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
# 5) Collaboration group + permissions baseline (V7.5.2)
########################################
step "BASELINE: ensuring collaboration group (${COLLAB_GROUP}) and normalizing permissions"
normalize_permissions
ok "Permissions baseline applied (CODE_OWNER=${CODE_OWNER}, OPS_USER=${OPS_USER}, WEB_USER=${WEB_USER}, GROUP=${COLLAB_GROUP})."

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
    DIR_LIST="$(ls -A "${DRUPAL_DIR}" 2>/dev/null)"; LS_EC=$?
    if [[ ${LS_EC} -ne 0 ]]; then
      warn "Cannot list ${DRUPAL_DIR} (ls exit=${LS_EC}); treating as NON-empty to be safe."
      TS_NOW="$(date +%Y%m%d_%H%M%S)"
      BACKUP_DIR="${DRUPAL_DIR}.broken_${TS_NOW}"
      warn "Moving unreadable/inconsistent dir to: ${BACKUP_DIR}"
      mv "${DRUPAL_DIR}" "${BACKUP_DIR}"
      NEED_CREATE_PROJECT=1
    elif [[ -z "${DIR_LIST}" ]]; then
      info "Directory ${DRUPAL_DIR} exists and is empty; will use it for create-project."
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
  # Ensure fixed roots and collaboration permissions.
  ensure_drupal_root
  normalize_permissions_pure

  step "INSTALL: creating Drupal project via Composer as ${OPS_USER}"

  # Extra safety: Composer refuses non-empty target (even a single hidden file). If anything is inside, move aside and retry.
  if find "${DRUPAL_DIR}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .; then
    TS_NOW="$(date +%Y%m%d_%H%M%S)"
    BACKUP_DIR="${DRUPAL_DIR}.nonempty_${TS_NOW}"
    warn "Project dir not empty before create-project. Moving it to: ${BACKUP_DIR}"
    ls -la "${DRUPAL_DIR}" | sed 's/^/[dir] /' || true
    mv "${DRUPAL_DIR}" "${BACKUP_DIR}"
    ensure_drupal_root
  fi

  # Run inside /var/www/drupal and use '.' so we keep the fixed root directory.
  # Debug: show target dir contents right before create-project (must be empty)
  ls -la "${DRUPAL_DIR}" | sed 's/^/[dir] /' || true
  as_app_user_drupal "${COMPOSER_BIN} create-project -n drupal/recommended-project:${DRUPAL_VERSION} ."
  # Create runtime public files dir early (installer + cache rebuilds need it)
  # (In --fix-perms mode we never create dirs; here we are in install mode)
  install -d -o "${WEB_USER}" -g "${COLLAB_GROUP}" -m 2775 "${WEB_ROOT}/sites/default/files" || true
  normalize_permissions_pure
  ok "Drupal codebase created at: ${DRUPAL_DIR}"
fi

########################################
# 11) Ensure Drush exists (per-project)
########################################
step "INSTALL: ensuring Drush exists (per-project)"
if [[ -x "${DRUPAL_DIR}/vendor/bin/drush" ]]; then
  ok "Drush already installed: $(as_app_user_drupal "./vendor/bin/drush --version" | head -n 1)"
else
  as_app_user_drupal "${COMPOSER_BIN} require -n drush/drush"
  ok "Drush installed: $(as_app_user_drupal "./vendor/bin/drush --version" | head -n 1)"
  normalize_permissions_pure
fi

########################################
# 12) Site install (minimal) if needed
########################################
# Ensure sites/default/files exists and follows the V7.5.2 ownership model
install -d -m 02775 -o "${CODE_OWNER}" -g "${COLLAB_GROUP}" "${WEB_ROOT}/sites/default"
install -d -m 02775 -o "${WEB_USER}" -g "${COLLAB_GROUP}" "${WEB_ROOT}/sites/default/files"
normalize_permissions

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
  step "INSTALL: running drush site:install (minimal) as ${OPS_USER}"
  as_app_user_drupal "./vendor/bin/drush -y site:install minimal \
    --db-url='mysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}' \
    --account-name=admin \
    --account-pass='${ADMIN_PASS}' \
    --site-name='Drupal' \
    --uri='${SITE_URI}'"
  ok "Drupal installation complete."
# Ensure runtime files dir ownership/perms are correct after install
if [[ -d "${WEB_ROOT}/sites/default/files" ]]; then
  chown -R "${WEB_USER}:${COLLAB_GROUP}" "${WEB_ROOT}/sites/default/files" 2>/dev/null || true
  find "${WEB_ROOT}/sites/default/files" -type d -exec chmod 2775 {} \; 2>/dev/null || true
  find "${WEB_ROOT}/sites/default/files" -type f -exec chmod g+rw {} \; 2>/dev/null || true
  ok "Runtime perms OK: ${WEB_ROOT}/sites/default/files (${WEB_USER}:${COLLAB_GROUP})"
fi
  normalize_permissions_pure
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

write_maintenance_doc
info "MAINTENANCE: ${DRUPAL_DIR}/MAINTENANCE.md"
info "MAINTENANCE (preview):"
if [[ -f "${DRUPAL_DIR}/MAINTENANCE.md" ]]; then
  sed -n '1,120p' "${DRUPAL_DIR}/MAINTENANCE.md" | sed 's/^/[MAINT] /' | while IFS= read -r line; do info "$line"; done
fi

ok "Done."

# Helpful tip for interactive usage
info "Tip: to enter OPS_USER interactive shell, run: sudo su - ${OPS_USER} -s /bin/bash"