#!/usr/bin/env bash
set -Eeuo pipefail

DEBUG="${DEBUG:-0}"
if [[ "${DEBUG}" == "1" ]]; then
  export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
  set -x
fi

# drupal_optimizerV0.1.6.sh
# Optimizer for a Drupal site installed by:
#   drupal_installV0.1.2.14_hard_single_cwd.sh
#
# Target shape:
# - Ubuntu 24.04.3 local IP testing
# - Nginx + PHP-FPM 8.3 + MariaDB
# - Performance: OPcache + APCu (no Redis, no Varnish)
# - Safe to run multiple times (idempotent-ish), creates backups before editing files
#
# Usage:
#   sudo -E bash drupal_optimizerV0.1.3.sh
#   sudo -E PROD_STRICT=1 bash drupal_optimizerV0.1.3.sh     # production-like OPcache (no timestamp checks)
#   sudo -E ENABLE_DRUPAL_PERF_CONFIG=0 bash drupal_optimizerV0.1.3.sh  # skip drush config:set tuning
#
# Notes (installer-coupled behavior):
# - Reads installer credentials env files under /var/lib/drupal-tools/credentials/
# - Uses www-data HOME=/var/www and COMPOSER_HOME=/var/www/.config/composer (same as installer)
# - Drush commands run inside /var/www/drupal (project root), with correct COMPOSER env

########################################
# Defaults (override via env vars)
########################################
SCRIPT_VERSION="V0.1.6"
APP_USER="${APP_USER:-www-data}"

# Installer state layout
STATE_ROOT="${STATE_ROOT:-/var/lib/drupal-tools}"
CREDS_DIR="${CREDS_DIR:-${STATE_ROOT}/credentials}"
CREDS_FILE="${CREDS_FILE:-}"   # empty => auto-pick newest drupal_*.env in CREDS_DIR

# Logs (installer uses /var/log/drupal-tools for install logs)
LOG_DIR="${LOG_DIR:-/var/log/drupal-tools}"
mkdir -p "${LOG_DIR}" >/dev/null 2>&1 || true
LOG_FILE="${LOG_FILE:-${LOG_DIR}/drupal_optimizer_${SCRIPT_VERSION}_$(date +%Y%m%d_%H%M%S).log}"
touch "${LOG_FILE}" >/dev/null 2>&1 || true
chmod 0600 "${LOG_FILE}" >/dev/null 2>&1 || true

PHP_VERSION="${PHP_VERSION:-8.3}"

# Fixed project root used by installer
DRUPAL_DIR_DEFAULT="/var/www/drupal"
WEB_ROOT="${WEB_ROOT:-$DRUPAL_DIR_DEFAULT}"   # project root (composer root)
WEB_PUBLIC="${WEB_PUBLIC:-}"                 # public docroot; infer as ${WEB_ROOT}/web when present

# Nginx site config created by installer
NGINX_SITE_CONF="${NGINX_SITE_CONF:-/etc/nginx/sites-available/drupal.conf}"

# URL used for curl / drush --uri
BASE_URL="${BASE_URL:-}"
DRUSH_URI="${DRUSH_URI:-}"

# Composer runtime (installer sets these for www-data)
COMPOSER_HOME_DIR="${COMPOSER_HOME_DIR:-/var/www/.config/composer}"
COMPOSER_CACHE_DIR="${COMPOSER_CACHE_DIR:-/var/www/.cache/composer}"

# Feature switches
ENABLE_PHP_TUNING="${ENABLE_PHP_TUNING:-1}"
ENABLE_APCU="${ENABLE_APCU:-1}"
ENABLE_SETTINGS_APCU="${ENABLE_SETTINGS_APCU:-1}"
ENABLE_NGINX_TUNING="${ENABLE_NGINX_TUNING:-1}"
# Nginx gzip behavior: auto|1|0
ENABLE_NGINX_GZIP="${ENABLE_NGINX_GZIP:-auto}"
ENABLE_MARIADB_TUNING="${ENABLE_MARIADB_TUNING:-1}"
ENABLE_CRON="${ENABLE_CRON:-1}"

# Drupal core performance config (via drush config:set)
ENABLE_DRUPAL_PERF_CONFIG="${ENABLE_DRUPAL_PERF_CONFIG:-1}"
PERF_PAGE_MAX_AGE="${PERF_PAGE_MAX_AGE:-900}"  # seconds, matches v6.4.x style

# Optional (disabled by default on local machines)
ENABLE_SYSCTL="${ENABLE_SYSCTL:-0}"

# Local vs production-like OPcache
PROD_STRICT="${PROD_STRICT:-0}"  # 0=dev-friendly validate timestamps; 1=prod-like

# APCu tuning
_DEFAULT_APCU_ENABLE_CLI=0
[[ "${PROD_STRICT}" == "1" ]] && _DEFAULT_APCU_ENABLE_CLI=1
APCU_ENABLE_CLI="${APCU_ENABLE_CLI:-${_DEFAULT_APCU_ENABLE_CLI}}"
APCU_SHM_SIZE="${APCU_SHM_SIZE:-128M}"

# OPcache parameters (some auto-tuned)
OPCACHE_MEMORY="${OPCACHE_MEMORY:-}"  # empty => auto
OPCACHE_INTERNED_STRINGS_BUFFER="${OPCACHE_INTERNED_STRINGS_BUFFER:-32}"
OPCACHE_MAX_ACCELERATED_FILES="${OPCACHE_MAX_ACCELERATED_FILES:-40000}"
OPCACHE_MAX_WASTED_PERCENTAGE="${OPCACHE_MAX_WASTED_PERCENTAGE:-10}"
OPCACHE_SAVE_COMMENTS="${OPCACHE_SAVE_COMMENTS:-1}"
OPCACHE_ENABLE_FILE_OVERRIDE="${OPCACHE_ENABLE_FILE_OVERRIDE:-1}"
OPCACHE_ENABLE_CLI="${OPCACHE_ENABLE_CLI:-0}"
OPCACHE_JIT_BUFFER_SIZE="${OPCACHE_JIT_BUFFER_SIZE:-0}"
OPCACHE_JIT="${OPCACHE_JIT:-0}"
REALPATH_CACHE_SIZE="${REALPATH_CACHE_SIZE:-4096K}"
REALPATH_CACHE_TTL="${REALPATH_CACHE_TTL:-600}"

# Dev/Prod timestamp behavior
OPCACHE_REVALIDATE_FREQ="${OPCACHE_REVALIDATE_FREQ:-}"
OPCACHE_VALIDATE_TIMESTAMPS="${OPCACHE_VALIDATE_TIMESTAMPS:-}"

# PHP/FPM base
PHP_MEM_LIMIT="${PHP_MEM_LIMIT:-512M}"
CLI_MEM_LIMIT="${CLI_MEM_LIMIT:-}"   # optional override
UPLOAD_MAX_FILESIZE="${UPLOAD_MAX_FILESIZE:-64M}"
POST_MAX_SIZE="${POST_MAX_SIZE:-64M}"
MAX_EXECUTION_TIME="${MAX_EXECUTION_TIME:-120}"
MAX_INPUT_VARS="${MAX_INPUT_VARS:-5000}"

# FPM pool auto-tuned if empty
FPM_PM_MAX_CHILDREN="${FPM_PM_MAX_CHILDREN:-}"
FPM_PM_START_SERVERS="${FPM_PM_START_SERVERS:-}"
FPM_PM_MIN_SPARE_SERVERS="${FPM_PM_MIN_SPARE_SERVERS:-}"
FPM_PM_MAX_SPARE_SERVERS="${FPM_PM_MAX_SPARE_SERVERS:-}"
FPM_PM_MAX_REQUESTS="${FPM_PM_MAX_REQUESTS:-500}"

# Cron tuning (systemd timer)
CRON_EVERY_MINUTES="${CRON_EVERY_MINUTES:-5}"
CRON_USE_FLOCK="${CRON_USE_FLOCK:-1}"

########################################
# Logging helpers
########################################
_ts(){ date '+%Y-%m-%d %H:%M:%S'; }
_log_plain(){ printf '[%s] %s\n' "$(_ts)" "$1" >>"$LOG_FILE"; }
_log(){
  local lvl="$1"; shift
  local msg="$*"
  local line="[$(_ts)] ${lvl} ${msg}"
  if [[ -t 1 ]]; then
    case "$lvl" in
      INFO)  printf '\033[32m%s\033[0m\n' "$line" ;;
      WARN)  printf '\033[33m%s\033[0m\n' "$line" ;;
      STEP)  printf '\033[34m%s\033[0m\n' "$line" ;;
      ERROR) printf '\033[31m%s\033[0m\n' "$line" ;;
      *)     printf '%s\n' "$line" ;;
    esac
  else
    printf '%s\n' "$line"
  fi
  _log_plain "${lvl} ${msg}"
}
info(){ _log INFO "$@"; }
warn(){ _log WARN "$@" >&2; }
step(){ _log STEP "$@"; }
die(){ _log ERROR "$@" >&2; exit 1; }

on_err(){
  local ec=$?
  local line="${BASH_LINENO[0]:-?}"
  local cmd="${BASH_COMMAND:-?}"
  warn "FAILED at line ${line}: ${cmd}"
  warn "Script failed (exit=${ec}). Log: ${LOG_FILE}"
  warn "Last 120 log lines:"
  tail -n 120 "${LOG_FILE}" >&2 || true
}
trap on_err ERR

need_root(){
  [[ $EUID -eq 0 ]] || die "Please run as root: sudo -E bash $0"
}

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

########################################
# Package helpers
########################################
apt_wait_locks(){
  # Wait for dpkg/apt locks (unattended-upgrades, etc.)
  command -v fuser >/dev/null 2>&1 || return 0
  local i=0 max=${APT_LOCK_WAIT_SECS:-120}
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
    (( i++ ))
    if (( i >= max )); then
      die "APT lock still held after ${max}s. Try: sudo systemctl stop unattended-upgrades && retry."
    fi
    sleep 1
  done
}

apt_install(){
  local pkgs=("$@")
  [[ "${APT_SKIP_INSTALL:-0}" == "1" ]] && die "APT_SKIP_INSTALL=1 and missing packages: ${pkgs[*]}"
  apt_wait_locks
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1
  apt_wait_locks
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}" >>"$LOG_FILE" 2>&1
}

ensure_pkg(){
  local pkg="$1"
  dpkg -s "$pkg" >/dev/null 2>&1 && return 0
  step "Installing package: $pkg"
  if ! apt_install "$pkg"; then
    warn "Failed installing package: $pkg"
    warn "Last 80 log lines:"
    tail -n 80 "$LOG_FILE" >&2 || true
    return 1
  fi
}

ensure_pkg_any(){
  # ensure_pkg_any pkg1 pkg2 ... (installs first available)
  local p
  for p in "$@"; do
    dpkg -s "$p" >/dev/null 2>&1 && return 0
  done
  # pick an installable candidate
  for p in "$@"; do
    if apt-cache show "$p" >/dev/null 2>&1; then
      step "Installing package: $p"
      if ! apt_install "$p"; then
        warn "Failed installing package: $p"
        warn "Last 80 log lines:"
        tail -n 80 "$LOG_FILE" >&2 || true
        return 1
      fi
      return 0
    fi
  done
  die "No installable package found among: $*"
}

########################################
# Backup helpers
########################################
backup_file_ret(){
  local f="$1"
  [[ -e "$f" ]] || return 0
  local ts; ts="$(date +%Y%m%d_%H%M%S)"
  local bak="${f}.bak_${ts}"
  cp -a "$f" "$bak"
  echo "$bak"
}
backup_file(){
  local f="$1"
  [[ -e "$f" ]] || return 0
  local bak
  bak="$(backup_file_ret "$f" || true)"
  [[ -n "${bak:-}" ]] && info "Backup: $f -> $bak"
  return 0
}

########################################
# Load install info from credentials file (installer-compatible)
########################################
pick_latest_creds(){
  [[ -d "${CREDS_DIR}" ]] || return 1
  local f
  f="$(ls -1t "${CREDS_DIR}"/drupal_*.env 2>/dev/null | head -n 1 || true)"
  [[ -n "${f}" && -f "${f}" ]] || return 1
  echo "$f"
}

load_creds(){
  if [[ -z "${CREDS_FILE}" ]]; then
    if CREDS_FILE="$(pick_latest_creds || true)"; then
      info "Auto-picked latest creds: ${CREDS_FILE}"
    else
      CREDS_FILE=""
    fi
  fi

  if [[ -n "${CREDS_FILE}" && -f "${CREDS_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${CREDS_FILE}"
    info "Loaded credentials: ${CREDS_FILE}"
  else
    warn "Credentials env not found (CREDS_FILE=${CREDS_FILE:-<empty>}). Will use defaults/env."
  fi

  # From installer creds: DRUPAL_DIR, SITE_URI, COMPOSER_HOME_DIR, etc.
  if [[ -n "${DRUPAL_DIR:-}" ]]; then
    WEB_ROOT="${WEB_ROOT:-$DRUPAL_DIR}"
  fi

  # Prefer installer-provided composer home
  if [[ -n "${COMPOSER_HOME_DIR:-}" ]]; then
    COMPOSER_HOME_DIR="${COMPOSER_HOME_DIR}"
  fi

  # Infer WEB_PUBLIC
  if [[ -z "${WEB_PUBLIC}" ]]; then
    if [[ -d "${WEB_ROOT}/web" ]]; then
      WEB_PUBLIC="${WEB_ROOT}/web"
    else
      WEB_PUBLIC="${WEB_ROOT}"
    fi
  fi

  # URL
  if [[ -z "${BASE_URL}" && -n "${SITE_URI:-}" ]]; then
    BASE_URL="${SITE_URI}"
  fi
  if [[ -z "${DRUSH_URI}" && -n "${SITE_URI:-}" ]]; then
    DRUSH_URI="${SITE_URI}"
  fi

  # Composer cache dir used by installer
  if [[ -z "${COMPOSER_CACHE_DIR}" ]]; then
    COMPOSER_CACHE_DIR="/var/www/.cache/composer"
  fi

  # Detect PHP version if directory missing (installer uses PHP 8.3, but keep robust)
  if [[ ! -d "/etc/php/${PHP_VERSION}" ]]; then
    local detected=""
    if command -v php >/dev/null 2>&1; then
      detected="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"
    fi
    if [[ -n "${detected}" && -d "/etc/php/${detected}" ]]; then
      warn "PHP_VERSION=${PHP_VERSION} not found under /etc/php. Auto-detected PHP_VERSION=${detected}."
      PHP_VERSION="${detected}"
    else
      # fallback: highest /etc/php/* dir
      detected="$(ls -1 /etc/php 2>/dev/null | egrep '^[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)"
      if [[ -n "${detected}" && -d "/etc/php/${detected}" ]]; then
        warn "PHP_VERSION=${PHP_VERSION} not found under /etc/php. Auto-picked PHP_VERSION=${detected}."
        PHP_VERSION="${detected}"
      fi
    fi
  fi

  info "WEB_ROOT=${WEB_ROOT}"
  info "WEB_PUBLIC=${WEB_PUBLIC}"
  info "APP_USER=${APP_USER}"
  info "COMPOSER_HOME_DIR=${COMPOSER_HOME_DIR}"
  info "COMPOSER_CACHE_DIR=${COMPOSER_CACHE_DIR}"
  [[ -n "${BASE_URL:-}" ]] && info "BASE_URL=${BASE_URL}"
}

########################################
# Run commands as APP_USER (installer-style environment)
########################################
q(){ printf "%q " "$@"; }

run_as_app_drupal(){
  # Usage: run_as_app_drupal <cmd> [args...]
  local cmd; cmd="$(q "$@")"
  # Use a login-like shell environment and always cd into WEB_ROOT (project root).
  # Keep COMPOSER_HOME/COMPOSER_CACHE_DIR aligned with the installer.
  su -s /bin/bash - "${APP_USER}" -c '
    export HOME="/var/www"
    export COMPOSER_HOME="$1"
    export COMPOSER_CACHE_DIR="$2"
    cd "$3" || exit 1
    bash -lc "$4"
  ' bash "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" "${WEB_ROOT}" "${cmd}"
}

drush_path(){
  local d="${WEB_ROOT}/vendor/bin/drush"
  [[ -x "$d" ]] && echo "$d" && return 0
  return 1
}

drush_run(){
  local drush
  if ! drush="$(drush_path)"; then
    warn "Drush not found at ${WEB_ROOT}/vendor/bin/drush (skip drush tasks)"
    return 0
  fi

  local uri="${DRUSH_URI:-${BASE_URL:-}}"
  if [[ -n "${uri}" ]]; then
    run_as_app_drupal "$drush" --uri="${uri}" "$@"
  else
    run_as_app_drupal "$drush" "$@"
  fi
}

########################################
# Resource detection (simple heuristic)
########################################
MEM_MB=0
CPU_CORES=1
detect_resources(){
  if [[ -r /proc/meminfo ]]; then
    MEM_MB="$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)"
  fi
  CPU_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  [[ "$CPU_CORES" =~ ^[0-9]+$ ]] || CPU_CORES=1
  [[ "$MEM_MB" =~ ^[0-9]+$ ]] || MEM_MB=0

  info "Detected resources: cpu=${CPU_CORES} mem=${MEM_MB}MB"

  # Auto set OPcache memory if not provided
  if [[ -z "${OPCACHE_MEMORY}" ]]; then
    if (( MEM_MB >= 8192 )); then
      OPCACHE_MEMORY="256"
    elif (( MEM_MB >= 4096 )); then
      OPCACHE_MEMORY="192"
    else
      OPCACHE_MEMORY="128"
    fi
  fi

  # Auto FPM pool sizing (very conservative for local)
  if [[ -z "${FPM_PM_MAX_CHILDREN}" ]]; then
    local mem_cap=4
    if (( MEM_MB > 0 )); then
      mem_cap=$(( MEM_MB / 256 ))  # allow ~256MB per child for safety
      (( mem_cap < 2 )) && mem_cap=2
      (( mem_cap > 16 )) && mem_cap=16
    fi
    local by_cpu="$CPU_CORES"
    (( by_cpu < 2 )) && by_cpu=2
    (( by_cpu > 8 )) && by_cpu=8
    local maxc="$by_cpu"
    (( mem_cap < maxc )) && maxc="$mem_cap"
    FPM_PM_MAX_CHILDREN="$maxc"
  fi

  if [[ -z "${FPM_PM_START_SERVERS}" ]]; then
    FPM_PM_START_SERVERS=$(( (FPM_PM_MAX_CHILDREN + 1) / 2 ))
    (( FPM_PM_START_SERVERS < 2 )) && FPM_PM_START_SERVERS=2
  fi
  if [[ -z "${FPM_PM_MIN_SPARE_SERVERS}" ]]; then
    FPM_PM_MIN_SPARE_SERVERS=2
  fi
  if [[ -z "${FPM_PM_MAX_SPARE_SERVERS}" ]]; then
    FPM_PM_MAX_SPARE_SERVERS=$(( FPM_PM_MAX_CHILDREN > 4 ? 4 : FPM_PM_MAX_CHILDREN ))
    (( FPM_PM_MAX_SPARE_SERVERS < 2 )) && FPM_PM_MAX_SPARE_SERVERS=2
  fi

  # OPcache timestamp behavior (dev/prod)
  if [[ -z "${OPCACHE_VALIDATE_TIMESTAMPS}" ]]; then
    if [[ "${PROD_STRICT}" == "1" ]]; then
      OPCACHE_VALIDATE_TIMESTAMPS="0"
    else
      OPCACHE_VALIDATE_TIMESTAMPS="1"
    fi
  fi
  if [[ -z "${OPCACHE_REVALIDATE_FREQ}" ]]; then
    if [[ "${PROD_STRICT}" == "1" ]]; then
      OPCACHE_REVALIDATE_FREQ="0"
    else
      OPCACHE_REVALIDATE_FREQ="2"
    fi
  fi

  info "Tuned: OPCACHE_MEMORY=${OPCACHE_MEMORY}MB, FPM_PM_MAX_CHILDREN=${FPM_PM_MAX_CHILDREN}"
  info "Tuned: OPCACHE_VALIDATE_TIMESTAMPS=${OPCACHE_VALIDATE_TIMESTAMPS}, OPCACHE_REVALIDATE_FREQ=${OPCACHE_REVALIDATE_FREQ}"
}

########################################
# Config helpers
########################################
set_kv_line(){
  # set_kv_line <file> <key_regex> <line>
  local f="$1" key="$2" line="$3"
  if [[ -f "$f" ]] && grep -qE "^\s*${key}\s*=" "$f"; then
    sed -i -E "s|^\s*${key}\s*=.*|${line}|" "$f"
  else
    echo "$line" >>"$f"
  fi
}

########################################
# 1) PHP-FPM + OPcache
########################################
optimize_php(){
  [[ "${ENABLE_PHP_TUNING}" == "1" ]] || { info "PHP tuning disabled by switch"; return 0; }

  step "1) PHP-FPM / OPcache tuning"

  info "Using PHP_VERSION=${PHP_VERSION}"
  info "FPM conf.d dir: /etc/php/${PHP_VERSION}/fpm/conf.d"
  info "CLI conf.d dir: /etc/php/${PHP_VERSION}/cli/conf.d"

  ensure_pkg_any "php${PHP_VERSION}-fpm" "php-fpm"
  ensure_pkg_any "php${PHP_VERSION}-cli" "php-cli"
  ensure_pkg_any "php${PHP_VERSION}-mysql" "php-mysql"
  ensure_pkg_any "php${PHP_VERSION}-xml" "php-xml"
  ensure_pkg_any "php${PHP_VERSION}-gd" "php-gd"
  ensure_pkg_any "php${PHP_VERSION}-curl" "php-curl"
  ensure_pkg_any "php${PHP_VERSION}-mbstring" "php-mbstring"
  ensure_pkg_any "php${PHP_VERSION}-zip" "php-zip"
  ensure_pkg_any "php${PHP_VERSION}-opcache" "php-opcache"

  # Dedicated override ini (fpm + cli) to avoid clobbering php.ini edits by installer
  local ini_fpm="/etc/php/${PHP_VERSION}/fpm/conf.d/99-drupal-optimizer.ini"
  local ini_cli="/etc/php/${PHP_VERSION}/cli/conf.d/99-drupal-optimizer.ini"

  [[ -d "/etc/php/${PHP_VERSION}/fpm/conf.d" ]] || die "Missing dir: /etc/php/${PHP_VERSION}/fpm/conf.d (PHP_VERSION wrong or php-fpm not installed?)"
  [[ -d "/etc/php/${PHP_VERSION}/cli/conf.d" ]] || die "Missing dir: /etc/php/${PHP_VERSION}/cli/conf.d (PHP_VERSION wrong or php-cli not installed?)"

  backup_file "$ini_fpm"
  backup_file "$ini_cli"

  local cli_mem="${CLI_MEM_LIMIT:-$PHP_MEM_LIMIT}"

  cat >"$ini_fpm" <<EOF
; drupal_optimizer ${SCRIPT_VERSION}
memory_limit=${PHP_MEM_LIMIT}
upload_max_filesize=${UPLOAD_MAX_FILESIZE}
post_max_size=${POST_MAX_SIZE}
max_execution_time=${MAX_EXECUTION_TIME}
max_input_vars=${MAX_INPUT_VARS}

; Realpath cache (helps Drupal autoloading)
realpath_cache_size=${REALPATH_CACHE_SIZE}
realpath_cache_ttl=${REALPATH_CACHE_TTL}

; OPcache
opcache.enable=1
opcache.memory_consumption=${OPCACHE_MEMORY}
opcache.interned_strings_buffer=${OPCACHE_INTERNED_STRINGS_BUFFER}
opcache.max_accelerated_files=${OPCACHE_MAX_ACCELERATED_FILES}
opcache.max_wasted_percentage=${OPCACHE_MAX_WASTED_PERCENTAGE}
opcache.save_comments=${OPCACHE_SAVE_COMMENTS}
opcache.enable_file_override=${OPCACHE_ENABLE_FILE_OVERRIDE}
opcache.validate_timestamps=${OPCACHE_VALIDATE_TIMESTAMPS}
opcache.revalidate_freq=${OPCACHE_REVALIDATE_FREQ}
opcache.jit_buffer_size=${OPCACHE_JIT_BUFFER_SIZE}
opcache.jit=${OPCACHE_JIT}
EOF

  cat >"$ini_cli" <<EOF
; drupal_optimizer ${SCRIPT_VERSION} (CLI overrides)
memory_limit=${cli_mem}
opcache.enable_cli=${OPCACHE_ENABLE_CLI}
EOF

  # FPM pool tuning
  local pool="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
  if [[ -f "$pool" ]]; then
    backup_file "$pool"
    set_kv_line "$pool" "pm" "pm = dynamic"
    set_kv_line "$pool" "pm\.max_children" "pm.max_children = ${FPM_PM_MAX_CHILDREN}"
    set_kv_line "$pool" "pm\.start_servers" "pm.start_servers = ${FPM_PM_START_SERVERS}"
    set_kv_line "$pool" "pm\.min_spare_servers" "pm.min_spare_servers = ${FPM_PM_MIN_SPARE_SERVERS}"
    set_kv_line "$pool" "pm\.max_spare_servers" "pm.max_spare_servers = ${FPM_PM_MAX_SPARE_SERVERS}"
    set_kv_line "$pool" "pm\.max_requests" "pm.max_requests = ${FPM_PM_MAX_REQUESTS}"
    set_kv_line "$pool" "request_terminate_timeout" "request_terminate_timeout = 300s"
  else
    warn "FPM pool file not found: $pool (skip pool tuning)"
  fi

  systemctl enable --now "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
  systemctl restart "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
  info "PHP-FPM restarted"
}

########################################
# 2) APCu
########################################
optimize_apcu(){
  [[ "${ENABLE_APCU}" == "1" ]] || { info "APCu disabled by switch"; return 0; }

  step "2) APCu tuning"

  # Installer installs php-apcu; ensure version package if available
  ensure_pkg_any "php${PHP_VERSION}-apcu" "php-apcu"
  phpenmod -v "${PHP_VERSION}" apcu >/dev/null 2>&1 || true

  local apcu_ini="/etc/php/${PHP_VERSION}/mods-available/apcu.ini"
  if [[ -f "${apcu_ini}" ]]; then
    backup_file "${apcu_ini}"
    set_kv_line "${apcu_ini}" "apc\.shm_size" "apc.shm_size=${APCU_SHM_SIZE}"
    set_kv_line "${apcu_ini}" "apc\.enable_cli" "apc.enable_cli=${APCU_ENABLE_CLI}"

    # Ensure symlinks exist (Ubuntu usually uses 20-apcu.ini)
    [[ -f "/etc/php/${PHP_VERSION}/fpm/conf.d/20-apcu.ini" ]] || ln -sf "${apcu_ini}" "/etc/php/${PHP_VERSION}/fpm/conf.d/20-apcu.ini"
    [[ -f "/etc/php/${PHP_VERSION}/cli/conf.d/20-apcu.ini" ]] || ln -sf "${apcu_ini}" "/etc/php/${PHP_VERSION}/cli/conf.d/20-apcu.ini"

    systemctl restart "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
    info "APCu configured: apc.shm_size=${APCU_SHM_SIZE}, apc.enable_cli=${APCU_ENABLE_CLI}"
  else
    warn "APCu ini not found: ${apcu_ini}"
  fi
}

########################################
# 3) Nginx tuning (global include only; does NOT rewrite site conf)
########################################
optimize_nginx(){
  [[ "${ENABLE_NGINX_TUNING}" == "1" ]] || { info "Nginx tuning disabled by switch"; return 0; }

  step "3) Nginx global tuning (safe include; gzip handled in nginx.conf)"

  ensure_pkg nginx

  # We intentionally do NOT manage gzip here (to avoid duplicate directive errors).
  # Enable gzip ONCE in /etc/nginx/nginx.conf (http{} block) or a single dedicated include.
  if grep -qE '^[[:space:]]*gzip[[:space:]]+on[[:space:]]*;' /etc/nginx/nginx.conf 2>/dev/null; then
    info "gzip already enabled in /etc/nginx/nginx.conf"
  else
    warn "gzip is NOT enabled in /etc/nginx/nginx.conf. Enable it ONCE there (http{} block) for compression."
  fi

  local conf="/etc/nginx/conf.d/99-drupal-optimizer.conf"
  local ts; ts="$(date +%Y%m%d_%H%M%S)"

  # If a previous run created a problematic file, temporarily move it away first.
  local disabled=""
  if [[ -f "${conf}" ]]; then
    disabled="${conf}.disabled_${ts}"
    mv "${conf}" "${disabled}"
    info "Temporarily moved existing optimizer conf aside: ${disabled}"
  fi

  # Baseline nginx config test (without our conf)
  if ! nginx -t >>"$LOG_FILE" 2>&1; then
    warn "Baseline nginx config test failed (even without ${conf})."
    warn "Fix nginx config first; leaving optimizer conf disabled: ${disabled:-<none>}"
    tail -n 120 "$LOG_FILE" >&2 || true
    return 0
  fi

  # Capture config to detect existing directives (best-effort)
  local cfg=""
  cfg="$(nginx -T 2>/dev/null || true)"

  nginx_has(){
    local name="$1"
    echo "${cfg}" | grep -qE "^[[:space:]]*${name}([[:space:]]|;)"
  }

  # Build conf with only directives that are NOT already present (avoid 'duplicate directive' errors)
  {
    echo "# drupal_optimizer ${SCRIPT_VERSION}"
    echo "# Generated file; safe to re-run."
    echo ""

    if ! nginx_has "client_max_body_size"; then
      echo "client_max_body_size 64m;"
    fi
    if ! nginx_has "fastcgi_buffers"; then
      echo "fastcgi_buffers 16 16k;"
    fi
    if ! nginx_has "fastcgi_buffer_size"; then
      echo "fastcgi_buffer_size 32k;"
    fi
    if ! nginx_has "keepalive_timeout"; then
      echo "keepalive_timeout 65;"
    fi
    if ! nginx_has "server_tokens"; then
      echo "server_tokens off;"
    fi
  } > "${conf}"

  if ! nginx -t >>"$LOG_FILE" 2>&1; then
    warn "Generated ${conf} caused nginx -t failure. Rolling back."
    rm -f "${conf}" || true
    if [[ -n "${disabled}" && -f "${disabled}" ]]; then
      mv "${disabled}" "${conf}" || true
      info "Restored previous optimizer conf."
    fi
    tail -n 120 "$LOG_FILE" >&2 || true
    return 0
  fi

  # Success: remove disabled file
  [[ -n "${disabled}" && -f "${disabled}" ]] && rm -f "${disabled}" || true

  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
  info "Nginx reloaded"

  [[ -f "${NGINX_SITE_CONF}" ]] && info "Nginx site conf (installer): ${NGINX_SITE_CONF}"
}


########################################
# 4) MariaDB tuning (conservative for local; compatible with installer DB users)
########################################
optimize_mariadb(){
  [[ "${ENABLE_MARIADB_TUNING}" == "1" ]] || { info "MariaDB tuning disabled by switch"; return 0; }

  step "4) MariaDB tuning"
  ensure_pkg mariadb-server

  # Buffer pool: 25% RAM capped at 1024MB, min 256MB
  local bp_mb=256
  if (( MEM_MB > 0 )); then
    bp_mb=$(( MEM_MB / 4 ))
    (( bp_mb < 256 )) && bp_mb=256
    (( bp_mb > 1024 )) && bp_mb=1024
  fi

  local conf="/etc/mysql/mariadb.conf.d/99-drupal-optimizer.cnf"
  backup_file "$conf"
  cat >"$conf" <<EOF
# drupal_optimizer ${SCRIPT_VERSION}
[mysqld]
# Conservative defaults for a single Drupal site on a dev/local box.
innodb_file_per_table=1
innodb_buffer_pool_size=${bp_mb}M
innodb_log_file_size=256M
innodb_flush_method=O_DIRECT
innodb_flush_log_at_trx_commit=2

# Avoid DNS lookups
skip_name_resolve=1

# Temp tables
tmp_table_size=64M
max_heap_table_size=64M

# Connections (local)
max_connections=150
EOF

  systemctl enable --now mariadb >/dev/null 2>&1 || true
  systemctl restart mariadb >/dev/null 2>&1 || true
  info "MariaDB restarted (innodb_buffer_pool_size=${bp_mb}M)"
}

########################################
# 5) Drupal settings.php: enable APCu backend for small bins
########################################
drupal_settings_path(){
  local s="${WEB_PUBLIC}/sites/default/settings.php"
  [[ -f "$s" ]] && echo "$s" && return 0
  # fallback
  s="${WEB_ROOT}/web/sites/default/settings.php"
  [[ -f "$s" ]] && echo "$s" && return 0
  return 1
}

write_settings_block(){
  local settings="$1" begin="$2" end="$3" block="$4"
  if grep -qF "${begin}" "${settings}"; then
    sed -i "/$(printf '%s' "${begin}" | sed 's/[][\/.^$*]/\\&/g')/,/$(printf '%s' "${end}" | sed 's/[][\/.^$*]/\\&/g')/d" "${settings}"
  fi
  cat >>"${settings}" <<EOF

${begin}
${block}
${end}
EOF
}

enable_apcu_in_settings(){
  [[ "${ENABLE_SETTINGS_APCU}" == "1" ]] || { info "settings.php APCu block disabled by switch"; return 0; }

  step "5) settings.php: enable APCu cache backend (bootstrap/config/discovery)"

  local settings
  if ! settings="$(drupal_settings_path)"; then
    warn "settings.php not found under WEB_PUBLIC=${WEB_PUBLIC}. Skip."
    return 0
  fi

  backup_file "${settings}"

  local begin="# --- BEGIN drupal_optimizer_${SCRIPT_VERSION} apcu ---"
  local end="# --- END drupal_optimizer_${SCRIPT_VERSION} apcu ---"

  local block
  block=$'if (extension_loaded(\'apcu\') && ini_get(\'apc.enabled\')) {\n  // Single-node optimization: speed up bootstrap/config/discovery.\n  // Drush/cron runs via CLI. If apc.enable_cli=0, skip on CLI to avoid APCUIterator errors.\n  if (PHP_SAPI !== \'cli\' || ini_get(\'apc.enable_cli\')) {\n    $settings[\'cache\'][\'bins\'][\'bootstrap\']  = \'cache.backend.apcu\';\n    $settings[\'cache\'][\'bins\'][\'discovery\']  = \'cache.backend.apcu\';\n    $settings[\'cache\'][\'bins\'][\'config\']     = \'cache.backend.apcu\';\n  }\n}\n'

  write_settings_block "${settings}" "${begin}" "${end}" "${block}"
  info "settings.php updated: ${settings}"

  # Clear caches if possible
  drush_run -y cr >/dev/null 2>&1 || true
}

apply_drupal_perf_config(){
  [[ "${ENABLE_DRUPAL_PERF_CONFIG}" == "1" ]] || { info "Drupal perf config disabled by switch"; return 0; }

  step "5B) Drupal core perf config (drush config:set system.performance)"

  # Best-effort: do not fail the script if config write fails.
  local ok=0
  drush_run -y config:set system.performance cache.page.max_age "${PERF_PAGE_MAX_AGE}" >/dev/null 2>&1 && ok=1 || true
  drush_run -y config:set system.performance css.preprocess 1 >/dev/null 2>&1 && ok=1 || true
  drush_run -y config:set system.performance js.preprocess 1 >/dev/null 2>&1 && ok=1 || true

  if [[ "${ok}" -eq 1 ]]; then
    info "Drupal perf config set: page max-age=${PERF_PAGE_MAX_AGE}, css/js preprocess=1"
    drush_run -y cr >/dev/null 2>&1 || true
  else
    warn "Could not apply Drupal perf config via drush (skip)."
  fi
}

########################################
# 6) Cron via systemd timer (drush cron)
########################################
install_cron_timer(){
  [[ "${ENABLE_CRON}" == "1" ]] || { info "Cron disabled by switch"; return 0; }

  step "6) Install systemd timer for drush cron (every ${CRON_EVERY_MINUTES} min)"

  local drush
  if ! drush="$(drush_path)"; then
    warn "Drush not found; skip cron timer."
    return 0
  fi

  local svc="/etc/systemd/system/drupal-cron.service"
  local timer="/etc/systemd/system/drupal-cron.timer"
  backup_file "$svc"
  backup_file "$timer"

  local uri="${DRUSH_URI:-${BASE_URL:-}}"
  local uri_arg=""
  [[ -n "$uri" ]] && uri_arg="--uri=${uri}"

  local flock_prefix=""
  if [[ "${CRON_USE_FLOCK}" == "1" ]]; then
    flock_prefix="/usr/bin/flock -n /run/drupal-cron.lock"
  fi

  cat >"$svc" <<EOF
[Unit]
Description=Drupal cron (drush) for ${WEB_ROOT}
After=network.target mariadb.service php${PHP_VERSION}-fpm.service

[Service]
Type=oneshot
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${WEB_ROOT}
Environment=HOME=/var/www
Environment=COMPOSER_HOME=${COMPOSER_HOME_DIR}
Environment=COMPOSER_CACHE_DIR=${COMPOSER_CACHE_DIR}
ExecStart=${flock_prefix} ${WEB_ROOT}/vendor/bin/drush -y ${uri_arg} cron
EOF

  cat >"$timer" <<EOF
[Unit]
Description=Run Drupal cron every ${CRON_EVERY_MINUTES} minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=${CRON_EVERY_MINUTES}min
Unit=drupal-cron.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now drupal-cron.timer >/dev/null 2>&1 || true
  systemctl restart drupal-cron.timer >/dev/null 2>&1 || true
  info "systemd timer installed: drupal-cron.timer"
}

########################################
# 8) sysctl (optional)
########################################
optimize_sysctl(){
  [[ "${ENABLE_SYSCTL}" == "1" ]] || { info "sysctl disabled by switch"; return 0; }
  step "8) sysctl tuning (optional)"
  local conf="/etc/sysctl.d/99-drupal-optimizer.conf"
  backup_file "$conf"
  cat >"$conf" <<'EOF'

# drupal_optimizer V0.1 - optional
net.core.somaxconn = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 100000
EOF
  sysctl --system >/dev/null 2>&1 || true
  info "Applied sysctl"
}

########################################
# 9) Verification (quick)
########################################
curl_headers(){
  local url="$1"
  have_cmd curl || return 1
  curl -sS -I -L --max-time 10 "$url" 2>/dev/null || true
}

verify(){
  step "9) Quick verification"

  if [[ -n "${BASE_URL:-}" ]]; then
    local h
    h="$(curl_headers "${BASE_URL}/" || true)"
    if [[ -n "$h" ]]; then
      info "Headers (${BASE_URL}/):"
      echo "$h" | egrep -i '^(HTTP/|Date:|Server:|Cache-Control:|Expires:|Via:|X-|X-Cache:|Set-Cookie:)' | sed 's/^/  /' || true
    else
      warn "Could not fetch ${BASE_URL}/"
    fi
  else
    warn "BASE_URL empty; skip curl verification."
  fi

  if have_cmd php; then
    info "PHP: $(php -v | head -n 1)"
    php -i 2>/dev/null | egrep -i '^(opcache.enable =>|opcache.memory_consumption =>|opcache.validate_timestamps =>|apc.enabled =>|apc.shm_size =>|apc.enable_cli =>)' | sed 's/^/  /' || true
  fi

  if have_cmd systemctl; then
    systemctl --no-pager --quiet is-active "php${PHP_VERSION}-fpm" && info "Service active: php${PHP_VERSION}-fpm" || warn "Service not active: php${PHP_VERSION}-fpm"
    systemctl --no-pager --quiet is-active nginx && info "Service active: nginx" || warn "Service not active: nginx"
    systemctl --no-pager --quiet is-active mariadb && info "Service active: mariadb" || warn "Service not active: mariadb"
    systemctl --no-pager --quiet is-active drupal-cron.timer && info "Timer active: drupal-cron.timer" || warn "Timer not active: drupal-cron.timer"
  fi

  # Drush quick status (best-effort)
  if drush_path >/dev/null 2>&1; then
    info "Drush: $(run_as_app_drupal "${WEB_ROOT}/vendor/bin/drush" --version | head -n 1 2>/dev/null || true)"
  fi
}

########################################
# Main
########################################
main(){
  need_root
  load_creds
  detect_resources

  optimize_php
  optimize_apcu
  optimize_nginx
  optimize_mariadb
  enable_apcu_in_settings
  apply_drupal_perf_config
  install_cron_timer
  optimize_sysctl
  verify

  info "Done. Log: $LOG_FILE"
}

main "$@"
