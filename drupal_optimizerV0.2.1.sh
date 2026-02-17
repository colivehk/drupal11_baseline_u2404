#!/usr/bin/env bash
set -Eeuo pipefail

DEBUG="${DEBUG:-0}"
if [[ "${DEBUG}" == "1" ]]; then
  export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
  set -x
fi

# drupal_optimizerV0.2.1.sh
# Optimizer for a Drupal site installed by:
#   drupal_installV0.1.2.14_hard_single_cwd.sh
#
# Target shape:
# - Ubuntu 24.04.3 local IP testing
# - Nginx + PHP-FPM 8.3 + MariaDB
# - Performance: OPcache + APCu (+ optional Redis), no Varnish
# - Safe to run multiple times (idempotent-ish), creates backups before editing files
#
# Usage:
#   sudo -E bash drupal_optimizerV0.2.1.sh
#   sudo -E PROD_STRICT=1 bash drupal_optimizerV0.2.1.sh     # production-like OPcache (no timestamp checks)
#   sudo -E ENABLE_DRUPAL_PERF_CONFIG=0 bash drupal_optimizerV0.2.1.sh  # skip drush config:set tuning
#
# Notes (installer-coupled behavior):
# - Reads installer credentials env files under /var/lib/drupal-tools/credentials/
# - Uses APP_USER (default: ubuntu) for composer/drush with COMPOSER_HOME under /home/ubuntu/.config/composer
# - Drush commands run inside /var/www/drupal (project root), with correct COMPOSER env

########################################
# Defaults (override via env vars)
########################################
SCRIPT_VERSION="V0.2.1"
APP_USER="${APP_USER:-ubuntu}"
WEB_USER="${WEB_USER:-www-data}"
COLLAB_GROUP="${COLLAB_GROUP:-drupal}"

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
APP_USER_HOME="${APP_USER_HOME:-}"

# Composer runtime (installer sets these for www-data)
COMPOSER_HOME_DIR="${COMPOSER_HOME_DIR:-}"
COMPOSER_CACHE_DIR="${COMPOSER_CACHE_DIR:-}"

# Feature switches
ENABLE_PHP_TUNING="${ENABLE_PHP_TUNING:-1}"
ENABLE_APCU="${ENABLE_APCU:-1}"
ENABLE_SETTINGS_APCU="${ENABLE_SETTINGS_APCU:-1}"
ENABLE_NGINX_TUNING="${ENABLE_NGINX_TUNING:-1}"
# Nginx gzip behavior: auto|1|0
ENABLE_NGINX_GZIP="${ENABLE_NGINX_GZIP:-auto}"
ENABLE_MARIADB_TUNING="${ENABLE_MARIADB_TUNING:-1}"
ENABLE_CRON="${ENABLE_CRON:-1}"
ENABLE_REDIS="${ENABLE_REDIS:-1}"
REDIS_MODULE_VERSION="${REDIS_MODULE_VERSION:-^1.11}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
ENABLE_UMASK_002="${ENABLE_UMASK_002:-1}"
ENABLE_ACL_MODE="${ENABLE_ACL_MODE:-0}"  # same as --acl
ENABLE_HARDEN_MODE="${ENABLE_HARDEN_MODE:-0}"
URI_OVERRIDE=\"${URI_OVERRIDE:-0}\"
TRUSTED_HOSTS="${TRUSTED_HOSTS:-}"
TRUSTED_HOSTS_FROM_URI="${TRUSTED_HOSTS_FROM_URI:-1}"


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
ok(){ _log OK "$@"; }
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


print_help() {
  cat <<EOF
Drupal Optimizer ${SCRIPT_VERSION}

Usage:
  sudo -E bash $(basename "$0") [--uri URL] [--acl|--no-acl] [--harden] [--trusted-hosts LIST]

Options:
  --uri URL            Override SITE_URI/BASE_URL for this run (also used for trusted_host_patterns).
  --acl                 Apply POSIX ACLs on sites/default/files so APP_USER can delete css/js even if your shell group list wasn't refreshed.
  --no-acl              Disable ACL mode (default).
  --harden              Protect sites/default (fixes "Not protected") and write trusted_host_patterns.
  --trusted-hosts LIST  Comma-separated hosts for trusted_host_patterns. Regex is allowed with prefix re: (e.g. example.com,re:^.+\.example\.com$)
  --no-trusted-uri      Do not auto-add host extracted from --uri into trusted_host_patterns.
  -h, --help            Show this help.

Environment toggles (examples):
  ENABLE_REDIS=1             Enable Redis integration (two-step safe mode).
  ENABLE_UPLOADPROGRESS=1    Enable uploadprogress PHP extension.
  ENABLE_IMAGEMAGICK=1       Install ImageMagick and PHP Imagick.
  ENABLE_ACL_MODE=1          Same as --acl.
  ENABLE_HARDEN_MODE=1       Same as --harden.
  TRUSTED_HOSTS="example.com,192.168.64.19"
  SITE_URI="http://192.168.64.19"     Optional; same effect as --uri when BASE_URL is empty.
  TRUSTED_HOSTS_FROM_URI=0   Do not auto-add host from --uri.
EOF
}

# Args (lightweight): ACL + harden helper
if [[ $# -gt 0 ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --acl) ENABLE_ACL_MODE=1; shift;;
      --no-acl) ENABLE_ACL_MODE=0; shift;;
--harden) ENABLE_HARDEN_MODE=1; shift;;
--trusted-hosts) TRUSTED_HOSTS="${2:-}"; shift 2;;
--trusted-hosts=*) TRUSTED_HOSTS="${1#*=}"; shift;;
    --uri) BASE_URL="${2:-}"; DRUSH_URI="${2:-}"; URI_OVERRIDE=1; shift 2;;
    --uri=*) BASE_URL="${1#*=}"; DRUSH_URI="${1#*=}"; URI_OVERRIDE=1; shift;;
--no-trusted-uri) TRUSTED_HOSTS_FROM_URI=0; shift;;
      -h|--help) print_help; exit 0;;
      *) die "Unknown argument: $1 (use --help)";;
    esac
  done
fi


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
  # Determine APP_USER home (for composer/drush runtime)
  if [[ -z "${APP_USER_HOME}" ]]; then
    APP_USER_HOME="$(getent passwd "${APP_USER}" 2>/dev/null | cut -d: -f6 || true)"
    [[ -z "${APP_USER_HOME}" ]] && APP_USER_HOME="/home/${APP_USER}"
  fi

  # Composer runtime defaults (collab-perms model: composer/drush run as APP_USER)
  if [[ -z "${COMPOSER_HOME_DIR}" ]]; then
    COMPOSER_HOME_DIR="${APP_USER_HOME}/.config/composer"
  fi
  if [[ -z "${COMPOSER_CACHE_DIR}" ]]; then
    COMPOSER_CACHE_DIR="${APP_USER_HOME}/.cache/composer"
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
  info "WEB_USER=${WEB_USER}"
  info "COLLAB_GROUP=${COLLAB_GROUP}"
  info "COMPOSER_HOME_DIR=${COMPOSER_HOME_DIR}"
  info "COMPOSER_CACHE_DIR=${COMPOSER_CACHE_DIR}"
  [[ -n "${BASE_URL:-}" ]] && info "BASE_URL=${BASE_URL}"
}

########################################
# Run commands as APP_USER (collab-perms: ubuntu runs composer/drush)
########################################
q(){ printf "%q " "$@"; }

run_as_app_drupal(){
  # Usage: run_as_app_drupal <cmd> [args...]
  local cmd; cmd="$(q "$@")"
  # Use a login-like shell environment and always cd into WEB_ROOT (project root).
  # Keep COMPOSER_HOME/COMPOSER_CACHE_DIR aligned with the installer.
  su -s /bin/bash - "${APP_USER}" -c '
    export HOME="$1"
    export COMPOSER_HOME="$2"
    export COMPOSER_CACHE_DIR="$3"
    umask 002
    cd "$4" || exit 1
    bash -lc "$5"
  ' bash "${APP_USER_HOME}" "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" "${WEB_ROOT}" "${cmd}"
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
# 8.x) Collab-perms helpers (ubuntu + www-data)
########################################
ensure_collab_group(){
  # Ensure shared group exists and memberships are correct.
  if ! getent group "${COLLAB_GROUP}" >/dev/null 2>&1; then
    step "Creating group: ${COLLAB_GROUP}"
    groupadd "${COLLAB_GROUP}" || true
  fi

  # Add users to group (best-effort).
  if id "${APP_USER}" >/dev/null 2>&1; then
    usermod -aG "${COLLAB_GROUP}" "${APP_USER}" >/dev/null 2>&1 || true
  else
    warn "User not found: ${APP_USER} (skip group membership)"
  fi
  if id "${WEB_USER}" >/dev/null 2>&1; then
    usermod -aG "${COLLAB_GROUP}" "${WEB_USER}" >/dev/null 2>&1 || true
  else
    warn "User not found: ${WEB_USER} (skip group membership)"
  fi

  # Ensure composer dirs exist (owned by APP_USER).
  mkdir -p "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" >/dev/null 2>&1 || true
  chown -R "${APP_USER}:${COLLAB_GROUP}" "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" >/dev/null 2>&1 || true
  chmod 0755 "${COMPOSER_HOME_DIR}" "${COMPOSER_CACHE_DIR}" >/dev/null 2>&1 || true

  # Make common code dirs group-inheriting (setgid) without changing owner.
  local d
  for d in "${WEB_ROOT}" "${WEB_ROOT}/web" "${WEB_ROOT}/web/modules" "${WEB_ROOT}/web/modules/custom" "${WEB_ROOT}/web/themes" "${WEB_ROOT}/web/themes/custom"; do
    [[ -d "$d" ]] || continue
    chgrp "${COLLAB_GROUP}" "$d" >/dev/null 2>&1 || true
    chmod g+s "$d" >/dev/null 2>&1 || true
    chmod 2775 "$d" >/dev/null 2>&1 || true
  done

  info "Collab group ensured: group=${COLLAB_GROUP}, ops=${APP_USER}, web=${WEB_USER}"
}

enable_umask_002(){
  [[ "${ENABLE_UMASK_002}" == "1" ]] || { info "umask=002 disabled by switch"; return 0; }
  step "Enable umask 002 for users in group ${COLLAB_GROUP}"
  local f="/etc/profile.d/umask-002-${COLLAB_GROUP}.sh"
  cat >"$f" <<EOF
# Generated by drupal_optimizer ${SCRIPT_VERSION}
# Purpose: reduce permission friction in a shared-code workflow.
# If the login user belongs to '${COLLAB_GROUP}', use group-writable defaults.
if command -v id >/dev/null 2>&1; then
  if id -nG "${USER:-}" 2>/dev/null | tr ' ' '\n' | grep -qx "${COLLAB_GROUP}"; then
    umask 002
  fi
fi
EOF
  chmod 0644 "$f" >/dev/null 2>&1 || true
  info "Wrote: $f (effective on NEW login shells)"
}



ensure_acl_tools() {
  command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1 && return 0
  ensure_pkg acl
  return 0
}

apply_acl_on_files_dir() {
  [[ "${ENABLE_ACL_MODE:-0}" == "1" ]] || return 0
  local files_dir="$1"
  [[ -d "${files_dir}" ]] || { warn "ACL: directory not found: ${files_dir}"; return 0; }
  ensure_acl_tools || { warn "ACL tools not available; skipping ACL."; return 0; }

  step "ACL: granting ${APP_USER} rwX on ${files_dir} (and default ACL for new files)"
  setfacl -R -m "u:${APP_USER}:rwX,u:${WEB_USER}:rwX,g:${COLLAB_GROUP}:rwX,m::rwX" "${files_dir}" >>"$LOG_FILE" 2>&1 || true
  find "${files_dir}" -type d -print0 2>/dev/null | xargs -0 -r setfacl -d -m "u:${APP_USER}:rwX,u:${WEB_USER}:rwX,g:${COLLAB_GROUP}:rwX,m::rwX" >>"$LOG_FILE" 2>&1 || true
  ok "ACL applied on: ${files_dir}"
}

fix_runtime_files_perms(){
  # Keep runtime writable area consistent.
  local files_dir="${WEB_PUBLIC}/sites/default/files"
  if [[ -d "${files_dir}" ]]; then
    chown -R "${WEB_USER}:${COLLAB_GROUP}" "${files_dir}" >/dev/null 2>&1 || true
    find "${files_dir}" -type d -exec chmod 2775 {} \; >/dev/null 2>&1 || true
    find "${files_dir}" -type f -exec chmod 0664 {} \; >/dev/null 2>&1 || true
    info "Runtime perms fixed: ${files_dir} -> ${WEB_USER}:${COLLAB_GROUP} (2775/664)"
  else
    warn "Runtime dir not found (${files_dir}); skipping sites/default/files permission fix."
  fi
}

########################################
# 8.y) Redis (two-stage: system first, then Drupal integration)
########################################
redis_stage1_system(){
  step "Redis stage 1/2: system packages + services"
  ensure_pkg redis-server
  ensure_pkg_any "php${PHP_VERSION}-redis" "php-redis"
  phpenmod -v "${PHP_VERSION}" redis >/dev/null 2>&1 || true
  systemctl enable --now redis-server >/dev/null 2>&1 || true
  systemctl restart "php${PHP_VERSION}-fpm" >/dev/null 2>&1 || true
  info "Redis service ensured + PHP redis extension enabled (if available)"
}

settings_has_redis_include(){
  local settings="${WEB_ROOT}/web/sites/default/settings.php"
  [[ -f "$settings" ]] || return 1
  grep -q "BEGIN DRUPAL_OPTIMIZER_REDIS" "$settings"
}

redis_stage2_drupal(){
  step "Redis stage 2/2: Drupal integration (composer + drush + settings)"
  local state_dir="${STATE_ROOT}/state"
  mkdir -p "$state_dir" >/dev/null 2>&1 || true
  local pending="$state_dir/redis.pending"

  # Only proceed if site is installed (settings.php exists).
  local settings="${WEB_ROOT}/web/sites/default/settings.php"
  if [[ ! -f "$settings" ]]; then
    warn "Site not installed yet (missing $settings). Redis stage2 deferred."
    echo "pending" >"$pending" 2>/dev/null || true
    warn "After site:install, re-run this script to finish Redis integration. Marker: $pending"
    return 0
  fi

  # Ensure composer project exists.
  if [[ ! -f "${WEB_ROOT}/composer.json" ]]; then
    warn "composer.json not found under ${WEB_ROOT} (skip Redis stage2)"
    echo "pending" >"$pending" 2>/dev/null || true
    return 0
  fi

  # Install drupal/redis if missing.
  if ! grep -q '"drupal/redis"' "${WEB_ROOT}/composer.json" 2>/dev/null; then
    step "Installing Drupal Redis module via Composer (${REDIS_MODULE_VERSION}) as ${APP_USER}"
    run_as_app_drupal composer require "drupal/redis:${REDIS_MODULE_VERSION}" >>"$LOG_FILE" 2>&1
  else
    info "Composer already requires drupal/redis (skip composer require)"
  fi

  # Enable module.
  drush_run en redis -y >>"$LOG_FILE" 2>&1 || true

  # Write settings.redis.php (owned by APP_USER).
  local redis_settings="${WEB_ROOT}/web/sites/default/settings.redis.php"
  run_as_app_drupal bash -lc "cat > $(printf %q "$redis_settings") <<'EOF'
<?php
/**
 * Redis settings (generated by drupal_optimizer ${SCRIPT_VERSION}).
 * Two-stage mode: safe to re-run.
 *
 * NOTE: If Redis is down, cache backend may fail. For critical environments,
 * consider a failover/chained backend strategy.
 */

\$settings['redis.connection']['interface'] = 'PhpRedis';
\$settings['redis.connection']['host'] = '${REDIS_HOST}';
\$settings['redis.connection']['port'] = ${REDIS_PORT};

// Use Redis for the default cache backend.
\$settings['cache']['default'] = 'cache.backend.redis';

// Container services provided by the redis module.
\$settings['container_yamls'][] = 'modules/contrib/redis/example.services.yml';
EOF" >>"$LOG_FILE" 2>&1
  # Prefer including settings.redis.php from settings.statekeeper.php (keeps settings.php stable).
  ensure_statekeeper_include
  ensure_statekeeper_file

  local sk="${WEB_PUBLIC}/sites/default/settings.statekeeper.php"
  local begin="# BEGIN DRUPAL_OPTIMIZER_REDIS_INCLUDE"
  local end="# END DRUPAL_OPTIMIZER_REDIS_INCLUDE"
  run_as_root bash -lc "perl -0777 -i -pe 's/\n\Q${begin}\E.*?\Q${end}\E\n/\n/s' $(printf %q \"$sk\")" >>"$LOG_FILE" 2>&1 || true
  cat >>"$sk" <<'EOF'
# BEGIN DRUPAL_OPTIMIZER_REDIS_INCLUDE
$redis_settings = $app_root . '/' . $site_path . '/settings.redis.php';
if (file_exists($redis_settings)) {
  include $redis_settings;
}
# END DRUPAL_OPTIMIZER_REDIS_INCLUDE
EOF

  chown "${APP_USER}:${COLLAB_GROUP}" "$sk" 2>/dev/null || true
  chmod 0640 "$sk" 2>/dev/null || true

  drush_run cr >>"$LOG_FILE" 2>&1 || true
  rm -f "$pending" >/dev/null 2>&1 || true
  info "Redis stage2 complete."
}

enable_redis_two_stage(){
  [[ "${ENABLE_REDIS}" == "1" ]] || { info "Redis disabled by switch"; return 0; }
  step "Enable Redis (two-stage mode)"
  redis_stage1_system
  redis_stage2_drupal
}



########################################
# 8.x) Security hardening (sites/default + trusted hosts)
########################################
escape_host_regex(){
  local h="${1:-}"
  [[ -n "${h}" ]] || return 1
  # Escape regex metacharacters so host is matched literally.
  local esc
  esc="$(printf '%s' "${h}" | perl -pe 's/([\\\\.^$|?*+(){}\\[\\]])/\\\\$1/g')"
  echo "^${esc}$"
}

extract_host_from_uri(){
  local u="${1:-}"
  [[ -n "${u}" ]] || return 1
  u="${u#*://}"
  u="${u%%/*}"

  # IPv6 in brackets: [::1]:8080
  if [[ "${u}" == \[*\]* ]]; then
    u="${u#\[}"
    u="${u%%\]*}"
    echo "${u}"
    return 0
  fi

  # Strip :port if present (IPv4/hostname)
  if [[ "${u}" == *:* ]]; then
    local tail="${u##*:}"
    if [[ "${tail}" =~ ^[0-9]+$ ]]; then
      u="${u%:*}"
    fi
  fi

  echo "${u}"
}

ensure_statekeeper_file(){
  local sd="${WEB_PUBLIC}/sites/default"
  local f="${sd}/settings.statekeeper.php"
  if [[ ! -f "$f" ]]; then
    step "Creating settings.statekeeper.php (owned by ${APP_USER}:${COLLAB_GROUP})"
    install -m 0640 -o "${APP_USER}" -g "${COLLAB_GROUP}" /dev/null "$f" >>"$LOG_FILE" 2>&1
    printf "<?php\n// settings.statekeeper.php (managed by drupal_* scripts)\n" | tee -a "$f" >/dev/null
  fi
  chown "${APP_USER}:${COLLAB_GROUP}" "$f" 2>/dev/null || true
  chmod 0640 "$f" 2>/dev/null || true
}

settings_has_statekeeper_include(){
  local settings="${WEB_PUBLIC}/sites/default/settings.php"
  [[ -f "${settings}" ]] || return 1
  # Be strict: detect any include of settings.statekeeper.php (marker-based or custom).
  grep -qE 'settings\\.statekeeper\\.php|BEGIN DRUPAL_STATEKEEPER_INCLUDE' "${settings}" 2>/dev/null
}

ensure_statekeeper_include(){
  local settings="${WEB_PUBLIC}/sites/default/settings.php"
  [[ -f "$settings" ]] || return 0
  if settings_has_statekeeper_include; then
    return 0
  fi
  step "Appending statekeeper include block to settings.php (as ${APP_USER})"
  run_as_app_drupal bash -lc "cat >> $(printf %q "$settings") <<'EOF'

# BEGIN DRUPAL_STATEKEEPER_INCLUDE
if (file_exists(\$app_root . '/' . \$site_path . '/settings.statekeeper.php')) {
  include \$app_root . '/' . \$site_path . '/settings.statekeeper.php';
}
# END DRUPAL_STATEKEEPER_INCLUDE
EOF" >>"$LOG_FILE" 2>&1
}

write_trusted_hosts(){
  local sd="${WEB_PUBLIC}/sites/default"
  local settings="${sd}/settings.php"
  local f="${sd}/settings.statekeeper.php"

  [[ -f "${settings}" ]] || { warn "settings.php not found; skipping trusted hosts."; return 0; }

  # Ensure statekeeper include exists (trusted hosts are written into settings.statekeeper.php only).
  if ! settings_has_statekeeper_include; then
    ensure_statekeeper_include
  fi
  if ! settings_has_statekeeper_include; then
    die "Cannot apply trusted hosts: settings.php does not include settings.statekeeper.php (check ownership/permissions)."
  fi

  ensure_statekeeper_file

  # Build trusted host regex patterns.
  local hosts_csv=""
  local uri_src="${DRUSH_URI:-${BASE_URL:-}}"
  local uri_host=""

  if [[ "${TRUSTED_HOSTS_FROM_URI}" == "1" && -n "${uri_src}" ]]; then
    uri_host="$(extract_host_from_uri "${uri_src}" || true)"
    if [[ -n "${uri_host}" ]]; then
      hosts_csv+="${uri_host},"
    fi
  fi

  if [[ -n "${TRUSTED_HOSTS}" ]]; then
    hosts_csv+="${TRUSTED_HOSTS},"
  fi

  # In strict mode, DO NOT auto-add localhost/127.0.0.1 unless the URI host is local.
  if [[ "${uri_host}" == "localhost" || "${uri_host}" == "127.0.0.1" || "${uri_host}" == "::1" ]]; then
    hosts_csv+="localhost,127.0.0.1,"
  fi

  # Normalize into unique patterns.
  declare -A seen
  local php_array=""
  IFS=',' read -r -a arr <<< "${hosts_csv%,}"
  for raw in "${arr[@]}"; do
    # trim
    local entry="${raw}"; entry="${entry#\"${entry%%[![:space:]]*}\"}"; entry="${entry%\"${entry##*[![:space:]]}\"}"
    [[ -n "${entry}" ]] || continue

    local pat=""
    if [[ "${entry}" == re:* || "${entry}" == regex:* ]]; then
      pat="${entry#*:}"
      pat="${pat#\"${pat%%[![:space:]]*}\"}"; pat="${pat%\"${pat##*[![:space:]]}\"}"
      [[ -n "${pat}" ]] || continue
      # Warn if not anchored.
      if [[ "${pat}" != ^* || "${pat}" != *$ ]]; then
        warn "trusted host regex is not anchored (recommended): ${pat}"
      fi
    else
      # Back-compat: if looks like raw regex, accept but warn.
      if [[ "${entry}" == ^* ]]; then
        warn "trusted host entry looks like a raw regex; prefer re:<pattern>. Accepting as-is: ${entry}"
        pat="${entry}"
      else
        # Allow full URL input.
        if [[ "${entry}" == *"://"* ]]; then
          entry="$(extract_host_from_uri "${entry}" || true)"
        fi
        [[ -n "${entry}" ]] || continue
        pat="$(escape_host_regex "${entry}")"
      fi
    fi

    [[ -n "${pat}" ]] || continue
    if [[ -z "${seen[${pat}]:-}" ]]; then
      seen[${pat}]=1
      php_array+="  '${pat}',\n"
    fi
  done

  if [[ -z "${php_array}" ]]; then
    warn "No trusted hosts computed; skipping trusted_host_patterns write."
    return 0
  fi

  step "Writing trusted_host_patterns into settings.statekeeper.php (strict)"

  # Remove previous block.
  run_as_root perl -0777 -i -pe 's#\n// BEGIN OPTIMIZER TRUSTED HOSTS.*?// END OPTIMIZER TRUSTED HOSTS\n##s' "${f}" || true

  # Append new block.
  cat >> "${f}" <<EOF

// BEGIN OPTIMIZER TRUSTED HOSTS (do not edit; managed by drupal_optimizer)
\$settings['trusted_host_patterns'] = [
$(printf '%b' "${php_array}")];
// END OPTIMIZER TRUSTED HOSTS
EOF

  chmod 0640 "${f}" || true
  chown "${APP_USER}:${COLLAB_GROUP}" "${f}" || true
}

harden_sites_default(){
  local sd="${WEB_PUBLIC}/sites/default"
  [[ -d "$sd" ]] || return 0
  step "Hardening permissions for sites/default (non-writable) and settings files"
  chown "${APP_USER}:${COLLAB_GROUP}" "$sd" 2>/dev/null || true
  chgrp "${COLLAB_GROUP}" "$sd" 2>/dev/null || true
  chmod 0755 "$sd" 2>/dev/null || true

  for f in settings.php settings.statekeeper.php settings.redis.php; do
    if [[ -f "${sd}/${f}" ]]; then
      chown "${APP_USER}:${COLLAB_GROUP}" "${sd}/${f}" 2>/dev/null || true
      chmod 0640 "${sd}/${f}" 2>/dev/null || true
    fi
  done
}

apply_hardening(){
  [[ "${ENABLE_HARDEN_MODE}" == "1" ]] || return 0
  ensure_statekeeper_include
  ensure_statekeeper_file
  harden_sites_default
  write_trusted_hosts
  drush_run cr >>"$LOG_FILE" 2>&1 || true
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
    systemctl --no-pager --quiet is-active redis-server && info "Service active: redis-server" || warn "Service not active: redis-server"
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

  ensure_collab_group
  enable_umask_002

  # Ensure runtime writable dir is sane before any drush cache rebuilds.
  fix_runtime_files_perms
  apply_acl_on_files_dir "${WEB_PUBLIC}/sites/default/files"

  apply_hardening

  optimize_php
  optimize_apcu
  optimize_nginx
  optimize_mariadb
  enable_apcu_in_settings
  apply_drupal_perf_config
  enable_redis_two_stage
  install_cron_timer
  optimize_sysctl
  verify

  info "Done. Log: $LOG_FILE"
}

main "$@"
