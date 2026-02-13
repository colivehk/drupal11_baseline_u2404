#!/usr/bin/env bash
set -euo pipefail

# ===========================================
# Drupal 11 baseline on Ubuntu 24.04.x
# - Nginx + PHP-FPM + MariaDB + Composer
# - DOES NOT install Drupal
# - Key changes: do NOT pre-create /var/www/drupal (Composer as www-data will create it)
# - Configure Composer HOME + auth/tokens for www-data
# ===========================================

# ---------- Toggles ----------
INSTALL_NGINX=1
INSTALL_MARIADB=1
INSTALL_PHP=1
INSTALL_COMPOSER=1
INSTALL_APCU=1

# PHP: Drupal 11 min PHP 8.3. Drupal 11.3+ recommends 8.4 (optional via PPA).
PHP_VERSION="8.3"
USE_ONDREJ_PPA=0            # set 1 if you explicitly want PHP 8.4
ONDREJ_PPA_NAME="ppa:ondrej/php"
PHP_VERSION_IF_PPA="8.4"

# Nginx
NGINX_SITE_NAME="drupal"
NGINX_SERVER_NAME="_"       # change later to your domain

# Drupal future path (NOT created here)
DRUPAL_PARENT="/var/www"    # we will grant www-data create rights here
DRUPAL_DIR="/var/www/drupal"
DRUPAL_DOCROOT="${DRUPAL_DIR}/web"

# Allow www-data to create /var/www/drupal by giving ACL on /var/www
ALLOW_WWWDATA_CREATE_UNDER_VAR_WWW=1

# Optional: let ubuntu user edit under /var/www conveniently (not required)
GRANT_UBUNTU_TO_WWWDATA_GROUP=0

# Composer HOME for www-data
WWW_COMPOSER_HOME="/var/www/.composer"

# Optional: create a small php test file under /var/www/html (safe baseline)
CREATE_PHP_TEST_PAGE=1

# Optional: SSH key for www-data (ONLY if you use git@... ssh URLs)
ENABLE_WWWDATA_SSH_KEY=0
SSH_KNOWN_HOSTS=("github.com" "gitlab.com")

# PHP tuning
PHP_MEMORY_LIMIT="512M"
PHP_MAX_EXEC_TIME="120"
PHP_UPLOAD_MAX_FILESIZE="64M"
PHP_POST_MAX_SIZE="64M"
PHP_MAX_INPUT_VARS="5000"

# MariaDB tuning
DB_TUNE_MAX_ALLOWED_PACKET="64M"

# Swap (useful for small VMs)
AUTO_SWAP=1
SWAPFILE="/swapfile"
SWAPSIZE_MB=2048

# ---------- Helpers ----------
need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[FATAL] Run as root: sudo bash $0"
    exit 1
  fi
}
log() { echo -e "[$(date +'%F %T')] $*"; }

apt_install() {
  local pkgs=("$@")
  export DEBIAN_FRONTEND=noninteractive
  log "APT install: ${pkgs[*]}"
  apt-get update -y
  apt-get install -y --no-install-recommends "${pkgs[@]}"
}

write_if_changed() {
  local path="$1"; shift
  local content="$1"; shift || true
  local tmp
  tmp="$(mktemp)"
  printf "%s" "${content}" > "${tmp}"
  if [[ -f "${path}" ]] && cmp -s "${tmp}" "${path}"; then
    rm -f "${tmp}"
    log "No change: ${path}"
    return 0
  fi
  install -m 0644 "${tmp}" "${path}"
  rm -f "${tmp}"
  log "Wrote: ${path}"
}

enable_service() {
  local svc="$1"
  systemctl enable --now "${svc}"
  systemctl is-active --quiet "${svc}" && log "Service active: ${svc}"
}

detect_default_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "${SUDO_USER}"
  else
    echo "ubuntu"
  fi
}

setup_swap_if_needed() {
  [[ "${AUTO_SWAP}" -eq 1 ]] || return 0

  local has_swap=0
  if swapon --noheadings --show=NAME 2>/dev/null | grep -q .; then
    has_swap=1
  fi

  local mem_kb mem_mb
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  mem_mb=$((mem_kb / 1024))

  if [[ "${has_swap}" -eq 0 && "${mem_mb}" -lt 2048 ]]; then
    if [[ -f "${SWAPFILE}" ]]; then
      log "Swapfile exists but not enabled; enabling: ${SWAPFILE}"
      chmod 600 "${SWAPFILE}" || true
      mkswap "${SWAPFILE}" >/dev/null || true
      swapon "${SWAPFILE}" || true
    else
      log "Creating swapfile (${SWAPSIZE_MB}MB) at ${SWAPFILE} (RAM=${mem_mb}MB, no swap)"
      fallocate -l "${SWAPSIZE_MB}M" "${SWAPFILE}" || dd if=/dev/zero of="${SWAPFILE}" bs=1M count="${SWAPSIZE_MB}"
      chmod 600 "${SWAPFILE}"
      mkswap "${SWAPFILE}" >/dev/null
      swapon "${SWAPFILE}"
    fi
    if ! grep -qE "^[^#].*\s${SWAPFILE}\s+swap\s" /etc/fstab; then
      echo "${SWAPFILE} none swap sw 0 0" >> /etc/fstab
      log "Added swap to /etc/fstab"
    fi
  else
    log "Swap check OK (RAM=${mem_mb}MB, swap_present=${has_swap})"
  fi
}

# ---------- Main ----------
need_root
DEFAULT_USER="$(detect_default_user)"

LOG_DIR="/var/log/drupal-tools"
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/baseline_v1.$(date +'%Y%m%d_%H%M%S').log"
exec > >(tee -a "${LOG_FILE}") 2>&1

log "Starting Drupal 11 baseline on Ubuntu 24.04.x"
log "Default user: ${DEFAULT_USER}"
log "Log file: ${LOG_FILE}"

setup_swap_if_needed

log "Base packages"
apt_install ca-certificates curl unzip git gnupg lsb-release software-properties-common acl jq

if [[ "${USE_ONDREJ_PPA}" -eq 1 ]]; then
  log "Enabling ${ONDREJ_PPA_NAME} (for PHP ${PHP_VERSION_IF_PPA})"
  add-apt-repository -y "${ONDREJ_PPA_NAME}"
  PHP_VERSION="${PHP_VERSION_IF_PPA}"
fi

# --- PHP ---
if [[ "${INSTALL_PHP}" -eq 1 ]]; then
  log "Installing PHP ${PHP_VERSION} + common extensions"
  PHP_PKGS=(
    "php${PHP_VERSION}-fpm"
    "php${PHP_VERSION}-cli"
    "php${PHP_VERSION}-common"
    "php${PHP_VERSION}-mysql"
    "php${PHP_VERSION}-xml"
    "php${PHP_VERSION}-gd"
    "php${PHP_VERSION}-curl"
    "php${PHP_VERSION}-mbstring"
    "php${PHP_VERSION}-zip"
    "php${PHP_VERSION}-intl"
    "php${PHP_VERSION}-opcache"
    "php${PHP_VERSION}-bcmath"
  )
  if [[ "${INSTALL_APCU}" -eq 1 ]]; then
    PHP_PKGS+=("php-apcu")
  fi
  apt_install "${PHP_PKGS[@]}"
  enable_service "php${PHP_VERSION}-fpm"

  # PHP ini tuning (FPM + CLI)
  for sapi in fpm cli; do
    ini="/etc/php/${PHP_VERSION}/${sapi}/php.ini"
    if [[ -f "${ini}" ]]; then
      log "Tuning ${ini}"
      sed -i -E \
        -e "s~^memory_limit\s*=.*~memory_limit = ${PHP_MEMORY_LIMIT}~" \
        -e "s~^max_execution_time\s*=.*~max_execution_time = ${PHP_MAX_EXEC_TIME}~" \
        -e "s~^upload_max_filesize\s*=.*~upload_max_filesize = ${PHP_UPLOAD_MAX_FILESIZE}~" \
        -e "s~^post_max_size\s*=.*~post_max_size = ${PHP_POST_MAX_SIZE}~" \
        -e "s~^max_input_vars\s*=.*~max_input_vars = ${PHP_MAX_INPUT_VARS}~" \
        "${ini}" || true
    fi
  done

  # OpCache baseline (FPM)
  OPCACHE_INI="/etc/php/${PHP_VERSION}/fpm/conf.d/99-drupal-opcache.ini"
  write_if_changed "${OPCACHE_INI}" \
"opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.revalidate_freq=2
opcache.validate_timestamps=1
"

  # Dedicated FPM pool for Drupal (separate sock)
  POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/drupal.conf"
  write_if_changed "${POOL}" \
"[drupal]
user = www-data
group = www-data

listen = /run/php/php${PHP_VERSION}-fpm-drupal.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 20
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 8

php_admin_value[memory_limit] = ${PHP_MEMORY_LIMIT}
php_admin_value[upload_max_filesize] = ${PHP_UPLOAD_MAX_FILESIZE}
php_admin_value[post_max_size] = ${PHP_POST_MAX_SIZE}
php_admin_value[max_execution_time] = ${PHP_MAX_EXEC_TIME}
"

  systemctl restart "php${PHP_VERSION}-fpm"
  log "PHP ready: $(php -v | head -n 1)"
fi

# --- MariaDB ---
if [[ "${INSTALL_MARIADB}" -eq 1 ]]; then
  log "Installing MariaDB"
  apt_install mariadb-server mariadb-client
  enable_service mariadb

  DB_CNF="/etc/mysql/mariadb.conf.d/99-drupal.cnf"
  write_if_changed "${DB_CNF}" \
"[mysqld]
max_allowed_packet = ${DB_TUNE_MAX_ALLOWED_PACKET}
innodb_file_per_table = 1
"
  systemctl restart mariadb
  log "MariaDB ready: $(mariadb --version | head -n 1)"
fi

# --- Composer (system-wide) ---
if [[ "${INSTALL_COMPOSER}" -eq 1 ]]; then
  if command -v composer >/dev/null 2>&1; then
    log "Composer already installed: $(composer --version)"
  else
    log "Installing Composer (official installer)"
    EXPECTED_SIG="$(curl -fsSL https://composer.github.io/installer.sig)"
    php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
    ACTUAL_SIG="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"
    if [[ "${EXPECTED_SIG}" != "${ACTUAL_SIG}" ]]; then
      log "[FATAL] Composer installer signature mismatch!"
      rm -f composer-setup.php
      exit 1
    fi
    php composer-setup.php --quiet --install-dir=/usr/local/bin --filename=composer
    rm -f composer-setup.php
    log "Composer installed: $(composer --version)"
  fi
fi

# --- www-data Composer HOME + keys (tokens/auth) ---
log "Configuring Composer HOME for www-data: ${WWW_COMPOSER_HOME}"
mkdir -p "${WWW_COMPOSER_HOME}/cache"
chown -R www-data:www-data "${WWW_COMPOSER_HOME}"
chmod 700 "${WWW_COMPOSER_HOME}"
chmod 700 "${WWW_COMPOSER_HOME}/cache"

# optional: export for interactive shells
cat >/etc/profile.d/www-data-composer.sh <<EOF
export COMPOSER_HOME="${WWW_COMPOSER_HOME}"
export COMPOSER_CACHE_DIR="${WWW_COMPOSER_HOME}/cache"
EOF
chmod 644 /etc/profile.d/www-data-composer.sh

# Apply tokens if provided (belong to www-data)
if command -v composer >/dev/null 2>&1; then
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    log "Setting github-oauth for www-data (auth.json under ${WWW_COMPOSER_HOME})"
    sudo -u www-data -H env COMPOSER_HOME="${WWW_COMPOSER_HOME}" \
      composer config -g github-oauth.github.com "${GITHUB_TOKEN}"
  fi

  if [[ -n "${GITLAB_TOKEN:-}" && -n "${GITLAB_HOST:-}" ]]; then
    log "Setting gitlab-token.${GITLAB_HOST} for www-data"
    sudo -u www-data -H env COMPOSER_HOME="${WWW_COMPOSER_HOME}" \
      composer config -g "gitlab-token.${GITLAB_HOST}" "${GITLAB_TOKEN}"
  fi

  # Optional: allow writing full auth.json directly (prefer env var to avoid editing script)
  # Usage: export COMPOSER_AUTH_JSON_B64="$(base64 -w0 auth.json)"
  if [[ -n "${COMPOSER_AUTH_JSON_B64:-}" ]]; then
    log "Writing full auth.json for www-data from COMPOSER_AUTH_JSON_B64"
    echo "${COMPOSER_AUTH_JSON_B64}" | base64 -d > "${WWW_COMPOSER_HOME}/auth.json"
    chown www-data:www-data "${WWW_COMPOSER_HOME}/auth.json"
    chmod 600 "${WWW_COMPOSER_HOME}/auth.json"
  fi
fi

# --- Allow www-data create /var/www/drupal (without pre-creating it) ---
if [[ "${ALLOW_WWWDATA_CREATE_UNDER_VAR_WWW}" -eq 1 ]]; then
  log "Granting www-data ACL on ${DRUPAL_PARENT} so it can create ${DRUPAL_DIR} itself"
  mkdir -p "${DRUPAL_PARENT}"
  # access ACL + default ACL so new dirs inherit usable perms for www-data
  setfacl -m u:www-data:rwx "${DRUPAL_PARENT}" || true
  setfacl -d -m u:www-data:rwx "${DRUPAL_PARENT}" || true
fi

if [[ "${GRANT_UBUNTU_TO_WWWDATA_GROUP}" -eq 1 ]]; then
  log "Adding ${DEFAULT_USER} to www-data group (optional dev convenience)"
  usermod -aG www-data "${DEFAULT_USER}" || true
fi

# --- Nginx ---
if [[ "${INSTALL_NGINX}" -eq 1 ]]; then
  log "Installing Nginx"
  apt_install nginx
  enable_service nginx

  SITE_AVAIL="/etc/nginx/sites-available/${NGINX_SITE_NAME}.conf"
  SITE_ENABLED="/etc/nginx/sites-enabled/${NGINX_SITE_NAME}.conf"

  # Root points to future Drupal docroot, but we DO NOT create it here.
  write_if_changed "${SITE_AVAIL}" \
"server {
    listen 80;
    listen [::]:80;

    server_name ${NGINX_SERVER_NAME};
    root ${DRUPAL_DOCROOT};

    index index.php index.html;

    access_log /var/log/nginx/${NGINX_SITE_NAME}.access.log;
    error_log  /var/log/nginx/${NGINX_SITE_NAME}.error.log;

    client_max_body_size ${PHP_POST_MAX_SIZE};

    # Deny hidden files and sensitive paths
    location ~* /(\\.git|\\.env|\\.ht|composer\\.(json|lock)|vendor)/ {
        deny all;
        return 404;
    }

    location = /favicon.ico { log_not_found off; access_log off; }
    location = /robots.txt  { log_not_found off; access_log off; }

    location / {
        try_files \$uri /index.php?\$query_string;
    }

    location ~ \\.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm-drupal.sock;
        fastcgi_read_timeout 300;
    }

    location ~* \\.(?:css|js|jpg|jpeg|gif|png|svg|webp|ico|ttf|otf|woff|woff2)\$ {
        expires 7d;
        add_header Cache-Control \"public, max-age=604800\";
        try_files \$uri =404;
    }
}
"

  if [[ -e /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
    log "Removed nginx default site link"
  fi
  ln -sf "${SITE_AVAIL}" "${SITE_ENABLED}"

  nginx -t
  systemctl reload nginx
  log "Nginx ready"

  if [[ "${CREATE_PHP_TEST_PAGE}" -eq 1 ]]; then
    # Put test under /var/www/html to avoid touching future Drupal dir
    mkdir -p /var/www/html
    cat >/var/www/html/_baseline.php <<'EOF'
<?php
header('Content-Type: text/plain; charset=UTF-8');
echo "OK: baseline PHP is working\n";
echo "PHP_VERSION=" . PHP_VERSION . "\n";
echo "SAPI=" . php_sapi_name() . "\n";
EOF
    chown root:root /var/www/html/_baseline.php
    chmod 644 /var/www/html/_baseline.php
    log "Created test page: http://<vm-ip>/_baseline.php (served only if your nginx root points to /var/www/html; otherwise ignore)"
  fi
fi

# --- Optional: www-data SSH key ---
if [[ "${ENABLE_WWWDATA_SSH_KEY}" -eq 1 ]]; then
  WWW_SSH_DIR="/var/www/.ssh"
  log "Preparing SSH key for www-data in ${WWW_SSH_DIR}"
  mkdir -p "${WWW_SSH_DIR}"
  chown -R www-data:www-data "${WWW_SSH_DIR}"
  chmod 700 "${WWW_SSH_DIR}"

  if [[ ! -f "${WWW_SSH_DIR}/id_ed25519" ]]; then
    sudo -u www-data -H ssh-keygen -t ed25519 -N "" -f "${WWW_SSH_DIR}/id_ed25519" -C "www-data@drupal-vm"
  fi

  for host in "${SSH_KNOWN_HOSTS[@]}"; do
    sudo -u www-data -H bash -lc "ssh-keyscan -H ${host} >> '${WWW_SSH_DIR}/known_hosts' 2>/dev/null || true"
  done
  chown www-data:www-data "${WWW_SSH_DIR}/known_hosts"
  chmod 644 "${WWW_SSH_DIR}/known_hosts"

  echo "==== www-data SSH public key (copy to your Git provider) ===="
  cat "${WWW_SSH_DIR}/id_ed25519.pub"
  echo "============================================================"
fi

log "Baseline complete."
log "Snapshot:"
command -v nginx >/dev/null && nginx -v 2>&1 | sed 's/^/[nginx] /'
command -v php >/dev/null && php -v | head -n 1 | sed 's/^/[php] /'
command -v mariadb >/dev/null && mariadb --version | head -n 1 | sed 's/^/[mariadb] /'
command -v composer >/dev/null && composer --version 2>/dev/null | sed 's/^/[composer] /' || true

log "IMPORTANT (install phase later): run Composer as www-data, and let it create ${DRUPAL_DIR} by itself."
log "Example later:"
log "  sudo -u www-data -H env COMPOSER_HOME=${WWW_COMPOSER_HOME} composer create-project drupal/recommended-project ${DRUPAL_DIR}"
