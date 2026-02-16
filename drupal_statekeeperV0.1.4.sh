#!/usr/bin/env bash
# drupal_statekeeperV0.1.4.sh
# Snapshot + Apply for Drupal (composer+drush) with incremental mode + change summary.
# Model: root for system writes; ubuntu runs composer/drush; www-data writes sites/default/files.
set -Eeuo pipefail

VERSION="drupal_statekeeperV0.1.3"
DRUPAL_DIR_DEFAULT="/var/www/drupal"
OPS_USER_DEFAULT="ubuntu"
WEB_USER_DEFAULT="www-data"
COLLAB_GROUP_DEFAULT="drupal"

SNAP_BASE_DEFAULT="/var/lib/drupal-tools/snapshots"
STATE_BASE_DEFAULT="/var/lib/drupal-tools/statekeeper"
SECRETS_BASE_DEFAULT="/var/lib/drupal-tools/secrets"

ts() { date +"%Y-%m-%d %H:%M:%S"; }
log() { echo "[$(ts)] $*"; }
ok()  { log "[OK] $*"; }
warn(){ log "[WARN] $*"; }
die() { log "[ERROR] $*"; exit 1; }

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run with sudo: sudo -E bash $0 ..."; }

ACTION=""
INCREMENTAL=0
FORCE=0
WITH_FILES=0
WITH_DB=0
INCLUDE_SECRETS=0
RESTORE_FILES=0
RESTORE_DB=0
RESTORE_SETTINGS_FULL=0
SETTINGS_FULL=0

DRUPAL_DIR="$DRUPAL_DIR_DEFAULT"
OPS_USER="$OPS_USER_DEFAULT"
WEB_USER="$WEB_USER_DEFAULT"
COLLAB_GROUP="$COLLAB_GROUP_DEFAULT"
SNAP_BASE="$SNAP_BASE_DEFAULT"
STATE_BASE="$STATE_BASE_DEFAULT"
SECRETS_BASE="$SECRETS_BASE_DEFAULT"
FROM_TARBALL=""
URI=""

usage() {
  cat <<'USAGE'
Usage:
  Snapshot:
    sudo -E bash drupal_statekeeperV0.1.4.sh snapshot [--incremental] [--force] [--with-files] [--with-db] [--acl|--no-acl]
      [--uri=http://IP] [--drupal-dir=/var/www/drupal]

  Apply:
    sudo -E bash drupal_statekeeperV0.1.4.sh apply --from=/path/to/drupal_snapshot_YYYYmmdd_HHMMSS.tar.gz
      [--restore-files] [--restore-db] [--uri=http://IP] [--drupal-dir=/var/www/drupal]

Notes:
  - Default model: OPS_USER=ubuntu runs composer/drush; WEB_USER=www-data writes sites/default/files.
  - settings.php changes:
      Recommended: put your custom additions into sites/default/settings.statekeeper.php
      Statekeeper will ensure settings.php includes settings.statekeeper.php via a marker block.
      Full settings.php snapshot/restore is optional (advanced):
        snapshot: --include-secrets --settings-full
        apply:    --restore-settings-full
USAGE
}


have_cmd() { command -v "$1" >/dev/null 2>&1; }

apply_acl_on_files_dir() {
  [[ "${ENABLE_ACL_MODE}" == "1" ]] || return 0
  local files_dir="$1"
  [[ -d "${files_dir}" ]] || { warn "ACL: directory not found: ${files_dir}"; return 0; }
  if ! have_cmd setfacl || ! have_cmd getfacl; then
    warn "ACL requested but setfacl/getfacl not found. Install package 'acl' or run drupal_optimizer with --acl."
    return 0
  fi
  step "ACL mode: grant ${OPS_USER} + ${WEB_USER} rwX on ${files_dir} (and default ACL)"
  setfacl -R -m "u:${OPS_USER}:rwX,u:${WEB_USER}:rwX,g:${COLLAB_GROUP}:rwX,m::rwX" "${files_dir}" >>"$LOG_FILE" 2>&1 || true
  find "${files_dir}" -type d -print0 2>/dev/null | xargs -0 -r setfacl -d -m "u:${OPS_USER}:rwX,u:${WEB_USER}:rwX,g:${COLLAB_GROUP}:rwX,m::rwX" >>"$LOG_FILE" 2>&1 || true
  ok "ACL applied on: ${files_dir}"
}


normalize_action() {
  case "${1:-}" in
    --snapshot) ACTION="snapshot"; shift ;;
    --apply)    ACTION="apply"; shift ;;
  esac
  echo "$@"
}

ARGS=("$@")
NEW_ARGS=()
if [[ "${#ARGS[@]}" -gt 0 ]]; then
  REST="$(normalize_action "${ARGS[0]}")"
  if [[ "$REST" != "${ARGS[0]}" ]]; then
    NEW_ARGS=("${ARGS[@]:1}")
  else
    NEW_ARGS=("${ARGS[@]}")
  fi
fi

if [[ -n "${ACTION}" ]]; then
  set -- "${NEW_ARGS[@]}"
fi

if [[ -z "${ACTION}" && "${#NEW_ARGS[@]}" -gt 0 ]]; then
  case "${NEW_ARGS[0]}" in
    snapshot|apply) ACTION="${NEW_ARGS[0]}"; shift; set -- "${NEW_ARGS[@]:1}" ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    snapshot|apply) ACTION="$1"; shift ;;
    --incremental) INCREMENTAL=1; shift ;;
    --force) FORCE=1; shift ;;
    --with-files) WITH_FILES=1; shift ;;
    --with-db) WITH_DB=1; shift ;;
    --acl) ENABLE_ACL_MODE=1; shift ;;
    --no-acl) ENABLE_ACL_MODE=0; shift ;;
    --include-secrets) INCLUDE_SECRETS=1; shift ;;
    --restore-files) RESTORE_FILES=1; shift ;;
    --restore-db) RESTORE_DB=1; shift ;;
    --settings-full) SETTINGS_FULL=1; shift ;;
    --restore-settings-full) RESTORE_SETTINGS_FULL=1; shift ;;
    --from=*) FROM_TARBALL="${1#*=}"; shift ;;
    --uri=*) URI="${1#*=}"; shift ;;
    --drupal-dir=*) DRUPAL_DIR="${1#*=}"; shift ;;
    --ops-user=*) OPS_USER="${1#*=}"; shift ;;
    --web-user=*) WEB_USER="${1#*=}"; shift ;;
    --collab-group=*) COLLAB_GROUP="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1 (try --help)" ;;
  esac
done

[[ -n "$ACTION" ]] || { usage; die "Missing action: snapshot|apply"; }

as_ops() {
  local cmd="$*"
  sudo -u "$OPS_USER" -H -E bash -lc "$cmd"
}

drush_cmd() {
  local extra_uri=""
  if [[ -n "$URI" ]]; then extra_uri="--uri=$URI"; fi
  echo "$DRUPAL_DIR/vendor/bin/drush $extra_uri"
}

drush_ops() {
  local dcmd
  dcmd="$(drush_cmd)"
  as_ops "cd '$DRUPAL_DIR' && $dcmd $*"
}

sha_file() {
  local f="$1"
  [[ -f "$f" ]] || { echo ""; return 0; }
  sha256sum "$f" | awk '{print $1}'
}

dir_hash() {
  local d="$1"
  [[ -d "$d" ]] || { echo ""; return 0; }
  (cd "$d" && find . -type f -print0 | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | awk '{print $1}')
}

write_dir_sha_list() {
  local d="$1"
  local out="$2"
  if [[ ! -d "$d" ]]; then
    : > "$out"
    return 0
  fi
  (cd "$d" && find . -type f -print0 | sort -z | xargs -0 sha256sum 2>/dev/null) > "$out" || true
}

ensure_dirs() {
  install -d -m 0755 "$SNAP_BASE" "$STATE_BASE" "$SECRETS_BASE"
}

timestamp_id() { date +"%Y%m%d_%H%M%S"; }

append_index() {
  local line="$1"
  install -d -m 0755 "$SNAP_BASE"
  local idx="$SNAP_BASE/index.md"
  if [[ ! -f "$idx" ]]; then
    cat > "$idx" <<EOF
# Statekeeper Snapshot Index

- Generated by $VERSION
- Root: $SNAP_BASE

EOF
  fi
  echo "$line" >> "$idx"
}

latest_path_file() { echo "$SNAP_BASE/latest.path"; }

read_latest_snapdir() {
  local lp; lp="$(latest_path_file)"
  [[ -f "$lp" ]] || { echo ""; return 0; }
  cat "$lp" 2>/dev/null || true
}

write_latest_snapdir() {
  local snapdir="$1"
  echo "$snapdir" > "$(latest_path_file)"
}

ensure_settings_include_block() {
  local settings_php="$DRUPAL_DIR/web/sites/default/settings.php"
  [[ -f "$settings_php" ]] || { warn "settings.php not found ($settings_php); cannot ensure include block yet."; return 0; }

  local begin="# BEGIN STATEKEEPER INCLUDE"
  local end="# END STATEKEEPER INCLUDE"
  local include_block
  include_block=$(cat <<'PHP'
# BEGIN STATEKEEPER INCLUDE
if (file_exists($app_root . '/' . $site_path . '/settings.statekeeper.php')) {
  include $app_root . '/' . $site_path . '/settings.statekeeper.php';
}
# END STATEKEEPER INCLUDE
PHP
)
  if grep -qF "$begin" "$settings_php"; then
    awk -v begin="$begin" -v end="$end" -v repl="$include_block" '
      BEGIN{inblk=0}
      $0==begin{print repl; inblk=1; next}
      $0==end{inblk=0; next}
      inblk==1{next}
      {print}
    ' "$settings_php" > "${settings_php}.tmp"
    mv "${settings_php}.tmp" "$settings_php"
    ok "Refreshed include block in settings.php"
  else
    printf "\n%s\n" "$include_block" >> "$settings_php"
    ok "Appended include block to settings.php"
  fi
}

ensure_settings_statekeeper_file() {
  local f="$DRUPAL_DIR/web/sites/default/settings.statekeeper.php"
  if [[ ! -f "$f" ]]; then
    cat > "$f" <<'PHP'
<?php
/**
 * Site-local overrides managed by Statekeeper.
 *
 * Put your custom settings here instead of editing settings.php directly.
 * This file is included from settings.php via a marker-managed include block.
 */
PHP
    ok "Created settings.statekeeper.php (empty template)"
  fi
  chmod 0644 "$f" || true
}

collect_state_to() {
  local out="$1"
  install -d -m 0755 "$out"
  install -d -m 0755 "$out/meta" "$out/lists" "$out/settings" "$out/config" "$out/custom"
  if [[ -f "$DRUPAL_DIR/composer.json" ]]; then cp -a "$DRUPAL_DIR/composer.json" "$out/meta/"; fi
  if [[ -f "$DRUPAL_DIR/composer.lock" ]]; then cp -a "$DRUPAL_DIR/composer.lock" "$out/meta/"; fi

  if [[ -x "$DRUPAL_DIR/vendor/bin/drush" ]]; then
    drush_ops "pml --status=enabled --type=module --format=list --no-core" > "$out/lists/enabled_modules.txt" 2>/dev/null || true
    sort -u "$out/lists/enabled_modules.txt" -o "$out/lists/enabled_modules.txt" 2>/dev/null || true

    drush_ops "theme:list --status=enabled --format=list" > "$out/lists/enabled_themes.txt" 2>/dev/null || true
    sort -u "$out/lists/enabled_themes.txt" -o "$out/lists/enabled_themes.txt" 2>/dev/null || true

    drush_ops "cget system.theme default --format=string" > "$out/lists/default_theme.txt" 2>/dev/null || true
    drush_ops "cget system.theme admin --format=string" > "$out/lists/admin_theme.txt" 2>/dev/null || true

    if [[ -f "$DRUPAL_DIR/web/sites/default/settings.php" ]]; then
      drush_ops "config:export -y --destination='$out/config/sync'" >/dev/null 2>&1 || true
    fi
  fi

  local sd="$DRUPAL_DIR/web/sites/default"
  for f in "settings.statekeeper.php" "settings.redis.php" "services.yml"; do
    if [[ -f "$sd/$f" ]]; then cp -a "$sd/$f" "$out/settings/"; fi
  done

  if [[ "$SETTINGS_FULL" -eq 1 || "$INCLUDE_SECRETS" -eq 1 ]]; then
    if [[ -f "$sd/settings.php" ]]; then cp -a "$sd/settings.php" "$out/settings/settings.php.full"; fi
  fi

  if [[ -d "$DRUPAL_DIR/web/modules/custom" ]]; then
    tar -C "$DRUPAL_DIR/web/modules" -czf "$out/custom/modules_custom.tar.gz" custom >/dev/null 2>&1 || true
  fi
  if [[ -d "$DRUPAL_DIR/web/themes/custom" ]]; then
    tar -C "$DRUPAL_DIR/web/themes" -czf "$out/custom/themes_custom.tar.gz" custom >/dev/null 2>&1 || true
  fi

  if [[ "$WITH_FILES" -eq 1 ]]; then
    local filesdir="$DRUPAL_DIR/web/sites/default/files"
    if [[ -d "$filesdir" ]]; then
      tar -C "$filesdir" -czf "$out/custom/public_files.tar.gz" \
        --exclude='css' --exclude='js' --exclude='php' --exclude='styles' --exclude='tmp' --exclude='.htaccess' . >/dev/null 2>&1 || true
    else
      warn "Public files dir missing ($filesdir); --with-files requested but nothing to pack."
    fi
  fi

  if [[ "$WITH_DB" -eq 1 ]]; then
    if [[ -x "$DRUPAL_DIR/vendor/bin/drush" && -f "$DRUPAL_DIR/web/sites/default/settings.php" ]]; then
      drush_ops "sql:dump --result-file='$out/custom/db.sql' --gzip" >/dev/null 2>&1 || warn "DB dump failed (drush sql:dump)."
    else
      warn "Site not installed or drush missing; cannot dump DB."
    fi
  fi
}

write_manifest() {
  local snapdir="$1"
  local man="$snapdir/manifest.env"
  local tmp="$snapdir/.tmp_state"
  rm -rf "$tmp"
  collect_state_to "$tmp"

  local composer_json_sha composer_lock_sha modules_sha themes_sha cfg_sha settings_sha custom_mod_sha custom_theme_sha files_sha db_sha settings_full_sha
  composer_json_sha="$(sha_file "$tmp/meta/composer.json")"
  composer_lock_sha="$(sha_file "$tmp/meta/composer.lock")"
  modules_sha="$(sha_file "$tmp/lists/enabled_modules.txt")"
  themes_sha="$(sha_file "$tmp/lists/enabled_themes.txt")"
  cfg_sha="$(dir_hash "$tmp/config/sync")"
  settings_sha="$(dir_hash "$tmp/settings")"
  custom_mod_sha="$(sha_file "$tmp/custom/modules_custom.tar.gz")"
  custom_theme_sha="$(sha_file "$tmp/custom/themes_custom.tar.gz")"
  files_sha="$(sha_file "$tmp/custom/public_files.tar.gz")"
  db_sha="$(sha_file "$tmp/custom/db.sql.gz")"
  settings_full_sha="$(sha_file "$tmp/settings/settings.php.full")"

  cat > "$man" <<EOF
version=$VERSION
timestamp=$(ts)
drupal_dir=$DRUPAL_DIR
ops_user=$OPS_USER
web_user=$WEB_USER
collab_group=$COLLAB_GROUP
uri=${URI}
with_files=$WITH_FILES
with_db=$WITH_DB
include_secrets=$INCLUDE_SECRETS
composer_json_sha=$composer_json_sha
composer_lock_sha=$composer_lock_sha
enabled_modules_sha=$modules_sha
enabled_themes_sha=$themes_sha
config_sync_sha=$cfg_sha
settings_dir_sha=$settings_sha
custom_modules_tar_sha=$custom_mod_sha
custom_themes_tar_sha=$custom_theme_sha
public_files_tar_sha=$files_sha
db_dump_sha=$db_sha
settings_php_full_sha=$settings_full_sha
EOF

  mkdir -p "$snapdir/lists"
  cp -a "$tmp/lists/." "$snapdir/lists/" 2>/dev/null || true

  if [[ -d "$tmp/config/sync" ]]; then
    mkdir -p "$snapdir/config"
    rsync -a "$tmp/config/sync/" "$snapdir/config/sync/" >/dev/null 2>&1 || true
  fi

  mkdir -p "$snapdir/settings" "$snapdir/custom" "$snapdir/meta"
  cp -a "$tmp/meta/." "$snapdir/meta/" 2>/dev/null || true
  cp -a "$tmp/settings/." "$snapdir/settings/" 2>/dev/null || true
  cp -a "$tmp/custom/." "$snapdir/custom/" 2>/dev/null || true

  write_dir_sha_list "$snapdir/config/sync" "$snapdir/meta/config_files.sha256"
  write_dir_sha_list "$snapdir/settings" "$snapdir/meta/settings_files.sha256"

  rm -rf "$tmp"
}

read_manifest_value() {
  local man="$1"; local key="$2"
  [[ -f "$man" ]] || { echo ""; return 0; }
  grep -E "^${key}=" "$man" 2>/dev/null | head -n1 | sed -E "s/^${key}=//" || true
}

diff_list_added_removed() {
  local old="$1"; local new="$2"; local label="$3"
  local added removed
  added="$(comm -13 <(sort -u "$old" 2>/dev/null) <(sort -u "$new" 2>/dev/null) 2>/dev/null || true)"
  removed="$(comm -23 <(sort -u "$old" 2>/dev/null) <(sort -u "$new" 2>/dev/null) 2>/dev/null || true)"
  if [[ -n "$added" ]]; then
    echo "- $label added:"
    echo "$added" | sed 's/^/  - /'
  fi
  if [[ -n "$removed" ]]; then
    echo "- $label removed:"
    echo "$removed" | sed 's/^/  - /'
  fi
}

diff_sha_lists() {
  local old="$1" new="$2" limit="${3:-50}"
  [[ -f "$old" && -f "$new" ]] || return 0
  awk '{print $2" "$1}' "$old" | sort > "${old}.m"
  awk '{print $2" "$1}' "$new" | sort > "${new}.m"
  comm -13 <(cut -d' ' -f1 "${old}.m") <(cut -d' ' -f1 "${new}.m") | head -n "$limit" | sed 's/^/  + /' > "${new}.added" || true
  comm -23 <(cut -d' ' -f1 "${old}.m") <(cut -d' ' -f1 "${new}.m") | head -n "$limit" | sed 's/^/  - /' > "${new}.removed" || true
  join -j 1 "${old}.m" "${new}.m" | awk '$2!=$3{print "  * "$1}' | head -n "$limit" > "${new}.modified" || true

  if [[ -s "${new}.added" || -s "${new}.removed" || -s "${new}.modified" ]]; then
    echo "- File changes (sample, max $limit):"
    [[ -s "${new}.added" ]] && { echo "  Added:"; cat "${new}.added"; }
    [[ -s "${new}.removed" ]] && { echo "  Removed:"; cat "${new}.removed"; }
    [[ -s "${new}.modified" ]] && { echo "  Modified:"; cat "${new}.modified"; }
  fi
  rm -f "${old}.m" "${new}.m" "${new}.added" "${new}.removed" "${new}.modified" || true
}

generate_summary_md() {
  local snapdir="$1"
  local prevdir="$2"
  local out="$snapdir/summary.md"

  local man="$snapdir/manifest.env"
  local prev_man="$prevdir/manifest.env"

  local changed=0
  {
    echo "# Snapshot Summary"
    echo ""
    echo "- Snapshot: \`$(basename "$snapdir")\`"
    [[ -n "$prevdir" ]] && echo "- Previous: \`$(basename "$prevdir")\`"
    echo "- Time: $(read_manifest_value "$man" timestamp)"
    echo ""

    if [[ -z "$prevdir" || ! -f "$prev_man" ]]; then
      echo "This is the first snapshot (no previous baseline)."
      echo ""
    else
      local keys=(
        composer_lock_sha
        enabled_modules_sha
        enabled_themes_sha
        config_sync_sha
        settings_dir_sha
        custom_modules_tar_sha
        custom_themes_tar_sha
        public_files_tar_sha
        db_dump_sha
        settings_php_full_sha
      )

      echo "## High-level changes"
      for k in "${keys[@]}"; do
        local a b
        a="$(read_manifest_value "$prev_man" "$k")"
        b="$(read_manifest_value "$man" "$k")"
        if [[ "$a" != "$b" ]]; then
          changed=1
          echo "- **$k**: changed"
        fi
      done
      if [[ "$changed" -eq 0 ]]; then
        echo "- No changes detected across tracked dimensions."
      fi
      echo ""

      if [[ -f "$prevdir/lists/enabled_modules.txt" && -f "$snapdir/lists/enabled_modules.txt" ]]; then
        echo "## Enabled modules changes"
        diff_list_added_removed "$prevdir/lists/enabled_modules.txt" "$snapdir/lists/enabled_modules.txt" "Modules"
        echo ""
      fi
      if [[ -f "$prevdir/lists/enabled_themes.txt" && -f "$snapdir/lists/enabled_themes.txt" ]]; then
        echo "## Enabled themes changes"
        diff_list_added_removed "$prevdir/lists/enabled_themes.txt" "$snapdir/lists/enabled_themes.txt" "Themes"
        echo ""
      fi

      if [[ -f "$prevdir/meta/config_files.sha256" && -f "$snapdir/meta/config_files.sha256" ]]; then
        echo "## Config sync changes"
        diff_sha_lists "$prevdir/meta/config_files.sha256" "$snapdir/meta/config_files.sha256" 50
        echo ""
      fi

      if [[ -f "$prevdir/meta/settings_files.sha256" && -f "$snapdir/meta/settings_files.sha256" ]]; then
        echo "## Settings files changes"
        diff_sha_lists "$prevdir/meta/settings_files.sha256" "$snapdir/meta/settings_files.sha256" 50
        echo ""
      fi
    fi

    echo "## Restore notes"
    echo "- Backend config changes are restored via \`drush cim\` (config import)."
    echo "- Some modules store state in DB (content entities / key_value / state). For full fidelity, snapshot with \`--with-db\`."
    echo "- Direct edits to \`settings.php\` are not overwritten by default. Put overrides in \`settings.statekeeper.php\` for clean restore."
  } > "$out"

  ok "Wrote summary: $out"
}

pack_snapshot_tarball() {
  local snapdir="$1"
  local tsid; tsid="$(basename "$snapdir" | sed 's/^snap_//')"
  local out="/home/$OPS_USER/drupal_snapshot_${tsid}.tar.gz"
  local tmp="/tmp/statekeeper_pack_$$"
  rm -rf "$tmp"
  install -d -m 0755 "$tmp/snapshot"
  rsync -a "$snapdir/" "$tmp/snapshot/" >/dev/null 2>&1 || true

  if [[ "$INCLUDE_SECRETS" -eq 0 ]]; then
    rm -rf "$tmp/snapshot/settings/settings.php.full" 2>/dev/null || true
    rm -rf "$tmp/snapshot/custom/db.sql" "$tmp/snapshot/custom/db.sql.gz" 2>/dev/null || true
  fi

  tar -C "$tmp" -czf "$out" snapshot >/dev/null 2>&1
  chown "$OPS_USER:$COLLAB_GROUP" "$out" 2>/dev/null || chown "$OPS_USER:$OPS_USER" "$out" 2>/dev/null || true
  chmod 0644 "$out" || true
  rm -rf "$tmp"
  ok "Snapshot bundle: $out"
  echo "$out"
}

snapshot_flow() {
  need_root
  ensure_dirs
  [[ -d "$DRUPAL_DIR" ]] || die "Drupal dir not found: $DRUPAL_DIR"

  if [[ -f "$DRUPAL_DIR/web/sites/default/settings.php" ]]; then
    ensure_settings_statekeeper_file
    ensure_settings_include_block
  apply_acl_on_files_dir "${DRUPAL_DIR}/web/sites/default/files"
  fi

  local cand="/tmp/statekeeper_cand_$$"
  rm -rf "$cand"
  install -d -m 0755 "$cand"
  write_manifest "$cand"
  local prevdir; prevdir="$(read_latest_snapdir)"

  if [[ "$INCREMENTAL" -eq 1 && "$FORCE" -eq 0 ]]; then
    if [[ -n "$prevdir" && -f "$prevdir/manifest.env" ]]; then
      local same=1
      while IFS='=' read -r k v; do
        [[ -z "$k" ]] && continue
        [[ "$k" == "timestamp" || "$k" == "version" ]] && continue
        local pv; pv="$(read_manifest_value "$prevdir/manifest.env" "$k")"
        if [[ "$pv" != "$v" ]]; then same=0; break; fi
      done < "$cand/manifest.env"
      if [[ "$WITH_DB" -eq 1 ]]; then same=0; fi
      if [[ "$same" -eq 1 ]]; then
        local nowid; nowid="$(timestamp_id)"
        append_index "- **$nowid** — SKIP (incremental): no changes since \`$(basename "$prevdir")\`"
        ok "Incremental snapshot: no changes since $(basename "$prevdir"); nothing new packaged."
        rm -rf "$cand"
        return 0
      fi
    fi
  fi

  local sid; sid="$(timestamp_id)"
  local snapdir="$SNAP_BASE/snap_$sid"
  install -d -m 0755 "$snapdir"
  rsync -a "$cand/" "$snapdir/" >/dev/null 2>&1 || true

  if [[ -n "$prevdir" && -d "$prevdir" ]]; then
    generate_summary_md "$snapdir" "$prevdir"
  else
    generate_summary_md "$snapdir" ""
  fi

  local highlights=""
  if [[ -f "$snapdir/summary.md" ]]; then
    highlights="$(awk '/## High-level changes/{flag=1;next} /^## /{flag=0} flag{print}' "$snapdir/summary.md" | head -n 8 | tr '\n' ';' | sed 's/;*$//' )"
  fi
  append_index "- **$sid** — CREATED: \`$(basename "$snapdir")\`${highlights:+ — ${highlights}}"
  write_latest_snapdir "$snapdir"

  local bundle; bundle="$(pack_snapshot_tarball "$snapdir")"

  echo ""
  ok "Snapshot created: $snapdir"
  ok "Bundle created:   $bundle"
  echo ""
  log "Summary preview (first 80 lines):"
  sed -n '1,80p' "$snapdir/summary.md" | sed 's/^/[SUMMARY] /' || true
  echo ""

  rm -rf "$cand"
}

apply_flow() {
  need_root
  ensure_dirs
  [[ -n "$FROM_TARBALL" ]] || die "apply requires --from=/path/to/snapshot.tar.gz"
  [[ -f "$FROM_TARBALL" ]] || die "Snapshot tarball not found: $FROM_TARBALL"
  [[ -d "$DRUPAL_DIR" ]] || die "Drupal dir not found: $DRUPAL_DIR"

  local tmp="/tmp/statekeeper_apply_$$"
  rm -rf "$tmp"
  install -d -m 0755 "$tmp"
  tar -xzf "$FROM_TARBALL" -C "$tmp"
  [[ -d "$tmp/snapshot" ]] || die "Invalid bundle: missing snapshot/ root."
  local snap="$tmp/snapshot"
  [[ -f "$snap/manifest.env" ]] || die "Invalid bundle: manifest.env missing."

  if [[ -f "$snap/meta/composer.json" ]]; then cp -a "$snap/meta/composer.json" "$DRUPAL_DIR/composer.json"; fi
  if [[ -f "$snap/meta/composer.lock" ]]; then cp -a "$snap/meta/composer.lock" "$DRUPAL_DIR/composer.lock"; fi
  chown "$OPS_USER:$COLLAB_GROUP" "$DRUPAL_DIR/composer.json" "$DRUPAL_DIR/composer.lock" 2>/dev/null || true

  if command -v composer >/dev/null 2>&1; then
    ok "Running composer install as $OPS_USER"
    as_ops "cd '$DRUPAL_DIR' && composer install --no-interaction --prefer-dist"
  else
    warn "composer not found; skipping composer install."
  fi

  if [[ -f "$snap/custom/modules_custom.tar.gz" ]]; then
    ok "Restoring web/modules/custom"
    tar -xzf "$snap/custom/modules_custom.tar.gz" -C "$DRUPAL_DIR/web/modules" || warn "Failed extracting modules_custom.tar.gz"
  fi
  if [[ -f "$snap/custom/themes_custom.tar.gz" ]]; then
    ok "Restoring web/themes/custom"
    tar -xzf "$snap/custom/themes_custom.tar.gz" -C "$DRUPAL_DIR/web/themes" || warn "Failed extracting themes_custom.tar.gz"
  fi
  [[ -d "$DRUPAL_DIR/web/modules/custom" ]] && chown -R "$OPS_USER:$COLLAB_GROUP" "$DRUPAL_DIR/web/modules/custom" 2>/dev/null || true
  [[ -d "$DRUPAL_DIR/web/themes/custom" ]] && chown -R "$OPS_USER:$COLLAB_GROUP" "$DRUPAL_DIR/web/themes/custom" 2>/dev/null || true

  if [[ -d "$snap/settings" ]]; then
    ok "Restoring settings helper files"
    for f in settings.statekeeper.php settings.redis.php services.yml; do
      if [[ -f "$snap/settings/$f" ]]; then
        cp -a "$snap/settings/$f" "$DRUPAL_DIR/web/sites/default/$f"
        chown "$OPS_USER:$COLLAB_GROUP" "$DRUPAL_DIR/web/sites/default/$f" 2>/dev/null || true
        chmod 0644 "$DRUPAL_DIR/web/sites/default/$f" || true
      fi
    done
  fi
  ensure_settings_include_block
  apply_acl_on_files_dir "${DRUPAL_DIR}/web/sites/default/files"

  if [[ "$RESTORE_SETTINGS_FULL" -eq 1 ]]; then
    if [[ -f "$snap/settings/settings.php.full" ]]; then
      local settings_php="$DRUPAL_DIR/web/sites/default/settings.php"
      cp -a "$settings_php" "${settings_php}.backup_statekeeper_$(timestamp_id)" 2>/dev/null || true
      cp -a "$snap/settings/settings.php.full" "$settings_php"
      chmod 0644 "$settings_php" || true
      ok "settings.php fully restored (backup kept)."
    else
      warn "--restore-settings-full requested but bundle lacks settings.php.full (use snapshot --include-secrets --settings-full)."
    fi
  fi

  if [[ "$RESTORE_FILES" -eq 1 ]]; then
    if [[ -f "$snap/custom/public_files.tar.gz" ]]; then
      ok "Restoring public files into sites/default/files"
      install -d -m 2775 "$DRUPAL_DIR/web/sites/default/files"
      tar -xzf "$snap/custom/public_files.tar.gz" -C "$DRUPAL_DIR/web/sites/default/files" || warn "Failed extracting public_files.tar.gz"
      chown -R "$WEB_USER:$COLLAB_GROUP" "$DRUPAL_DIR/web/sites/default/files" 2>/dev/null || true
    else
      warn "--restore-files requested but snapshot has no public_files.tar.gz"
    fi
  fi

  if [[ "$RESTORE_DB" -eq 1 ]]; then
    if [[ -f "$snap/custom/db.sql.gz" ]]; then
      warn "DB restore will overwrite your current DB."
      if [[ -x "$DRUPAL_DIR/vendor/bin/drush" ]]; then
        ok "Restoring DB via drush sql:cli"
        gunzip -c "$snap/custom/db.sql.gz" | drush_ops "sql:cli" || warn "DB restore failed."
      else
        warn "drush missing; cannot restore DB."
      fi
    else
      warn "--restore-db requested but snapshot has no db.sql.gz (use snapshot --with-db --include-secrets)."
    fi
  fi

  if [[ -x "$DRUPAL_DIR/vendor/bin/drush" && -f "$DRUPAL_DIR/web/sites/default/settings.php" ]]; then
    ok "Reconciling enabled modules/themes to snapshot"
    local desired_mod="$snap/lists/enabled_modules.txt"
    local desired_theme="$snap/lists/enabled_themes.txt"

    if [[ -s "$desired_mod" ]]; then
      local mods; mods="$(tr '\n' ' ' < "$desired_mod" | xargs)"
      [[ -n "$mods" ]] && drush_ops "en -y $mods" || true
    fi
    if [[ -s "$desired_theme" ]]; then
      local themes; themes="$(tr '\n' ' ' < "$desired_theme" | xargs)"
      [[ -n "$themes" ]] && drush_ops "en -y $themes" || true
    fi

    local def admin
    def="$(cat "$snap/lists/default_theme.txt" 2>/dev/null | tail -n1 | tr -d '\r' || true)"
    admin="$(cat "$snap/lists/admin_theme.txt" 2>/dev/null | tail -n1 | tr -d '\r' || true)"
    [[ -n "$def" ]] && drush_ops "cset system.theme default '$def' -y" || true
    [[ -n "$admin" ]] && drush_ops "cset system.theme admin '$admin' -y" || true

    local tmpcur="$tmp/current_modules.txt" tmpdes="$tmp/desired_modules.txt" extra=""
    drush_ops "pml --status=enabled --type=module --format=list --no-core" > "$tmpcur" 2>/dev/null || true
    sort -u "$tmpcur" -o "$tmpcur" 2>/dev/null || true
    if [[ -s "$desired_mod" ]]; then
      sort -u "$desired_mod" > "$tmpdes"
      extra="$(comm -23 "$tmpcur" "$tmpdes" 2>/dev/null | tr '\n' ' ' | xargs || true)"
      if [[ -n "$extra" ]]; then
        warn "Uninstalling modules not in snapshot (best effort): $extra"
        drush_ops "pmu -y $extra" || warn "Some modules could not be uninstalled."
      fi
    fi

    local tmptc="$tmp/current_themes.txt" tmptd="$tmp/desired_themes.txt" extrat=""
    drush_ops "theme:list --status=enabled --format=list" > "$tmptc" 2>/dev/null || true
    sort -u "$tmptc" -o "$tmptc" 2>/dev/null || true
    if [[ -s "$desired_theme" ]]; then
      sort -u "$desired_theme" > "$tmptd"
      extrat="$(comm -23 "$tmptc" "$tmptd" 2>/dev/null | tr '\n' ' ' | xargs || true)"
      if [[ -n "$extrat" ]]; then
        warn "Uninstalling themes not in snapshot (best effort): $extrat"
        drush_ops "theme:uninstall -y $extrat" || drush_ops "pmu -y $extrat" || warn "Some themes could not be uninstalled."
      fi
    fi

    local sysyml="$snap/config/sync/system.site.yml"
    if [[ -f "$sysyml" ]]; then
      local uuid
      uuid="$(grep -E '^uuid:' "$sysyml" | head -n1 | awk '{print $2}' | tr -d '\r' || true)"
      [[ -n "$uuid" ]] && drush_ops "cset system.site uuid '$uuid' -y" || true
    fi

    if [[ -d "$snap/config/sync" && -n "$(ls -A "$snap/config/sync" 2>/dev/null)" ]]; then
      ok "Importing configuration (cim)"
      drush_ops "cim -y --source='$snap/config/sync'" || warn "Config import had warnings/errors."
    else
      warn "No config/sync in snapshot; skipping config import."
    fi

    drush_ops "updb -y" || true
    drush_ops "cr" || true
  else
    warn "Site not installed or drush missing; skipping reconciliation."
  fi

  ok "Apply complete."
  rm -rf "$tmp"
}

case "$ACTION" in
  snapshot) snapshot_flow ;;
  apply)    apply_flow ;;
  *) usage; die "Unknown action: $ACTION" ;;
esac
