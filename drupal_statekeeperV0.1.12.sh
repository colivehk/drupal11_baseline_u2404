#!/usr/bin/env bash
set -euo pipefail

VERSION="0.1.12"

# drupal_statekeeperV0.1.12.sh
#
# Key behavior (requested)
# - trusted_host_patterns are ALWAYS written to sites/default/settings.statekeeper.php
# - settings.php is only modified to ensure it includes settings.statekeeper.php, and only if missing
# - include detection: if settings.php already references settings.statekeeper.php anywhere, we do NOT add a new include block
# - if the marker block exists, we refresh it idempotently
# - apply: if settings.php was restored, ensure include is re-applied AFTER restore (fixes include order)
# - if --trusted-hosts is provided, HARDEN is auto-enabled (permissions + include + trusted-host write)
#
# Run with: sudo -E bash ./drupal_statekeeperV0.1.12.sh ...

############################
# Defaults
############################
DEFAULT_DRUPAL_DIR="/var/www/drupal"
STATE_DIR="/var/lib/drupal-tools/statekeeper"
SNAP_DIR="${STATE_DIR}/snapshots"

OPS_USER_DEFAULT="ubuntu"
OPS_GROUP_DEFAULT="drupal"

############################
# Logging
############################
_ts() { date '+%Y-%m-%d %H:%M:%S'; }
info() { echo "[$(_ts)] [INFO] $*"; }
warn() { echo "[$(_ts)] [WARN] $*" >&2; }
ok()   { echo "[$(_ts)] [ OK ] $*"; }
die()  { echo "[$(_ts)] [FAIL] $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Please run as root (e.g. sudo -E bash $0 ...)."
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

require_python3() {
  have_cmd python3 || die "python3 is required but not found. Please install: sudo apt-get update && sudo apt-get install -y python3"
}

############################
# Helpers
############################
trim() {
  local s="$1"
  # shellcheck disable=SC2001
  s="$(echo "$s" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
  printf '%s' "$s"
}

# Detect docroot.
# - If /var/www/drupal/web/core exists -> docroot is /var/www/drupal/web
# - Else if /var/www/drupal/core exists -> docroot is /var/www/drupal
resolve_docroot() {
  local drupal_dir="$1"
  if [[ -d "${drupal_dir}/web/core" ]]; then
    echo "${drupal_dir}/web"
  elif [[ -d "${drupal_dir}/core" ]]; then
    echo "${drupal_dir}"
  else
    die "Cannot find Drupal docroot under ${drupal_dir} (expected web/core or core)."
  fi
}

# Extract host from URI/URL.
# Accepts: http(s)://host[:port]/..., host[:port], [::1]:port, http://[::1]:8080/
uri_host() {
  local u="$1"
  u="$(trim "$u")"
  [[ -z "$u" ]] && return 1

  # strip scheme
  if [[ "$u" == *"://"* ]]; then
    u="${u#*://}"
  fi
  # strip path/query/fragment
  u="${u%%/*}"
  u="${u%%\?*}"
  u="${u%%\#*}"

  # IPv6 in brackets
  if [[ "$u" == \[*\]* ]]; then
    local inside
    inside="${u#\[}"
    inside="${inside%%\]*}"
    printf '%s' "$inside"
    return 0
  fi

  # strip port
  printf '%s' "${u%%:*}"
}

is_local_host() {
  local h="$1"
  case "$h" in
    localhost|127.0.0.1|::1) return 0;;
    *) return 1;;
  esac
}

python_re_escape() {
  local s="$1"
  python3 - <<'PY' "$s"
import re, sys
print(re.escape(sys.argv[1]))
PY
}


# Generic deduper for ANY managed block pairs within a file.
# Recognizes BEGIN/END markers in common comment styles (#, //, ;, /* */).
# Keeps the LAST occurrence per tag (tag normalization strips trailing (...) or [...] notes).
dedupe_managed_blocks_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  require_python3

  python3 - "$file" <<'PY'
import re, sys, os

path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

begin_re = re.compile(r'^(?P<indent>\s*)(?P<prefix>#|//)\s*BEGIN\s+(?P<label>[A-Za-z0-9_:\-\.]+)\s*$')
end_re   = re.compile(r'^(?P<indent>\s*)(?P<prefix>#|//)\s*END\s+(?P<label>[A-Za-z0-9_:\-\.]+)\s*$')

def norm_label(label: str) -> str:
    u = label.upper()
    # Canonicalize historically different tags that manage the SAME setting.
    if 'FILE_CHMOD' in u:
        return 'DRUPAL_TOOLS_FILE_CHMOD'
    return label

blocks = []
stack = []
for i, line in enumerate(lines):
    m = begin_re.match(line)
    if m:
        label = m.group('label')
        stack.append({
            'start': i,
            'orig': label,
            'norm': norm_label(label),
            'begin_indent': m.group('indent'),
            'begin_prefix': m.group('prefix'),
        })
        continue

    m = end_re.match(line)
    if m and stack:
        start = stack.pop()
        blocks.append({
            'start': start['start'],
            'end': i,
            'orig': start['orig'],
            'norm': start['norm'],
            'begin_indent': start['begin_indent'],
            'begin_prefix': start['begin_prefix'],
            'end_indent': m.group('indent'),
            'end_prefix': m.group('prefix'),
        })

if not blocks:
    sys.exit(0)

# Keep only the LAST block per normalized label.
last_by_norm = {}
for idx, blk in enumerate(blocks):
    last_by_norm[blk['norm']] = idx

out = list(lines)
changed = False

# Process from end to start so indices stay valid.
for idx, blk in sorted(enumerate(blocks), key=lambda x: x[1]['start'], reverse=True):
    if idx != last_by_norm[blk['norm']]:
        del out[blk['start']:blk['end'] + 1]
        changed = True
    else:
        # Rewrite marker lines to canonical label if needed.
        bline = f"{blk['begin_indent']}{blk['begin_prefix']} BEGIN {blk['norm']}\n"
        eline = f"{blk['end_indent']}{blk['end_prefix']} END {blk['norm']}\n"
        if out[blk['start']] != bline:
            out[blk['start']] = bline
            changed = True
        if out[blk['end']] != eline:
            out[blk['end']] = eline
            changed = True

if changed:
    tmp = path + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        f.writelines(out)
    os.replace(tmp, path)

PY
}
looks_like_regex_no_prefix() {
  # Heuristic: treat as regex-looking if it contains common regex meta beyond '.'
  # Examples: starts with ^, ends with $, contains \\, [, ], (, ), |, +, ?, {, }, or '.*'
  local s="$1"
  [[ "$s" =~ ^\^ ]] && return 0
  [[ "$s" =~ \$$ ]] && return 0
  [[ "$s" == *".*"* ]] && return 0
  [[ "$s" == *"\\"* ]] && return 0
  [[ "$s" == *"["* ]] && return 0
  [[ "$s" == *"]"* ]] && return 0
  [[ "$s" == *"("* ]] && return 0
  [[ "$s" == *")"* ]] && return 0
  [[ "$s" == *"|"* ]] && return 0
  [[ "$s" == *"+"* ]] && return 0
  [[ "$s" == *"?"* ]] && return 0
  [[ "$s" == *"{"* ]] && return 0
  [[ "$s" == *"}"* ]] && return 0
  return 1
}

ensure_anchored() {
  local p="$1"
  p="$(trim "$p")"
  [[ -z "$p" ]] && { echo ""; return 0; }
  [[ "$p" == ^* ]] || p="^${p}"
  [[ "$p" == *\$ ]] || p="${p}$"
  printf '%s' "$p"
}

unique_lines() {
  # Reads lines from stdin, outputs unique lines preserving first-seen order
  awk '!seen[$0]++'
}

############################
# Settings include management
############################
ensure_settings_statekeeper_file() {
  local settings_dir="$1"
  local f="${settings_dir}/settings.statekeeper.php"
  local settings_php="${settings_dir}/settings.php"

  require_python3

  # Create if missing (atomic).
  if [[ ! -f "$f" ]]; then
    info "Creating ${f} (atomic)"
    python3 - <<'PYIN' "$f" "$settings_php"
import os, sys, tempfile

target = sys.argv[1]
settings_php = sys.argv[2]
uid = gid = None
if os.path.isfile(settings_php):
    st = os.stat(settings_php)
    uid, gid = st.st_uid, st.st_gid

base = """<?php
// settings.statekeeper.php (managed by drupal_* scripts)

"""

d = os.path.dirname(target) or "."
fd, tmp = tempfile.mkstemp(prefix=".statekeeper.init.", dir=d)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(base)
    os.chmod(tmp, 0o644)
    if uid is not None:
        try:
            os.chown(tmp, uid, gid)
        except PermissionError:
            pass
    os.replace(tmp, target)
finally:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PYIN
    ok "Created: ${f}"
  fi

  # Normalize + repair (atomic + 去重):
  # - strip UTF-8 BOM
  # - ensure EXACTLY one '<?php' opening tag
  # - repair accidental variable escaping (e.g. '\$app_root') that breaks parsing
  # - dedupe known managed blocks (keep LAST occurrence)
  # - keep original perms/owner/group
  python3 - <<'PYIN' "$f"
import os, sys, re, tempfile, subprocess, time, codecs, shutil

path = sys.argv[1]
st = os.stat(path)
mode = st.st_mode & 0o777
uid, gid = st.st_uid, st.st_gid

SAFE = """<?php
/**
 * Statekeeper settings placeholder.
 * Auto-repaired to keep Drupal/Drush bootable.
 * Regenerate via drupal_statekeeper workflow if you need overrides.
 */
"""

def atomic_replace(new_text: str):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".statekeeper.repair.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, uid, gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass

raw = open(path, "rb").read()
if raw.startswith(codecs.BOM_UTF8):
    raw = raw[len(codecs.BOM_UTF8):]

text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")

# If file looks suspicious, keep a backup before we touch it.
suspicious = (text.count("<?php") > 1) or (r"\$app_root" in text) or (r"\$site_path" in text)
if suspicious:
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    try:
        shutil.copy2(path, f"{path}.bad.{ts}")
    except Exception:
        pass

# Ensure exactly one php tag.
lines = text.split("\n")
out = []
seen = False
for line in lines:
    if re.match(r"^\s*<\?php\b\s*$", line):
        if not seen:
            out.append("<?php")
            seen = True
        continue
    out.append(line)
if not seen:
    out = ["<?php"] + out
text2 = "\n".join(out)

# Repair accidental escaping of PHP variables that breaks parsing.
fixes = {
    r"\$app_root": "$app_root",
    r"\$site_path": "$site_path",
    r"\$settings": "$settings",
    r"\$config": "$config",
    r"\$databases": "$databases",
}
for k, v in fixes.items():
    text2 = text2.replace(k, v)

# Generic dedupe for ANY managed blocks: keep the LAST occurrence for each tag.
# Supports markers like "# BEGIN X"/"# END X", "// BEGIN X", "/* BEGIN X */" etc.
def _norm_tag(t: str) -> str:
    t = re.sub(r"\s+", " ", t.strip())
    # Drop trailing "(...)" or "[...]" notes (common in "managed by ..." markers).
    t = re.sub(r"\s*(\([^)]*\)|\[[^\]]*\])\s*$", "", t).strip()
    return t

begin_re = re.compile(r"^\s*(?:#|//|;|/\*+)\s*BEGIN\s+(.+?)\s*(?:\*/\s*)?$")
end_re   = re.compile(r"^\s*(?:#|//|;|/\*+)\s*END\s+(.+?)\s*(?:\*/\s*)?$")

blocks = []
stack = []
off = 0
for ln in text2.splitlines(True):
    mb = begin_re.match(ln)
    if mb:
        stack.append((_norm_tag(mb.group(1)), off))
        off += len(ln)
        continue
    me = end_re.match(ln)
    if me and stack:
        tag = _norm_tag(me.group(1))
        if stack[-1][0] == tag:
            btag, start = stack.pop()
            blocks.append((btag, start, off + len(ln)))
    off += len(ln)

from collections import defaultdict
by = defaultdict(list)
for t, s0, e0 in blocks:
    by[t].append((s0, e0))

remove = []
for t, spans in by.items():
    if len(spans) > 1:
        spans = sorted(spans, key=lambda x: x[0])
        remove.extend(spans[:-1])

if remove:
    remove = sorted(remove, key=lambda x: x[0])
    pieces = []
    pos = 0
    for s0, e0 in remove:
        if s0 < pos:
            continue
        pieces.append(text2[pos:s0])
        pos = e0
    pieces.append(text2[pos:])
    text2 = "".join(pieces)
if not text2.endswith("\n"):
    text2 += "\n"

# Lint the would-be content; if it fails, fall back to SAFE placeholder.
php = "/usr/bin/php"
if os.path.isfile(php) and os.access(php, os.X_OK):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".statekeeper.lint.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text2)
        r = subprocess.run([php, "-l", tmp], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0:
            ts = time.strftime("%Y-%m-%d_%H%M%S")
            try:
                shutil.copy2(path, f"{path}.bad.{ts}")
            except Exception:
                pass
            atomic_replace(SAFE)
        else:
            atomic_replace(text2)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
else:
    atomic_replace(text2)
PYIN

  ok "settings.statekeeper.php normalized/repaired (atomic + 去重)"
}

ensure_settings_include_block() {
  local settings_php="$1"

  [[ -f "$settings_php" ]] || die "settings.php not found: ${settings_php}"

  # If settings.php already references settings.statekeeper.php anywhere, treat as included ✅
  if grep -q "settings\.statekeeper\.php" "$settings_php"; then
    # If marker exists, refresh marker block to canonical; otherwise leave untouched.
    if grep -q "^# BEGIN STATEKEEPER INCLUDE$" "$settings_php"; then
      info "Refreshing existing STATEKEEPER INCLUDE marker block in settings.php"
    else
      ok "settings.php already includes settings.statekeeper.php (no changes)."
      return 0
    fi
  fi

  local canonical
  canonical=$(cat <<'PHP'
# BEGIN STATEKEEPER INCLUDE
$__sk = $app_root . '/' . $site_path . '/settings.statekeeper.php';
if (is_file($__sk)) {
  $__head = @file_get_contents($__sk, FALSE, NULL, 0, 8192) ?: '';
  if (preg_match('/^\s*<\?php\b/', $__head) && substr_count($__head, '<?php') === 1) {
    include $__sk;
  }
}
# END STATEKEEPER INCLUDE
PHP
  )

  require_python3

  python3 - <<'PY' "$settings_php" "$canonical"
import os, sys, re, tempfile
path = sys.argv[1]
block = sys.argv[2]
st = os.stat(path)
mode = st.st_mode & 0o777
uid, gid = st.st_uid, st.st_gid

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    text = f.read()

begin = '# BEGIN STATEKEEPER INCLUDE'
end = '# END STATEKEEPER INCLUDE'
pat = re.compile(re.escape(begin) + r'.*?' + re.escape(end), re.S)
matches = list(pat.finditer(text))

if matches:
    first_start = matches[0].start()
    text_wo = pat.sub('', text)
    # Insert canonical block where the FIRST occurrence used to be (dedupe).
    before = text_wo[:first_start].rstrip('\n')
    after = text_wo[first_start:].lstrip('\n')
    new_text = before + '\n' + block.rstrip('\n') + '\n' + after
else:
    # No marker block: append unless already included somewhere.
    if 'settings.statekeeper.php' in text:
        new_text = text
    else:
        new_text = text.rstrip('\n') + '\n\n' + block.rstrip('\n') + '\n'

if new_text != text:
    d = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.settings.php.', dir=d)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(new_text)
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, uid, gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass
PY

  # Dedupe any duplicate managed blocks in settings.php (keep last)
  dedupe_managed_blocks_file "$settings_php"

  if grep -q "settings\.statekeeper\.php" "$settings_php"; then
    ok "settings.php include for settings.statekeeper.php is ensured."
  else
    die "Failed to ensure settings.php include for settings.statekeeper.php (ref not found after write)."
  fi
}

############################
# Trusted hosts block management
############################
write_trusted_hosts_block() {
  local settings_dir="$1"
  local patterns_file="${settings_dir}/settings.statekeeper.php"
  shift || true
  local patterns=("$@")

  [[ -f "$patterns_file" ]] || die "Missing: ${patterns_file}"

  local php_entries=""
  local p
  for p in "${patterns[@]}"; do
    # Escape single quotes for PHP string literal
    p=${p//\'/\\\'}
    php_entries+="  '${p}',"$'\n'
  done

  local block
  block=$(cat <<PHP
# BEGIN STATEKEEPER TRUSTED HOSTS
\$settings['trusted_host_patterns'] = [
${php_entries}];
# END STATEKEEPER TRUSTED HOSTS
PHP
  )

  require_python3

  python3 - <<'PY' "$patterns_file" "$block"
import os, sys, re, tempfile
path = sys.argv[1]
block = sys.argv[2]
st = os.stat(path)
mode = st.st_mode & 0o777
uid, gid = st.st_uid, st.st_gid

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    text = f.read()

begin = '# BEGIN STATEKEEPER TRUSTED HOSTS'
end = '# END STATEKEEPER TRUSTED HOSTS'
pat = re.compile(re.escape(begin) + r'.*?' + re.escape(end), re.S)
text_wo = pat.sub('', text).rstrip('\n')
new_text = text_wo + '\n\n' + block.rstrip('\n') + '\n'

if new_text != text:
    d = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.statekeeper.hosts.', dir=d)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(new_text)
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, uid, gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass
PY

  # Dedupe any duplicate managed blocks in settings.statekeeper.php (keep last)
  dedupe_managed_blocks_file "$patterns_file"

  ok "trusted_host_patterns written to settings.statekeeper.php (idempotent block)."
}

build_trusted_patterns() {
  local trusted_hosts_csv="$1"
  local uri="$2"

  local -a items=()

  if [[ -z "${trusted_hosts_csv}" ]]; then
    [[ -n "${uri}" ]] || die "--trusted-hosts not provided and --uri is empty. Please pass --uri=http(s)://HOST"
    local h
    h="$(uri_host "${uri}")" || die "Cannot parse host from --uri: ${uri}"
    [[ -n "$h" ]] || die "Empty host parsed from --uri: ${uri}"
    trusted_hosts_csv="$h"

    if is_local_host "$h"; then
      # Local triple (strict)
      trusted_hosts_csv="${trusted_hosts_csv},localhost,127.0.0.1,::1"
    fi
  fi

  IFS=',' read -r -a items <<< "$trusted_hosts_csv"

  local -a patterns=()
  local raw

  for raw in "${items[@]}"; do
    raw="$(trim "$raw")"
    [[ -z "$raw" ]] && continue

    if [[ "$raw" =~ ^(re|regex):(.*)$ ]]; then
      local rp
      rp="$(trim "${BASH_REMATCH[2]}")"
      [[ -n "$rp" ]] || die "Empty pattern after re:/regex: prefix in --trusted-hosts"
      patterns+=("$(ensure_anchored "$rp")")
      continue
    fi

    if looks_like_regex_no_prefix "$raw"; then
      warn "trusted-host entry looks like regex but missing 're:' prefix: '${raw}'. Keeping compatibility (treated as regex), but consider using 're:...'."
      patterns+=("$(ensure_anchored "$raw")")
      continue
    fi

    # Treat as exact hostname/IP; strip port if user passed host:port.
    local h="$raw"
    if [[ "$h" == \[*\]* ]]; then
      # [::1]:8080
      h="${h#\[}"; h="${h%%\]*}"
    else
      h="${h%%:*}"
    fi

    local esc
    esc="$(python_re_escape "$h")"
    patterns+=("^${esc}$")
  done

  printf '%s\n' "${patterns[@]}" | unique_lines
}

warn_if_uri_host_not_matched() {
  local uri="$1"; shift || true
  local -a patterns=("$@")
  [[ -n "$uri" ]] || return 0
  local h
  h="$(uri_host "$uri" 2>/dev/null || true)"
  [[ -n "$h" ]] || return 0

  require_python3

  local ok_match
  ok_match=$(python3 - <<'PY' "$h" "${patterns[@]}"
import re, sys
host = sys.argv[1]
patterns = sys.argv[2:]
for p in patterns:
    try:
        if re.match(p, host):
            print('YES')
            sys.exit(0)
    except re.error:
        pass
print('NO')
PY
  )

  if [[ "$ok_match" != "YES" ]]; then
    warn "--uri host '${h}' does not appear to match any trusted_host_patterns. You may lock yourself out."
  fi
}

############################
# Hardening permissions
############################
pick_ops_user() {
  local u="$1"
  if [[ -n "$u" ]]; then
    echo "$u"; return 0
  fi
  if [[ -n "${SUDO_USER:-}" ]]; then
    echo "${SUDO_USER}"; return 0
  fi
  echo "$OPS_USER_DEFAULT"
}

pick_ops_group() {
  local g="$1"
  if [[ -n "$g" ]]; then
    echo "$g"; return 0
  fi
  if getent group "$OPS_GROUP_DEFAULT" >/dev/null 2>&1; then
    echo "$OPS_GROUP_DEFAULT"; return 0
  fi
  if getent group www-data >/dev/null 2>&1; then
    warn "Group '${OPS_GROUP_DEFAULT}' not found; using 'www-data' instead."
    echo "www-data"; return 0
  fi
  warn "Group '${OPS_GROUP_DEFAULT}' not found; using current group of settings.php instead."
  echo ""
}

harden_permissions() {
  local settings_dir="$1"
  local ops_user="$2"
  local ops_group="$3"

  local settings_php="${settings_dir}/settings.php"
  [[ -f "$settings_php" ]] || die "Missing settings.php: ${settings_php}"

  local group_to_use="$ops_group"
  if [[ -z "$group_to_use" ]]; then
    group_to_use="$(stat -c '%G' "$settings_php" 2>/dev/null || echo "")"
  fi

  info "Hardening permissions under ${settings_dir} (owner=${ops_user}, group=${group_to_use:-<keep>})"

  chmod 0755 "$settings_dir"

  local f
  for f in settings.php settings.statekeeper.php settings.redis.php; do
    if [[ -f "${settings_dir}/${f}" ]]; then
      chmod 0640 "${settings_dir}/${f}"
      chown "$ops_user" "${settings_dir}/${f}" || true
      if [[ -n "$group_to_use" ]]; then
        chgrp "$group_to_use" "${settings_dir}/${f}" || true
      fi
    fi
  done

  chown "$ops_user" "$settings_dir" || true
  if [[ -n "$group_to_use" ]]; then
    chgrp "$group_to_use" "$settings_dir" || true
  fi

  ok "Permissions hardened (sites/default=0755, settings*.php=0640)."
}

############################
# Snapshot/restore
############################
snapshot_create() {
  local docroot="$1"
  local settings_dir="$2"
  local ts="$3"
  local snap_path="${SNAP_DIR}/${ts}"

  mkdir -p "$snap_path"

  info "Saving snapshot to ${snap_path}"

  local f
  for f in settings.php settings.statekeeper.php settings.redis.php services.yml; do
    if [[ -f "${settings_dir}/${f}" ]]; then
      cp -a "${settings_dir}/${f}" "${snap_path}/${f}"
    fi
  done

  {
    echo "version=${VERSION}"
    echo "timestamp=${ts}"
    echo "docroot=${docroot}"
    echo "settings_dir=${settings_dir}"
  } > "${snap_path}/MANIFEST.txt"

  ok "Snapshot created: ${snap_path}"
}

snapshot_capture_acl() {
  local settings_dir="$1"
  local snap_path="$2"

  if ! have_cmd getfacl; then
    warn "getfacl not found; skipping --acl capture."
    return 0
  fi

  info "Capturing ACLs for ${settings_dir}"
  getfacl -R -p "$settings_dir" > "${snap_path}/acl.sites_default.txt" || warn "getfacl failed"
}

apply_from_snapshot() {
  local settings_dir="$1"
  local snap_path="$2"
  local restore_settings_full="$3"  # 1/0

  [[ -d "$snap_path" ]] || die "Snapshot directory not found: ${snap_path}"

  info "Applying snapshot from ${snap_path}"

  if [[ -f "${snap_path}/settings.statekeeper.php" ]]; then
    cp -a "${snap_path}/settings.statekeeper.php" "${settings_dir}/settings.statekeeper.php"
  fi

  if [[ "$restore_settings_full" == "1" ]]; then
    [[ -f "${snap_path}/settings.php" ]] || die "Snapshot missing settings.php; cannot --restore-settings-full"
    cp -a "${snap_path}/settings.php" "${settings_dir}/settings.php"
  fi

  if [[ -f "${snap_path}/settings.redis.php" ]]; then
    cp -a "${snap_path}/settings.redis.php" "${settings_dir}/settings.redis.php"
  fi
  if [[ -f "${snap_path}/services.yml" ]]; then
    cp -a "${snap_path}/services.yml" "${settings_dir}/services.yml"
  fi

  ok "Snapshot files restored (settings.statekeeper.php always; settings.php only if --restore-settings-full)."
}

apply_restore_acl() {
  local snap_path="$1"
  local acl_file="${snap_path}/acl.sites_default.txt"

  if [[ ! -f "$acl_file" ]]; then
    return 0
  fi
  if ! have_cmd setfacl; then
    warn "setfacl not found; cannot restore ACLs from snapshot."
    return 0
  fi

  info "Restoring ACLs from ${acl_file}"
  setfacl --restore="$acl_file" || warn "setfacl restore failed"
}

latest_snapshot_path() {
  [[ -d "$SNAP_DIR" ]] || return 1
  ls -1dt "${SNAP_DIR}"/* 2>/dev/null | head -n 1
}

############################
# Usage
############################
usage() {
  cat <<'USAGE'
Drupal Statekeeper v0.1.6

Usage:
  sudo -E bash drupal_statekeeperV0.1.6.sh <command> [options]

Commands:
  snapshot   Create a snapshot of key files under sites/default
  apply      Restore from a snapshot (safe by default)
  harden     Ensure include + write trusted_host_patterns + tighten permissions
  status     Print resolved paths

Common options:
  --drupal-dir=PATH        Drupal project root (default: /var/www/drupal)
  --ops-user=USER          Owner for hardened files (default: SUDO_USER or ubuntu)
  --ops-group=GROUP        Group for hardened files (default: drupal, fallback to www-data)

Trusted-host / harden options:
  --harden                 Enable hardening (permissions + include + trusted host write)
  --trusted-hosts=CSV      Comma-separated list. Exact hosts are auto-escaped & anchored.
                           Regex requires prefix: re:... or regex:...
                           If it "looks like regex" without prefix, script warns but keeps compatibility.
  --uri=URL                Used to derive host when --trusted-hosts is not given.

Snapshot options:
  --acl                    Capture ACLs of sites/default (requires getfacl)
  --incremental            Accepted for compatibility (no-op in this version)

Apply options:
  --from=PATH              Snapshot directory path (default: latest)
  --restore-settings-full  Also restore settings.php from snapshot (DANGEROUS)

Examples:
  # Strictest: derive from URI and write ONLY to settings.statekeeper.php
  sudo -E bash drupal_statekeeperV0.1.6.sh snapshot --harden --uri=http://192.168.64.19

  # Multiple exact hosts
  sudo -E bash drupal_statekeeperV0.1.6.sh snapshot --harden --uri=https://example.com \
    --trusted-hosts=example.com,www.example.com

  # Subdomains via regex (must use re:)
  sudo -E bash drupal_statekeeperV0.1.6.sh snapshot --harden --uri=https://example.com \
    --trusted-hosts='re:(.+\\.)?example\\.com'
USAGE
}

############################
# Arg parsing
############################
COMMAND="${1:-}"
shift || true

DRUPAL_DIR="$DEFAULT_DRUPAL_DIR"
OPS_USER=""
OPS_GROUP=""
URI=""
TRUSTED_HOSTS=""
HARDEN=0
ACL=0
INCREMENTAL=0
FROM=""
RESTORE_SETTINGS_FULL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --drupal-dir=*) DRUPAL_DIR="${1#*=}" ;;
    --ops-user=*) OPS_USER="${1#*=}" ;;
    --ops-group=*) OPS_GROUP="${1#*=}" ;;
    --uri=*) URI="${1#*=}" ;;
    --trusted-hosts=*) TRUSTED_HOSTS="${1#*=}" ;;
    --harden) HARDEN=1 ;;
    --acl) ACL=1 ;;
    --incremental) INCREMENTAL=1 ;;
    --from=*) FROM="${1#*=}" ;;
    --restore-settings-full) RESTORE_SETTINGS_FULL=1 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
  shift
done

# Auto-enable harden if trusted-hosts is provided (requested behavior)
if [[ -n "$TRUSTED_HOSTS" ]]; then
  HARDEN=1
fi

DOCROOT="$(resolve_docroot "$DRUPAL_DIR")"
SETTINGS_DIR="${DOCROOT}/sites/default"
SETTINGS_PHP="${SETTINGS_DIR}/settings.php"

############################
# Commands
############################
case "$COMMAND" in
  ""|help|--help|-h)
    usage
    exit 0
    ;;

  status)
    echo "version=${VERSION}"
    echo "drupal_dir=${DRUPAL_DIR}"
    echo "docroot=${DOCROOT}"
    echo "settings_dir=${SETTINGS_DIR}"
    echo "state_dir=${STATE_DIR}"
    echo "snap_dir=${SNAP_DIR}"
    exit 0
    ;;

  harden)
    need_root
    [[ -d "$SETTINGS_DIR" ]] || die "Missing settings directory: ${SETTINGS_DIR}"
    [[ -f "$SETTINGS_PHP" ]] || die "Missing settings.php: ${SETTINGS_PHP}"

    mkdir -p "$STATE_DIR" "$SNAP_DIR"

    ensure_settings_statekeeper_file "$SETTINGS_DIR"
    ensure_settings_include_block "$SETTINGS_PHP"

    mapfile -t PATTERNS < <(build_trusted_patterns "$TRUSTED_HOSTS" "$URI")
    [[ "${#PATTERNS[@]}" -gt 0 ]] || die "No trusted_host_patterns generated."

    warn_if_uri_host_not_matched "$URI" "${PATTERNS[@]}"
    write_trusted_hosts_block "$SETTINGS_DIR" "${PATTERNS[@]}"

    local_user="$(pick_ops_user "$OPS_USER")"
    local_group="$(pick_ops_group "$OPS_GROUP")"
    harden_permissions "$SETTINGS_DIR" "$local_user" "$local_group"
    ;;

  snapshot)
    need_root
    [[ -d "$SETTINGS_DIR" ]] || die "Missing settings directory: ${SETTINGS_DIR}"
    [[ -f "$SETTINGS_PHP" ]] || die "Missing settings.php: ${SETTINGS_PHP}"

    mkdir -p "$STATE_DIR" "$SNAP_DIR"

    if [[ "$INCREMENTAL" == "1" ]]; then
      warn "--incremental is accepted for compatibility but is a no-op in v0.1.6."
    fi

    # If harden is enabled, apply strict include + trusted-host + perms BEFORE taking the snapshot.
    if [[ "$HARDEN" == "1" ]]; then
      ensure_settings_statekeeper_file "$SETTINGS_DIR"
      ensure_settings_include_block "$SETTINGS_PHP"

      mapfile -t PATTERNS < <(build_trusted_patterns "$TRUSTED_HOSTS" "$URI")
      [[ "${#PATTERNS[@]}" -gt 0 ]] || die "No trusted_host_patterns generated."

      warn_if_uri_host_not_matched "$URI" "${PATTERNS[@]}"
      write_trusted_hosts_block "$SETTINGS_DIR" "${PATTERNS[@]}"

      local_user="$(pick_ops_user "$OPS_USER")"
      local_group="$(pick_ops_group "$OPS_GROUP")"
      harden_permissions "$SETTINGS_DIR" "$local_user" "$local_group"
    fi

    TS="$(date '+%Y%m%d_%H%M%S')"
    SNAP_PATH="${SNAP_DIR}/${TS}"

    snapshot_create "$DOCROOT" "$SETTINGS_DIR" "$TS"

    if [[ "$ACL" == "1" ]]; then
      snapshot_capture_acl "$SETTINGS_DIR" "$SNAP_PATH"
    fi

    echo "$SNAP_PATH"
    ;;

  apply)
    need_root
    [[ -d "$SETTINGS_DIR" ]] || die "Missing settings directory: ${SETTINGS_DIR}"
    [[ -f "$SETTINGS_PHP" ]] || die "Missing settings.php: ${SETTINGS_PHP}"

    snap_path=""
    if [[ -n "$FROM" ]]; then
      snap_path="$FROM"
    else
      snap_path="$(latest_snapshot_path || true)"
      [[ -n "$snap_path" ]] || die "No snapshots found under ${SNAP_DIR}. Use snapshot first or pass --from=PATH."
    fi

    apply_from_snapshot "$SETTINGS_DIR" "$snap_path" "$RESTORE_SETTINGS_FULL"

    # IMPORTANT: ensure include AFTER restore (requested fix)
    ensure_settings_statekeeper_file "$SETTINGS_DIR"
    ensure_settings_include_block "$SETTINGS_PHP"

    apply_restore_acl "$snap_path"

    # If user requested --harden (or passed --trusted-hosts), re-apply strict trusted-hosts and perms
    if [[ "$HARDEN" == "1" ]]; then
      mapfile -t PATTERNS < <(build_trusted_patterns "$TRUSTED_HOSTS" "$URI")
      warn_if_uri_host_not_matched "$URI" "${PATTERNS[@]}"
      write_trusted_hosts_block "$SETTINGS_DIR" "${PATTERNS[@]}"

      local_user="$(pick_ops_user "$OPS_USER")"
      local_group="$(pick_ops_group "$OPS_GROUP")"
      harden_permissions "$SETTINGS_DIR" "$local_user" "$local_group"
    fi

    ok "Apply complete."
    ;;

  *)
    die "Unknown command: ${COMMAND} (use --help)"
    ;;
esac
