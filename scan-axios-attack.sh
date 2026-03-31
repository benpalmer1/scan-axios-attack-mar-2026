#!/usr/bin/env bash
# =============================================================================
# Axios Supply Chain Attack Scanner (macOS/Linux - Bash)
# =============================================================================
# Scans for compromised axios versions (1.14.1, 0.30.4) and the malicious
# plain-crypto-js payload package from the 30-31 March 2026 npm supply-chain
# compromise.
#
# Attack summary:
#   - Hijacked maintainer npm account used to publish poisoned axios releases
#   - axios@1.14.1 and axios@0.30.4 inject plain-crypto-js@4.2.1 as a
#     dependency whose postinstall hook drops a cross-platform remote access
#     trojan (RAT) targeting macOS, Windows, and Linux
#   - Ref: https://github.com/axios/axios/issues/10604
#   - Ref: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
#
# Usage: chmod +x scan-axios-attack.sh && ./scan-axios-attack.sh
#        ./scan-axios-attack.sh /custom/search/root
# =============================================================================
# Keep this script ASCII-only and limited to Bash/zsh shared features; avoid eval-built find arguments for compatibility.

set -euo pipefail

# --- Configuration -----------------------------------------------------------
COMPROMISED_VERSIONS=("1.14.1" "0.30.4")
MALICIOUS_PKG="plain-crypto-js"
SEARCH_ROOT="${1:-/}"
SKIP_DIRS=(".Trash" "Library/Caches" "Library/Application Support/Google" "Library/Safari" "System" "Library/Apple")

# --- Colours -----------------------------------------------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

# --- State -------------------------------------------------------------------
TOTAL_AXIOS_FOUND=0
COMPROMISED_FOUND=0
MALICIOUS_PKG_FOUND=0
OTHER_MALICIOUS_PKG_HITS=0
SECURITY_HOLDER_PKG_FOUND=0
RAT_ARTIFACTS_FOUND=0
FINDINGS=()
EXCLUDE_ARGS=()

# --- Helpers -----------------------------------------------------------------
banner() {
  printf '\n%b============================================================%b\n' "$BLUE" "$NC"
  printf '%b  %s%b\n' "$BOLD" "$1" "$NC"
  printf '%b============================================================%b\n' "$BLUE" "$NC"
}
ok()     { echo "  ${GREEN}[OK]${NC} $1"; }
warn()   { echo "  ${YELLOW}[WARN]${NC} $1"; }
fail()   { echo "  ${RED}[FAIL]${NC} $1"; }
info()   { echo "  ${CYAN}[INFO]${NC} $1"; }

build_find_excludes() {
  EXCLUDE_ARGS=()
  local dir
  for dir in "${SKIP_DIRS[@]}"; do
    EXCLUDE_ARGS+=(-not -path "*/$dir/*")
  done
}

get_package_version() {
  local package_json="$1"
  local version
  version=$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$package_json" 2>/dev/null | head -n 1 || true)
  if [[ -n "$version" ]]; then
    echo "$version"
  else
    echo "unknown"
  fi
}

lockfile_has_package_version() {
  local lockfile="$1"
  local package_name="$2"
  local version="$3"

  if command -v perl >/dev/null 2>&1; then
    PKG="$package_name" CV="$version" perl -0ne '
      my $pkg = quotemeta $ENV{PKG};
      my $cv = quotemeta $ENV{CV};
      my $found = /"node_modules\/$pkg"\s*:\s*\{.{0,1200}?"version"\s*:\s*"$cv"/s
               || /"$pkg"\s*:\s*\{.{0,1200}?"version"\s*:\s*"$cv"/s
               || /(?:^|\n)$pkg@.*?(?:\r?\n).{0,400}?version\s+"$cv"/s
               || /(?:^|\n)\s*\/?$pkg\@$cv(?:\(|:|$)/m;
      exit($found ? 0 : 1);
    ' "$lockfile" >/dev/null 2>&1
    return $?
  fi

  awk -v pkg="$package_name" -v cv="$version" '
    BEGIN {
      content = ""
      pkg_escaped = pkg
      cv_escaped = cv
      gsub(/[][\\.^$*+?(){}|]/, "\\\\&", pkg_escaped)
      gsub(/\./, "\\\\.", cv_escaped)
    }
    { content = content $0 "\n" }
    END {
      gsub(/\r/, "", content)
      normalized = content
      gsub(/\n/, " ", normalized)

      found = normalized ~ "\"node_modules/" pkg_escaped "\"[[:space:]]*:[[:space:]]*\\{.{0,1200}\"version\"[[:space:]]*:[[:space:]]*\"" cv_escaped "\""
           || normalized ~ "\"" pkg_escaped "\"[[:space:]]*:[[:space:]]*\\{.{0,1200}\"version\"[[:space:]]*:[[:space:]]*\"" cv_escaped "\""
           || normalized ~ "(^| )" pkg_escaped "@.{0,400}version[[:space:]]+\"" cv_escaped "\""
           || normalized ~ "(^| )[[:space:]]*/?" pkg_escaped "@" cv_escaped "(\\(|:|$)"

      exit(found ? 0 : 1)
    }
  ' "$lockfile" >/dev/null 2>&1
}

bun_lockfile_has_package_version() {
  local lockfile="$1"
  local package_name="$2"
  local version="$3"

  strings "$lockfile" 2>/dev/null | awk -v pkg="$package_name" -v cv="$version" '
    BEGIN { window = 0; found = 0 }
    index($0, pkg) > 0 { window = 12 }
    window > 0 && index($0, cv) > 0 { found = 1 }
    window > 0 { window-- }
    END { exit(found ? 0 : 1) }
  '
}

package_version_category() {
  local version="$1"
  case "$version" in
    "4.2.1") echo "malicious" ;;
    "0.0.1-security.0") echo "security" ;;
    ""|"unknown") echo "unknown" ;;
    *) echo "other" ;;
  esac
}

lockfile_has_compromised_axios() {
  lockfile_has_package_version "$1" "axios" "$2"
}

bun_lockfile_has_compromised_axios() {
  bun_lockfile_has_package_version "$1" "axios" "$2"
}

build_find_excludes

# =============================================================================
echo ""
echo "${RED}${BOLD}  +=========================================================+${NC}"
echo "${RED}${BOLD}  |         AXIOS SUPPLY CHAIN ATTACK SCANNER                |${NC}"
echo "${RED}${BOLD}  |     npm supply-chain compromise / RAT dropper            |${NC}"
echo "${RED}${BOLD}  |      30-31 Mar 2026 - axios 1.14.1 / 0.30.4             |${NC}"
echo "${RED}${BOLD}  |      https://github.com/axios/axios/issues/10604        |${NC}"
echo "${RED}${BOLD}  +=========================================================+${NC}"
echo ""
info "Search root: ${BOLD}$SEARCH_ROOT${NC}"
info "Date:        $(date '+%Y-%m-%d %H:%M:%S')"
info "Host:        $(hostname)"
info "User:        $(whoami)"

# =============================================================================
# 1. Installed axios in node_modules
# =============================================================================
banner "1/7  Scanning node_modules for axios installations"

while IFS= read -r pkg_json; do
  if [[ -f "$pkg_json" ]]; then
    version=$(get_package_version "$pkg_json")
    location=$(dirname "$pkg_json")
    TOTAL_AXIOS_FOUND=$((TOTAL_AXIOS_FOUND + 1))

    is_compromised=false
    for cv in "${COMPROMISED_VERSIONS[@]}"; do
      if [[ "$version" == "$cv" ]]; then
        is_compromised=true
        break
      fi
    done

    if $is_compromised; then
      COMPROMISED_FOUND=$((COMPROMISED_FOUND + 1))
      fail "${RED}COMPROMISED${NC} axios@${BOLD}$version${NC}"
      fail "  Location: $location"
      FINDINGS+=("CRITICAL: Compromised axios@$version at $location")
    else
      ok "axios@${version} (safe) - ${location/$SEARCH_ROOT/\~}"
    fi
  fi
done < <(find "$SEARCH_ROOT" -path "*/node_modules/axios/package.json" "${EXCLUDE_ARGS[@]}" 2>/dev/null)

if [[ $TOTAL_AXIOS_FOUND -eq 0 ]]; then
  ok "No axios installations found in any node_modules"
fi

# =============================================================================
# 2. axios in dependency files (package.json, lockfiles)
# =============================================================================
banner "2/7  Scanning dependency manifests and lockfiles"

dep_file_hits=0

# package.json (non-node_modules)
while IFS= read -r pj; do
  if grep -q '"axios"' "$pj" 2>/dev/null; then
    version_spec=$(grep '"axios"' "$pj" 2>/dev/null | head -1 | sed 's/.*"axios" *: *"//;s/".*//')
    dep_file_hits=$((dep_file_hits + 1))
    info "package.json declares axios@${BOLD}$version_spec${NC} - ${pj/$SEARCH_ROOT/\~}"
  fi
done < <(find "$SEARCH_ROOT" -name "package.json" -not -path "*/node_modules/*" "${EXCLUDE_ARGS[@]}" 2>/dev/null)

# Lockfiles
for lockfile_name in "package-lock.json" "npm-shrinkwrap.json" "yarn.lock" "pnpm-lock.yaml" "bun.lock" "bun.lockb"; do
  while IFS= read -r lf; do
    if [[ "$lockfile_name" == "bun.lockb" ]]; then
      if ! command -v strings >/dev/null 2>&1; then
        warn "strings not installed - bun.lockb scan skipped for ${lf/$SEARCH_ROOT/\~}"
        continue
      fi

      if strings "$lf" 2>/dev/null | grep -q "axios"; then
        dep_file_hits=$((dep_file_hits + 1))

        for cv in "${COMPROMISED_VERSIONS[@]}"; do
          if bun_lockfile_has_compromised_axios "$lf" "$cv"; then
            COMPROMISED_FOUND=$((COMPROMISED_FOUND + 1))
            fail "${RED}COMPROMISED version $cv referenced${NC} - ${lf/$SEARCH_ROOT/\~}"
            FINDINGS+=("CRITICAL: Lockfile references compromised axios@$cv at $lf")
          fi
        done

        warn "axios referenced in binary lockfile - ${lf/$SEARCH_ROOT/\~}"
      fi
    else
      if grep -q "axios" "$lf" 2>/dev/null; then
        dep_file_hits=$((dep_file_hits + 1))

        for cv in "${COMPROMISED_VERSIONS[@]}"; do
          if lockfile_has_compromised_axios "$lf" "$cv"; then
            COMPROMISED_FOUND=$((COMPROMISED_FOUND + 1))
            fail "${RED}COMPROMISED version $cv referenced${NC} - ${lf/$SEARCH_ROOT/\~}"
            FINDINGS+=("CRITICAL: Lockfile references compromised axios@$cv at $lf")
          fi
        done

        info "axios referenced in ${lockfile_name} - ${lf/$SEARCH_ROOT/\~}"
      fi
    fi
  done < <(find "$SEARCH_ROOT" -name "$lockfile_name" -not -path "*/node_modules/*" "${EXCLUDE_ARGS[@]}" 2>/dev/null)
done

if [[ $dep_file_hits -eq 0 ]]; then
  ok "No axios references in any dependency manifests or lockfiles"
fi

# =============================================================================
# 3. Malicious plain-crypto-js package
# =============================================================================
banner "3/7  Scanning for malicious ${MALICIOUS_PKG} package"

# Check node_modules
while IFS= read -r mpath; do
  pkg_json="$mpath/package.json"
  pkg_version=$(get_package_version "$pkg_json")
  pkg_category=$(package_version_category "$pkg_version")

  case "$pkg_category" in
    malicious)
      MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
      fail "${RED}CONFIRMED MALICIOUS PACKAGE${NC}: ${MALICIOUS_PKG}@${BOLD}$pkg_version${NC} at $mpath"
      FINDINGS+=("CRITICAL: Confirmed malicious ${MALICIOUS_PKG}@$pkg_version at $mpath")
      ;;
    security)
      SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
      ok "${MALICIOUS_PKG}@$pkg_version security-holder package installed at ${mpath/$SEARCH_ROOT/\~}"
      ;;
    *)
      OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
      warn "${MALICIOUS_PKG}@$pkg_version found at ${mpath/$SEARCH_ROOT/\~} - not the confirmed malicious 4.2.1 release"
      FINDINGS+=("WARNING: ${MALICIOUS_PKG}@$pkg_version found at $mpath - review whether this package is expected")
      ;;
  esac
done < <(find "$SEARCH_ROOT" -path "*/node_modules/$MALICIOUS_PKG" -type d "${EXCLUDE_ARGS[@]}" 2>/dev/null)

# Check all dependency files for references
pcj_refs=0
while IFS= read -r pj; do
  if [[ "$pj" == *.lockb ]]; then
    if ! command -v strings >/dev/null 2>&1; then
      warn "strings not installed - bun.lockb dependency scan skipped for ${pj/$SEARCH_ROOT/\~}"
      continue
    fi

    if strings "$pj" 2>/dev/null | grep -q "$MALICIOUS_PKG"; then
      pcj_refs=$((pcj_refs + 1))
      if bun_lockfile_has_package_version "$pj" "$MALICIOUS_PKG" "4.2.1"; then
        MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
        fail "${RED}CONFIRMED MALICIOUS REFERENCE${NC} in ${pj/$SEARCH_ROOT/\~}: ${MALICIOUS_PKG}@4.2.1"
        FINDINGS+=("CRITICAL: Lockfile references confirmed malicious ${MALICIOUS_PKG}@4.2.1 at $pj")
      elif bun_lockfile_has_package_version "$pj" "$MALICIOUS_PKG" "0.0.1-security.0"; then
        SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
        ok "${MALICIOUS_PKG}@0.0.1-security.0 referenced in bun lockfile ${pj/$SEARCH_ROOT/\~}"
      else
        OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
        warn "${MALICIOUS_PKG} referenced in ${pj/$SEARCH_ROOT/\~} (version unclear or non-malicious)"
        FINDINGS+=("WARNING: ${MALICIOUS_PKG} referenced in $pj with version unclear or not equal to 4.2.1")
      fi
    fi
  elif grep -q "$MALICIOUS_PKG" "$pj" 2>/dev/null; then
    pcj_refs=$((pcj_refs + 1))
    if [[ "$pj" == *.json ]]; then
      pcj_spec=$(grep '"plain-crypto-js"' "$pj" 2>/dev/null | head -1 | sed 's/.*"plain-crypto-js" *: *"//;s/".*//')
      if [[ "$pcj_spec" == *"4.2.1"* ]]; then
        MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
        fail "${RED}CONFIRMED MALICIOUS REFERENCE${NC} in ${pj/$SEARCH_ROOT/\~}: ${MALICIOUS_PKG}@4.2.1"
        FINDINGS+=("CRITICAL: Dependency manifest references confirmed malicious ${MALICIOUS_PKG}@4.2.1 at $pj")
      elif [[ "$pcj_spec" == *"0.0.1-security.0"* ]]; then
        SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
        ok "${MALICIOUS_PKG}@0.0.1-security.0 referenced in ${pj/$SEARCH_ROOT/\~}"
      elif [[ -n "$pcj_spec" ]]; then
        OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
        warn "${MALICIOUS_PKG}@${pcj_spec} referenced in ${pj/$SEARCH_ROOT/\~} - not confirmed malicious"
        FINDINGS+=("WARNING: ${MALICIOUS_PKG}@${pcj_spec} referenced in $pj - review whether this package/version is expected")
      else
        OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
        warn "${MALICIOUS_PKG} referenced in ${pj/$SEARCH_ROOT/\~} (version unclear)"
        FINDINGS+=("WARNING: ${MALICIOUS_PKG} referenced in $pj with version unclear")
      fi
    elif lockfile_has_package_version "$pj" "$MALICIOUS_PKG" "4.2.1"; then
      MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
      fail "${RED}CONFIRMED MALICIOUS REFERENCE${NC} in ${pj/$SEARCH_ROOT/\~}: ${MALICIOUS_PKG}@4.2.1"
      FINDINGS+=("CRITICAL: Lockfile references confirmed malicious ${MALICIOUS_PKG}@4.2.1 at $pj")
    elif lockfile_has_package_version "$pj" "$MALICIOUS_PKG" "0.0.1-security.0"; then
      SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
      ok "${MALICIOUS_PKG}@0.0.1-security.0 referenced in ${pj/$SEARCH_ROOT/\~}"
    else
      OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
      warn "${MALICIOUS_PKG} referenced in ${pj/$SEARCH_ROOT/\~} (version unclear or non-malicious)"
      FINDINGS+=("WARNING: ${MALICIOUS_PKG} referenced in $pj with version unclear or not equal to 4.2.1")
    fi
  fi
done < <(find "$SEARCH_ROOT" \( -name "package.json" -o -name "package-lock.json" -o -name "npm-shrinkwrap.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "bun.lock" -o -name "bun.lockb" \) -not -path "*/node_modules/*" "${EXCLUDE_ARGS[@]}" 2>/dev/null)

if [[ $MALICIOUS_PKG_FOUND -eq 0 && $OTHER_MALICIOUS_PKG_HITS -eq 0 && $SECURITY_HOLDER_PKG_FOUND -eq 0 ]]; then
  ok "No trace of ${MALICIOUS_PKG} anywhere"
fi

# =============================================================================
# 4. Package manager caches
# =============================================================================
banner "4/7  Scanning package manager caches"

# npm cache
if [[ -d "$HOME/.npm" ]]; then
  # The npm _cacache stores both registry manifests (packuments) and actual
  # package tarballs. Packuments list ALL published versions of a package,
  # so a grep hit for "1.14.1" in a manifest is expected and NOT a compromise.
  #
  # To distinguish real risk from metadata noise we check two things:
  #   1. index-v5 keys - a key like "axios/-/axios-1.14.1.tgz" means the
  #      actual compromised tarball was fetched and cached.
  #   2. plain-crypto-js index keys - if the malicious package was ever
  #      resolved, it will have its own index entry.

  npm_cache_risk="none"

  # Check index for actual tarball cache entries for compromised versions
  for cv in "${COMPROMISED_VERSIONS[@]}"; do
    if grep -rl "axios-${cv}.tgz" "$HOME/.npm/_cacache/index-v5/" 2>/dev/null | head -1 | grep -q .; then
      npm_cache_risk="tarball"
      COMPROMISED_FOUND=$((COMPROMISED_FOUND + 1))
      fail "${RED}Compromised axios@$cv TARBALL cached${NC} - actual package was downloaded"
      FINDINGS+=("CRITICAL: Compromised axios@$cv tarball in npm cache - run 'npm cache clean --force'")
    fi
  done

  # Check for plain-crypto-js tarball cache entries versus registry metadata.
  pcj_malicious_tarball=$(grep -rl "${MALICIOUS_PKG}-4.2.1.tgz" "$HOME/.npm/_cacache/index-v5/" 2>/dev/null | head -1 || true)
  pcj_security_tarball=$(grep -rl "${MALICIOUS_PKG}-0.0.1-security.0.tgz" "$HOME/.npm/_cacache/index-v5/" 2>/dev/null | head -1 || true)
  pcj_index_metadata=$(grep -rl "request-cache:https://registry.npmjs.org/${MALICIOUS_PKG}" "$HOME/.npm/_cacache/index-v5/" 2>/dev/null | head -1 || true)

  if [[ -n "$pcj_malicious_tarball" ]]; then
    npm_cache_risk="tarball"
    MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
    fail "${RED}${MALICIOUS_PKG}@4.2.1 tarball cached${NC} - confirmed malicious package download"
    FINDINGS+=("CRITICAL: ${MALICIOUS_PKG}@4.2.1 tarball in npm cache - run 'npm cache clean --force'")
  elif [[ -n "$pcj_security_tarball" ]]; then
    SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
    info "${MALICIOUS_PKG}@0.0.1-security.0 security-holder tarball cached"
    ok "npm cache includes the security-holder replacement for ${MALICIOUS_PKG}"
  elif [[ -n "$pcj_index_metadata" ]]; then
    info "${MALICIOUS_PKG} appears in npm cache registry metadata only"
    info "This does not prove that ${MALICIOUS_PKG}@4.2.1 was downloaded"
  fi

  # If no tarball-level hits, do a broader content scan and classify as metadata
  if [[ "$npm_cache_risk" == "none" ]]; then
    manifest_hits=0
    for cv in "${COMPROMISED_VERSIONS[@]}"; do
      if grep -rl "axios.*$cv" "$HOME/.npm/_cacache/content-v2/" 2>/dev/null | head -1 | grep -q .; then
        manifest_hits=$((manifest_hits + 1))
      fi
    done

    pcj_manifest=$(grep -rl "$MALICIOUS_PKG" "$HOME/.npm/_cacache/content-v2/" 2>/dev/null | head -1 || true)

    if [[ $manifest_hits -gt 0 || -n "$pcj_manifest" ]]; then
      info "Compromised version strings appear in npm cache ${BOLD}registry manifests only${NC}"
      info "This is expected - npm caches the full version list for resolved packages"
      info "No actual compromised tarballs were downloaded (low risk)"
      ok "npm cache - metadata references only, no compromised packages cached"
    else
      ok "npm cache clean of axios and ${MALICIOUS_PKG}"
    fi
  fi
else
  ok "No npm cache directory found"
fi

# bun cache
if [[ -d "$HOME/.bun/install/cache" ]]; then
  if find "$HOME/.bun/install/cache" -maxdepth 1 -name "axios@*" 2>/dev/null | grep -q .; then
    while IFS= read -r bun_axios; do
      bun_ver=$(basename "$bun_axios" | sed 's/axios@//;s/@.*//')
      for cv in "${COMPROMISED_VERSIONS[@]}"; do
        if [[ "$bun_ver" == "$cv" ]]; then
          COMPROMISED_FOUND=$((COMPROMISED_FOUND + 1))
          fail "${RED}Compromised axios@$cv in bun cache${NC}"
          FINDINGS+=("CRITICAL: Compromised axios@$cv in bun cache - clear bun cache")
        fi
      done
      info "axios@$bun_ver in bun cache"
    done < <(find "$HOME/.bun/install/cache" -maxdepth 1 -name "axios@*" 2>/dev/null)
  else
    ok "bun cache clean of axios"
  fi

  if find "$HOME/.bun/install/cache" -maxdepth 1 -name "${MALICIOUS_PKG}@*" 2>/dev/null | grep -q .; then
    while IFS= read -r bun_pcj; do
      bun_pcj_ver=$(basename "$bun_pcj" | sed "s/${MALICIOUS_PKG}@//;s/@.*//")
      bun_pcj_category=$(package_version_category "$bun_pcj_ver")
      case "$bun_pcj_category" in
        malicious)
          MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
          fail "${RED}${MALICIOUS_PKG}@4.2.1 found in bun cache${NC}"
          FINDINGS+=("CRITICAL: ${MALICIOUS_PKG}@4.2.1 in bun cache")
          ;;
        security)
          SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
          ok "${MALICIOUS_PKG}@0.0.1-security.0 security-holder package found in bun cache"
          ;;
        *)
          OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
          warn "${MALICIOUS_PKG}@${bun_pcj_ver} found in bun cache - not the confirmed malicious 4.2.1 release"
          FINDINGS+=("WARNING: ${MALICIOUS_PKG}@${bun_pcj_ver} found in bun cache - review whether this package/version is expected")
          ;;
      esac
    done < <(find "$HOME/.bun/install/cache" -maxdepth 1 -name "${MALICIOUS_PKG}@*" 2>/dev/null)
  else
    ok "bun cache clean of ${MALICIOUS_PKG}"
  fi
else
  ok "No bun cache directory found"
fi

# yarn cache
if command -v yarn >/dev/null 2>&1; then
  yarn_cache=$(yarn cache dir 2>/dev/null || echo "")
  if [[ -n "$yarn_cache" && -d "$yarn_cache" ]]; then
    if find "$yarn_cache" -name "axios-*" 2>/dev/null | grep -q .; then
      warn "axios found in yarn cache"
    else
      ok "yarn cache clean of axios"
    fi
  fi
else
  ok "yarn not installed - skipped"
fi

# pnpm cache
if command -v pnpm >/dev/null 2>&1; then
  pnpm_store=$(pnpm store path 2>/dev/null || echo "")
  if [[ -n "$pnpm_store" && -d "$pnpm_store" ]]; then
    if find "$pnpm_store" -name "axios" -type d 2>/dev/null | grep -q .; then
      warn "axios found in pnpm store"
    else
      ok "pnpm store clean of axios"
    fi
  fi
else
  ok "pnpm not installed - skipped"
fi

# Global npm
if command -v npm >/dev/null 2>&1; then
  npm_global_prefix=$(npm prefix -g 2>/dev/null || true)
  if [[ -z "$npm_global_prefix" ]]; then
    warn "Unable to determine npm global prefix - global npm check skipped"
  elif [[ -d "$npm_global_prefix/lib/node_modules/axios" ]]; then
    gver=$(get_package_version "$npm_global_prefix/lib/node_modules/axios/package.json")
    warn "axios@$gver installed globally"
    for cv in "${COMPROMISED_VERSIONS[@]}"; do
      if [[ "$gver" == "$cv" ]]; then
        fail "${RED}COMPROMISED axios@$cv installed globally${NC}"
        FINDINGS+=("CRITICAL: Compromised axios@$cv installed globally - run 'npm uninstall -g axios'")
      fi
    done
  else
    ok "No global axios installation"
  fi
else
  ok "npm not installed - global npm check skipped"
fi

# =============================================================================
# 5. IDE extensions
# =============================================================================
banner "5/7  Scanning IDE extensions"

ide_axios_count=0
for ide_dir in "$HOME/.cursor/extensions" "$HOME/.vscode/extensions" "$HOME/.vscode-server/extensions" "$HOME/.antigravity/extensions" "$HOME/.windsurf/extensions"; do
  ide_name=$(basename "$(dirname "$ide_dir")" | sed 's/^\.//')
  if [[ -d "$ide_dir" ]]; then
    while IFS= read -r ext_axios; do
      version=$(get_package_version "$ext_axios")
      ext_name=$(echo "$ext_axios" | sed "s|$ide_dir/||;s|/node_modules/axios/package.json||")
      ide_axios_count=$((ide_axios_count + 1))

      is_compromised=false
      for cv in "${COMPROMISED_VERSIONS[@]}"; do
        [[ "$version" == "$cv" ]] && is_compromised=true
      done

      if $is_compromised; then
        COMPROMISED_FOUND=$((COMPROMISED_FOUND + 1))
        fail "${RED}COMPROMISED${NC} axios@${BOLD}$version${NC} in $ide_name extension: $ext_name"
        FINDINGS+=("CRITICAL: Compromised axios@$version in $ide_name extension $ext_name")
      else
        ok "axios@$version (safe) in $ide_name extension: $ext_name"
      fi
    done < <(find "$ide_dir" -path "*/node_modules/axios/package.json" 2>/dev/null)

    while IFS= read -r ext_pcj; do
      ext_pcj_dir=$(dirname "$ext_pcj")
      ext_pcj_version=$(get_package_version "$ext_pcj_dir/package.json")
      ext_pcj_category=$(package_version_category "$ext_pcj_version")
      ext_name=$(echo "$ext_pcj_dir" | sed "s|$ide_dir/||;s|/node_modules/${MALICIOUS_PKG}||")

      case "$ext_pcj_category" in
        malicious)
          MALICIOUS_PKG_FOUND=$((MALICIOUS_PKG_FOUND + 1))
          fail "${RED}CONFIRMED MALICIOUS PACKAGE${NC}: ${MALICIOUS_PKG}@${BOLD}$ext_pcj_version${NC} in $ide_name extension: $ext_name"
          FINDINGS+=("CRITICAL: Confirmed malicious ${MALICIOUS_PKG}@$ext_pcj_version in $ide_name extension $ext_name")
          ;;
        security)
          SECURITY_HOLDER_PKG_FOUND=$((SECURITY_HOLDER_PKG_FOUND + 1))
          ok "${MALICIOUS_PKG}@${ext_pcj_version} security-holder package in $ide_name extension: $ext_name"
          ;;
        *)
          OTHER_MALICIOUS_PKG_HITS=$((OTHER_MALICIOUS_PKG_HITS + 1))
          warn "${MALICIOUS_PKG}@${ext_pcj_version} found in $ide_name extension: $ext_name - not the confirmed malicious 4.2.1 release"
          FINDINGS+=("WARNING: ${MALICIOUS_PKG}@$ext_pcj_version found in $ide_name extension $ext_name - review whether this package is expected")
          ;;
      esac
    done < <(find "$ide_dir" -path "*/node_modules/${MALICIOUS_PKG}/package.json" 2>/dev/null)
  fi
done

if [[ $ide_axios_count -eq 0 ]]; then
  ok "No axios found in any IDE extensions"
fi

# =============================================================================
# 6. RAT artifact scan (macOS-specific)
# =============================================================================
banner "6/7  Scanning for RAT artifacts"

# LaunchAgents
if [[ -d "$HOME/Library/LaunchAgents" ]]; then
  suspicious_agents=0
  while IFS= read -r plist; do
    plist_name=$(basename "$plist")
    # Flag anything that doesn't match known vendors
    if ! echo "$plist_name" | grep -qiE "^(com\.apple\.|com\.google\.|com\.microsoft\.|com\.adobe\.|com\.logitech\.|com\.logi\.|com\.zoom\.|org\.mozilla\.|com\.cloudflare\.|com\.bitdefender\.|com\.1password\.|com\.raycast\.|com\.hegenberg\.|com\.objective-see\.)"; then
      # Check if the plist references anything crypto/node related
      if grep -qiE "crypto|node_modules|plain-crypto|axios|npm" "$plist" 2>/dev/null; then
        suspicious_agents=$((suspicious_agents + 1))
        RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
        fail "${RED}Suspicious LaunchAgent${NC}: $plist_name"
        FINDINGS+=("WARNING: Suspicious LaunchAgent $plist_name references crypto/node")
      fi
    fi
  done < <(find "$HOME/Library/LaunchAgents" -name "*.plist" 2>/dev/null)

  if [[ $suspicious_agents -eq 0 ]]; then
    ok "LaunchAgents clean"
  fi
else
  ok "No LaunchAgents directory"
fi

# System LaunchDaemons
if [[ -d "/Library/LaunchDaemons" ]]; then
  suspicious_daemons=0
  while IFS= read -r plist; do
    if grep -qiE "crypto|node_modules|plain-crypto|axios" "$plist" 2>/dev/null; then
      suspicious_daemons=$((suspicious_daemons + 1))
      RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
      fail "${RED}Suspicious LaunchDaemon${NC}: $(basename "$plist")"
      FINDINGS+=("WARNING: Suspicious LaunchDaemon $(basename "$plist")")
    fi
  done < <(find "/Library/LaunchDaemons" -name "*.plist" 2>/dev/null)

  if [[ $suspicious_daemons -eq 0 ]]; then
    ok "LaunchDaemons clean"
  fi
fi

# Cron jobs
if command -v crontab >/dev/null 2>&1; then
  cron_output=$(crontab -l 2>/dev/null || echo "")
  if [[ -n "$cron_output" ]]; then
    if echo "$cron_output" | grep -qiE "crypto|plain-crypto|axios"; then
      RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
      fail "${RED}Suspicious cron job found${NC}"
      FINDINGS+=("WARNING: Suspicious cron job referencing crypto/axios")
    else
      ok "Cron jobs clean ($(echo "$cron_output" | wc -l | tr -d ' ') jobs, none suspicious)"
    fi
  else
    ok "No cron jobs configured"
  fi
else
  ok "crontab not installed - cron scan skipped"
fi

# Suspicious processes
crypto_procs=$(ps aux 2>/dev/null | grep -iE "plain.crypto|crypto.js" | grep -v grep || true)
if [[ -n "$crypto_procs" ]]; then
  RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
  fail "${RED}Suspicious process running${NC}:"
  echo "$crypto_procs" | while IFS= read -r proc; do
    fail "  $proc"
  done
  FINDINGS+=("CRITICAL: Suspicious crypto-related process running")
else
  ok "No suspicious processes running"
fi

# Temp directories
temp_artifacts_found=0
for tmp_dir in "/tmp" "/var/tmp" "${TMPDIR:-/tmp}"; do
  if [[ -d "$tmp_dir" ]]; then
    suspicious_tmp=$(find "$tmp_dir" -maxdepth 2 \( -name "*crypto*" -o -name "*axios*" -o -name "$MALICIOUS_PKG" \) 2>/dev/null | grep -v "CryptoTokenKit" || true)
    if [[ -n "$suspicious_tmp" ]]; then
      temp_artifacts_found=1
      RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
      fail "${RED}Suspicious files in $tmp_dir${NC}:"
      echo "$suspicious_tmp" | while IFS= read -r sf; do fail "  $sf"; done
      FINDINGS+=("WARNING: Suspicious files in $tmp_dir")
    fi
  fi
done
if [[ $temp_artifacts_found -eq 0 ]]; then
  ok "Temp directories clean"
fi

# Check ~/.local/bin and ~/.config for unexpected executables
local_config_artifacts_found=0
for check_dir in "$HOME/.local/bin" "$HOME/.config"; do
  if [[ -d "$check_dir" ]]; then
    suspicious_bins=$(find "$check_dir" -maxdepth 3 \( -name "*crypto*" -o -name "*axios*" -o -name "$MALICIOUS_PKG" \) 2>/dev/null || true)
    if [[ -n "$suspicious_bins" ]]; then
      local_config_artifacts_found=1
      RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
      fail "${RED}Suspicious files in $check_dir${NC}"
      FINDINGS+=("WARNING: Suspicious files in $check_dir")
    fi
  fi
done
if [[ $local_config_artifacts_found -eq 0 ]]; then
  ok "Local bin/config directories clean"
fi

# =============================================================================
# 7. Linux-specific checks (if not macOS)
# =============================================================================
banner "7/7  Platform-specific checks"

if [[ "$(uname)" == "Linux" ]]; then
  # Systemd user services
  if [[ -d "$HOME/.config/systemd/user" ]]; then
    suspicious_services=$(grep -rl "crypto\|axios\|$MALICIOUS_PKG" "$HOME/.config/systemd/user/" 2>/dev/null || true)
    if [[ -n "$suspicious_services" ]]; then
      RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
      fail "${RED}Suspicious systemd user services found${NC}"
      FINDINGS+=("WARNING: Suspicious systemd services")
    else
      ok "Systemd user services clean"
    fi
  else
    ok "No systemd user services directory"
  fi

  # XDG autostart
  if [[ -d "$HOME/.config/autostart" ]]; then
    suspicious_autostart=$(grep -rl "crypto\|axios\|$MALICIOUS_PKG" "$HOME/.config/autostart/" 2>/dev/null || true)
    if [[ -n "$suspicious_autostart" ]]; then
      RAT_ARTIFACTS_FOUND=$((RAT_ARTIFACTS_FOUND + 1))
      fail "${RED}Suspicious autostart entries found${NC}"
      FINDINGS+=("WARNING: Suspicious autostart entries")
    else
      ok "Autostart entries clean"
    fi
  else
    ok "No autostart directory"
  fi
else
  ok "macOS detected - LaunchAgent/Daemon checks completed above"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "${BLUE}============================================================${NC}"
echo "${BOLD}  SCAN COMPLETE${NC}"
echo "${BLUE}============================================================${NC}"
echo ""
echo "  Axios installations found:      ${BOLD}$TOTAL_AXIOS_FOUND${NC}"
echo "  Compromised versions found:     $([ $COMPROMISED_FOUND -gt 0 ] && echo "${RED}${BOLD}$COMPROMISED_FOUND${NC}" || echo "${GREEN}${BOLD}$COMPROMISED_FOUND${NC}")"
echo "  Confirmed ${MALICIOUS_PKG}@4.2.1 found: $([ $MALICIOUS_PKG_FOUND -gt 0 ] && echo "${RED}${BOLD}$MALICIOUS_PKG_FOUND${NC}" || echo "${GREEN}${BOLD}$MALICIOUS_PKG_FOUND${NC}")"
echo "  Other ${MALICIOUS_PKG} hits:    $([ $OTHER_MALICIOUS_PKG_HITS -gt 0 ] && echo "${YELLOW}${BOLD}$OTHER_MALICIOUS_PKG_HITS${NC}" || echo "${GREEN}${BOLD}$OTHER_MALICIOUS_PKG_HITS${NC}")"
echo "  ${MALICIOUS_PKG} security-holder hits: $([ $SECURITY_HOLDER_PKG_FOUND -gt 0 ] && echo "${GREEN}${BOLD}$SECURITY_HOLDER_PKG_FOUND${NC}" || echo "${GREEN}${BOLD}$SECURITY_HOLDER_PKG_FOUND${NC}")"
echo "  Suspicious RAT artifacts:       $([ $RAT_ARTIFACTS_FOUND -gt 0 ] && echo "${RED}${BOLD}$RAT_ARTIFACTS_FOUND${NC}" || echo "${GREEN}${BOLD}$RAT_ARTIFACTS_FOUND${NC}")"
echo ""

if [[ ${#FINDINGS[@]} -gt 0 ]]; then
  echo "${RED}${BOLD}  +=========================================================+${NC}"
  echo "${RED}${BOLD}  |  ACTION REQUIRED - COMPROMISED PACKAGES DETECTED        |${NC}"
  echo "${RED}${BOLD}  +=========================================================+${NC}"
  echo ""
  for finding in "${FINDINGS[@]}"; do
    echo "  ${RED}*${NC} $finding"
  done
  echo ""
  echo "  ${BOLD}Remediation steps:${NC}"
  echo "  1. Delete compromised node_modules directories"
  echo "  2. Pin axios to a safe version (1.14.0 or 0.30.3)"
  echo "  3. Delete lockfiles and reinstall: rm package-lock.json && npm install"
  echo "  4. Clear caches: npm cache clean --force"
  echo "  5. Investigate and remove any RAT artifacts"
  echo "  6. Rotate any credentials/tokens on this machine"
  echo ""
  exit 1
else
  echo "${GREEN}${BOLD}  +=========================================================+${NC}"
  echo "${GREEN}${BOLD}  |  SCAN CLEAN - NO COMPROMISE INDICATORS FOUND            |${NC}"
  echo "${GREEN}${BOLD}  +=========================================================+${NC}"
  echo ""
  echo "  ${YELLOW}Note:${NC} The malicious postinstall payload is designed to self-destruct"
  echo "  after execution and overwrite its own package.json with a clean stub."
  echo "  A clean scan does ${BOLD}not${NC} guarantee the payload never ran. If axios@1.14.1"
  echo "  or axios@0.30.4 was ever installed on this machine, even briefly, treat"
  echo "  it as potentially compromised and rotate exposed credentials."
  echo ""
  exit 0
fi
