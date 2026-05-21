#!/usr/bin/env bash
# Cross-checks installed npm packages against deny-packages.yaml.
# Scans `package-lock.json` (npm) and `pnpm-lock.yaml` (pnpm) anywhere in
# the caller repo. Emits GitHub Actions error annotations + a Markdown
# job summary. Exits 1 on any match, 0 otherwise.
#
# Usage: check-packages.sh <deny-packages.yaml> <caller-repo-dir>

set -euo pipefail

denylist="${1:?usage: check-packages.sh <deny-packages.yaml> <caller-repo-dir>}"
repo_dir="${2:?usage: check-packages.sh <deny-packages.yaml> <caller-repo-dir>}"

SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# Hard-assert required tooling. Without this, a missing or broken jq/yq
# would silently produce no matches and let bad packages through — fail-
# open is the worst behavior for a security gate.
for tool in jq yq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "::error::required tool \`$tool\` not found on PATH"
    {
      echo "## Package denylist check"
      echo ""
      echo "**Result:** ❌ Configuration error — \`$tool\` not installed."
    } >> "$SUMMARY"
    exit 4
  fi
done

severity_icon() {
  case "$1" in
    critical) echo "🔴 critical" ;;
    high)     echo "🟠 high" ;;
    medium)   echo "🟡 medium" ;;
    low)      echo "🟢 low" ;;
    *)        echo "⚪ ${1:-unknown}" ;;
  esac
}

if [[ ! -f "$denylist" ]]; then
  echo "::error::deny-packages file not found: $denylist"
  {
    echo "## Package denylist check"
    echo ""
    echo "**Result:** ❌ Configuration error — \`$denylist\` not found."
  } >> "$SUMMARY"
  exit 3
fi

# Find lockfiles, skipping vendored copies in node_modules/.
npm_locks=()
while IFS= read -r f; do [[ -n "$f" ]] && npm_locks+=("$f"); done < <(find "$repo_dir" -type f -name 'package-lock.json' -not -path '*/node_modules/*' 2>/dev/null || true)
pnpm_locks=()
while IFS= read -r f; do [[ -n "$f" ]] && pnpm_locks+=("$f"); done < <(find "$repo_dir" -type f -name 'pnpm-lock.yaml' -not -path '*/node_modules/*' 2>/dev/null || true)

total_lockfiles=$(( ${#npm_locks[@]} + ${#pnpm_locks[@]} ))

if [[ "$total_lockfiles" -eq 0 ]]; then
  {
    echo "## Package denylist check"
    echo ""
    echo "**Result:** ✅ Skipped"
    echo ""
    echo "No \`package-lock.json\` or \`pnpm-lock.yaml\` found — nothing to scan."
  } >> "$SUMMARY"
  exit 0
fi

# Flatten denylist into records separated by the ASCII Unit Separator
# (\x1f, U+001F). We deliberately avoid `|` as a field separator because
# advisory URLs and reason strings can legitimately contain pipes, which
# would silently corrupt the row split downstream and let a denied
# package through. \x1f never appears in human-authored YAML.
# yq (mikefarah) doesn't take --arg like jq; the separator is inlined
# via shell expansion into the expression string.
SEP=$'\x1f'
denied_pairs="$(yq -r '
  .entries[]
  | select(.ecosystem == "npm")
  | . as $entry
  | (.bad_versions // [])[]
  | "\($entry.package)@\(.)" + "'"$SEP"'" + ($entry.reason // "")
    + "'"$SEP"'" + ($entry.severity // "")
    + "'"$SEP"'" + ($entry.advisory // "")
' "$denylist")"

denylist_count=$(yq -r '.entries | length' "$denylist")
denied_versions_count=$(printf '%s\n' "$denied_pairs" | grep -c '^' || true)

if [[ -z "$denied_pairs" ]]; then
  {
    echo "## Package denylist check"
    echo ""
    echo "**Result:** ✅ Skipped"
    echo ""
    echo "deny-packages.yaml has no npm entries — nothing to enforce."
  } >> "$SUMMARY"
  exit 0
fi

violations_file=$(mktemp)
installed_count=0

scan_npm_lock() {
  local lockfile="$1"
  local rel="${lockfile#"$repo_dir"/}"

  # Branch by lockfileVersion. v1 stores transitive deps NESTED under
  # `.dependencies.<name>.dependencies.<nested>` — flat top-level reads
  # miss transitive packages entirely and let denied SHAs through. v2/v3
  # flatten everything into `.packages` (keys like `node_modules/x/...`).
  #
  # We do NOT use `|| true` here — failure to parse a lockfile is a hard
  # error because silently scanning zero entries is a security bypass.
  local ver
  ver=$(jq -r '.lockfileVersion // 1' "$lockfile")

  local entries
  if [[ "$ver" == "1" ]]; then
    # v1: recursively walk every nested `.dependencies` map.
    entries=$(jq -r '
      def walk_deps:
        if type == "object" and (.dependencies | type) == "object" then
          (.dependencies | to_entries[] | "\(.key)\t\(.value.version // "")"),
          (.dependencies | to_entries[] | .value | walk_deps)
        else empty end;
      walk_deps
    ' "$lockfile")
  else
    # v2 / v3: `.packages` is already flat. Some entries (e.g. workspaces,
    # bundled deps) lack `.version` — drop those.
    entries=$(jq -r '
      .packages // {} | to_entries[]
      | select(.key != "")
      | "\(.value.name // (.key | sub("^.*node_modules/"; "")))\t\(.value.version // "")"
    ' "$lockfile")
  fi

  while IFS=$'\t' read -r name version; do
    [[ -z "$name" || -z "$version" ]] && continue
    installed_count=$((installed_count + 1))
    while IFS="$SEP" read -r denied reason severity advisory; do
      [[ -z "$denied" ]] && continue
      if [[ "${name}@${version}" == "$denied" ]]; then
        # `printf` so `$reason` / `$advisory` from YAML cannot trigger
        # command substitution (backticks, $(...) ) that `echo "..."`
        # would still expand even inside double quotes.
        printf '::error file=%s::DENIED npm package: %s — %s (severity: %s) — see %s\n' \
          "$rel" "${name}@${version}" "$reason" "$severity" "$advisory"
        printf '%s\t%s\t%s\t%s\t%s\n' "$rel" "${name}@${version}" "$severity" "$reason" "$advisory" >> "$violations_file"
      fi
    done <<< "$denied_pairs"
  done <<< "$entries"
}

scan_pnpm_lock() {
  local lockfile="$1"
  local rel="${lockfile#"$repo_dir"/}"
  # pnpm v6+: `packages:` map with keys like "/foo@1.2.3" or
  # "/@scope/foo@1.2.3(peer)". Strip the leading slash and any
  # (peer) suffix.
  #
  # We do NOT use `|| true` here — yq failure is a hard error because
  # silently scanning zero entries would be a security bypass.
  local entries
  entries="$(yq -r '
    .packages // {} | keys | .[]
    | sub("^/"; "")
    | sub("\\(.*\\)$"; "")
  ' "$lockfile")"

  while read -r spec; do
    [[ -z "$spec" ]] && continue
    installed_count=$((installed_count + 1))
    while IFS="$SEP" read -r denied reason severity advisory; do
      [[ -z "$denied" ]] && continue
      if [[ "$spec" == "$denied" ]]; then
        printf '::error file=%s::DENIED npm package: %s — %s (severity: %s) — see %s\n' \
          "$rel" "$spec" "$reason" "$severity" "$advisory"
        printf '%s\t%s\t%s\t%s\t%s\n' "$rel" "$spec" "$severity" "$reason" "$advisory" >> "$violations_file"
      fi
    done <<< "$denied_pairs"
  done <<< "$entries"
}

if [[ ${#npm_locks[@]}  -gt 0 ]]; then for f in "${npm_locks[@]}";  do scan_npm_lock  "$f"; done; fi
if [[ ${#pnpm_locks[@]} -gt 0 ]]; then for f in "${pnpm_locks[@]}"; do scan_pnpm_lock "$f"; done; fi

violations=$(wc -l < "$violations_file" | tr -d ' ')

{
  echo "## Package denylist check"
  echo ""
  if [[ "$violations" -gt 0 ]]; then
    echo "**Result:** ❌ Failed — $violations match(es) against deny-packages.yaml"
  else
    echo "**Result:** ✅ Passed"
  fi
  echo ""
  echo "| Lockfiles scanned | Installed entries | Denylist entries | Bad versions tracked |"
  echo "|---|---|---|---|"
  echo "| $total_lockfiles | $installed_count | $denylist_count | $denied_versions_count |"
  echo ""

  if [[ "$violations" -gt 0 ]]; then
    echo "### Compromised packages found"
    echo ""
    echo "| Lockfile | Package@Version | Severity | Reason | Advisory |"
    echo "|---|---|---|---|---|"
    while IFS=$'\t' read -r f pkg sev reason adv; do
      adv_link="—"
      [[ -n "$adv" ]] && adv_link="[link]($adv)"
      # Escape pipes so they don't break the markdown table layout.
      reason_md="${reason//|/\\|}"
      printf '| `%s` | `%s` | %s | %s | %s |\n' "$f" "$pkg" "$(severity_icon "$sev")" "$reason_md" "$adv_link"
    done < "$violations_file"
    echo ""
    echo "> To resolve: bump the affected package to a clean version (check the advisory for the patched release), then regenerate your lockfile."
    echo "> If you believe an entry is incorrect, open a PR on [huggingface/deny-actions-registry](https://github.com/huggingface/deny-actions-registry)."
  fi
} >> "$SUMMARY"

rm -f "$violations_file"

if [[ "$violations" -gt 0 ]]; then
  echo ""
  echo "Found $violations compromised package(s). PR is blocked."
  exit 1
fi

echo "✓ No compromised packages found."
