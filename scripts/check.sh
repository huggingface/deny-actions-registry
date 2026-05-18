#!/usr/bin/env bash
# Cross-checks `uses:` references in workflow files against denylist.yaml.
# Emits GitHub Actions error annotations + a Markdown job summary.
# Exits 1 on any match, 0 otherwise.
#
# Usage: check.sh <denylist.yaml> <workflows-dir>

set -euo pipefail

denylist="${1:?usage: check.sh <denylist.yaml> <workflows-dir>}"
workflows_dir="${2:?usage: check.sh <denylist.yaml> <workflows-dir>}"

# Anywhere we'd write to $GITHUB_STEP_SUMMARY, fall back to stdout when running
# outside GitHub Actions (local testing).
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

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
  echo "::error::denylist file not found: $denylist"
  {
    echo "## Denylist check"
    echo ""
    echo "**Result:** ❌ Configuration error"
    echo ""
    echo "Denylist file not found at \`$denylist\`."
  } >> "$SUMMARY"
  exit 3
fi

if [[ ! -d "$workflows_dir" ]]; then
  echo "No workflows directory at $workflows_dir — nothing to scan."
  {
    echo "## Denylist check"
    echo ""
    echo "**Result:** ✅ Skipped"
    echo ""
    echo "No \`.github/workflows/\` directory in the caller repo — nothing to scan."
  } >> "$SUMMARY"
  exit 0
fi

shopt -s nullglob
workflow_files=("$workflows_dir"/*.yml "$workflows_dir"/*.yaml)
if [[ ${#workflow_files[@]} -eq 0 ]]; then
  echo "No workflow files found — nothing to scan."
  {
    echo "## Denylist check"
    echo ""
    echo "**Result:** ✅ Skipped"
    echo ""
    echo "No workflow files in \`$workflows_dir\` — nothing to scan."
  } >> "$SUMMARY"
  exit 0
fi

# Build a flat list of denied "action@sha" pairs.
denied_pairs="$(yq -r '
  .entries[]
  | . as $entry
  | (.bad_shas // [])[]
  | "\($entry.action)@\(.)|\($entry.reason)|\($entry.severity)|\($entry.advisory)"
' "$denylist")"

denylist_count=$(yq -r '.entries | length' "$denylist")
denied_shas_count=$(printf '%s\n' "$denied_pairs" | grep -c '^' || true)

if [[ -z "$denied_pairs" ]]; then
  {
    echo "## Denylist check"
    echo ""
    echo "**Result:** ✅ Skipped"
    echo ""
    echo "Denylist has no entries with \`bad_shas\` — nothing to enforce."
  } >> "$SUMMARY"
  exit 0
fi

# Scan and collect violations into a tmp file (so we can build the table after).
violations_file=$(mktemp)
uses_count=0

for file in "${workflow_files[@]}"; do
  rel="${file#./}"
  while IFS=: read -r lineno match; do
    use="$(echo "$match" | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["'"'"']//; s/["'"'"']$//')"
    [[ "$use" == ./* || "$use" == docker://* || -z "$use" ]] && continue
    uses_count=$((uses_count + 1))

    while IFS='|' read -r denied reason severity advisory; do
      [[ -z "$denied" ]] && continue
      if [[ "$use" == "$denied" ]]; then
        echo "::error file=$file,line=$lineno::DENIED: $use — $reason (severity: $severity) — see $advisory"
        # tab-separated for the table builder
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$rel" "$lineno" "$use" "$severity" "$reason" "$advisory" >> "$violations_file"
      fi
    done <<< "$denied_pairs"
  done < <(grep -nE '^\s*-?\s*uses:\s*[^[:space:]]+' "$file" || true)
done

violations=$(wc -l < "$violations_file" | tr -d ' ')

# Build the job summary.
{
  echo "## Denylist check"
  echo ""
  if [[ "$violations" -gt 0 ]]; then
    echo "**Result:** ❌ Failed — $violations violation(s) found"
  else
    echo "**Result:** ✅ Passed"
  fi
  echo ""
  echo "| Workflows scanned | \`uses:\` references | Denylist entries | Bad SHAs tracked |"
  echo "|---|---|---|---|"
  echo "| ${#workflow_files[@]} | $uses_count | $denylist_count | $denied_shas_count |"
  echo ""

  if [[ "$violations" -gt 0 ]]; then
    echo "### Violations"
    echo ""
    echo "| File | Line | Action | Severity | Reason | Advisory |"
    echo "|---|---|---|---|---|---|"
    while IFS=$'\t' read -r f l u sev reason adv; do
      adv_link="—"
      [[ -n "$adv" ]] && adv_link="[link]($adv)"
      printf '| `%s` | %s | `%s` | %s | %s | %s |\n' "$f" "$l" "$u" "$(severity_icon "$sev")" "$reason" "$adv_link"
    done < "$violations_file"
    echo ""
    echo "> To resolve: update the action to a known-good SHA."
    echo "> If you believe this entry is incorrect, open a PR on [huggingface/deny-actions-registry](https://github.com/huggingface/deny-actions-registry)."
  fi
} >> "$SUMMARY"

rm -f "$violations_file"

if [[ "$violations" -gt 0 ]]; then
  echo ""
  echo "Found $violations denylist violation(s). PR is blocked."
  exit 1
fi

echo "✓ No denylist violations found."
