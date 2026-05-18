#!/usr/bin/env bash
# Cross-checks `uses:` references in workflow files against denylist.yaml.
# Emits GitHub Actions error annotations and exits 1 on any match.
#
# Usage: check.sh <denylist.yaml> <workflows-dir>

set -euo pipefail

denylist="${1:?usage: check.sh <denylist.yaml> <workflows-dir>}"
workflows_dir="${2:?usage: check.sh <denylist.yaml> <workflows-dir>}"

if [[ ! -f "$denylist" ]]; then
  echo "::error::denylist file not found: $denylist"
  exit 3
fi

if [[ ! -d "$workflows_dir" ]]; then
  echo "No workflows directory at $workflows_dir — nothing to scan."
  exit 0
fi

shopt -s nullglob
workflow_files=("$workflows_dir"/*.yml "$workflows_dir"/*.yaml)
if [[ ${#workflow_files[@]} -eq 0 ]]; then
  echo "No workflow files found — nothing to scan."
  exit 0
fi

# Build a flat list of denied "action@sha" pairs.
denied_pairs="$(yq -r '
  .entries[]
  | . as $entry
  | (.bad_shas // [])[]
  | "\($entry.action)@\(.)|\($entry.reason)|\($entry.severity)|\($entry.advisory)"
' "$denylist")"

if [[ -z "$denied_pairs" ]]; then
  echo "Denylist is empty — nothing to check."
  exit 0
fi

violations=0

for file in "${workflow_files[@]}"; do
  # Extract every `uses: owner/repo@ref` with its line number.
  # Skip local actions (./...) and docker:// references.
  while IFS=: read -r lineno match; do
    use="$(echo "$match" | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["'"'"']//; s/["'"'"']$//')"
    [[ "$use" == ./* || "$use" == docker://* || -z "$use" ]] && continue

    while IFS='|' read -r denied reason severity advisory; do
      if [[ "$use" == "$denied" ]]; then
        echo "::error file=$file,line=$lineno::DENIED action: $use — $reason (severity: $severity) — see $advisory"
        violations=$((violations + 1))
      fi
    done <<< "$denied_pairs"
  done < <(grep -nE '^\s*-?\s*uses:\s*[^[:space:]]+' "$file" || true)
done

if [[ $violations -gt 0 ]]; then
  echo ""
  echo "::error::Found $violations denylist violation(s). PR is blocked."
  echo "To resolve: update the action to a known-good SHA, or open an issue on huggingface/deny-actions-registry."
  exit 1
fi

echo "✓ No denylist violations found."
