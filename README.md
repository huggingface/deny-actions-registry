# deny-actions-registry

Org-wide denylist of GitHub Actions versions that must never run in
`huggingface/*` workflows, plus a reusable validation workflow
enforced via an Organization Ruleset.

## What this protects against

Three classes of risk on every PR / push to `main`:

1. **Non-pinned actions** — `uses: foo/bar@v1` (mutable tag) is rejected.
   Only 40-char commit SHAs are accepted. Enforced by [pinact].
2. **Comment / SHA mismatch** — `uses: foo/bar@<sha>  # v1.2.3` where
   the comment lies about the version is rejected.
3. **Known-compromised SHAs** — anything listed in `denylist.yaml`
   (CVE-2025-30066 tj-actions, reviewdog supply-chain, etc.) is rejected.

[pinact]: https://github.com/suzuki-shunsuke/pinact

## How it's wired

```
Org Ruleset (Required workflow)
       │
       ▼
deny-actions-registry/.github/workflows/validate.yml
       │
       ├──► pinact --check          (pin + min_age + comment verify)
       └──► scripts/check.sh        (denylist scan)
```

Every repo in scope inherits the check automatically — no per-repo file
to maintain.

## Files

| Path | Purpose |
|---|---|
| `denylist.yaml`              | Source of truth for blocked SHAs |
| `.github/workflows/validate.yml`     | Reusable workflow called by the org ruleset |
| `.github/workflows/advisory-sync.yml`| (TODO) Cron that auto-PRs new advisories |
| `scripts/check.sh`           | Parses workflows + cross-checks denylist |
| `.pinact.yaml`               | Self-pinning config for this repo |
| `.github/CODEOWNERS`         | Required reviewers for denylist edits |

## Adding an entry

Open a PR editing `denylist.yaml`:

```yaml
- action: owner/repo
  bad_shas:
    - <40-char SHA>
  bad_versions:
    - v1.2.3
  reason: "Short description of the incident"
  advisory: https://github.com/advisories/GHSA-...
  severity: critical
  added: YYYY-MM-DD
  added_by: you@huggingface.co
```

CODEOWNERS will request review automatically.

## Adding a repo to the protection scope

Done via Organization Ruleset (preferred) — see
`Organization Settings → Repository → Rulesets → New ruleset`,
type *Branch*, target *all repositories* (or filtered by custom
property), rule *Require workflows to pass*, pointing to:

```
huggingface/deny-actions-registry/.github/workflows/validate.yml@<sha>
```

## Caller-side usage

While the org ruleset is the production path, repos can also call the
workflow directly:

```yaml
jobs:
  security:
    uses: huggingface/deny-actions-registry/.github/workflows/validate.yml@<sha>
```

## Visibility

This repo is **internal**. Keeping the denylist non-public avoids signaling
to attackers which SHAs are being monitored.
