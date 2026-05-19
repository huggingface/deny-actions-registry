#!/usr/bin/env python3
"""scan-org.py — periodic org-wide security scan.

Iterates over every non-archived, non-fork repo in the org, runs the same
four checks as validate.yml against each repo's default branch, and
upserts one issue per affected repo in a central tracking repo.

Behavior matrix per repo:
  | violations? | existing open issue? | action                |
  |-------------|----------------------|------------------------|
  | none        | no                   | (nothing)             |
  | none        | yes                  | close it with comment |
  | some        | no                   | open a new issue      |
  | some        | yes                  | edit body in place    |

Required env vars:
  GH_TOKEN       PAT with contents:read on org + issues:write on TRACKING_REPO
  REGISTRY_DIR   path to a checkout of this repo (for scripts + YAML files)

Optional env vars:
  ORG            default: huggingface
  TRACKING_REPO  default: huggingface/tracking-issues
  CONCURRENCY    default: 8
  EXCLUDE_REPOS  comma-separated list of repos to skip (full names)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ORG            = os.environ.get("ORG", "huggingface")
TRACKING_REPO  = os.environ.get("TRACKING_REPO", "huggingface/tracking-issues")
GH_TOKEN       = os.environ.get("GH_TOKEN", "")
REGISTRY_DIR   = os.environ.get("REGISTRY_DIR", "")
CONCURRENCY    = int(os.environ.get("CONCURRENCY", "8"))
EXCLUDE_REPOS  = set(filter(None, os.environ.get("EXCLUDE_REPOS", "").split(",")))

ISSUE_PREFIX = "[security-scan]"
GH_ENV       = {**os.environ, "GH_TOKEN": GH_TOKEN}

if not GH_TOKEN:
    sys.exit("GH_TOKEN is required")
if not REGISTRY_DIR or not Path(REGISTRY_DIR).is_dir():
    sys.exit(f"REGISTRY_DIR not found: {REGISTRY_DIR}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run(cmd, **kw):
    """Run a command, return CompletedProcess. Never raises."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def gh_json(args):
    """Run `gh <args>` and parse the JSON output. Returns None on error."""
    r = run(["gh", *args], env=GH_ENV)
    if r.returncode != 0:
        sys.stderr.write(f"gh {' '.join(args)} -> {r.returncode}\n{r.stderr}\n")
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# list repos
# ---------------------------------------------------------------------------

def list_target_repos():
    """All non-archived, non-fork repos in the org with a default branch."""
    repos = gh_json([
        "repo", "list", ORG,
        "--limit", "1000",
        "--no-archived",
        "--source",  # excludes forks
        "--json", "name,nameWithOwner,defaultBranchRef,isPrivate,visibility",
    ])
    if repos is None:
        sys.exit("Failed to list repos — check PAT permissions.")
    out = []
    for r in repos:
        if not r.get("defaultBranchRef"):  # empty repo
            continue
        if r["nameWithOwner"] in EXCLUDE_REPOS:
            continue
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# scan one repo
# ---------------------------------------------------------------------------

def scan_repo(repo):
    """Clone shallow + run the four checks. Return dict of failing checks."""
    name = repo["nameWithOwner"]
    branch = repo["defaultBranchRef"]["name"]
    workdir = Path(tempfile.mkdtemp(prefix=f"scan-{repo['name']}-"))
    target = workdir / "checkout"

    try:
        url = f"https://x-access-token:{GH_TOKEN}@github.com/{name}.git"
        r = run(["git", "clone", "--depth=1", "--quiet", "-b", branch, url, str(target)])
        if r.returncode != 0:
            return {"_error": f"clone failed: {r.stderr.strip()[:300]}"}

        results = {}

        # Job 1: pinact (only if there are workflows)
        wf_dir = target / ".github" / "workflows"
        if wf_dir.is_dir() and any(wf_dir.iterdir()):
            r = run(["pinact", "run", "--check"], cwd=target, env=GH_ENV)
            if r.returncode != 0:
                results["pinact"] = (r.stdout + r.stderr).strip()

        # Job 2: action denylist
        if wf_dir.is_dir():
            summary = workdir / "denylist.md"
            env = {**GH_ENV, "GITHUB_STEP_SUMMARY": str(summary)}
            r = run([
                "bash", str(Path(REGISTRY_DIR) / "scripts" / "check.sh"),
                str(Path(REGISTRY_DIR) / "denylist.yaml"),
                str(wf_dir),
            ], env=env)
            if r.returncode != 0 and summary.exists():
                results["denylist"] = summary.read_text()

        # Job 3: package denylist
        summary = workdir / "packages.md"
        env = {**GH_ENV, "GITHUB_STEP_SUMMARY": str(summary)}
        r = run([
            "bash", str(Path(REGISTRY_DIR) / "scripts" / "check-packages.sh"),
            str(Path(REGISTRY_DIR) / "deny-packages.yaml"),
            str(target),
        ], env=env)
        if r.returncode != 0 and summary.exists():
            results["deny_packages"] = summary.read_text()

        # Job 4: osv-scanner
        r = run(
            ["osv-scanner", "scan", "source", "--recursive", "--format=table", "."],
            cwd=target,
        )
        # 0 = clean, 1 = vulns found, 128 = no supported files
        if r.returncode == 1:
            results["osv"] = r.stdout.strip()

        return results
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# render issue body
# ---------------------------------------------------------------------------

CHECK_LABELS = {
    "pinact":        "Action pinning (pinact)",
    "denylist":      "Action denylist",
    "deny_packages": "Package denylist (npm)",
    "osv":           "OSV scan (CVEs + malware)",
}


def render_issue_body(repo, results):
    name = repo["nameWithOwner"]
    branch = repo["defaultBranchRef"]["name"]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if "_error" in results:
        return textwrap.dedent(f"""\
            ## Security scan — `{name}`

            **Last scanned:** {ts}
            **Status:** ⚠️ Scan error — `{results['_error']}`

            _Generated by [scan-org.py](https://github.com/huggingface/deny-actions-registry/blob/main/scripts/scan-org.py)._
            """)

    lines = []
    lines.append(f"## Security scan — `{name}`")
    lines.append("")
    lines.append(f"**Last scanned:** {ts}")
    lines.append(f"**Branch:** `{branch}`")
    lines.append(f"**Failing checks:** {len(results)}")
    lines.append("")
    lines.append("| Check | Status |")
    lines.append("|---|---|")
    for key, label in CHECK_LABELS.items():
        status = "❌ violations" if key in results else "✅"
        lines.append(f"| {label} | {status} |")
    lines.append("")

    for key, label in CHECK_LABELS.items():
        if key not in results:
            continue
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"<details><summary>Details</summary>")
        lines.append("")
        body = results[key].strip()
        # If it already looks like markdown, keep it; otherwise wrap as code.
        if body.startswith("##") or body.startswith("| "):
            lines.append(body)
        else:
            lines.append("```")
            lines.append(body)
            lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("### How to fix")
    lines.append("")
    lines.append(f"1. Open a PR on `{name}` that addresses the violations above.")
    lines.append(f"2. The `validate.yml` workflow re-checks on PR.")
    lines.append(f"3. This issue auto-closes on the next scan once all checks pass.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Generated by "
                 "[scan-org.py](https://github.com/huggingface/deny-actions-registry/blob/main/scripts/scan-org.py)._")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# upsert issue in TRACKING_REPO
# ---------------------------------------------------------------------------

def find_existing_issue(target_repo_name):
    """Find an open issue in TRACKING_REPO whose title matches the prefix+repo."""
    title = f"{ISSUE_PREFIX} {target_repo_name}"
    issues = gh_json([
        "issue", "list",
        "--repo", TRACKING_REPO,
        "--state", "open",
        "--search", f"in:title \"{title}\"",
        "--json", "number,title",
        "--limit", "5",
    ])
    if not issues:
        return None
    for i in issues:
        if i["title"] == title:
            return i["number"]
    return None


def upsert_issue(repo, results):
    name = repo["nameWithOwner"]
    title = f"{ISSUE_PREFIX} {name}"
    body = render_issue_body(repo, results)
    existing = find_existing_issue(name)

    if not results:
        # nothing to report
        if existing:
            run(["gh", "issue", "comment", str(existing),
                 "--repo", TRACKING_REPO,
                 "--body", f"✓ All checks passing on `{name}` as of latest scan. Closing."],
                env=GH_ENV)
            run(["gh", "issue", "close", str(existing),
                 "--repo", TRACKING_REPO,
                 "--reason", "completed"], env=GH_ENV)
            return "closed"
        return "clean"

    if existing:
        run(["gh", "issue", "edit", str(existing),
             "--repo", TRACKING_REPO,
             "--body", body], env=GH_ENV)
        return f"updated #{existing}"
    else:
        r = run(["gh", "issue", "create",
                 "--repo", TRACKING_REPO,
                 "--title", title,
                 "--body", body,
                 "--label", "security-scan"], env=GH_ENV)
        if r.returncode != 0:
            # Most likely the label doesn't exist — retry without it.
            r = run(["gh", "issue", "create",
                     "--repo", TRACKING_REPO,
                     "--title", title,
                     "--body", body], env=GH_ENV)
        return "created" if r.returncode == 0 else f"create-failed: {r.stderr.strip()[:200]}"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def process_repo(repo):
    name = repo["nameWithOwner"]
    try:
        results = scan_repo(repo)
    except Exception as e:
        results = {"_error": f"unhandled exception: {e}"}
    action = upsert_issue(repo, results)
    return name, action, results


def main():
    repos = list_target_repos()
    print(f"Scanning {len(repos)} repos in {ORG} (concurrency={CONCURRENCY})…")

    n_clean = n_dirty = n_error = n_closed = 0
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = {ex.submit(process_repo, r): r for r in repos}
        for fut in as_completed(futures):
            try:
                name, action, results = fut.result()
            except Exception as e:
                sys.stderr.write(f"worker crashed: {e}\n")
                continue
            tag = "✓" if action in ("clean",) else ("→" if action == "closed" else "✗")
            print(f"  {tag} {name}: {action}")
            if action == "clean":
                n_clean += 1
            elif action == "closed":
                n_closed += 1
            elif "_error" in results:
                n_error += 1
            else:
                n_dirty += 1

    print()
    print(f"Done. {n_clean} clean / {n_dirty} dirty / {n_closed} closed / {n_error} errors.")
    # exit 0 even if violations were found — the issues ARE the report.


if __name__ == "__main__":
    main()
