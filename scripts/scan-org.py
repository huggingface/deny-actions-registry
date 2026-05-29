#!/usr/bin/env python3
"""
Daily org-wide scan for unpinned / denylisted GitHub Actions.

For each non-archived, non-fork repo in the target org (all visibilities —
public, private and internal):
  1. Fetch every file under `.github/workflows/` via the GitHub API.
  2. Run `pinact run --check` on the downloaded files to find unpinned actions.
  3. Cross-check every `uses: action@sha` reference against the denylist's
     `bad_shas` entries.

Violations are reported as one tracking issue per repo in the target
tracking repo (default: huggingface/tracking-issues), with a stable title
prefix so subsequent runs update / close the same issue idempotently:
  - new violation       → create issue
  - still violating     → update issue body
  - no longer violating → close issue with a "✅ resolved" comment

Auth:
  - GH_TOKEN env var with: contents:read on the target org's repos and
    issues:write on the tracking repo. In CI this is the token minted by
    actions/create-github-app-token from a dedicated GitHub App.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ISSUE_TITLE_PREFIX = "[deny-actions scan]"
API_ROOT = "https://api.github.com"
PINACT_OUTPUT_ANN = re.compile(
    r"^::error file=([^,]+),line=(\d+),title=pinact error::(.*)$"
)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)


def gh_api(token: str, method: str, path: str, body: dict | None = None,
           accept: str = "application/vnd.github+json"):
    url = path if path.startswith("http") else f"{API_ROOT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", accept)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            text = resp.read()
            link = resp.headers.get("Link", "")
            if accept == "application/vnd.github.raw":
                return text, link
            return (json.loads(text) if text else None), link
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"[api] {method} {path} -> {e.code} {e.reason}\n")
        if e.code == 404:
            return None, ""
        body_text = e.read().decode(errors="replace")
        sys.stderr.write(body_text[:500] + "\n")
        return None, ""


def parse_next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        if 'rel="next"' in part:
            m = re.search(r"<([^>]+)>", part)
            if m:
                return m.group(1)
    return None


def list_org_repos(token: str, org: str) -> list[dict]:
    """Non-archived, non-fork repos in the org, all visibilities
    (public + private + internal). `type=all` returns every repo the
    authenticated token can see — for the scanner App that is all repos
    it is installed on."""
    repos = []
    url = f"{API_ROOT}/orgs/{org}/repos?type=all&per_page=100"
    while url:
        page, link = gh_api(token, "GET", url)
        if page is None:
            break
        for r in page:
            if r.get("archived") or r.get("fork") or r.get("disabled"):
                continue
            repos.append({
                "full_name": r["full_name"],
                "name": r["name"],
                "visibility": r.get("visibility", "public"),
            })
        url = parse_next_link(link)
    return repos


def list_workflow_files(token: str, repo_full_name: str) -> list[dict]:
    """List files under .github/workflows/ (top-level only — GitHub Actions
    does not recurse anyway)."""
    page, _ = gh_api(token, "GET",
                     f"/repos/{repo_full_name}/contents/.github/workflows")
    if not page or not isinstance(page, list):
        return []
    return [f for f in page
            if f.get("type") == "file"
            and (f["name"].endswith(".yml") or f["name"].endswith(".yaml"))]


def download_file(token: str, repo_full_name: str, path: str, dest: Path) -> bool:
    raw, _ = gh_api(token, "GET",
                    f"/repos/{repo_full_name}/contents/{path}",
                    accept="application/vnd.github.raw")
    if raw is None:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    return True


def run_pinact(workdir: Path) -> tuple[int, str]:
    """Run `pinact run --check` in workdir. Returns (exit_code, combined_output)."""
    proc = subprocess.run(
        ["pinact", "run", "--check"],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def parse_pinact_output(text: str) -> list[dict]:
    """Return one dict per unpinned-action violation."""
    text = ANSI.sub("", text)
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = PINACT_OUTPUT_ANN.match(lines[i])
        if not m:
            i += 1
            continue
        fpath, ln, msg = m.group(1), int(m.group(2)), m.group(3).strip()
        current = suggested = None
        for j in range(i + 1, min(i + 6, len(lines))):
            s = lines[j].rstrip()
            if s.startswith("-") and "uses:" in s:
                current = s[1:].strip()
            elif s.startswith("+") and "uses:" in s:
                suggested = s[1:].strip()
                break
        out.append({
            "file": fpath,
            "line": ln,
            "current": current,
            "suggested": suggested,
            "message": msg,
        })
        i += 1
    return out


def load_denylist(path: Path) -> list[dict]:
    """Return a flat list of {action, sha, reason, severity, advisory}."""
    import yaml  # PyYAML is installed in the GitHub runner image
    data = yaml.safe_load(path.read_text())
    flat = []
    for entry in data.get("entries", []):
        action = entry["action"]
        for sha in entry.get("bad_shas", []) or []:
            flat.append({
                "action": action,
                "sha": sha,
                "reason": entry.get("reason", ""),
                "severity": entry.get("severity", ""),
                "advisory": entry.get("advisory", ""),
            })
    return flat


def scan_denylist(workdir: Path, denylist: list[dict]) -> list[dict]:
    """Scan every workflow file for `uses: action@sha` and flag denylisted ones."""
    denied_pairs = {(d["action"], d["sha"]): d for d in denylist}
    if not denied_pairs:
        return []
    out = []
    workflows_dir = workdir / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    for f in sorted(workflows_dir.iterdir()):
        if f.suffix not in (".yml", ".yaml"):
            continue
        for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            m = USES_RE.match(line)
            if not m:
                continue
            ref = m.group(1).strip().strip("'\"").split("#")[0].strip()
            if "@" not in ref:
                continue
            action, _, sha = ref.partition("@")
            key = (action, sha)
            if key in denied_pairs:
                d = denied_pairs[key]
                out.append({
                    "file": f"{workflows_dir.name}/{f.name}",
                    "line": i,
                    "ref": ref,
                    **d,
                })
    return out


def scan_repo(token: str, repo: dict, denylist: list[dict],
              workroot: Path) -> dict:
    files = list_workflow_files(token, repo["full_name"])
    if not files:
        return {"pinact": [], "denylist": [], "n_workflows": 0}
    workdir = workroot / repo["name"]
    for f in files:
        download_file(token, repo["full_name"], f["path"],
                      workdir / ".github" / "workflows" / f["name"])
    code, output = run_pinact(workdir)
    pinact_violations = parse_pinact_output(output) if code != 0 else []
    denylist_violations = scan_denylist(workdir, denylist)
    return {
        "pinact": pinact_violations,
        "denylist": denylist_violations,
        "n_workflows": len(files),
    }


def build_issue_body(repo_full_name: str, result: dict) -> str:
    lines = [
        f"<!-- managed-by: deny-actions-scan -->",
        f"Daily deny-actions scan flagged violations in **{repo_full_name}**.",
        "",
        f"- Workflows scanned: {result['n_workflows']}",
        f"- Unpinned actions: {len(result['pinact'])}",
        f"- Denylisted SHAs: {len(result['denylist'])}",
        "",
    ]
    if result["denylist"]:
        lines += ["## Denylisted SHAs (CRITICAL)", "",
                  "| File | Line | Reference | Severity | Reason | Advisory |",
                  "|---|---|---|---|---|---|"]
        for v in result["denylist"]:
            adv = f"[link]({v['advisory']})" if v.get("advisory") else "—"
            lines.append(
                f"| `{v['file']}` | {v['line']} | `{v['ref']}` | "
                f"{v.get('severity', '')} | {v.get('reason', '')} | {adv} |"
            )
        lines.append("")
    if result["pinact"]:
        lines += ["## Unpinned actions", "",
                  "| File | Line | Current | Suggested SHA |",
                  "|---|---|---|---|"]
        for v in result["pinact"]:
            cur = (v["current"] or "").replace("uses: ", "")
            sug = (v["suggested"] or "—").replace("uses: ", "")
            lines.append(f"| `{v['file']}` | {v['line']} | `{cur}` | `{sug}` |")
        lines.append("")
        lines.append("> Fix locally: `pinact run` in the repo root, then commit.")
        lines.append("")
    lines.append(
        f"_Source: huggingface/deny-actions-registry — re-runs daily, "
        f"this issue is updated or closed automatically._"
    )
    return "\n".join(lines)


def issue_title(repo_full_name: str) -> str:
    return f"{ISSUE_TITLE_PREFIX} {repo_full_name}"


def find_existing_issue(token: str, tracking_repo: str,
                        repo_full_name: str) -> dict | None:
    q = f'repo:{tracking_repo} is:issue is:open in:title "{issue_title(repo_full_name)}"'
    page, _ = gh_api(token, "GET",
                     f"/search/issues?q={urllib.parse.quote(q)}&per_page=5")
    if not page:
        return None
    for item in page.get("items", []):
        if item.get("title") == issue_title(repo_full_name):
            return item
    return None


def upsert_issue(token: str, tracking_repo: str, repo_full_name: str,
                 result: dict, dry_run: bool):
    existing = find_existing_issue(token, tracking_repo, repo_full_name)
    has_violations = bool(result["pinact"] or result["denylist"])

    if has_violations:
        body = build_issue_body(repo_full_name, result)
        if existing:
            if dry_run:
                print(f"  [DRY] would UPDATE #{existing['number']}")
                return
            gh_api(token, "PATCH",
                   f"/repos/{tracking_repo}/issues/{existing['number']}",
                   {"body": body})
            print(f"  ↻ updated tracking issue #{existing['number']}")
        else:
            if dry_run:
                print(f"  [DRY] would CREATE issue for {repo_full_name}")
                return
            created, _ = gh_api(token, "POST",
                                f"/repos/{tracking_repo}/issues",
                                {"title": issue_title(repo_full_name),
                                 "body": body,
                                 "labels": ["security", "deny-actions-scan"]})
            if created:
                print(f"  + created tracking issue #{created.get('number')}")
    else:
        if existing:
            if dry_run:
                print(f"  [DRY] would CLOSE #{existing['number']} (resolved)")
                return
            gh_api(token, "POST",
                   f"/repos/{tracking_repo}/issues/{existing['number']}/comments",
                   {"body": "✅ Resolved — no violations in latest scan."})
            gh_api(token, "PATCH",
                   f"/repos/{tracking_repo}/issues/{existing['number']}",
                   {"state": "closed", "state_reason": "completed"})
            print(f"  ✓ closed tracking issue #{existing['number']} (resolved)")


def append_summary(text: str):
    sm = os.environ.get("GITHUB_STEP_SUMMARY")
    if sm:
        with open(sm, "a") as fh:
            fh.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--denylist", required=True, type=Path)
    ap.add_argument("--tracking-repo", required=True,
                    help="owner/repo where tracking issues are filed")
    ap.add_argument("--max-repos", type=int, default=0,
                    help="Limit number of repos scanned (0 = no limit, for testing)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Don't create/update/close issues, just print")
    args = ap.parse_args()

    token = os.environ.get("GH_TOKEN", "")
    if not token:
        sys.exit("GH_TOKEN env var required")

    denylist = load_denylist(args.denylist)
    print(f"Denylist: {len(denylist)} denied SHAs across "
          f"{len({d['action'] for d in denylist})} actions")

    repos = list_org_repos(token, args.org)
    if args.max_repos:
        repos = repos[:args.max_repos]
    print(f"Scanning {len(repos)} repos in {args.org}/")

    summary_rows = []
    violating = 0
    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        workroot = Path(tmp)
        for i, repo in enumerate(repos, 1):
            print(f"[{i}/{len(repos)}] {repo['full_name']}")
            try:
                result = scan_repo(token, repo, denylist, workroot)
            except Exception as e:
                print(f"  ⚠ scan failed: {e}")
                continue
            n_pin = len(result["pinact"])
            n_deny = len(result["denylist"])
            if n_pin or n_deny:
                violating += 1
                print(f"  ✗ {n_pin} unpinned, {n_deny} denylisted")
                summary_rows.append(
                    f"| [{repo['full_name']}](https://github.com/{repo['full_name']}) "
                    f"| {result['n_workflows']} | {n_pin} | {n_deny} |"
                )
            upsert_issue(token, args.tracking_repo, repo["full_name"],
                         result, args.dry_run)

    elapsed = time.time() - started
    print(f"\nDone. {violating}/{len(repos)} repos violating. Elapsed: {elapsed:.0f}s")

    summary = [
        "## Daily deny-actions scan",
        "",
        f"- Org: `{args.org}`",
        f"- Repos scanned: {len(repos)}",
        f"- Repos with violations: {violating}",
        f"- Duration: {elapsed:.0f}s",
        "",
    ]
    if summary_rows:
        summary += [
            "### Violating repos",
            "",
            "| Repo | Workflows | Unpinned | Denylisted |",
            "|---|---|---|---|",
            *summary_rows,
            "",
        ]
    else:
        summary.append("✅ No violations found.")
    append_summary("\n".join(summary) + "\n")


if __name__ == "__main__":
    main()
