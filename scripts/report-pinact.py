#!/usr/bin/env python3
"""
Parse pinact --check output and:
  1. Render a GitHub Actions job summary (Markdown).
  2. For fork PRs only, post a PR review with `Apply suggestion` blocks for
     each auto-fixable violation. (Same-repo PRs get an auto-pin commit
     pushed by the calling workflow before this script runs.)

Environment variables (all optional; missing ones disable features gracefully):
  PINACT_OUTPUT     path to the captured pinact stdout (default: /tmp/pinact.out)
  PINACT_EXITCODE   pinact's exit code as a string
  CALLER_DIR        directory containing the caller repo (default: caller)
  AUTOFIX_PUSHED    "true" if an auto-pin commit was just pushed
  GH_TOKEN          GITHUB_TOKEN with pull-requests:write
  GH_REPO           "owner/repo" of the PR
  PR_NUMBER         PR number (as string); empty means "not a PR"
  PR_HEAD_SHA       head commit SHA of the PR
  PR_HEAD_REPO      "owner/repo" of the PR head (different if from a fork)
"""

import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict

ANSI = re.compile(r"\x1b\[[0-9;]*m")
ANN  = re.compile(r"^::error file=([^,]+),line=(\d+),title=pinact error::(.*)$")

PINACT_OUTPUT   = os.environ.get("PINACT_OUTPUT", "/tmp/pinact.out")
PINACT_EXITCODE = os.environ.get("PINACT_EXITCODE", "0")
CALLER_DIR      = os.environ.get("CALLER_DIR", "caller")
AUTOFIX_PUSHED  = os.environ.get("AUTOFIX_PUSHED", "") == "true"
GH_TOKEN        = os.environ.get("GH_TOKEN", "")
GH_REPO         = os.environ.get("GH_REPO", "")
PR_NUMBER       = os.environ.get("PR_NUMBER", "")
PR_HEAD_SHA     = os.environ.get("PR_HEAD_SHA", "")
PR_HEAD_REPO    = os.environ.get("PR_HEAD_REPO", "")
SUMMARY_FILE    = os.environ.get("GITHUB_STEP_SUMMARY", "/dev/stdout")
IS_FORK         = bool(PR_HEAD_REPO and PR_HEAD_REPO != GH_REPO)


def parse_pinact_output(text: str):
    """Return (fixable, unfixable) dicts: file -> list of violations."""
    text = ANSI.sub("", text)
    fixable   = defaultdict(list)  # file -> [(line, current, suggested, indent)]
    unfixable = defaultdict(list)  # file -> [(line, message, snippet)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = ANN.match(lines[i])
        if not m:
            i += 1
            continue
        fpath, ln, content = m.group(1), int(m.group(2)), m.group(3).strip()
        current = suggested = None
        for j in range(i + 1, min(i + 6, len(lines))):
            s = lines[j].rstrip()
            if s.startswith("-") and "uses:" in s:
                current = s[1:]  # keep leading whitespace
            elif s.startswith("+") and "uses:" in s:
                suggested = s[1:]
                break
        if current is not None and suggested is not None:
            fixable[fpath].append((ln, current, suggested))
        else:
            snippet = ""
            for j in range(i + 1, min(i + 6, len(lines))):
                s = lines[j].strip()
                if "uses:" in s:
                    snippet = s
                    break
            unfixable[fpath].append((ln, content, snippet))
        i += 1
    return fixable, unfixable


def count_workflows_and_uses(caller_dir: str):
    base = os.path.join(caller_dir, ".github", "workflows")
    files = glob.glob(os.path.join(base, "*.yml")) + glob.glob(os.path.join(base, "*.yaml"))
    n_uses = 0
    for p in files:
        with open(p) as f:
            for line in f:
                if re.match(r"^\s*-?\s*uses:\s*\S", line):
                    n_uses += 1
    return len(files), n_uses


def short_sha(use: str) -> str:
    return re.sub(r"@([0-9a-f]{40})", lambda m: "@" + m.group(1)[:10] + "…", use)


def write_summary(fixable, unfixable, n_files, n_uses, ec):
    total_fix   = sum(len(v) for v in fixable.values())
    total_unfix = sum(len(v) for v in unfixable.values())
    total       = total_fix + total_unfix

    with open(SUMMARY_FILE, "a") as sm:
        def w(s=""):
            sm.write(s + "\n")

        w("## Pinact — pin check")
        w()
        if ec == "0":
            w("**Result:** ✅ Passed")
        else:
            w(f"**Result:** ❌ Failed — {total} violation(s) across "
              f"{len(fixable) + len(unfixable)} file(s)")
        w()
        w("| Workflows scanned | `uses:` references | Auto-fixable | Need manual fix |")
        w("|---|---|---|---|")
        w(f"| {n_files} | {n_uses} | {total_fix} | {total_unfix} |")
        w()

        if AUTOFIX_PUSHED:
            w("> 🤖 **Auto-pinned and pushed a fix commit** to this PR's branch. "
              "GitHub does not re-trigger workflows on bot-pushed commits — "
              "click **Re-run all jobs** above (or push any other commit) to "
              "re-validate.")
            w()

        if fixable:
            if AUTOFIX_PUSHED:
                heading = "### Auto-fixed in the just-pushed commit"
                intro   = "The bot pinned these to their SHAs in a follow-up commit."
            elif IS_FORK:
                heading = "### Auto-fixable (suggestions posted as PR review)"
                intro   = ("This PR comes from a fork, so the bot cannot push a "
                           "fix commit. Apply the inline suggestions instead, or "
                           "run `pinact run` locally.")
            else:
                heading = "### Auto-fixable"
                intro   = ("Run `pinact run` locally and commit, or re-run "
                           "this workflow to let the bot push a fix.")
            w(heading)
            w()
            w(intro)
            w()
            for fpath in sorted(fixable):
                w(f"#### `{fpath}`")
                w()
                w("| Line | Current | Suggested |")
                w("|---|---|---|")
                for ln, cur, sug in fixable[fpath]:
                    cur_disp = cur.strip().replace("uses: ", "")
                    sug_disp = short_sha(sug.strip().replace("uses: ", ""))
                    w(f"| {ln} | `{cur_disp}` | `{sug_disp}` |")
                w()

        if unfixable:
            w("### Need manual fix")
            w()
            w("Pinact cannot resolve these automatically (invalid SHA "
              "reference, `@latest`, etc.). Edit the workflow by hand.")
            w()
            for fpath in sorted(unfixable):
                w(f"#### `{fpath}`")
                w()
                w("| Line | Reference | Problem |")
                w("|---|---|---|")
                for ln, msg, snip in unfixable[fpath]:
                    ref = snip.replace("uses: ", "") if snip else "—"
                    w(f"| {ln} | `{ref}` | {msg} |")
                w()


def gh_api(method: str, path: str, body: dict | None = None):
    url = f"https://api.github.com{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {GH_TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"[gh_api] {method} {path} -> {e.code} {e.reason}\n")
        sys.stderr.write(e.read().decode(errors="replace") + "\n")
        return None


def fetch_pr_commentable_lines() -> dict[str, set[int]]:
    """Return {filename: {line_numbers_in_diff_RIGHT_side}}.

    GitHub PR review API only accepts inline comments on lines that are
    part of the PR's diff hunks (added or context lines on the new file).
    Any other (path, line) returns 422 Unprocessable Entity.
    """
    commentable: dict[str, set[int]] = {}
    page = 1
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    while True:
        files = gh_api("GET", f"/repos/{GH_REPO}/pulls/{PR_NUMBER}/files?per_page=100&page={page}")
        if not files:
            break
        for f in files:
            path = f["filename"]
            patch = f.get("patch") or ""
            lines: set[int] = commentable.setdefault(path, set())
            cur = 0
            for ln in patch.split("\n"):
                m = hunk_re.match(ln)
                if m:
                    cur = int(m.group(1))
                    continue
                if not ln:
                    continue
                first = ln[0]
                if first == "+" and not ln.startswith("+++"):
                    lines.add(cur)
                    cur += 1
                elif first == " ":
                    lines.add(cur)
                    cur += 1
                elif first == "-":
                    pass  # removed, doesn't advance new-file cursor
        if len(files) < 100:
            break
        page += 1
    return commentable


def post_pr_suggestions(fixable, unfixable):
    """Post one PR review with inline suggestions for fixable violations.

    Only runs on fork PRs — same-repo PRs are handled by the workflow's
    auto-pin commit step before this script runs. Violations on files/lines
    outside the PR diff cannot be commented inline (GitHub API limitation)
    — those are reported in the review body instead.
    """
    if not PR_NUMBER or not GH_TOKEN or not GH_REPO or not PR_HEAD_SHA:
        sys.stderr.write("[suggestions] not a PR context, skipping.\n")
        return
    if not IS_FORK:
        sys.stderr.write("[suggestions] same-repo PR, auto-pin handled the fix — "
                         "skipping inline suggestions.\n")
        return
    if not fixable and not unfixable:
        return

    commentable = fetch_pr_commentable_lines()

    comments = []
    out_of_diff_fixable: list[tuple[str, int, str, str]] = []
    for fpath, items in fixable.items():
        allowed = commentable.get(fpath, set())
        for ln, cur, sug in items:
            if ln not in allowed:
                out_of_diff_fixable.append((fpath, ln, cur.strip(), sug.strip()))
                continue
            indent_match = re.match(r"^(\s*)", cur)
            indent = indent_match.group(1) if indent_match else ""
            sug_line = sug.lstrip("\n")
            if not sug_line.startswith(indent):
                sug_line = indent + sug_line.lstrip()
            comments.append({
                "path": fpath,
                "line": ln,
                "side": "RIGHT",
                "body": (
                    "Pin to a 40-char SHA.\n"
                    "```suggestion\n"
                    f"{sug_line}\n"
                    "```"
                ),
            })

    body_lines = ["**Pinact** found unpinned actions in this repo."]
    if comments:
        body_lines.append(
            f"\n{len(comments)} inline suggestion(s) below — click "
            "*Apply suggestion* on each."
        )
    if out_of_diff_fixable:
        body_lines.append(
            "\n**Auto-fixable, but outside this PR's diff** "
            "(run `pinact run` locally and commit):"
        )
        for fpath, ln, cur, sug in out_of_diff_fixable:
            cur_disp = cur.replace("uses: ", "")
            sug_disp = short_sha(sug.replace("uses: ", ""))
            body_lines.append(f"- `{fpath}:{ln}` — `{cur_disp}` → `{sug_disp}`")
    if unfixable:
        body_lines.append("\n**Need manual fix** (pinact cannot resolve):")
        for fpath in sorted(unfixable):
            for ln, msg, snip in unfixable[fpath]:
                ref = snip.replace("uses: ", "") if snip else "?"
                body_lines.append(f"- `{fpath}:{ln}` — `{ref}` → {msg}")

    review = {
        "commit_id": PR_HEAD_SHA,
        "body": "\n".join(body_lines),
        "event": "COMMENT",
        "comments": comments,
    }

    result = gh_api("POST", f"/repos/{GH_REPO}/pulls/{PR_NUMBER}/reviews", review)
    if result:
        sys.stderr.write(
            f"[suggestions] posted review: {len(comments)} inline + "
            f"{len(out_of_diff_fixable)} out-of-diff fixable + "
            f"{sum(len(v) for v in unfixable.values())} unfixable.\n"
        )


def main():
    if not os.path.exists(PINACT_OUTPUT):
        sys.stderr.write(f"pinact output not found at {PINACT_OUTPUT}\n")
        return

    with open(PINACT_OUTPUT) as f:
        text = f.read()

    fixable, unfixable = parse_pinact_output(text)
    n_files, n_uses = count_workflows_and_uses(CALLER_DIR)
    write_summary(fixable, unfixable, n_files, n_uses, PINACT_EXITCODE)

    if PINACT_EXITCODE != "0":
        post_pr_suggestions(fixable, unfixable)


if __name__ == "__main__":
    main()
