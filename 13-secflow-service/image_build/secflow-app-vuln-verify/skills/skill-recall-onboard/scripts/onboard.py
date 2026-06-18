#!/usr/bin/env python3
"""Bring local Claude skills under skill-recall management.

See ../SKILL.md for the full state-machine description.
"""
from __future__ import annotations

# --- secocto config: load ~/.config/secocto/.env (setdefault semantics) ---
from pathlib import Path as _P
_env_file = _P.home() / ".config" / "secocto" / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        if "=" in _line and not _line.lstrip().startswith("#"):
            _k, _v = _line.split("=", 1)
            __import__("os").environ.setdefault(_k.strip(), _v.strip().strip("\x27\""))

import argparse
import dataclasses
import json
import os
import subprocess
import sys
from enum import Enum
from pathlib import Path

try:
    import httpx
    import yaml
except ImportError as e:  # pragma: no cover
    sys.exit(f"missing dependency ({e.name}); run: pip install httpx pyyaml")


# ============================ args / env ============================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    default_skills_dir = str(Path(__file__).resolve().parents[2])
    p.add_argument("--skills-dir", default=default_skills_dir,
                   help="default auto-detected from script location")
    p.add_argument("--org", default="demo",
                   help="Gitea org/namespace for new repos (default: demo)")
    p.add_argument("--gitea-url",
                   default=os.environ.get("GITEA_URL", "http://localhost:3010"))
    p.add_argument("--recall-url",
                   default=os.environ.get("SKILL_RECALL_URL", "http://localhost:8090"))
    p.add_argument("--gitea-token",
                   default=os.environ.get("GITEA_TOKEN", ""))
    p.add_argument("--skill", help="only process this one skill (debugging)")
    p.add_argument("--dry-run", action="store_true",
                   help="show the plan but do not write")
    p.add_argument("--no-project", action="store_true",
                   help="skip auto-discovery of project-level skills")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    return p.parse_args()


# ========================= frontmatter parse =========================
def read_frontmatter(skill_md: Path) -> dict | None:
    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    s = text.lstrip("﻿").lstrip()
    if not s.startswith("---"):
        return None
    body = s[3:]
    # find closing '---' on its own line
    idx = 0
    while True:
        nl = body.find("\n---", idx)
        if nl == -1:
            return None
        after = nl + 4
        if after >= len(body) or body[after] in ("\n", "\r"):
            break
        idx = nl + 1
    fm_text = body[:nl]
    try:
        d = yaml.safe_load(fm_text)
        return d if isinstance(d, dict) else None
    except yaml.YAMLError:
        return None


# ============================ classification ============================
class Status(str, Enum):
    BOOTSTRAP        = "BOOTSTRAP"
    MANAGED_LOCAL    = "MANAGED_LOCAL"
    FOREIGN_REMOTE   = "FOREIGN_REMOTE"
    PLATFORM_HAS_IT  = "PLATFORM_HAS_IT"
    NEW              = "NEW"
    NO_SKILL_MD      = "NO_SKILL_MD"


@dataclasses.dataclass
class SkillEntry:
    slug: str
    path: Path
    status: Status
    source: str = "global"
    note: str = ""


def git_remote_url(skill_dir: Path) -> str | None:
    if not (skill_dir / ".git").exists():
        return None
    r = subprocess.run(
        ["git", "-C", str(skill_dir), "remote", "get-url", "origin"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def classify(skill_dir: Path, gitea_url: str, org: str,
             recall: httpx.Client) -> SkillEntry:
    slug = skill_dir.name

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return SkillEntry(slug, skill_dir, Status.NO_SKILL_MD, "no SKILL.md")

    fm = read_frontmatter(skill_md) or {}
    if (fm.get("namespace") or "").strip().lower() == "bootstrap":
        return SkillEntry(slug, skill_dir, Status.BOOTSTRAP, "namespace=bootstrap")

    remote = git_remote_url(skill_dir)
    if remote is not None:
        if remote == "":
            return SkillEntry(slug, skill_dir, Status.MANAGED_LOCAL,
                              ".git exists, no origin")
        if gitea_url.rstrip("/") in remote:
            return SkillEntry(slug, skill_dir, Status.MANAGED_LOCAL,
                              f"origin={_redact(remote)}")
        return SkillEntry(slug, skill_dir, Status.FOREIGN_REMOTE,
                          f"origin={_redact(remote)}")

    # No local .git -> consult skill-recall
    try:
        r = recall.get(f"/skills/{org}/{slug}")
    except httpx.HTTPError as e:
        return SkillEntry(slug, skill_dir, Status.NEW, f"recall check failed: {e}")
    if r.status_code == 200:
        return SkillEntry(slug, skill_dir, Status.PLATFORM_HAS_IT,
                          "found on skill-recall")
    if r.status_code == 404:
        return SkillEntry(slug, skill_dir, Status.NEW, "")
    return SkillEntry(slug, skill_dir, Status.NEW,
                      f"recall returned {r.status_code} (treating as NEW)")


def _redact(url: str) -> str:
    # http://user:secret@host/x -> http://user:***@host/x
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        if "@" in rest:
            auth, host = rest.split("@", 1)
            if ":" in auth:
                u, _ = auth.split(":", 1)
                auth = f"{u}:***"
            return f"{scheme}://{auth}@{host}"
    return url


def find_project_skills_dir(start: Path | None = None) -> Path | None:
    """Walk up from *start* (default cwd) looking for .opencode/skills or .claude/skills."""
    cur = start or Path.cwd()
    while True:
        for candidate in (cur / ".opencode" / "skills", cur / ".claude" / "skills"):
            if candidate.is_dir():
                return candidate
        parent = cur.parent
        if parent == cur:
            return None
        cur = parent


# ============================ onboarding ============================
def onboard_one(entry: SkillEntry, *, gitea_url: str, gitea_token: str,
                recall_url: str, org: str) -> dict:
    slug = entry.slug
    actions: list[str] = []

    # 1) Create Gitea repo
    r = httpx.post(
        f"{gitea_url}/api/v1/orgs/{org}/repos",
        headers={"Authorization": f"token {gitea_token}"},
        json={"name": slug, "auto_init": False,
              "default_branch": "main", "private": False},
        timeout=15, trust_env=False,
    )
    if r.status_code == 201:
        actions.append("gitea repo created")
    elif r.status_code == 409:
        actions.append("gitea repo existed (reusing)")
    else:
        raise RuntimeError(f"create gitea repo: {r.status_code} {r.text[:200]}")

    # 2) git init / commit / tag / push
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "skill-recall-onboard",
        "GIT_AUTHOR_EMAIL": "onboard@local",
        "GIT_COMMITTER_NAME": "skill-recall-onboard",
        "GIT_COMMITTER_EMAIL": "onboard@local",
        # Strip any system proxy that could mangle localhost git pushes
        "http_proxy": "", "https_proxy": "",
        "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
    }
    _git(entry.path, ["init", "-b", "main"], env=env)
    _git(entry.path, ["add", "-A"], env=env)
    _git(entry.path, ["commit", "-m", f"onboard {slug} v1.0.0"], env=env)
    _git(entry.path, ["tag", "v1.0.0"], env=env)

    clean_remote = f"{gitea_url.rstrip('/')}/{org}/{slug}.git"
    _git(entry.path, ["remote", "add", "origin", clean_remote], env=env)
    _git(entry.path, [
        "-c", "credential.helper=",
        "-c", f"http.extraheader=Authorization: token {gitea_token}",
        "push", "-u", "origin", "main", "v1.0.0",
    ], env=env)
    actions.append("git init+commit+tag v1.0.0+push")

    # 3) Trigger immediate skill-recall sync (don't wait for webhook)
    try:
        r = httpx.post(f"{recall_url}/admin/sync/{org}/{slug}",
                       timeout=30, trust_env=False)
        if r.status_code == 200:
            actions.append(f"recall sync -> {r.json().get('action', '?')}")
        else:
            actions.append(f"recall sync returned {r.status_code}")
    except Exception as e:
        actions.append(f"recall sync error: {e}")

    return {"slug": slug, "ok": True, "actions": actions}


def _git(cwd: Path, args: list[str], env: dict) -> None:
    r = subprocess.run(["git", *args], cwd=str(cwd),
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        # Don't print the http.extraheader arg back at the user
        safe_args = ["***" if a.startswith("http.extraheader=") else a for a in args]
        raise RuntimeError(
            f"git {' '.join(safe_args)} failed: {(r.stderr or r.stdout).strip()}"
        )


_NO_PROXY_ENV = {
    **os.environ,
    "http_proxy": "", "https_proxy": "",
    "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
}


def _git_capture(cwd: Path, args: list[str]) -> str:
    """Run git, return stdout on success, empty string on failure."""
    r = subprocess.run(["git", *args], cwd=str(cwd),
                       capture_output=True, text=True, env=_NO_PROXY_ENV)
    return r.stdout.strip() if r.returncode == 0 else ""


def _pending_state(skill_dir: Path) -> dict:
    """Inspect a MANAGED_LOCAL skill for work that needs pushing.

    Returns {dirty, unpushed_commits, unpushed_tags}.
    """
    dirty = bool(_git_capture(skill_dir, ["status", "--porcelain"]))

    branch = _git_capture(skill_dir, ["rev-parse", "--abbrev-ref", "HEAD"]) or "main"

    # Fetch so we can compare against the remote's view. Best-effort —
    # if the remote is down we still want to report something useful.
    subprocess.run(
        ["git", "fetch", "--tags", "origin"],
        cwd=str(skill_dir), capture_output=True, text=True, env=_NO_PROXY_ENV,
    )

    unpushed_commits = _git_capture(
        skill_dir, ["log", f"origin/{branch}..HEAD", "--oneline"]
    ).splitlines() if _git_capture(
        skill_dir, ["rev-parse", "--verify", f"origin/{branch}"]
    ) else _git_capture(skill_dir, ["log", "--oneline"]).splitlines()

    local_tags = set(_git_capture(skill_dir, ["tag"]).splitlines())
    remote_tag_lines = _git_capture(
        skill_dir, ["ls-remote", "--tags", "origin"]
    ).splitlines()
    remote_tags = {
        line.rsplit("refs/tags/", 1)[-1].replace("^{}", "")
        for line in remote_tag_lines if "refs/tags/" in line
    }
    unpushed_tags = sorted(local_tags - remote_tags)

    return {
        "dirty": dirty,
        "branch": branch,
        "unpushed_commits": unpushed_commits,
        "unpushed_tags": unpushed_tags,
    }


def push_pending(entry: SkillEntry, *, gitea_token: str,
                 recall_url: str, org: str) -> dict:
    """Push any unpushed commits/tags for a MANAGED_LOCAL skill.

    Returns {slug, ok, actions, up_to_date}. Refuses to touch a dirty
    tree — the user may have in-flight evolve work we shouldn't auto-commit.
    """
    slug = entry.slug
    actions: list[str] = []

    state = _pending_state(entry.path)

    if state["dirty"]:
        return {
            "slug": slug, "ok": False, "up_to_date": False,
            "error": "working tree dirty (commit or stash first)",
            "actions": actions,
        }

    if not state["unpushed_commits"] and not state["unpushed_tags"]:
        return {"slug": slug, "ok": True, "up_to_date": True, "actions": ["already up-to-date"]}

    env = {
        **os.environ,
        "http_proxy": "", "https_proxy": "",
        "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
    }
    push_args = [
        "-c", "credential.helper=",
        "-c", f"http.extraheader=Authorization: token {gitea_token}",
        "push", "origin", state["branch"],
    ]
    push_args.extend(state["unpushed_tags"])
    _git(entry.path, push_args, env=env)

    summary_parts = []
    if state["unpushed_commits"]:
        summary_parts.append(f"{len(state['unpushed_commits'])} commit(s)")
    if state["unpushed_tags"]:
        summary_parts.append(f"tag(s) {','.join(state['unpushed_tags'])}")
    actions.append(f"pushed {' + '.join(summary_parts)}")

    try:
        r = httpx.post(f"{recall_url}/admin/sync/{org}/{slug}",
                       timeout=30, trust_env=False)
        if r.status_code == 200:
            actions.append(f"recall sync -> {r.json().get('action', '?')}")
        else:
            actions.append(f"recall sync returned {r.status_code}")
    except Exception as e:
        actions.append(f"recall sync error: {e}")

    return {"slug": slug, "ok": True, "up_to_date": False, "actions": actions}


# ============================ pre-flight ============================
def preflight(args: argparse.Namespace) -> None:
    if not args.gitea_token:
        sys.exit("ERROR: GITEA_TOKEN env var or --gitea-token required")
    if not Path(args.skills_dir).is_dir():
        sys.exit(f"ERROR: skills dir not found: {args.skills_dir}")
    try:
        r = httpx.get(f"{args.gitea_url}/api/v1/version",
                      timeout=5, trust_env=False)
        if not r.json().get("version"):
            sys.exit(f"ERROR: Gitea at {args.gitea_url}: bad version response")
    except Exception as e:
        sys.exit(f"ERROR: cannot reach Gitea at {args.gitea_url}: {e}")
    try:
        r = httpx.get(f"{args.recall_url}/healthz",
                      timeout=5, trust_env=False)
        if r.json().get("status") != "ok":
            sys.exit(f"ERROR: skill-recall at {args.recall_url} unhealthy")
    except Exception as e:
        sys.exit(f"ERROR: cannot reach skill-recall at {args.recall_url}: {e}")


# ============================ output ============================
ORDER = [Status.NEW, Status.PLATFORM_HAS_IT, Status.MANAGED_LOCAL,
         Status.FOREIGN_REMOTE, Status.BOOTSTRAP, Status.NO_SKILL_MD]


def print_text_summary(entries: list[SkillEntry], skills_root: Path) -> None:
    by_status: dict[Status, list[SkillEntry]] = {}
    for e in entries:
        by_status.setdefault(e.status, []).append(e)
    print(f"Scanned {len(entries)} dir(s) in {skills_root}")
    for s in ORDER:
        items = by_status.get(s, [])
        if not items:
            continue
        print(f"\n  {s.value:18} ({len(items)})")
        for e in items:
            parts = []
            if e.source != "global":
                parts.append(e.source)
            if e.note:
                parts.append(e.note)
            extra = f"   [{', '.join(parts)}]" if parts else ""
            print(f"    - {e.slug}{extra}")


# ============================ main ============================
def main() -> int:
    args = parse_args()
    preflight(args)

    skills_root = Path(args.skills_dir)
    dirs_to_scan: list[tuple[Path, str]] = [(skills_root, "global")]

    if not args.no_project:
        project_dir = find_project_skills_dir()
        if project_dir:
            dirs_to_scan.append((project_dir, "project"))

    seen: dict[str, tuple[Path, str]] = {}
    for dir_path, source in dirs_to_scan:
        for child in sorted(dir_path.iterdir()):
            if child.is_dir() and child.name not in seen:
                seen[child.name] = (child, source)

    candidates = [path for path, _ in seen.values()]
    source_map = {slug: source for slug, (_, source) in seen.items()}

    if args.skill:
        candidates = [d for d in candidates if d.name == args.skill]
        if not candidates:
            sys.exit(f"--skill {args.skill}: not found under scanned dirs")

    recall = httpx.Client(base_url=args.recall_url, timeout=10, trust_env=False)
    entries = [classify(d, args.gitea_url, args.org, recall) for d in candidates]
    recall.close()

    for e in entries:
        e.source = source_map.get(e.slug, "global")

    to_onboard = [e for e in entries if e.status == Status.NEW]
    # Only push for MANAGED_LOCAL skills whose origin points at our Gitea.
    # Rows with `.git` but no origin are the user's in-flight work — we don't
    # know where to send them, so skip.
    to_push = [e for e in entries
               if e.status == Status.MANAGED_LOCAL and e.note.startswith("origin=")]
    foreign = [e for e in entries if e.status == Status.FOREIGN_REMOTE]

    # ----- summary -----
    if args.json:
        out: dict = {
            "skills_dir": str(skills_root),
            "org": args.org,
            "dry_run": args.dry_run,
            "summary": {s.value: sum(1 for e in entries if e.status == s) for s in Status},
            "entries": [{"slug": e.slug, "status": e.status.value, "source": e.source, "note": e.note}
                        for e in entries],
        }
    else:
        print_text_summary(entries, skills_root)

    if args.dry_run:
        if not args.json:
            parts = []
            if to_onboard:
                parts.append(f"onboard {len(to_onboard)} new skill(s)")
            if to_push:
                parts.append(f"check {len(to_push)} managed skill(s) for unpushed commits/tags")
            if parts:
                print(f"\n[DRY RUN] would {', '.join(parts)}; re-run without --dry-run to apply.")
            else:
                print("\n[DRY RUN] nothing would change.")
        else:
            print(json.dumps(out, indent=2))
        return 0 if not foreign else 1

    # ----- apply -----
    results: list[dict] = []
    for i, e in enumerate(to_onboard, 1):
        if not args.json:
            print(f"\n  [{i}/{len(to_onboard)}] {e.slug}")
        try:
            r = onboard_one(
                e, gitea_url=args.gitea_url, gitea_token=args.gitea_token,
                recall_url=args.recall_url, org=args.org,
            )
            results.append(r)
            if not args.json:
                for a in r["actions"]:
                    print(f"        {a}")
        except Exception as exc:
            results.append({"slug": e.slug, "ok": False, "error": str(exc)})
            if not args.json:
                print(f"        FAILED: {exc}")

    push_results: list[dict] = []
    pushed = 0
    dirty = 0
    if to_push and not args.json:
        print(f"\n  Checking {len(to_push)} managed skill(s) for unpushed changes:")
    for e in to_push:
        try:
            r = push_pending(
                e, gitea_token=args.gitea_token,
                recall_url=args.recall_url, org=args.org,
            )
        except Exception as exc:
            r = {"slug": e.slug, "ok": False, "error": str(exc), "actions": []}
        push_results.append(r)
        if not args.json:
            if r.get("up_to_date"):
                continue  # don't spam the console with up-to-date skills
            print(f"    - {e.slug}")
            if not r.get("ok"):
                print(f"        SKIPPED: {r.get('error', 'unknown')}")
            else:
                pushed += 1
                for a in r["actions"]:
                    print(f"        {a}")
        else:
            if r.get("ok") and not r.get("up_to_date"):
                pushed += 1
        if not r.get("ok"):
            dirty += 1

    ok = sum(1 for r in results if r["ok"])
    fail = len(results) - ok
    if args.json:
        out["results"] = results
        out["push_results"] = push_results
        print(json.dumps(out, indent=2))
    else:
        summary = f"\nDone: {ok} onboarded, {fail} failed"
        if to_push:
            summary += f", {pushed} pushed, {dirty} dirty-skipped"
        summary += f", {len(foreign)} foreign-remote skipped."
        print(summary)
    return 1 if (fail or foreign or dirty) else 0


if __name__ == "__main__":
    sys.exit(main())
