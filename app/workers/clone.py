"""Clone task — GitHub tarball/git clone + ClawHub ZIP download."""

import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from app.config import CLONE_TIMEOUT, MAX_REPO_SIZE_MB, CLAWHUB_API_BASE
from app.db import update_scan_status
from app.engine.scanner import parse_github_url, parse_clawhub_url, is_clawhub_url
from app.workers import celery_app
from app.workers._progress import publish_progress


def _download_tarball(owner: str, repo: str, clone_dir: Path, timeout: int) -> Path | None:
    """Download and extract a GitHub tarball. Returns repo dir or None on failure."""
    for branch in ("main", "master"):
        url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.tar.gz"
        try:
            req = Request(url, headers={"User-Agent": "SkillGuard/1.0"})
            resp = urlopen(req, timeout=timeout)
            data = BytesIO(resp.read())
            break
        except (HTTPError, URLError):
            continue
    else:
        return None

    try:
        with tarfile.open(fileobj=data, mode="r:gz") as tar:
            # Security: filter out absolute paths and path traversal
            safe_members = []
            for m in tar.getmembers():
                if m.name.startswith("/") or ".." in m.name:
                    continue
                safe_members.append(m)
            tar.extractall(path=str(clone_dir), members=safe_members)

        # GitHub tarball extracts to {repo}-{branch}/ directory
        extracted = [d for d in clone_dir.iterdir() if d.is_dir()]
        if len(extracted) == 1:
            target = clone_dir / repo
            if extracted[0] != target:
                extracted[0].rename(target)
            return target
        return None
    except Exception:
        return None


def _download_clawhub_zip(slug: str, clone_dir: Path, timeout: int) -> Path | None:
    """Download and extract a ClawHub skill ZIP. Returns skill dir or None."""
    url = f"{CLAWHUB_API_BASE}/download?slug={slug}"
    try:
        req = Request(url, headers={"User-Agent": "SkillGuard/1.0"})
        resp = urlopen(req, timeout=timeout)
        data = BytesIO(resp.read())
    except (HTTPError, URLError):
        return None

    try:
        with zipfile.ZipFile(data) as zf:
            # Security: filter out absolute paths and path traversal
            safe_names = [
                n for n in zf.namelist()
                if not n.startswith("/") and ".." not in n
            ]
            zf.extractall(path=str(clone_dir), members=[
                zf.getinfo(n) for n in safe_names
            ])

        # Determine target: if ZIP extracts into a single subdir, use that;
        # otherwise use clone_dir itself as the skill root
        children = [d for d in clone_dir.iterdir() if d.is_dir()]
        if len(children) == 1:
            return children[0]

        # Files extracted flat — treat clone_dir as skill root
        if any(clone_dir.glob("*.md")):
            return clone_dir

        return clone_dir
    except Exception:
        return None


@celery_app.task(bind=True, name="clone_repo")
def clone_repo(self, scan_id: str, github_url: str) -> str:
    """Download a skill repo/package and return the local path.

    Supports:
      - GitHub URLs: tarball download → git clone fallback
      - ClawHub URLs: ZIP download via ClawHub API
    """
    update_scan_status(scan_id, "cloning")
    publish_progress(scan_id, "cloning", 10)

    clone_dir = Path(tempfile.mkdtemp(prefix="sg_clone_"))

    if is_clawhub_url(github_url):
        # ── ClawHub path ──
        slug = parse_clawhub_url(github_url)
        target = _download_clawhub_zip(slug, clone_dir, timeout=CLONE_TIMEOUT)

        if target is None:
            shutil.rmtree(clone_dir, ignore_errors=True)
            update_scan_status(scan_id, "error", error_message=f"ClawHub download failed for: {slug}")
            publish_progress(scan_id, "error", 0)
            raise RuntimeError(f"Failed to download ClawHub skill: {slug}")

        # Size check
        total_size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
        if total_size > MAX_REPO_SIZE_MB * 1024 * 1024:
            shutil.rmtree(clone_dir, ignore_errors=True)
            update_scan_status(scan_id, "error", error_message=f"Skill exceeds {MAX_REPO_SIZE_MB}MB limit")
            publish_progress(scan_id, "error", 0)
            raise ValueError(f"Skill size exceeds {MAX_REPO_SIZE_MB}MB limit")

        update_scan_status(scan_id, "cloned")
        publish_progress(scan_id, "cloned", 30)
        return str(target)

    # ── GitHub path ──
    owner, repo, subpath = parse_github_url(github_url)

    # Fast path: tarball download (no git protocol overhead)
    target = _download_tarball(owner, repo, clone_dir, timeout=CLONE_TIMEOUT)

    if target is None:
        # Fallback: git clone
        target = clone_dir / repo
        clone_url = f"https://github.com/{owner}/{repo}.git"

        env = os.environ.copy()
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", clone_url, str(target)],
                env=env,
                timeout=CLONE_TIMEOUT,
                capture_output=True,
                check=True,
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(clone_dir, ignore_errors=True)
            update_scan_status(scan_id, "error", error_message="Clone timed out")
            publish_progress(scan_id, "error", 0)
            raise
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            stderr = exc.stderr.decode(errors="replace") if exc.stderr else str(exc)
            update_scan_status(scan_id, "error", error_message=f"Clone failed: {stderr[:500]}")
            publish_progress(scan_id, "error", 0)
            raise

    # Check repo size
    total_size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    if total_size > MAX_REPO_SIZE_MB * 1024 * 1024:
        shutil.rmtree(clone_dir, ignore_errors=True)
        update_scan_status(scan_id, "error", error_message=f"Repo exceeds {MAX_REPO_SIZE_MB}MB limit")
        publish_progress(scan_id, "error", 0)
        raise ValueError(f"Repo size exceeds {MAX_REPO_SIZE_MB}MB limit")

    # Get commit SHA (only available with git clone)
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        commit_sha = result.stdout.strip()
        update_scan_status(scan_id, "cloned", commit_sha=commit_sha)
    except Exception:
        update_scan_status(scan_id, "cloned")

    publish_progress(scan_id, "cloned", 30)

    # If there's a subpath, verify it exists
    skill_path = target / subpath if subpath else target
    if not skill_path.is_dir():
        shutil.rmtree(clone_dir, ignore_errors=True)
        update_scan_status(scan_id, "error", error_message=f"Subpath not found: {subpath}")
        publish_progress(scan_id, "error", 0)
        raise FileNotFoundError(f"Subpath {subpath} not found in repo")

    return str(skill_path)
