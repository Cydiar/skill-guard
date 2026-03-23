"""Git clone task — fast tarball download with git clone fallback."""

import os
import shutil
import subprocess
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from app.config import CLONE_TIMEOUT, MAX_REPO_SIZE_MB
from app.db import update_scan_status
from app.engine.scanner import parse_github_url
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


@celery_app.task(bind=True, name="clone_repo")
def clone_repo(self, scan_id: str, github_url: str) -> str:
    """Download a GitHub repo and return the local path.

    Strategy: try fast tarball download first, fall back to git clone.

    Security:
      - Tarball: safe member filtering, size limit check
      - Git: GIT_CONFIG_NOSYSTEM=1, shallow clone (depth 1)
      - Timeout enforced
      - Repo size checked after extraction
    """
    update_scan_status(scan_id, "cloning")
    publish_progress(scan_id, "cloning", 10)

    owner, repo, subpath = parse_github_url(github_url)

    clone_dir = Path(tempfile.mkdtemp(prefix="sg_clone_"))

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
