"""Skill Guard configuration."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Database
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "data" / "skillguard.db")))

# Git clone limits
CLONE_TIMEOUT = int(os.getenv("CLONE_TIMEOUT", "120"))
MAX_REPO_SIZE_MB = int(os.getenv("MAX_REPO_SIZE_MB", "500"))
AUDIT_TIMEOUT = int(os.getenv("AUDIT_TIMEOUT", "60"))

# Allowed domains
ALLOWED_DOMAINS = {"github.com", "clawhub.ai"}

# ClawHub download API
CLAWHUB_API_BASE = os.getenv(
    "CLAWHUB_API_BASE",
    "https://wry-manatee-359.convex.site/api/v1",
)

# Report expiry (days)
REPORT_EXPIRY_DAYS = int(os.getenv("REPORT_EXPIRY_DAYS", "7"))

# Deep Scan
DEEP_SCAN_MAX_TURNS = int(os.getenv("DEEP_SCAN_MAX_TURNS", "15"))
DEEP_SCAN_TOOL_TIMEOUT = int(os.getenv("DEEP_SCAN_TOOL_TIMEOUT", "30"))
DEEP_SCAN_TOTAL_TIMEOUT = int(os.getenv("DEEP_SCAN_TOTAL_TIMEOUT", "600"))

# Deep Scan models (credentials provided by user at runtime)
DEEP_SCAN_MODELS = {
    "claude-sonnet-4-6": {"label": "Sonnet 4.6 Sonnet", "input_per_m": 3.0, "output_per_m": 15.0},
    "claude-opus-4-6": {"label": "Sonnet 4.6 Opus", "input_per_m": 15.0, "output_per_m": 75.0},
}
DEEP_SCAN_DEFAULT_MODEL = "claude-sonnet-4-6"
