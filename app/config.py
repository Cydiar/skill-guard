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
MAX_REPO_SIZE_MB = int(os.getenv("MAX_REPO_SIZE_MB", "100"))
AUDIT_TIMEOUT = int(os.getenv("AUDIT_TIMEOUT", "60"))

# Allowed domains
ALLOWED_DOMAINS = {"github.com"}

# Report expiry (days)
REPORT_EXPIRY_DAYS = int(os.getenv("REPORT_EXPIRY_DAYS", "7"))

# Deep Scan
DEEP_SCAN_MAX_TURNS = int(os.getenv("DEEP_SCAN_MAX_TURNS", "15"))
DEEP_SCAN_TOOL_TIMEOUT = int(os.getenv("DEEP_SCAN_TOOL_TIMEOUT", "30"))
DEEP_SCAN_TOTAL_TIMEOUT = int(os.getenv("DEEP_SCAN_TOTAL_TIMEOUT", "600"))

# Built-in LLM for Deep Scan
DEEP_SCAN_BASE_URL = os.getenv("DEEP_SCAN_BASE_URL", "https://cc-api.pipellm.ai")
DEEP_SCAN_API_KEY = os.getenv("DEEP_SCAN_API_KEY", "pipe-c3f5096340a619ce10cc764681f753546b34058b3a45ac998e6f7378beb72174")
DEEP_SCAN_MODELS = {
    "claude-sonnet-4-6": {"label": "Claude Sonnet 4.6", "input_per_m": 3.0, "output_per_m": 15.0},
    "claude-opus-4-6": {"label": "Claude Opus 4.6", "input_per_m": 15.0, "output_per_m": 75.0},
}
DEEP_SCAN_DEFAULT_MODEL = "claude-sonnet-4-6"
