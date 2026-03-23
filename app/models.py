"""Pydantic schemas for request/response validation."""

from typing import Optional
from pydantic import BaseModel, field_validator
from urllib.parse import urlparse


class ScanRequest(BaseModel):
    github_url: str

    @field_validator("github_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.hostname not in ("github.com", "www.github.com"):
            raise ValueError("Only github.com URLs are supported")
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError("URL must be in the format https://github.com/owner/repo")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    status: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    phase: str = ""
    progress: int = 0
    skill_name: str = ""
    error_message: str = ""
    is_multi_skill: bool = False
    total_skills: int = 0
    done_skills: int = 0


class FindingItem(BaseModel):
    dimension: str
    severity: str
    file_path: str = ""
    line_number: int = 0
    pattern: str = ""
    description: str
    reference: str = ""
    remediation_zh: str = ""
    remediation_en: str = ""


class TokenEstimateResponse(BaseModel):
    l1_skill_md: int = 0
    l2_eager: int = 0
    l2_lazy: int = 0
    l3_total: int = 0
    l1_chars: int = 0
    l2_eager_chars: int = 0
    l2_lazy_chars: int = 0
    l3_chars: int = 0
    eager_files: list[str] = []
    lazy_files: list[str] = []


class CostEstimateResponse(BaseModel):
    model: str
    input_per_m: float = 0
    output_per_m: float = 0
    cache_input_per_m: float = 0
    light_cost: float = 0
    typical_cost: float = 0
    heavy_cost: float = 0


class ChildScanSummary(BaseModel):
    scan_id: str
    skill_name: str = ""
    risk_score: int = 0
    risk_level: str = ""
    finding_count: int = 0


class ReportResponse(BaseModel):
    scan_id: str
    github_url: str = ""
    skill_name: str = ""
    risk_score: int = 0
    risk_level: str = ""
    findings: list[FindingItem] = []
    dimension_summary: dict = {}
    token_estimate: Optional[TokenEstimateResponse] = None
    cost_estimates: list[CostEstimateResponse] = []
    file_inventory: dict = {}
    created_at: str = ""
    is_multi_skill: bool = False
    parent_scan_id: str = ""
    children: list[ChildScanSummary] = []


# ── Deep Scan Models ────────────────────────────────────────────────


class DeepScanRequest(BaseModel):
    scan_id: str
    model: str = "claude-sonnet-4-6"


class DeepScanResponse(BaseModel):
    deep_scan_id: str
    status: str


class DeepScanStatusResponse(BaseModel):
    deep_scan_id: str
    status: str
    phase: str = ""
    progress: int = 0
    error_message: str = ""
    total_turns: int = 0
    total_tool_calls: int = 0


class TraceStepItem(BaseModel):
    step_number: int
    role: str
    content: str = ""
    timestamp: str = ""
    risk_level: Optional[str] = None
    related_finding: Optional[str] = None


class EvidenceItem(BaseModel):
    evidence_type: str
    risk_level: str
    description: str
    tool_name: str = ""
    tool_input: dict = {}
    tool_output: str = ""
    related_finding_id: Optional[str] = None
    related_finding_desc: Optional[str] = None
