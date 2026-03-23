"""Rules management — read/write configurable audit rules (rules.yaml)."""

import re
import sys
from pathlib import Path
from typing import List, Optional

import yaml
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

# ── Path to rules.yaml ───────────────────────────────────────────────────────

_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "rules.yaml"

# ── Pydantic models ──────────────────────────────────────────────────────────


class RuleItem(BaseModel):
    id: str
    pattern: str
    description: str
    severity: str = "MEDIUM"
    enabled: bool = True
    whitelist: List[str] = []

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v

    @field_validator("pattern")
    @classmethod
    def check_pattern(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("pattern cannot be empty")
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}")
        return v


class RulesPayload(BaseModel):
    data_exfiltration: Optional[List[RuleItem]] = None
    supply_chain: Optional[List[RuleItem]] = None
    resource_abuse: Optional[List[RuleItem]] = None
    license_compliance: Optional[List[RuleItem]] = None
    least_privilege: Optional[List[RuleItem]] = None
    prompt_injection_auxiliary: Optional[List[RuleItem]] = None


# ── Helpers ──────────────────────────────────────────────────────────────────

# Dimension display metadata: key -> (label_en, label_zh, desc_en, desc_zh)
DIMENSION_META = {
    "data_exfiltration": ("Data Exfiltration", "数据外泄", "Sensitive file access & outbound requests", "敏感文件读取与外发请求检测"),
    "supply_chain": ("Supply Chain", "供应链", "Dependency pinning & pipe-to-shell", "依赖版本锁定与管道执行检测"),
    "resource_abuse": ("Resource Abuse", "资源滥用", "Infinite loops, large fetches, retries", "无限循环、大量数据拉取、重试检测"),
    "license_compliance": ("License Compliance", "许可证合规", "Proprietary / commercial indicators", "专有/商业许可证指标检测"),
    "least_privilege": ("Least Privilege", "权限最小化", "Tool declarations & dangerous combos", "工具声明与危险组合检测"),
    "prompt_injection_auxiliary": ("Prompt Injection (Aux)", "Prompt 注入(辅助)", "Zero-width chars, base64, HTML comments", "零宽字符、base64 长串、HTML 注释检测"),
}


def _read_rules() -> dict:
    """Read rules.yaml and return raw dict."""
    if not _RULES_PATH.exists():
        return {}
    with open(_RULES_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def _write_rules(data: dict) -> None:
    """Write dict back to rules.yaml with comments header."""
    header = (
        "# SkillGuard 可配置规则 (Configurable Rules)\n"
        "# 由 Rules Editor UI 自动生成 — 手动编辑同样有效\n"
        "#\n"
        "# enabled:   true/false\n"
        "# severity:  CRITICAL / HIGH / MEDIUM / LOW / INFO\n"
        "# whitelist: [] 子字符串匹配白名单\n\n"
    )
    yaml_content = yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    _RULES_PATH.write_text(header + yaml_content, encoding="utf-8")


# ── Router ───────────────────────────────────────────────────────────────────

router = APIRouter(tags=["rules"])


@router.get("/api/rules")
async def get_rules():
    """Return all configurable rules grouped by dimension."""
    data = _read_rules()
    # Attach dimension metadata
    meta = {}
    for key, (en, zh, desc_en, desc_zh) in DIMENSION_META.items():
        rules = data.get(key, [])
        # Filter out non-list entries (comments parsed as something else)
        if not isinstance(rules, list):
            rules = []
        meta[key] = {
            "label_en": en,
            "label_zh": zh,
            "desc_en": desc_en,
            "desc_zh": desc_zh,
            "rules": rules,
        }
    return meta


@router.put("/api/rules")
async def save_rules(payload: RulesPayload):
    """Save all configurable rules back to rules.yaml."""
    data = {}
    for key in DIMENSION_META:
        rules_list = getattr(payload, key, None)
        if rules_list is not None:
            data[key] = [r.model_dump() for r in rules_list]
        else:
            data[key] = []
    _write_rules(data)
    return {"ok": True, "message": "Rules saved", "path": str(_RULES_PATH)}


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    """Rules editor page."""
    return request.app.state.templates.TemplateResponse(
        "rules.html", {"request": request}
    )
