"""Report API endpoints — JSON and HTML report retrieval."""

import json
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from app.db import get_scan, get_scan_findings, get_child_scans
from app.models import ReportResponse, FindingItem, TokenEstimateResponse, CostEstimateResponse, ChildScanSummary

# Make scripts/ importable for HtmlRenderer
_scripts_dir = str(Path(__file__).resolve().parent.parent.parent / "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

router = APIRouter(prefix="/api/report", tags=["report"])


@router.get("/{scan_id}", response_model=ReportResponse)
async def get_report_json(scan_id: str):
    """Return the full audit report as JSON."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "done":
        raise HTTPException(status_code=400, detail=f"Scan is not complete (status: {scan['status']})")

    report_data = json.loads(scan["report_json"]) if scan["report_json"] else {}
    findings = get_scan_findings(scan_id)

    is_multi = bool(scan.get("is_multi_skill"))
    children = []
    if is_multi:
        child_scans = get_child_scans(scan_id)
        for cs in child_scans:
            child_findings = get_scan_findings(cs["id"])
            children.append(ChildScanSummary(
                scan_id=cs["id"],
                skill_name=cs.get("skill_name", ""),
                risk_score=cs.get("risk_score", 0),
                risk_level=cs.get("risk_level", ""),
                finding_count=len(child_findings),
            ))

    return ReportResponse(
        scan_id=scan_id,
        github_url=scan.get("github_url", ""),
        skill_name=report_data.get("skill_name", scan.get("skill_name", "")),
        risk_score=report_data.get("risk_score", scan.get("risk_score", 0)),
        risk_level=report_data.get("risk_level", scan.get("risk_level", "")),
        findings=[
            FindingItem(
                dimension=f.get("dimension", ""),
                severity=f.get("severity", ""),
                file_path=f.get("file_path", ""),
                line_number=f.get("line_number", 0),
                pattern=f.get("pattern", ""),
                description=f.get("description", ""),
                reference=f.get("reference", ""),
                remediation_zh=f.get("remediation_zh", ""),
                remediation_en=f.get("remediation_en", ""),
            )
            for f in findings
        ],
        dimension_summary=report_data.get("dimension_summary", {}),
        token_estimate=TokenEstimateResponse(**report_data["token_estimate"]) if report_data.get("token_estimate") else None,
        cost_estimates=[
            CostEstimateResponse(**c) for c in report_data.get("cost_estimates", [])
        ],
        file_inventory=report_data.get("file_inventory", {}),
        created_at=scan.get("created_at", ""),
        is_multi_skill=is_multi,
        parent_scan_id=scan.get("parent_scan_id") or "",
        children=children,
    )


@router.get("/{scan_id}/html", response_class=HTMLResponse)
async def get_report_html(scan_id: str):
    """Return the audit report as a self-contained HTML page."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "done":
        raise HTTPException(status_code=400, detail=f"Scan is not complete (status: {scan['status']})")

    report_data = json.loads(scan["report_json"]) if scan["report_json"] else {}

    # Reconstruct AuditReport dataclass for HtmlRenderer
    from audit_skill import AuditReport, Finding, TokenEstimate, HtmlRenderer

    token_est_data = report_data.get("token_estimate", {})
    token_estimate = TokenEstimate(
        l1_skill_md=token_est_data.get("l1_skill_md", 0),
        l2_eager=token_est_data.get("l2_eager", 0),
        l2_lazy=token_est_data.get("l2_lazy", 0),
        l3_total=token_est_data.get("l3_total", 0),
        l1_chars=token_est_data.get("l1_chars", 0),
        l2_eager_chars=token_est_data.get("l2_eager_chars", 0),
        l2_lazy_chars=token_est_data.get("l2_lazy_chars", 0),
        l3_chars=token_est_data.get("l3_chars", 0),
        eager_files=token_est_data.get("eager_files", []),
        lazy_files=token_est_data.get("lazy_files", []),
    )

    from audit_skill import CostEstimate, ModelPricing

    cost_estimates = []
    for c in report_data.get("cost_estimates", []):
        ce = CostEstimate(
            model_name=c.get("model", ""),
            input_per_m=c.get("input_per_m", 0),
            output_per_m=c.get("output_per_m", 0),
            cache_input_per_m=c.get("cache_input_per_m", 0),
            light_cost=c.get("light_cost", 0),
            typical_cost=c.get("typical_cost", 0),
            heavy_cost=c.get("heavy_cost", 0),
        )
        cost_estimates.append(ce)

    findings = [
        Finding(
            dimension=f.get("dimension", ""),
            severity=f.get("severity", ""),
            file_path=f.get("file_path", ""),
            line_number=f.get("line_number", 0),
            pattern=f.get("pattern", ""),
            description=f.get("description", ""),
            reference=f.get("reference", ""),
            remediation_zh=f.get("remediation_zh", ""),
            remediation_en=f.get("remediation_en", ""),
        )
        for f in report_data.get("findings", [])
    ]

    audit_report = AuditReport(
        skill_name=report_data.get("skill_name", ""),
        skill_path=report_data.get("skill_path", ""),
        file_inventory=report_data.get("file_inventory", {}),
        risk_score=report_data.get("risk_score", 0),
        risk_level=report_data.get("risk_level", ""),
        findings=findings,
        dimension_summary=report_data.get("dimension_summary", {}),
        token_estimate=token_estimate,
        cost_estimates=cost_estimates,
    )

    # Use HtmlRenderer to generate HTML string
    import tempfile
    renderer = HtmlRenderer()
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as tmp:
        tmp_path = Path(tmp.name)

    renderer.render([audit_report], tmp_path, target=scan.get("github_url", ""))
    html_content = tmp_path.read_text(encoding="utf-8")
    tmp_path.unlink(missing_ok=True)

    return HTMLResponse(content=html_content)
