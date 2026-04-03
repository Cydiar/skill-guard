"""Page routes — SSR with Jinja2 templates."""

import sys
import tempfile
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.db import get_scan, get_scan_findings, get_recent_scans, get_child_scans, get_deep_scan, get_trace_steps, get_deep_scans_for_scan

# Make scripts/ importable
_scripts_dir = str(Path(__file__).resolve().parent.parent.parent / "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

router = APIRouter(tags=["pages"])

# Cache the methodology HTML (static content, only changes on code deploy/restart)
_methodology_cache: str | None = None


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Home page with URL input and recent scans."""
    recent = get_recent_scans(limit=20)

    deep_scan_map = {}
    for scan in recent:
        ds_list = get_deep_scans_for_scan(scan["id"])
        if ds_list:
            deep_scan_map[scan["id"]] = ds_list

    return request.app.state.templates.TemplateResponse(
        "index.html",
        {"request": request, "recent_scans": recent, "deep_scan_map": deep_scan_map},
    )


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    """Scanning progress page."""
    scan = get_scan(scan_id)
    if not scan:
        return HTMLResponse(content="Scan not found", status_code=404)
    return request.app.state.templates.TemplateResponse(
        "scanning.html",
        {"request": request, "scan": scan},
    )


@router.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    """Report display page."""
    scan = get_scan(scan_id)
    if not scan:
        return HTMLResponse(content="Scan not found", status_code=404)
    if scan["status"] != "done":
        return request.app.state.templates.TemplateResponse(
            "scanning.html",
            {"request": request, "scan": scan},
        )

    import json

    # Multi-skill summary page
    if scan.get("is_multi_skill"):
        report_data = json.loads(scan["report_json"]) if scan["report_json"] else {}
        children = get_child_scans(scan_id)

        # Compute token aggregates from child reports
        token_stats = {"l1_total": 0, "l2_eager_total": 0, "l2_lazy_total": 0, "l3_total": 0, "l1l2_values": [], "top_consumers": []}
        for child in children:
            if child.get("report_json"):
                try:
                    crj = json.loads(child["report_json"])
                except (json.JSONDecodeError, TypeError):
                    continue
                te = crj.get("token_estimate", {})
                l1 = te.get("l1_skill_md", 0)
                l2e = te.get("l2_eager", 0)
                l2l = te.get("l2_lazy", 0)
                l3 = te.get("l3_total", 0)
                l1l2 = l1 + l2e + l2l
                token_stats["l1_total"] += l1
                token_stats["l2_eager_total"] += l2e
                token_stats["l2_lazy_total"] += l2l
                token_stats["l3_total"] += l3
                token_stats["l1l2_values"].append(l1l2)
                token_stats["top_consumers"].append({"name": child.get("skill_name", ""), "l1": l1, "l2e": l2e, "l2l": l2l, "total": l1l2})

        l1l2_total = token_stats["l1_total"] + token_stats["l2_eager_total"] + token_stats["l2_lazy_total"]
        n = len(token_stats["l1l2_values"]) or 1
        vals = sorted(token_stats["l1l2_values"])
        token_stats["l1l2_total"] = l1l2_total
        token_stats["avg_l1l2"] = l1l2_total // n
        token_stats["median_l1l2"] = vals[len(vals) // 2] if vals else 0
        token_stats["max_l1l2"] = max(vals) if vals else 0
        token_stats["top_consumers"] = sorted(token_stats["top_consumers"], key=lambda x: x["total"], reverse=True)[:5]

        # Build deep scan status map: child_scan_id -> list of deep scans
        deep_scan_map = {}
        for child in children:
            child_ds = get_deep_scans_for_scan(child["id"])
            if child_ds:
                deep_scan_map[child["id"]] = child_ds

        return request.app.state.templates.TemplateResponse(
            "summary.html",
            {
                "request": request,
                "scan": scan,
                "report": report_data,
                "children": children,
                "token_stats": token_stats,
                "deep_scan_map": deep_scan_map,
            },
        )

    # Single-skill report page
    report_data = json.loads(scan["report_json"]) if scan["report_json"] else {}
    findings = get_scan_findings(scan_id)

    # Group findings by dimension
    findings_by_dim = {}
    for f in findings:
        dim = f.get("dimension", "Unknown")
        findings_by_dim.setdefault(dim, []).append(f)

    return request.app.state.templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "scan": scan,
            "report": report_data,
            "findings": findings,
            "findings_by_dim": findings_by_dim,
        },
    )


@router.get("/methodology", response_class=HTMLResponse)
async def methodology_page(request: Request):
    """Serve the audit methodology page (generated from audit_skill.py, wrapped in base.html)."""
    global _methodology_cache
    if _methodology_cache is None:
        import re
        from audit_skill import HtmlRenderer
        renderer = HtmlRenderer()
        tmp_path = Path(tempfile.mktemp(suffix=".html"))
        try:
            renderer.render_methodology(tmp_path, report_filename="")
            full_html = tmp_path.read_text(encoding="utf-8")
        finally:
            tmp_path.unlink(missing_ok=True)
        # Extract body content: between <div class="main-container" ...> and <!-- Footer -->
        m = re.search(
            r'<div\s+class="main-container"[^>]*>(.*?)<!-- Footer -->',
            full_html,
            re.DOTALL,
        )
        _methodology_cache = m.group(1).strip() if m else full_html
    return request.app.state.templates.TemplateResponse(
        "methodology.html",
        {"request": request, "methodology_content": _methodology_cache},
    )


# ── Deep Scan Page Routes ───────────────────────────────────────────


@router.get("/deep-scan/{deep_scan_id}", response_class=HTMLResponse)
async def deep_scan_page(request: Request, deep_scan_id: str):
    """Deep Scan progress page."""
    deep_scan = get_deep_scan(deep_scan_id)
    if not deep_scan:
        return HTMLResponse(content="Deep scan not found", status_code=404)

    # If done, redirect to report
    if deep_scan["status"] == "done":
        from starlette.responses import RedirectResponse
        return RedirectResponse(url=f"/deep-scan/{deep_scan_id}/report")

    # Get parent scan info for context
    scan = get_scan(deep_scan["scan_id"]) if deep_scan.get("scan_id") else None

    return request.app.state.templates.TemplateResponse(
        "deep_scanning.html",
        {"request": request, "deep_scan": deep_scan, "scan": scan},
    )


@router.get("/deep-scan/{deep_scan_id}/report", response_class=HTMLResponse)
async def trace_report_page(request: Request, deep_scan_id: str):
    """Trace report page for a completed deep scan."""
    import json

    deep_scan = get_deep_scan(deep_scan_id)
    if not deep_scan:
        return HTMLResponse(content="Deep scan not found", status_code=404)
    if deep_scan["status"] != "done":
        return request.app.state.templates.TemplateResponse(
            "deep_scanning.html",
            {"request": request, "deep_scan": deep_scan},
        )

    report = json.loads(deep_scan["report_json"]) if deep_scan.get("report_json") else {}
    trace_steps = get_trace_steps(deep_scan_id)
    evidences = report.get("evidences", [])

    # Render evidence cards and trace timeline HTML
    from app.engine.evidence_renderer import render_evidence_cards, render_trace_timeline
    evidence_html = render_evidence_cards(evidences)
    trace_html = render_trace_timeline(trace_steps)

    return request.app.state.templates.TemplateResponse(
        "trace_report.html",
        {
            "request": request,
            "deep_scan": deep_scan,
            "report": report,
            "trace_steps": trace_steps,
            "evidences": evidences,
            "evidence_html": evidence_html,
            "trace_html": trace_html,
        },
    )
