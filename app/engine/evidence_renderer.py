"""Evidence card renderer for Trace reports.

Generates structured HTML evidence cards embedded in the Trace report.
MVP: no PNG screenshots — uses styled HTML cards instead.
"""

import html
import json
from typing import Optional


def render_evidence_card(evidence: dict) -> str:
    """Render a single evidence item as an HTML card.

    Args:
        evidence: dict with keys: evidence_type, risk_level, description,
                  tool_name, tool_input, tool_output,
                  related_finding_id, related_finding_desc
    """
    ev_type = evidence.get("evidence_type", "tool_call")
    renderer = _RENDERERS.get(ev_type, _render_tool_call_card)
    return renderer(evidence)


def render_evidence_cards(evidences: list[dict]) -> str:
    """Render all evidence items as HTML cards."""
    if not evidences:
        return '<div class="text-gray-500 text-sm">No evidence captured during dynamic analysis.</div>'
    cards = [render_evidence_card(e) for e in evidences]
    return "\n".join(cards)


def render_trace_timeline(trace_steps: list[dict]) -> str:
    """Render trace steps as an HTML timeline."""
    if not trace_steps:
        return '<div class="text-gray-500 text-sm">No trace steps recorded.</div>'

    items = []
    for step in trace_steps:
        role = step.get("role", "")
        content = step.get("content", "")
        risk_level = step.get("risk_level")
        step_num = step.get("step_number", 0)

        role_config = _ROLE_STYLES.get(role, _ROLE_STYLES["user"])

        # Try to parse JSON content for structured display
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                content_html = _render_json_content(parsed, role)
            else:
                content_html = f'<pre class="text-xs whitespace-pre-wrap break-all">{html.escape(content[:2000])}</pre>'
        except (json.JSONDecodeError, TypeError):
            content_html = f'<pre class="text-xs whitespace-pre-wrap break-all">{html.escape(str(content)[:2000])}</pre>'

        risk_badge = ""
        if risk_level:
            risk_color = _RISK_COLORS.get(risk_level, "gray")
            risk_badge = f'<span class="ml-2 px-2 py-0.5 rounded text-xs font-medium bg-{risk_color}-100 dark:bg-{risk_color}-900/30 text-{risk_color}-700 dark:text-{risk_color}-400">{html.escape(risk_level)}</span>'

        items.append(f'''
        <div class="relative pl-8 pb-6 border-l-2 {role_config['border']} last:pb-0">
            <div class="absolute -left-2 top-0 w-4 h-4 rounded-full {role_config['dot']}"></div>
            <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-medium {role_config['label_color']}">#{step_num} {role_config['label']}</span>
                {risk_badge}
                <span class="text-xs text-gray-400">{html.escape(step.get('timestamp', ''))}</span>
            </div>
            <div class="p-3 rounded-lg {role_config['bg']} text-sm">
                {content_html}
            </div>
        </div>
        ''')

    return f'<div class="space-y-0">{"".join(items)}</div>'


# ── Internal renderers ──────────────────────────────────────────────


_RISK_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
}

_ROLE_STYLES = {
    "user": {
        "label": "User",
        "label_color": "text-blue-600 dark:text-blue-400",
        "border": "border-blue-200 dark:border-blue-800",
        "dot": "bg-blue-500",
        "bg": "bg-blue-50 dark:bg-blue-900/10",
    },
    "assistant": {
        "label": "Assistant",
        "label_color": "text-purple-600 dark:text-purple-400",
        "border": "border-purple-200 dark:border-purple-800",
        "dot": "bg-purple-500",
        "bg": "bg-purple-50 dark:bg-purple-900/10",
    },
    "tool_call": {
        "label": "Tool Call",
        "label_color": "text-amber-600 dark:text-amber-400",
        "border": "border-amber-200 dark:border-amber-800",
        "dot": "bg-amber-500",
        "bg": "bg-amber-50 dark:bg-amber-900/10",
    },
    "tool_result": {
        "label": "Tool Result",
        "label_color": "text-green-600 dark:text-green-400",
        "border": "border-green-200 dark:border-green-800",
        "dot": "bg-green-500",
        "bg": "bg-gray-50 dark:bg-gray-900/50",
    },
    "evidence": {
        "label": "Evidence",
        "label_color": "text-red-600 dark:text-red-400",
        "border": "border-red-200 dark:border-red-800",
        "dot": "bg-red-500",
        "bg": "bg-red-50 dark:bg-red-900/10",
    },
}


def _render_json_content(data: dict, role: str) -> str:
    """Render parsed JSON content based on role type."""
    if role == "tool_call":
        name = html.escape(data.get("name", ""))
        args = data.get("arguments", {})
        args_str = html.escape(json.dumps(args, indent=2, ensure_ascii=False)[:1000])
        return f'''
        <div class="font-mono">
            <span class="font-bold text-amber-700 dark:text-amber-400">{name}</span>
            <pre class="mt-1 text-xs whitespace-pre-wrap break-all text-gray-600 dark:text-gray-400">{args_str}</pre>
        </div>'''
    elif role == "tool_result":
        name = html.escape(data.get("name", ""))
        output = html.escape(data.get("output", "")[:2000])
        is_error = data.get("is_error", False)
        error_class = "text-red-600 dark:text-red-400" if is_error else ""
        return f'''
        <div>
            <span class="font-mono text-xs font-bold">{name}</span>
            {' <span class="text-red-500 text-xs">[ERROR]</span>' if is_error else ''}
            <pre class="mt-1 text-xs whitespace-pre-wrap break-all bg-black/5 dark:bg-white/5 rounded p-2 {error_class}">{output}</pre>
        </div>'''
    elif role == "evidence":
        ev_type = html.escape(data.get("type", ""))
        risk = html.escape(data.get("risk_level", ""))
        desc = html.escape(data.get("description", ""))
        risk_color = _RISK_COLORS.get(risk, "gray")
        return f'''
        <div class="border-l-4 border-{risk_color}-500 pl-3">
            <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold bg-{risk_color}-100 dark:bg-{risk_color}-900/30 text-{risk_color}-700 dark:text-{risk_color}-400">{risk}</span>
                <span class="text-xs text-gray-500">{ev_type}</span>
            </div>
            <p class="mt-1 text-sm">{desc}</p>
        </div>'''
    else:
        return f'<pre class="text-xs whitespace-pre-wrap break-all">{html.escape(json.dumps(data, indent=2, ensure_ascii=False)[:2000])}</pre>'


def _render_terminal_card(evidence: dict) -> str:
    """Render a terminal command evidence card."""
    command = evidence.get("tool_input", {}).get("command", "")
    output = evidence.get("tool_output", "")
    risk_level = evidence.get("risk_level", "MEDIUM")
    description = evidence.get("description", "")
    risk_color = _RISK_COLORS.get(risk_level, "gray")
    related = evidence.get("related_finding_desc", "")

    return f'''
    <div class="rounded-xl border border-{risk_color}-200 dark:border-{risk_color}-800 overflow-hidden mb-4">
        <div class="px-4 py-2 bg-{risk_color}-50 dark:bg-{risk_color}-900/20 flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold bg-{risk_color}-100 dark:bg-{risk_color}-900/30 text-{risk_color}-700 dark:text-{risk_color}-400">{html.escape(risk_level)}</span>
                <span class="text-sm font-medium">Terminal Command</span>
            </div>
        </div>
        <div class="p-4">
            <p class="text-sm mb-3">{html.escape(description)}</p>
            <div class="bg-gray-900 rounded-lg p-3 font-mono text-sm">
                <div class="text-green-400">$ {html.escape(command[:500])}</div>
                <div class="text-gray-300 mt-1 whitespace-pre-wrap text-xs">{html.escape(output[:1000])}</div>
            </div>
            {f'<div class="mt-3 text-xs text-gray-500"><strong>Related finding:</strong> {html.escape(related[:200])}</div>' if related else ''}
        </div>
    </div>'''


def _render_file_operation_card(evidence: dict) -> str:
    """Render a file operation evidence card."""
    file_path = evidence.get("tool_input", {}).get("file_path", "")
    output = evidence.get("tool_output", "")
    risk_level = evidence.get("risk_level", "MEDIUM")
    description = evidence.get("description", "")
    risk_color = _RISK_COLORS.get(risk_level, "gray")

    return f'''
    <div class="rounded-xl border border-{risk_color}-200 dark:border-{risk_color}-800 overflow-hidden mb-4">
        <div class="px-4 py-2 bg-{risk_color}-50 dark:bg-{risk_color}-900/20 flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold bg-{risk_color}-100 dark:bg-{risk_color}-900/30 text-{risk_color}-700 dark:text-{risk_color}-400">{html.escape(risk_level)}</span>
                <span class="text-sm font-medium">File Operation</span>
            </div>
        </div>
        <div class="p-4">
            <p class="text-sm mb-3">{html.escape(description)}</p>
            <div class="text-xs font-mono text-gray-600 dark:text-gray-400 mb-2">{html.escape(file_path)}</div>
            <pre class="text-xs bg-gray-50 dark:bg-gray-900 rounded p-3 whitespace-pre-wrap break-all overflow-auto max-h-48">{html.escape(output[:1500])}</pre>
        </div>
    </div>'''


def _render_network_card(evidence: dict) -> str:
    """Render a network request evidence card."""
    command = evidence.get("tool_input", {}).get("command", "")
    output = evidence.get("tool_output", "")
    risk_level = evidence.get("risk_level", "MEDIUM")
    description = evidence.get("description", "")
    risk_color = _RISK_COLORS.get(risk_level, "gray")

    return f'''
    <div class="rounded-xl border border-{risk_color}-200 dark:border-{risk_color}-800 overflow-hidden mb-4">
        <div class="px-4 py-2 bg-{risk_color}-50 dark:bg-{risk_color}-900/20 flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold bg-{risk_color}-100 dark:bg-{risk_color}-900/30 text-{risk_color}-700 dark:text-{risk_color}-400">{html.escape(risk_level)}</span>
                <span class="text-sm font-medium">Network Request</span>
            </div>
        </div>
        <div class="p-4">
            <p class="text-sm mb-3">{html.escape(description)}</p>
            <div class="bg-gray-900 rounded-lg p-3 font-mono text-xs text-gray-300 whitespace-pre-wrap">{html.escape(command[:500])}</div>
            <pre class="mt-2 text-xs bg-gray-50 dark:bg-gray-900 rounded p-3 whitespace-pre-wrap break-all overflow-auto max-h-48">{html.escape(output[:1000])}</pre>
        </div>
    </div>'''


def _render_tool_call_card(evidence: dict) -> str:
    """Render a generic tool call evidence card."""
    tool_name = evidence.get("tool_name", "")
    tool_input = evidence.get("tool_input", {})
    output = evidence.get("tool_output", "")
    risk_level = evidence.get("risk_level", "MEDIUM")
    description = evidence.get("description", "")
    risk_color = _RISK_COLORS.get(risk_level, "gray")
    related = evidence.get("related_finding_desc", "")

    input_str = json.dumps(tool_input, indent=2, ensure_ascii=False)[:800]

    return f'''
    <div class="rounded-xl border border-{risk_color}-200 dark:border-{risk_color}-800 overflow-hidden mb-4">
        <div class="px-4 py-2 bg-{risk_color}-50 dark:bg-{risk_color}-900/20 flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold bg-{risk_color}-100 dark:bg-{risk_color}-900/30 text-{risk_color}-700 dark:text-{risk_color}-400">{html.escape(risk_level)}</span>
                <span class="text-sm font-medium">Tool Call: {html.escape(tool_name)}</span>
            </div>
        </div>
        <div class="p-4">
            <p class="text-sm mb-3">{html.escape(description)}</p>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <div class="text-xs font-medium text-gray-500 mb-1">Input</div>
                    <pre class="text-xs bg-gray-50 dark:bg-gray-900 rounded p-2 whitespace-pre-wrap break-all">{html.escape(input_str)}</pre>
                </div>
                <div>
                    <div class="text-xs font-medium text-gray-500 mb-1">Output</div>
                    <pre class="text-xs bg-gray-50 dark:bg-gray-900 rounded p-2 whitespace-pre-wrap break-all overflow-auto max-h-48">{html.escape(output[:1000])}</pre>
                </div>
            </div>
            {f'<div class="mt-3 text-xs p-2 rounded bg-amber-50 dark:bg-amber-900/10 border border-amber-100 dark:border-amber-800/30"><strong>Related static finding:</strong> {html.escape(related[:300])}</div>' if related else ''}
        </div>
    </div>'''


_RENDERERS = {
    "terminal_command": _render_terminal_card,
    "file_operation": _render_file_operation_card,
    "network_request": _render_network_card,
    "tool_call": _render_tool_call_card,
}
