#!/usr/bin/env python3
"""Generate Skill Guard PRD documentation site from markdown files.
Uses the same Shadcn/ui design system as the audit report.
"""

import html as H
import re
from pathlib import Path

PRD_DIR = Path(__file__).parent.parent / "docs" / "prd"
OUTPUT = PRD_DIR / "index.html"


# ── Markdown → HTML ─────────────────────────────────────────────────────────

def inline(text: str) -> str:
    """Convert inline markdown."""
    t = H.escape(text)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", t)
    t = re.sub(r"`(.+?)`", r'<code>\1</code>', t)
    t = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2" target="_blank">\1</a>', t)
    # arrows
    t = t.replace("→", "&rarr;").replace("←", "&larr;")
    return t


def md2html(md: str, skip_h1: bool = True) -> str:
    """Convert markdown to HTML."""
    lines = md.split("\n")
    out = []
    in_code = False
    in_ul = False
    in_ol = False
    in_table = False
    first_h1 = True

    def close_list():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    def close_table():
        nonlocal in_table
        if in_table:
            out.append("</tbody></table></div>")
            in_table = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # ── Code block ──
        if line.strip().startswith("```"):
            if not in_code:
                close_list()
                close_table()
                in_code = True
                lang = line.strip()[3:].strip()
                cls = f' class="lang-{H.escape(lang)}"' if lang else ""
                out.append(f'<div class="code-wrap"><pre><code{cls}>')
                i += 1
                continue
            else:
                in_code = False
                out.append("</code></pre></div>")
                i += 1
                continue
        if in_code:
            out.append(H.escape(line))
            i += 1
            continue

        # ── Empty line ──
        if not line.strip():
            close_list()
            i += 1
            continue

        # ── Headings ──
        hm = re.match(r"^(#{1,4})\s+(.+)", line)
        if hm:
            close_list()
            close_table()
            level = len(hm.group(1))
            text = hm.group(2).strip()
            if level == 1 and skip_h1 and first_h1:
                first_h1 = False
                i += 1
                continue
            tag = f"h{min(level + 1, 4)}"  # h1→h2, h2→h3, etc.
            cls = f"doc-h{min(level + 1, 4)}"
            out.append(f'<{tag} class="{cls}">{inline(text)}</{tag}>')
            i += 1
            continue

        # ── Table ──
        if line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not in_table:
                close_list()
                in_table = True
                out.append('<div class="table-wrap"><table><thead><tr>')
                for c in cells:
                    out.append(f"<th>{inline(c)}</th>")
                out.append("</tr></thead><tbody>")
                # skip separator
                if i + 1 < len(lines) and re.match(r"^\|[\s\-:|]+\|?$", lines[i + 1].strip()):
                    i += 2
                else:
                    i += 1
                continue
            else:
                if re.match(r"^[\s\-:|]+$", line.replace("|", "")):
                    i += 1
                    continue
                out.append("<tr>")
                for c in cells:
                    out.append(f"<td>{inline(c)}</td>")
                out.append("</tr>")
                i += 1
                continue

        # Close table if not table line
        close_table()

        # ── Horizontal rule ──
        if re.match(r"^---+$", line.strip()):
            close_list()
            out.append('<hr class="doc-hr">')
            i += 1
            continue

        # ── Checkbox list ──
        cm = re.match(r"^(\s*)- \[([ x])\]\s+(.+)", line)
        if cm:
            if not in_ul:
                in_ul = True
                out.append('<ul class="checklist">')
            checked = " checked" if cm.group(2) == "x" else ""
            out.append(f'<li><input type="checkbox"{checked} disabled><span>{inline(cm.group(3))}</span></li>')
            i += 1
            continue

        # ── Unordered list ──
        um = re.match(r"^(\s*)[-*]\s+(.+)", line)
        if um:
            if not in_ul:
                close_list()
                in_ul = True
                out.append('<ul class="doc-ul">')
            out.append(f"<li>{inline(um.group(2))}</li>")
            i += 1
            continue

        # ── Ordered list ──
        om = re.match(r"^(\s*)\d+\.\s+(.+)", line)
        if om:
            if not in_ol:
                close_list()
                in_ol = True
                out.append('<ol class="doc-ol">')
            out.append(f"<li>{inline(om.group(2))}</li>")
            i += 1
            continue

        # Close lists if not list item
        close_list()

        # ── Blockquote ──
        if line.strip().startswith("> "):
            text = line.strip()[2:]
            out.append(f'<blockquote class="doc-quote">{inline(text)}</blockquote>')
            i += 1
            continue

        # ── Paragraph ──
        out.append(f"<p>{inline(line.strip())}</p>")
        i += 1

    close_list()
    close_table()
    if in_code:
        out.append("</code></pre></div>")

    return "\n".join(out)


# ── Read PRD files ──────────────────────────────────────────────────────────

def load_prds():
    docs = []
    for f in sorted(PRD_DIR.glob("PRD-*.md")):
        content = f.read_text(encoding="utf-8")
        title_m = re.match(r"^#\s+(.+)", content)
        title = title_m.group(1) if title_m else f.stem
        parts = f.stem.split("-", 2)
        short_id = f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else f.stem
        subtitle = title.split(":", 1)[1].strip() if ":" in title else title
        # Phase label
        phase_map = {
            "001": "Overview", "002": "UX Flow", "003": "Phase 1",
            "004": "Phase 2", "005": "Phase 3", "006": "Phase 4",
            "007": "Architecture", "008": "Roadmap",
        }
        phase = phase_map.get(parts[1], "") if len(parts) >= 2 else ""
        docs.append({
            "id": f.stem.lower(),
            "short_id": short_id.upper(),
            "title": title,
            "subtitle": subtitle,
            "phase": phase,
            "body_html": md2html(content),
        })
    return docs


# ── Generate HTML ───────────────────────────────────────────────────────────

def generate():
    docs = load_prds()

    nav_items = "\n".join(
        f'<button class="nav-btn" data-doc="{d["id"]}">'
        f'<span class="nav-badge">{H.escape(d["short_id"])}</span>'
        f'<span class="nav-text">{H.escape(d["subtitle"])}</span>'
        f'</button>'
        for d in docs
    )

    mobile_pills = "\n".join(
        f'<button class="pill" data-doc="{d["id"]}">{H.escape(d["short_id"])}</button>'
        for d in docs
    )

    sections = "\n".join(
        f'<article class="doc" id="{d["id"]}">'
        f'<div class="doc-head">'
        f'<div class="doc-meta"><span class="badge-blue">{H.escape(d["short_id"])}</span>'
        f'<span class="badge-muted">{H.escape(d["phase"])}</span></div>'
        f'<h1 class="doc-h1">{H.escape(d["subtitle"])}</h1>'
        f'</div>'
        f'<div class="doc-content">{d["body_html"]}</div>'
        f'</article>'
        for d in docs
    )

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Skill Guard — Product Requirements</title>
<script>
(function(){{var t=localStorage.getItem('audit-theme');
if(t==='light')document.documentElement.classList.remove('dark');
else document.documentElement.classList.add('dark');}})();
</script>
<style>
/* ── Design Tokens (Light) ─────────────────────────────────────── */
:root {{
  --background: 0 0% 100%;
  --foreground: 0 0% 3.9%;
  --card: 0 0% 100%;
  --card-foreground: 0 0% 3.9%;
  --popover: 0 0% 100%;
  --popover-foreground: 0 0% 3.9%;
  --primary: 0 0% 9%;
  --primary-foreground: 0 0% 98%;
  --secondary: 0 0% 96.1%;
  --secondary-foreground: 0 0% 9%;
  --muted: 0 0% 96.1%;
  --muted-foreground: 0 0% 45.1%;
  --accent: 0 0% 96.1%;
  --accent-foreground: 0 0% 9%;
  --destructive: 0 84.2% 60.2%;
  --border: 0 0% 89.8%;
  --input: 0 0% 89.8%;
  --ring: 0 0% 3.9%;
  --radius: 0.5rem;
  --success: 142 76% 36%;
  --warning: 38 92% 50%;
  --info: 217 91% 60%;
  --card-shadow: 0 0% 0% / 0.08;
  --sidebar-w: 280px;
}}

/* ── Design Tokens (Dark) ──────────────────────────────────────── */
.dark {{
  --background: 0 0% 3.9%;
  --foreground: 0 0% 98%;
  --card: 0 0% 5.5%;
  --card-foreground: 0 0% 98%;
  --popover: 0 0% 5.5%;
  --popover-foreground: 0 0% 98%;
  --primary: 0 0% 98%;
  --primary-foreground: 0 0% 9%;
  --secondary: 0 0% 14.9%;
  --secondary-foreground: 0 0% 98%;
  --muted: 0 0% 14.9%;
  --muted-foreground: 0 0% 63.9%;
  --accent: 0 0% 14.9%;
  --accent-foreground: 0 0% 98%;
  --border: 0 0% 14.9%;
  --input: 0 0% 14.9%;
  --ring: 0 0% 83.1%;
  --card-shadow: 0 0% 0% / 0.15;
}}

/* ── Reset & Base ──────────────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: hsl(var(--background));
  color: hsl(var(--foreground));
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}}
a {{ color: hsl(var(--info)); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* ── Layout ────────────────────────────────────────────────────── */
.shell {{ display: flex; min-height: 100vh; }}

/* ── Sidebar ───────────────────────────────────────────────────── */
.sidebar {{
  width: var(--sidebar-w); position: fixed; top: 0; left: 0; bottom: 0;
  overflow-y: auto; background: hsl(var(--card));
  border-right: 1px solid hsl(var(--border)); z-index: 20;
  display: flex; flex-direction: column;
}}
.side-head {{
  padding: 1.5rem 1.25rem 1rem; border-bottom: 1px solid hsl(var(--border));
}}
.side-logo {{
  display: flex; align-items: center; gap: 0.5rem;
  font-size: 1.0625rem; font-weight: 700; letter-spacing: -0.03em;
  color: hsl(var(--foreground));
}}
.side-logo svg {{ width: 20px; height: 20px; color: hsl(var(--info)); }}
.side-sub {{
  font-size: 0.6875rem; color: hsl(var(--muted-foreground));
  text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500;
  margin-top: 0.25rem;
}}
.side-actions {{
  display: flex; gap: 0.375rem; padding: 0.75rem 1.25rem;
  border-top: 1px solid hsl(var(--border)); margin-top: auto;
}}
.side-nav {{ flex: 1; overflow-y: auto; padding: 0.5rem 0; }}

.nav-btn {{
  display: flex; align-items: center; gap: 0.625rem;
  width: 100%; padding: 0.5rem 1.25rem; border: none; background: none;
  cursor: pointer; color: hsl(var(--muted-foreground)); font: inherit;
  font-size: 0.8125rem; text-align: left; transition: all 0.15s;
  border-left: 2px solid transparent;
}}
.nav-btn:hover {{
  color: hsl(var(--foreground)); background: hsl(var(--muted) / 0.5);
}}
.nav-btn.active {{
  color: hsl(var(--foreground)); background: hsl(var(--info) / 0.08);
  border-left-color: hsl(var(--info)); font-weight: 500;
}}
.nav-badge {{
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.625rem; font-weight: 600; color: hsl(var(--info));
  background: hsl(var(--info) / 0.1); padding: 0.125rem 0.375rem;
  border-radius: 4px; flex-shrink: 0; letter-spacing: 0.02em;
}}
.nav-text {{
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}}

/* ── Main Content ──────────────────────────────────────────────── */
.main {{
  margin-left: var(--sidebar-w); flex: 1;
  padding: 2.5rem 3rem; max-width: 820px;
}}

/* ── Document Sections ─────────────────────────────────────────── */
.doc {{ display: none; animation: fadeIn 0.25s ease; }}
.doc.active {{ display: block; }}
@keyframes fadeIn {{
  from {{ opacity: 0; transform: translateY(6px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}

.doc-head {{
  margin-bottom: 2rem; padding-bottom: 1.25rem;
  border-bottom: 1px solid hsl(var(--border));
}}
.doc-meta {{ display: flex; gap: 0.5rem; margin-bottom: 0.625rem; }}
.badge-blue {{
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.6875rem; font-weight: 600;
  padding: 0.2rem 0.55rem; border-radius: 9999px;
  background: hsl(var(--info) / 0.12); color: hsl(var(--info));
}}
.badge-muted {{
  font-size: 0.6875rem; font-weight: 500;
  padding: 0.2rem 0.55rem; border-radius: 9999px;
  background: hsl(var(--muted)); color: hsl(var(--muted-foreground));
}}
.doc-h1 {{
  font-size: 1.75rem; font-weight: 700; letter-spacing: -0.03em;
  line-height: 1.25; color: hsl(var(--foreground));
}}

/* ── Typography ────────────────────────────────────────────────── */
.doc-content p {{
  margin-bottom: 0.75rem; font-size: 0.875rem; line-height: 1.7;
  color: hsl(var(--foreground));
}}
.doc-h2 {{
  font-size: 1.125rem; font-weight: 600; letter-spacing: -0.02em;
  margin: 2rem 0 0.75rem; padding-bottom: 0.5rem;
  border-bottom: 1px solid hsl(var(--border));
  color: hsl(var(--foreground));
}}
.doc-h3 {{
  font-size: 0.9375rem; font-weight: 600; margin: 1.5rem 0 0.5rem;
  color: hsl(var(--foreground));
}}
.doc-h4 {{
  font-size: 0.875rem; font-weight: 600; margin: 1rem 0 0.375rem;
  color: hsl(var(--foreground));
}}
.doc-h5 {{ font-size: 0.8125rem; font-weight: 600; margin: 0.75rem 0 0.25rem; }}
code {{
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 0.8em; background: hsl(var(--muted));
  padding: 0.125rem 0.375rem; border-radius: 3px;
}}

/* ── Code Block ────────────────────────────────────────────────── */
.code-wrap {{
  margin: 0.75rem 0; border-radius: var(--radius);
  border: 1px solid hsl(var(--border));
  background: hsl(var(--muted) / 0.5); overflow: hidden;
}}
.code-wrap pre {{
  padding: 1rem 1.25rem; overflow-x: auto; margin: 0;
  font-family: "SF Mono", SFMono-Regular, ui-monospace, Menlo, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 0.8125rem; line-height: 1.55; white-space: pre;
  color: hsl(var(--foreground)); tab-size: 4;
  -webkit-text-size-adjust: none;
}}
.code-wrap code {{ background: none; padding: 0; font-size: inherit; }}

/* ── Tables ────────────────────────────────────────────────────── */
.table-wrap {{
  overflow-x: auto; margin: 0.75rem 0;
  border: 1px solid hsl(var(--border)); border-radius: var(--radius);
}}
table {{
  width: 100%; border-collapse: collapse; font-size: 0.8125rem;
}}
th {{
  text-align: left; font-weight: 500; color: hsl(var(--muted-foreground));
  padding: 0.625rem 0.875rem; border-bottom: 1px solid hsl(var(--border));
  font-size: 0.75rem; background: hsl(var(--muted) / 0.3);
}}
td {{
  padding: 0.625rem 0.875rem;
  border-bottom: 1px solid hsl(var(--border) / 0.5);
  vertical-align: top;
}}
tbody tr {{ transition: background 0.1s; }}
tbody tr:hover {{ background: hsl(var(--muted) / 0.3); }}
tbody tr:last-child td {{ border-bottom: none; }}

/* ── Lists ─────────────────────────────────────────────────────── */
.doc-ul, .doc-ol {{
  margin: 0.5rem 0 0.75rem 1.5rem; font-size: 0.875rem;
}}
.doc-ul li, .doc-ol li {{
  margin-bottom: 0.3rem; line-height: 1.6;
  padding-left: 0.25rem;
}}
.checklist {{
  list-style: none; margin: 0.5rem 0 0.75rem 0; font-size: 0.875rem;
}}
.checklist li {{
  display: flex; align-items: center; gap: 0.5rem;
  margin-bottom: 0.25rem; line-height: 1.5;
}}
.checklist input[type="checkbox"] {{ accent-color: hsl(var(--info)); }}

/* ── Blockquote ────────────────────────────────────────────────── */
.doc-quote {{
  border-left: 3px solid hsl(var(--info) / 0.4);
  padding: 0.625rem 1rem; margin: 0.75rem 0;
  background: hsl(var(--info) / 0.04);
  border-radius: 0 var(--radius) var(--radius) 0;
  font-size: 0.875rem; color: hsl(var(--muted-foreground));
}}
.doc-hr {{
  border: none; border-top: 1px solid hsl(var(--border)); margin: 1.75rem 0;
}}

/* ── Buttons ───────────────────────────────────────────────────── */
.btn-icon {{
  display: inline-flex; align-items: center; justify-content: center;
  width: 2rem; height: 2rem; border-radius: var(--radius);
  border: 1px solid hsl(var(--border)); background: hsl(var(--card));
  color: hsl(var(--muted-foreground)); cursor: pointer;
  transition: all 0.15s; flex-shrink: 0;
}}
.btn-icon:hover {{
  background: hsl(var(--accent)); color: hsl(var(--accent-foreground));
  border-color: hsl(var(--ring) / 0.3);
}}
.btn-icon svg {{ width: 14px; height: 14px; }}
.btn-icon .icon-sun {{ display: none; }}
.btn-icon .icon-moon {{ display: block; }}
.dark .btn-icon .icon-sun {{ display: block; }}
.dark .btn-icon .icon-moon {{ display: none; }}

/* ── Mobile ────────────────────────────────────────────────────── */
.mobile-bar {{
  display: none; position: sticky; top: 0; z-index: 15;
  background: hsl(var(--card)); border-bottom: 1px solid hsl(var(--border));
  padding: 0.625rem 1rem; overflow-x: auto; white-space: nowrap;
  gap: 0.375rem;
}}
.pill {{
  padding: 0.3rem 0.625rem; border-radius: 9999px;
  border: 1px solid hsl(var(--border)); background: none;
  color: hsl(var(--muted-foreground)); font-size: 0.6875rem;
  font-weight: 600; cursor: pointer; white-space: nowrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}}
.pill.active {{
  background: hsl(var(--info) / 0.1); color: hsl(var(--info));
  border-color: hsl(var(--info) / 0.3);
}}
@media (max-width: 768px) {{
  .sidebar {{ display: none; }}
  .main {{ margin-left: 0; padding: 1.5rem 1rem; }}
  .mobile-bar {{ display: flex; }}
  .doc-h1 {{ font-size: 1.375rem; }}
}}

/* ── Footer ────────────────────────────────────────────────────── */
.doc-foot {{
  margin-top: 3rem; padding-top: 1rem;
  border-top: 1px solid hsl(var(--border));
  font-size: 0.75rem; color: hsl(var(--muted-foreground));
}}
</style>
</head>
<body>
<div class="shell">

<!-- Sidebar -->
<nav class="sidebar">
  <div class="side-head">
    <div class="side-logo">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Skill Guard
    </div>
    <div class="side-sub">Product Requirements Document</div>
  </div>
  <div class="side-nav">
{nav_items}
  </div>
  <div class="side-actions">
    <button class="btn-icon" id="themeBtn" title="Toggle theme">
      <svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
    </button>
  </div>
</nav>

<!-- Mobile Nav -->
<div class="mobile-bar">
{mobile_pills}
</div>

<!-- Main -->
<main class="main">
{sections}
<div class="doc-foot">Skill Guard PRD &middot; {len(docs)} documents</div>
</main>

</div>
<script>
(function(){{
  var html=document.documentElement;
  document.getElementById('themeBtn').addEventListener('click',function(){{
    var d=html.classList.toggle('dark');
    localStorage.setItem('audit-theme',d?'dark':'light');
  }});
  var btns=document.querySelectorAll('[data-doc]');
  var docs=document.querySelectorAll('.doc');
  function go(id){{
    docs.forEach(function(d){{d.classList.toggle('active',d.id===id)}});
    btns.forEach(function(b){{b.classList.toggle('active',b.dataset.doc===id)}});
    history.replaceState(null,null,'#'+id);
  }}
  btns.forEach(function(b){{
    b.addEventListener('click',function(){{go(b.dataset.doc);window.scrollTo(0,0)}});
  }});
  go(location.hash.slice(1)||docs[0].id);
}})();
</script>
</body>
</html>'''

    OUTPUT.write_text(html, encoding="utf-8")
    print(f"Generated: {OUTPUT} ({len(html):,} bytes, {len(docs)} documents)")


if __name__ == "__main__":
    generate()
