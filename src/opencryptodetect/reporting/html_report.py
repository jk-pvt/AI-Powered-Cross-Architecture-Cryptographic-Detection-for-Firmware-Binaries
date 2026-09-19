"""Standalone local HTML report generator with embedded styles and zero external dependencies."""

from pathlib import Path

from jinja2 import Template

from opencryptodetect.cli.formatting import format_size
from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.version import __version__

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenCryptoDetect Report - {{ ctx.file_path.name }}</title>
<style>
  :root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-card: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --accent-hover: #0ea5e9;
    --danger: #ef4444;
    --warning: #f59e0b;
    --success: #10b981;
    --border: #475569;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    margin: 0;
    padding: 2rem;
    line-height: 1.6;
  }
  .container {
    max-width: 1200px;
    margin: 0 auto;
  }
  header {
    border-bottom: 2px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h1, h2, h3 {
    margin: 0 0 1rem 0;
    color: var(--text-primary);
  }
  h1 { font-size: 2rem; display: flex; align-items: center; gap: 0.5rem; }
  .badge {
    font-size: 0.85rem;
    padding: 0.25rem 0.6rem;
    border-radius: 9999px;
    background-color: var(--accent);
    color: #0f172a;
    font-weight: 600;
  }
  .badge-danger { background-color: var(--danger); color: white; }
  .badge-warning { background-color: var(--warning); color: #0f172a; }
  .badge-success { background-color: var(--success); color: white; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
  }
  .card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.5rem;
  }
  .card-title {
    font-size: 1rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.5rem;
  }
  .card-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 2rem;
    background-color: var(--bg-secondary);
    border-radius: 0.5rem;
    overflow: hidden;
  }
  th, td {
    padding: 0.9rem 1.2rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  th {
    background-color: #1a2333;
    color: var(--text-secondary);
    font-size: 0.85rem;
    text-transform: uppercase;
  }
  tr:last-child td { border-bottom: none; }
  .evidence-list {
    margin: 0;
    padding-left: 1.2rem;
    font-size: 0.9rem;
    color: var(--text-secondary);
  }
  .evidence-list li { margin-bottom: 0.3rem; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  .section-block {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>OpenCryptoDetect <span class="badge">v{{ version }}</span></h1>
      <div style="color: var(--text-secondary)">Cross-Architecture Cryptographic Primitive Detection</div>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 0.9rem; color: var(--text-secondary);">Target Binary</div>
      <div style="font-size: 1.2rem; font-weight: 600;">{{ ctx.file_path.name }}</div>
    </div>
  </header>

  <!-- 1. Metadata & Analysis Summary Cards -->
  <div class="grid">
    <div class="card">
      <div class="card-title">Architecture</div>
      <div class="card-value">{{ ctx.architecture|upper }} ({{ ctx.bitness }}-bit)</div>
      <div style="font-size: 0.85rem; color: var(--text-secondary)">Endianness: {{ ctx.endianness }}</div>
    </div>
    <div class="card">
      <div class="card-title">Functions Analyzed</div>
      <div class="card-value">{{ ctx.functions|length }}</div>
      <div style="font-size: 0.85rem; color: var(--text-secondary)">Format: {{ ctx.file_format }}</div>
    </div>
    <div class="card">
      <div class="card-title">Crypto Findings</div>
      <div class="card-value">{{ ctx.findings|length }}</div>
      <div style="font-size: 0.85rem; color: var(--text-secondary)">Duration: {{ "%.3f"|format(ctx.timing.total_seconds) }}s</div>
    </div>
    <div class="card">
      <div class="card-title">File Size</div>
      <div class="card-value">{{ format_size(ctx.file_size_bytes) }}</div>
      <div style="font-size: 0.75rem; color: var(--text-secondary); word-break: break-all;">{{ ctx.file_sha256[:20] }}...</div>
    </div>
  </div>

  <!-- 2. Cryptographic Inventory Table -->
  <h2>Cryptographic Inventory</h2>
  <table>
    <thead>
      <tr>
        <th>Algorithm</th>
        <th>Primitive</th>
        <th>Location</th>
        <th>Confidence</th>
        <th>Methods</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      {% for f in ctx.findings %}
      <tr>
        <td><strong>{{ f.algorithm }}</strong></td>
        <td>{{ f.primitive_type }}</td>
        <td class="mono">0x{{ "%x"|format(f.address) }} ({{ f.function_name }})</td>
        <td>
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <div style="background-color: var(--card); width: 60px; height: 8px; border-radius: 4px; overflow: hidden;">
              <div style="width: {{ f.confidence * 100 }}%; height: 100%; background-color: var(--accent);"></div>
            </div>
            <span>{{ "%.2f"|format(f.confidence) }}</span>
          </div>
        </td>
        <td>{{ f.detection_methods|join(', ') }}</td>
        <td>
          {% if f.security_status in ['weak', 'insecure'] %}
            <span class="badge badge-danger">{{ f.security_status|upper }}</span>
          {% elif f.security_status == 'deprecated' %}
            <span class="badge badge-warning">DEPRECATED</span>
          {% elif f.security_status == 'non-cryptographic' %}
            <span class="badge" style="background-color: #64748b; color: white;">CHECKSUM</span>
          {% else %}
            <span class="badge badge-success">SECURE</span>
          {% endif %}
        </td>
      </tr>
      {% else %}
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 2rem;">
          No cryptographic primitives detected.
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <!-- 3. Individual Findings & Explainability -->
  {% if ctx.findings %}
  <h2>Detailed Findings & Explainability</h2>
  {% for f in ctx.findings %}
  <div class="section-block">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.8rem;">
      <h3 style="margin: 0; color: var(--accent);">{{ f.algorithm }} at 0x{{ "%x"|format(f.address) }}</h3>
      <span class="badge">Confidence {{ "%.2f"|format(f.confidence) }}</span>
    </div>
    {% if f.security_note %}
    <div style="background-color: rgba(239, 68, 68, 0.1); border-left: 4px solid var(--danger); padding: 0.8rem; margin-bottom: 1rem; border-radius: 4px; color: #fca5a5;">
      <strong>Security Advisory:</strong> {{ f.security_note }}
    </div>
    {% endif %}
    <div style="font-weight: 600; margin-bottom: 0.4rem;">Evidence:</div>
    <ul class="evidence-list">
      {% for ev in f.evidence %}
      <li>{{ ev }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endfor %}
  {% endif %}

  <!-- 4. Library Fingerprinting -->
  {% if ctx.library_candidates %}
  <h2>Library Fingerprints</h2>
  <div class="section-block">
    {% for lib in ctx.library_candidates %}
    <div style="margin-bottom: 1rem;">
      <div style="display: flex; justify-content: space-between; font-weight: 600;">
        <span>{{ lib.library_name }}</span>
        <span style="color: var(--accent)">Confidence: {{ "%.2f"|format(lib.confidence) }}</span>
      </div>
      <ul class="evidence-list" style="margin-top: 0.4rem;">
        {% for ev in lib.evidence %}
        <li>{{ ev }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- 5. Methodology & Limitations -->
  <h2>Methodology & Limitations</h2>
  <div class="section-block" style="color: var(--text-secondary); font-size: 0.95rem;">
    <p><strong>Methodology:</strong> OpenCryptoDetect evaluates binary artifacts using a multi-stage pipeline combining Capstone linear/recursive disassembly, basic block CFG topological loop analysis, deterministic S-box/constant matching, ARX operation densities, and trained ML classifiers.</p>
    <p><strong>Limitations:</strong> Static binary analysis cannot account for heavy runtime packing, virtualization, or dynamic in-memory code generation. Findings reflect statically recovered symbols, instructions, and referenced tables.</p>
  </div>
</div>
</body>
</html>
"""


def generate_html_report(ctx: AnalysisContext, output_path: Path) -> Path:
    """Render and write standalone HTML report."""
    tmpl = Template(HTML_TEMPLATE)
    html_content = tmpl.render(
        ctx=ctx,
        version=__version__,
        format_size=format_size,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
