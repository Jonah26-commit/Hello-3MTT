"""
Report Generator
Produces professional security reports from scan detection data.
"""

import json
from datetime import datetime
from utils.colors import Colors


class ReportGenerator:
    def generate(self, detections: list, output: str, fmt: str):
        if fmt == "html":
            self._html(detections, output)
        elif fmt == "json":
            self._json(detections, output)
        elif fmt == "txt":
            self._txt(detections, output)

    def _html(self, detections, output):
        high = [d for d in detections if d["severity"] == "HIGH"]
        medium = [d for d in detections if d["severity"] == "MEDIUM"]
        low = [d for d in detections if d["severity"] == "LOW"]

        rows = ""
        for d in detections:
            color = {"HIGH": "#ff4d4d", "MEDIUM": "#ffaa00", "LOW": "#88cc00"}.get(d["severity"], "#aaa")
            qstatus = "✓ Quarantined" if d.get("quarantined") else "⚠ Active"
            qcolor = "#44cc88" if d.get("quarantined") else "#ff6666"
            threat_list = "<br>".join(f"[{t['type']}] {t['description']}" for t in d["threats"])
            rows += f"""
            <tr>
                <td><code style="font-size:0.85em">{d['filepath']}</code></td>
                <td><span style="color:{color};font-weight:bold">{d['severity']}</span></td>
                <td style="font-size:0.85em">{threat_list}</td>
                <td style="color:{qcolor}">{qstatus}</td>
                <td style="font-size:0.8em;color:#888">{d['timestamp'][:19]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AntiWorm Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; padding: 2rem; }}
  .header {{ border-left: 4px solid #58a6ff; padding: 1rem 1.5rem; margin-bottom: 2rem; background: #161b22; border-radius: 0 8px 8px 0; }}
  .header h1 {{ font-size: 1.8rem; color: #58a6ff; }}
  .header p {{ color: #8b949e; margin-top: 0.3rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: #161b22; border-radius: 8px; padding: 1.2rem; text-align: center; border: 1px solid #30363d; }}
  .stat .num {{ font-size: 2.5rem; font-weight: bold; }}
  .stat .label {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.3rem; }}
  .high .num {{ color: #ff4d4d; }}
  .medium .num {{ color: #ffaa00; }}
  .low .num {{ color: #88cc00; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }}
  th {{ background: #21262d; padding: 0.8rem 1rem; text-align: left; font-size: 0.85rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.8rem 1rem; border-top: 1px solid #21262d; font-size: 0.9rem; vertical-align: top; }}
  tr:hover td {{ background: #1c2128; }}
  .footer {{ margin-top: 2rem; color: #8b949e; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡 AntiWorm Security Report</h1>
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; Total Detections: {len(detections)}</p>
</div>
<div class="stats">
  <div class="stat high"><div class="num">{len(high)}</div><div class="label">HIGH Severity</div></div>
  <div class="stat medium"><div class="num">{len(medium)}</div><div class="label">MEDIUM Severity</div></div>
  <div class="stat low"><div class="num">{len(low)}</div><div class="label">LOW / INFO</div></div>
</div>
<table>
  <thead>
    <tr><th>File Path</th><th>Severity</th><th>Detections</th><th>Status</th><th>Timestamp</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<div class="footer">AntiWorm &mdash; Standalone Worm Detection Tool &mdash; For authorized use only</div>
</body>
</html>"""

        with open(output, "w") as f:
            f.write(html)

    def _json(self, detections, output):
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_detections": len(detections),
            "detections": detections,
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2)

    def _txt(self, detections, output):
        lines = [
            "=" * 60,
            "  ANTIWORM SECURITY REPORT",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Total Detections: {len(detections)}",
            "=" * 60, "",
        ]
        for i, d in enumerate(detections, 1):
            lines.append(f"[{i}] {d['filepath']}")
            lines.append(f"    Severity : {d['severity']}")
            lines.append(f"    Status   : {'Quarantined' if d.get('quarantined') else 'Active'}")
            for t in d["threats"]:
                lines.append(f"    → [{t['type']}] {t['description']}")
            lines.append("")
        with open(output, "w") as f:
            f.write("\n".join(lines))
