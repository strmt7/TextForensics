from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .report import build_forensic_bundle


HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TextForensics</title>
<style>
:root{color-scheme:light dark;--bg:#0b0d10;--panel:#14181d;--muted:#9aa4af;--line:#2a3139;--text:#f4f7fa;--accent:#5bb8ff;--good:#6edb9a;--warn:#ffca6e}
*{box-sizing:border-box} body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:1040px;margin:0 auto;padding:42px 22px 70px} h1{font-size:36px;margin:0 0 4px;letter-spacing:-.03em}.tag{color:var(--muted);margin-bottom:28px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin:14px 0} textarea{width:100%;min-height:250px;resize:vertical;border-radius:12px;border:1px solid var(--line);padding:15px;background:#0f1216;color:var(--text);font:14px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}
button{border:0;border-radius:10px;background:var(--accent);color:#06111a;font-weight:700;padding:11px 18px;cursor:pointer;margin-top:12px}.privacy{font-size:12px;color:var(--muted);margin-left:10px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metric{background:#0f1216;border:1px solid var(--line);border-radius:12px;padding:15px}.label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.value{font-size:24px;font-weight:760;margin-top:5px}.wide{grid-column:span 2}.hidden{display:none}.warning{color:var(--warn)}
table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px} code{font-size:12px}details{margin-top:12px}pre{overflow:auto;white-space:pre-wrap;background:#0f1216;border:1px solid var(--line);border-radius:10px;padding:14px}@media(max-width:760px){.grid{grid-template-columns:1fr 1fr}.wide{grid-column:span 2}}
</style>
</head>
<body><main>
<h1>TextForensics</h1><div class="tag">Cross-examine AI-text detectors. Measure the evidence before trusting the verdict.</div>
<section class="panel"><textarea id="text" placeholder="Paste text here. It stays on this machine."></textarea><br><button id="run">Analyze</button><span class="privacy">Local server · no text is uploaded by the built-in detector</span></section>
<section id="results" class="hidden">
<div class="grid">
  <div class="metric"><div class="label">Consensus</div><div class="value" id="consensus">—</div></div>
  <div class="metric"><div class="label">Evidence grade</div><div class="value" id="grade">—</div></div>
  <div class="metric"><div class="label">Independent families</div><div class="value" id="families">—</div></div>
  <div class="metric"><div class="label">Words</div><div class="value" id="words">—</div></div>
</div>
<section class="panel"><h2>Why this grade?</h2><div id="factors"></div></section>
<section class="panel"><h2>Detector evidence</h2><table><thead><tr><th>Detector</th><th>Family</th><th>Verdict</th><th>Score</th><th>Calibrated probability</th></tr></thead><tbody id="detectors"></tbody></table></section>
<section class="panel"><h2>Warnings</h2><div id="warnings"></div><details><summary>Raw forensic bundle</summary><pre id="raw"></pre></details></section>
</section>
<script>
const $=id=>document.getElementById(id); const esc=s=>String(s??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
$('run').onclick=async()=>{const text=$('text').value.trim();if(!text)return; $('run').disabled=true;$('run').textContent='Analyzing…';try{const r=await fetch('/api/report',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Analysis failed');$('results').classList.remove('hidden');$('consensus').textContent=d.consensus.verdict;$('grade').textContent=d.verdict_integrity.grade;$('families').textContent=d.verdict_integrity.independent_families;$('words').textContent=d.input.word_count;$('factors').innerHTML=d.verdict_integrity.factors.length?d.verdict_integrity.factors.map(x=>`<div>• ${esc(x.replaceAll('_',' '))}</div>`).join(''):'No negative integrity factors.';$('detectors').innerHTML=d.detector_results.map(x=>`<tr><td>${esc(x.detector_id)}<br><code>${esc(x.detector_version)}</code></td><td>${esc(x.detector_family)}</td><td>${esc(x.verdict)}</td><td>${x.score==null?'—':(x.score*100).toFixed(1)+'%'}</td><td>${x.calibrated_ai_probability==null?'—':(x.calibrated_ai_probability*100).toFixed(1)+'%'}</td></tr>`).join('');const warns=[...d.consensus.warnings,...d.detector_results.flatMap(x=>x.warnings||[]),...d.limitations];$('warnings').innerHTML=[...new Set(warns)].map(x=>`<div class="warning">• ${esc(x)}</div>`).join('');$('raw').textContent=JSON.stringify(d,null,2);}catch(e){alert(e.message)}finally{$('run').disabled=false;$('run').textContent='Analyze'}};
</script></main></body></html>'''


def analyze_payload(payload: dict[str, Any]) -> dict[str, Any]:
    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("A non-empty 'text' string is required.")
    return build_forensic_bundle(text).to_dict()


def make_handler():
    class Handler(BaseHTTPRequestHandler):
        server_version = "TextForensics/0.1"

        def _headers(self, status: int, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/", "/index.html"}:
                self._headers(404, "text/plain; charset=utf-8")
                self.wfile.write(b"Not found")
                return
            body = HTML.encode("utf-8")
            self._headers(200, "text/html; charset=utf-8")
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/report":
                self._headers(404, "application/json")
                self.wfile.write(b'{"error":"not found"}')
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 2_000_000:
                    raise ValueError("Request is too large (2 MB limit).")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                result = analyze_payload(payload)
                body = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self._headers(200, "application/json; charset=utf-8")
                self.wfile.write(body)
            except (ValueError, json.JSONDecodeError) as exc:
                body = json.dumps({"error": str(exc)}).encode("utf-8")
                self._headers(400, "application/json; charset=utf-8")
                self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8765, *, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), make_handler())
    url = f"http://{host}:{port}/"
    print(f"TextForensics local UI: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
