from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import ensure_bind_allowed, is_loopback_host, is_unspecified_host, validate_text_input
from .report import build_forensic_bundle

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TextForensics</title>
<style>
:root{color-scheme:light dark;--bg:#0b0d10;--panel:#14181d;--muted:#9aa4af;--line:#2a3139;--text:#f4f7fa;--accent:#5bb8ff;--warn:#ffca6e}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:1040px;margin:0 auto;padding:42px 22px 70px}h1{font-size:36px;margin:0 0 4px;letter-spacing:-.03em}.tag{color:var(--muted);margin-bottom:28px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin:14px 0}textarea{width:100%;min-height:250px;resize:vertical;border-radius:12px;border:1px solid var(--line);padding:15px;background:#0f1216;color:var(--text);font:14px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}
button{border:0;border-radius:10px;background:var(--accent);color:#06111a;font-weight:700;padding:11px 18px;cursor:pointer;margin-top:12px}.privacy{font-size:12px;color:var(--muted);margin-left:10px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metric{background:#0f1216;border:1px solid var(--line);border-radius:12px;padding:15px}.label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.value{font-size:22px;font-weight:760;margin-top:5px}.hidden{display:none}.warning{color:var(--warn)}
table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px}code{font-size:12px}details{margin-top:12px}pre{overflow:auto;white-space:pre-wrap;background:#0f1216;border:1px solid var(--line);border-radius:10px;padding:14px}.state{font-weight:650}@media(max-width:760px){.grid{grid-template-columns:1fr 1fr}}
</style>
</head>
<body><main>
<h1>TextForensics</h1>
<div class="tag">Audit detector evidence before trusting a verdict.</div>
<section class="panel">
<textarea id="text" placeholder="Paste text here. The built-in analysis stays on this machine."></textarea><br>
<button id="run">Analyze</button><span class="privacy">Local-first · no telemetry</span>
</section>
<section id="results" class="hidden">
<div class="grid">
  <div class="metric"><div class="label">Consensus</div><div class="value" id="consensus">—</div></div>
  <div class="metric"><div class="label">Evidence coverage</div><div class="value" id="coverage">—</div></div>
  <div class="metric"><div class="label">Detector families</div><div class="value" id="families">—</div></div>
  <div class="metric"><div class="label">Words</div><div class="value" id="words">—</div></div>
</div>
<section class="panel"><h2>Trust Map</h2><table><thead><tr><th>Dimension</th><th>State</th><th>Reason</th></tr></thead><tbody id="trust"></tbody></table></section>
<section class="panel"><h2>Detector evidence</h2><table><thead><tr><th>Detector</th><th>Family</th><th>Verdict</th><th>Native score</th><th>Calibrated probability</th></tr></thead><tbody id="detectors"></tbody></table></section>
<section class="panel"><h2>Limitations and warnings</h2><div id="warnings"></div>
<details><summary>Legacy alpha integrity diagnostic</summary><pre id="legacy"></pre></details>
<details><summary>Raw forensic bundle</summary><pre id="raw"></pre></details></section>
</section>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
$('run').onclick=async()=>{
 const text=$('text').value.trim();if(!text)return;
 $('run').disabled=true;$('run').textContent='Analyzing…';
 try{
  const r=await fetch('/api/report',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text:text})});
  const d=await r.json();if(!r.ok)throw new Error(d.error||'Analysis failed');
  $('results').classList.remove('hidden');
  $('consensus').textContent=d.consensus.verdict;
  $('coverage').textContent=d.trust_map.overall;
  $('families').textContent=d.consensus.independent_families;
  $('words').textContent=d.input.word_count;
  $('trust').innerHTML=d.trust_map.dimensions.map(function(x){return '<tr><td>'+esc(x.dimension.replaceAll('_',' '))+'</td><td class="state">'+esc(x.state)+'</td><td>'+esc(x.reason)+'</td></tr>';}).join('');
  $('detectors').innerHTML=d.detector_results.map(function(x){return '<tr><td>'+esc(x.detector_id)+'<br><code>'+esc(x.detector_version)+'</code></td><td>'+esc(x.detector_family)+'</td><td>'+esc(x.verdict)+'</td><td>'+(x.score==null?'—':esc(x.score))+'</td><td>'+(x.calibrated_ai_probability==null?'—':(x.calibrated_ai_probability*100).toFixed(1)+'%')+'</td></tr>';}).join('');
  const warns=[...d.consensus.warnings,...d.detector_results.flatMap(x=>x.warnings||[]),...d.limitations];
  $('warnings').innerHTML=[...new Set(warns)].map(function(x){return '<div class="warning">• '+esc(x)+'</div>';}).join('');
  $('legacy').textContent=JSON.stringify(d.verdict_integrity,null,2);
  $('raw').textContent=JSON.stringify(d,null,2);
 }catch(e){alert(e.message)}finally{$('run').disabled=false;$('run').textContent='Analyze'}
};
</script></main></body></html>"""


class TextForensicsHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def analyze_payload(
    payload: dict[str, Any],
    *,
    max_input_bytes: int = 2_000_000,
) -> dict[str, Any]:
    text = payload.get("text")
    validated = validate_text_input(
        text,
        max_input_bytes=max_input_bytes,
    )
    return build_forensic_bundle(validated).to_dict()


def make_handler(*, max_input_bytes: int = 2_000_000):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self) -> str:
            return "TextForensics"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self'; "
                "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'",
            )
            self.send_header(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=()",
            )
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send(
                    200,
                    b'{"status":"ok"}',
                    "application/json; charset=utf-8",
                )
                return
            if self.path not in {"/", "/index.html"}:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/report":
                self._send(
                    404,
                    b'{"error":"not found"}',
                    "application/json; charset=utf-8",
                )
                return

            if self.headers.get("Transfer-Encoding"):
                self._send(
                    400,
                    b'{"error":"chunked request bodies are not supported"}',
                    "application/json; charset=utf-8",
                )
                return

            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._send(
                    411,
                    b'{"error":"content-length required"}',
                    "application/json; charset=utf-8",
                )
                return

            try:
                length = int(raw_length)
                if length < 0 or length > max_input_bytes + 65_536:
                    raise ValueError("Request body is too large.")
                raw = self.rfile.read(length)
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("JSON body must be an object.")
                result = analyze_payload(
                    payload,
                    max_input_bytes=max_input_bytes,
                )
                body = json.dumps(
                    result,
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self._send(
                    400,
                    b'{"error":"invalid request"}',
                    "application/json; charset=utf-8",
                )

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    open_browser: bool = True,
    allow_remote: bool = False,
    max_input_bytes: int = 2_000_000,
) -> None:
    ensure_bind_allowed(host, allow_remote=allow_remote)
    server = TextForensicsHTTPServer(
        (host, port),
        make_handler(max_input_bytes=max_input_bytes),
    )
    display_host = "127.0.0.1" if is_unspecified_host(host) else host
    url = f"http://{display_host}:{port}/"
    print(f"TextForensics UI: {url}")
    if not is_loopback_host(host):
        print(
            "Warning: network-visible browser UI enabled explicitly. "
            "Place it behind appropriate access controls in shared environments."
        )
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
