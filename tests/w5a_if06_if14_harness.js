// Minimal-DOM + Chart-recorder harness for the W5 web-console fixes
// (IF-06 complete/streaming paths + IF-14 export wiring).
//
// Usage:
//   node tests/w5a_if06_if14_harness.js <path-to-app.js> '<case-json>'
//
// Loads the shipped app.js in a vm context with stub DOM elements and a
// recording Chart stub, drives the named function with the supplied
// bundle, and prints captured outputs as JSON on stdout. Any exception
// thrown by the driven function is captured in `error` (not swallowed
// by the harness) so the test can assert the real UI code runs clean.
//
// Case JSON: {"fn": "complete"|"streaming"|"ws_url"|"export",
//             "bundle": {...}, "extra": {...}}
//   complete:  handleCompleteAnalysis(bundle, 123)
//   streaming: updateStreamingDetectorList(bundle.detector_results)
//   ws_url:    webSocketUrl({protocol, host}) from extra.location
//   export:    exportAnalysis(extra.format); the fetch stub answers
//              with extra.response {contentType, disposition, body}
//              and the harness records the request + download.
//
// No browser is opened and no network is used.
const fs = require('fs');
const vm = require('vm');

const appPath = process.argv[2];
const testCase = JSON.parse(process.argv[3]);
const source = fs.readFileSync(appPath, 'utf8');

function escapeText(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const fillTexts = [];
const chartCreations = [];
const anchorClicks = [];
const fetchCalls = [];
const createdBlobs = [];

function makeCtx() {
  return {
    save() {},
    restore() {},
    fillText(text) {
      fillTexts.push(String(text));
    },
    textAlign: '',
    textBaseline: '',
    font: '',
    fillStyle: '',
  };
}

function makeElement(id, tag) {
  const el = {
    _html: '',
    _text: '',
    _value: '',
    id: id || '',
    tag: tag || 'div',
    style: {},
    dataset: {},
    href: '',
    download: '',
    classList: { add() {}, remove() {}, toggle() {} },
    set innerHTML(v) {
      this._html = String(v);
    },
    get innerHTML() {
      return this._html;
    },
    set textContent(v) {
      this._text = String(v);
      this._html = escapeText(this._text);
    },
    get textContent() {
      return this._text;
    },
    get value() {
      return this._value;
    },
    set value(v) {
      this._value = String(v);
    },
    getContext() {
      return makeCtx();
    },
    addEventListener() {},
    querySelectorAll() {
      return [];
    },
    querySelector() {
      return makeElement();
    },
    scrollIntoView() {},
    click() {
      anchorClicks.push({ href: this.href, download: this.download });
    },
  };
  return el;
}

class RecordingChart {
  constructor(ctx, config) {
    this.ctx = ctx;
    this.config = config;
    this.chartArea = { left: 0, top: 0, width: 200, height: 100 };
    chartCreations.push({
      type: config.type,
      data: config.data,
      options: config.options,
    });
  }
  draw() {}
  update() {}
  destroy() {}
}

class RecordingBlob {
  constructor(parts, options) {
    this.parts = (parts || []).map((p) => String(p));
    this.type = (options && options.type) || '';
    createdBlobs.push({ parts: this.parts, type: this.type });
  }
  async text() {
    return this.parts.join('');
  }
}

const elements = {};
function getElement(id) {
  if (!elements[id]) elements[id] = makeElement(id);
  return elements[id];
}

const extra = testCase.extra || {};
const canned = extra.response || {};
const cannedBlob = new RecordingBlob(
  [canned.body || ''],
  { type: canned.contentType || 'application/octet-stream' }
);
// The canned response blob must not count as a client-constructed Blob.
createdBlobs.length = 0;

async function stubFetch(url, options) {
  fetchCalls.push({ url, options: options || null });
  return {
    ok: true,
    status: 200,
    headers: {
      get(name) {
        const lower = String(name).toLowerCase();
        if (lower === 'content-type') return canned.contentType || null;
        if (lower === 'content-disposition') return canned.disposition || null;
        return null;
      },
    },
    async blob() {
      return cannedBlob;
    },
    async json() {
      return {};
    },
    async text() {
      return canned.body || '';
    },
  };
}

const sandbox = {
  document: {
    getElementById: (id) => getElement(id),
    createElement: (tag) => makeElement('', tag),
    querySelector: () => makeElement(),
    querySelectorAll: () => [],
    addEventListener() {},
    documentElement: {},
  },
  window: {
    addEventListener() {},
    location: { host: 'test.local:8765', protocol: 'https:' },
  },
  Chart: RecordingChart,
  getComputedStyle: () => ({ getPropertyValue: () => '#ffffff' }),
  console,
  URL: { createObjectURL: () => 'blob:fake-url', revokeObjectURL() {} },
  Blob: RecordingBlob,
  alert() {},
  fetch: stubFetch,
  __error: null,
  __p: null,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

const bundle = testCase.bundle || {};
let driver = '';
switch (testCase.fn) {
  case 'complete':
    // Real Chart.js invokes draw() during render; the shipped gauge
    // writes its centre text inside an overridden draw().
    driver = `\n;try { handleCompleteAnalysis(${JSON.stringify(bundle)}, 123); if (state.charts.gauge) state.charts.gauge.draw(); } catch (e) { __error = String(e && e.stack || e); }\n`;
    break;
  case 'streaming':
    driver = `\n;try { updateStreamingDetectorList(${JSON.stringify(bundle.detector_results || [])}); } catch (e) { __error = String(e && e.stack || e); }\n`;
    break;
  case 'ws_url': {
    const loc = extra.location || { protocol: 'https:', host: 'test.local:8765' };
    driver = `\n;try { __wsUrl = webSocketUrl(${JSON.stringify(loc)}); } catch (e) { __error = String(e && e.stack || e); }\n`;
    break;
  }
  case 'export': {
    const fmt = extra.format || 'csv';
    driver =
      `\n;state.currentAnalysis = ${JSON.stringify(bundle)};` +
      `\n;try { const __r = exportAnalysis(${JSON.stringify(fmt)}); __p = __r && typeof __r.catch === 'function' ? __r.catch((e) => { __error = String(e && e.stack || e); }) : Promise.resolve(); } catch (e) { __error = String(e && e.stack || e); }\n`;
    break;
  }
  default:
    throw new Error(`unknown fn: ${testCase.fn}`);
}

vm.runInContext(source + driver, sandbox);

async function finish() {
  if (sandbox.__p) await sandbox.__p;
  const out = {
    error: sandbox.__error,
    wsUrl: sandbox.__wsUrl || null,
    fillTexts,
    charts: chartCreations.map((c) => ({
      type: c.type,
      datasets: (c.data.datasets || []).map((d) => d.data),
      labels: c.data.labels || null,
      datasetLabel: (c.data.datasets || [])[0] && c.data.datasets[0].label,
    })),
    texts: {},
    html: {},
    fetchCalls: fetchCalls.map((c) => ({
      url: c.url,
      method: c.options && c.options.method,
      body: c.options && c.options.body,
      headers: c.options && c.options.headers,
    })),
    anchorClicks,
    createdBlobs,
    responseBlobType: cannedBlob.type,
  };
  for (const [id, el] of Object.entries(elements)) {
    if (el._text) out.texts[id] = el._text;
    if (el._html) out.html[id] = el._html;
  }
  process.stdout.write(JSON.stringify(out));
}

finish().catch((e) => {
  process.stdout.write(JSON.stringify({ error: String((e && e.stack) || e) }));
  process.exitCode = 1;
});
