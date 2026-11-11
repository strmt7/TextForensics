// Minimal-DOM + Chart-recorder harness for the IF-04 gauge/probability
// fix (W2 Worker E).
//
// Usage:
//   node tests/w2e_if04_harness.js <path-to-app.js> '<case-json>'
//
// Loads the shipped app.js in a vm context with stub DOM elements and a
// recording Chart stub, drives the probability-rendering functions with
// the supplied bundle, and prints captured outputs as JSON on stdout.
//
// Case JSON: {"fn": "gauge"|"metrics"|"detector_chart"|"verdict"|"compare"|
//             "history"|"detector_list", "bundle": {...}, "extra": {...}}
// No browser is opened and no network is used. The harness records what
// the UI *would* display (gauge dataset, centre text, metric text,
// chart data, rendered HTML) -- it does not execute a real browser.
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

function makeElement(id) {
  const el = {
    _html: '',
    _text: '',
    _value: '',
    id: id || '',
    style: {},
    dataset: {},
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
    click() {},
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

const elements = {};
function getElement(id) {
  if (!elements[id]) elements[id] = makeElement(id);
  return elements[id];
}

const sandbox = {
  document: {
    getElementById: (id) => getElement(id),
    createElement: () => makeElement(),
    querySelector: () => makeElement(),
    querySelectorAll: () => [],
    addEventListener() {},
    documentElement: {},
  },
  window: {
    addEventListener() {},
    location: { host: 'test.local', protocol: 'https:' },
  },
  Chart: RecordingChart,
  getComputedStyle: () => ({ getPropertyValue: () => '#ffffff' }),
  console,
  URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
  Blob: class Blob {},
  alert() {},
  fetch: async () => ({ json: async () => ({}) }),
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

const bundle = testCase.bundle || {};
const extra = testCase.extra || {};
let driver = '';
switch (testCase.fn) {
  case 'gauge':
    // Real Chart.js invokes draw() during render; the shipped gauge
    // writes its centre text inside an overridden draw(), so call it
    // explicitly to capture what would be displayed.
    driver = `\n;renderGaugeChart(${JSON.stringify(bundle)});\n;state.charts.gauge.draw();\n`;
    break;
  case 'metrics':
    driver = `\n;updateMetrics(${JSON.stringify(bundle)}, 123);\n`;
    break;
  case 'detector_chart':
    driver = `\n;renderDetectorChart(${JSON.stringify(bundle.consensus || bundle)});\n`;
    break;
  case 'verdict':
    driver = `\n;renderVerdictDisplay(${JSON.stringify(bundle)});\n`;
    break;
  case 'detector_list':
    driver = `\n;renderDetectorList(${JSON.stringify(bundle.detector_results || [])});\n`;
    break;
  case 'compare': {
    // Compare view needs both analyses on state + compare elements.
    driver =
      `\n;state.currentAnalysis = ${JSON.stringify(bundle)};` +
      `\n;state.secondAnalysis = ${JSON.stringify(extra.second || {})};` +
      `\n;renderCompareView();\n`;
    break;
  }
  case 'history': {
    // Local history path: addToHistory reads elements.textInput.
    driver =
      `\n;elements.textInput.value = ${JSON.stringify(extra.text || 'sample text')};` +
      `\n;addToHistory(${JSON.stringify(bundle)});\n` +
      `\n;renderHistory();\n`;
    break;
  }
  default:
    throw new Error(`unknown fn: ${testCase.fn}`);
}

vm.runInContext(source + driver, sandbox);

const out = {
  fillTexts,
  charts: chartCreations.map((c) => ({
    type: c.type,
    datasets: (c.data.datasets || []).map((d) => d.data),
    labels: c.data.labels || null,
    datasetLabel: (c.data.datasets || [])[0] && c.data.datasets[0].label,
  })),
  texts: {},
  html: {},
};
for (const [id, el] of Object.entries(elements)) {
  if (el._text) out.texts[id] = el._text;
  if (el._html) out.html[id] = el._html;
}
process.stdout.write(JSON.stringify(out));
