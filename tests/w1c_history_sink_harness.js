// Minimal-DOM harness for the IF-05 history sink (W1 Worker C).
//
// Usage:
//   node tests/w1c_history_sink_harness.js <path-to-app.js> '<server-history-item-json>'
//
// Loads the shipped app.js in a vm context with stub DOM elements, drives
// renderServerHistory() with the supplied item, and prints the resulting
// container innerHTML as JSON on stdout.
//
// The stub for document.createElement implements the same textContent ->
// innerHTML escaping contract a real browser element provides (&, <, >),
// so escapeHtml() in app.js behaves as it does in a browser. Attribute
// escaping is app.js's own job (escapeAttr); this harness does NOT escape
// attribute values for it.
//
// No browser is opened and no network is used.
const fs = require('fs');
const vm = require('vm');

const appPath = process.argv[2];
const item = JSON.parse(process.argv[3]);
const source = fs.readFileSync(appPath, 'utf8');

function escapeText(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function makeElement() {
  const el = {
    _html: '',
    _text: '',
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
    addEventListener() {},
    classList: { add() {}, remove() {}, toggle() {} },
    querySelectorAll() {
      return [];
    },
    querySelector() {
      return makeElement();
    },
    dataset: {},
  };
  return el;
}

const historyList = makeElement();

const sandbox = {
  document: {
    getElementById: (id) => (id === 'historyList' ? historyList : makeElement()),
    createElement: () => makeElement(),
    querySelector: () => makeElement(),
    addEventListener() {},
  },
  window: { addEventListener() {} },
  console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

// The driver runs in the SAME script evaluation as app.js, so it can see
// the script-scoped `state` const and call renderServerHistory().
const driver = `\n;state.serverHistory = [${JSON.stringify(item)}];\nrenderServerHistory();\n`;
vm.runInContext(source + driver, sandbox);
process.stdout.write(JSON.stringify({ innerHTML: historyList.innerHTML }));
