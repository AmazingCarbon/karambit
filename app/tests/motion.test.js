"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(require.resolve("../ui/app.js"), "utf8");

function node() {
  const classes = new Set();
  return {
    hidden: true, children: [], classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c) },
    replaceChildren(...children) { this.children = children; },
    setAttribute() {},
  };
}

test("navigateFolder plays the list entrance, while renderLists refresh does not", () => {
  const played = [];
  const rows = node();
  const context = vm.createContext({
    currentView: "secrets", currentFolder: "", selectedSecret: null,
    $: (id) => id === "rows" ? rows : { focus() {} },
    playIn: (n) => played.push(n), renderSecrets() {}, renderYoloBanner() {}, renderInspector() {}, renderAwsPage() {},
    document: { querySelectorAll: () => [] },
  });
  vm.runInContext(source.slice(source.indexOf("function renderLists()"), source.indexOf("async function deleteFolder(")), context);
  vm.runInContext('navigateFolder("stripe"); renderLists(); renderLists()', context);
  assert.deepEqual(played, [rows]);
});

test("renderInspector slides in only when the panel was hidden", () => {
  const panel = { ...node(), contains: () => false };
  const played = [];
  const context = vm.createContext({
    $: (id) => id === "inspector" ? panel : {},
    secrets: [{ name: "stripe/key" }], selectedSecret: "stripe/key", renderAwsDetail() {},
    playIn: (...args) => played.push(args),
  });
  // Exercise the real opening/refresh branch before the unchanged content renderer.
  const prefix = source.slice(source.indexOf("function renderInspector()"), source.indexOf('  const close = el("button"', source.indexOf("function renderInspector()")));
  vm.runInContext(`${prefix}\n}`, context);
  vm.runInContext('renderInspector(); renderInspector(); renderInspector()', context);
  assert.deepEqual(played, [[panel, "slide-in"]]);
  vm.runInContext('selectedSecret = null; renderInspector(); selectedSecret = "stripe/key"; renderInspector()', context);
  assert.equal(played.length, 2);
});

test("renderLeaseRows fades only new per-key or YOLO rows, never refreshed rows", () => {
  const nodes = new Map();
  const context = vm.createContext({
    $: (id) => { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); },
    leasesOf: (s) => s.leases || [], yolosFor: (s) => s.yolos || [],
    granteeValue: (to) => to.value, granteeName: (to) => to.value,
    leaseRow: node, yoloAccessRow: node, endAllYolosFor: () => [], detailEndPatterns: () => [], endAllYoloNote: () => "",
    detail: { kind: "secret", name: "stripe/key" }, yoloError: "", MAX_LEASES_PER_SECRET: 8,
  });
  vm.runInContext(source.slice(source.indexOf("function renderLeaseRows("), source.indexOf("// Button and help for the agent chosen")), context);
  const render = (leases, yolos = []) => {
    context.items = [{ name: "stripe/key", leases, yolos }];
    vm.runInContext("renderLeaseRows(items, false)", context);
    return nodes.get("lease-rows").children.map((n) => n.classList.contains("row-in"));
  };
  const lease = (value) => ({ to: { type: "kind", value }, expires: 100 });
  assert.deepEqual(render([lease("pi")]), [false]);
  assert.deepEqual(render([lease("pi")]), [false]);
  assert.deepEqual(render([lease("pi"), lease("claude")]), [false, true]);
  const yolo = { path: "stripe", to: { type: "kind", value: "pi" } };
  assert.deepEqual(render([lease("pi"), lease("claude")], [yolo]), [false, false, true]);
  assert.deepEqual(render([lease("pi"), lease("claude")], [yolo]), [false, false, false]);
  vm.runInContext('detail.name = "stripe/other"', context);
  assert.deepEqual(render([lease("pi")]), [false]);
});

test("playIn removes its entrance class when animation ends", () => {
  const n = node();
  let done;
  n.addEventListener = (name, handler, opts) => { assert.equal(name, "animationend"); assert.equal(opts.once, true); done = handler; };
  const context = vm.createContext({ n });
  vm.runInContext(source.slice(source.indexOf("function playIn("), source.indexOf("function show(")), context);
  vm.runInContext('playIn(n, "slide-in")', context);
  assert.equal(n.classList.contains("slide-in"), true);
  done();
  assert.equal(n.classList.contains("slide-in"), false);
});
