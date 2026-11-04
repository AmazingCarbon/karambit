// Source-named tests for YOLO metadata selection. No mock backend ships in the app.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(require.resolve("../ui/app.js"), "utf8");
function ui(yolos) {
  const context = vm.createContext({ yolos, yoloError: "", Date, el: (tag, attrs) => ({ tag, ...attrs }), endsAt: (ts) => `ends time:${ts}` });
  vm.runInContext(source.slice(source.indexOf("const folderYolos ="), source.indexOf("function renderYoloBanner()")), context);
  return (expression) => vm.runInContext(expression, context);
}
const now = Date.now() / 1000;
const access = (extra = {}) => ({ expires: now + 3600, granted: now - 60, to_label: "pi agents", covered: ["stripe/key"], added: ["stripe/key"], ...extra });
test("yoloOf requires verified coverage and a live access", () => {
  const run = ui({ stripe: [access(), access({ covered: ["stripe/other"], expires: now - 1 })] });
  assert.equal(run('yoloOf("stripe/key").to_label'), "pi agents");
  assert.equal(run('yoloOf("stripe/other")'), null);
  assert.equal(run('yoloOf("stripe/unobserved")'), null);
  assert.equal(ui({ stripe: [access({ covered: undefined })] })('yoloOf("stripe/key")'), null);
});
test("soonestYolo picks the soonest end across agents on one folder", () => {
  const run = ui({ stripe: [access({ expires: now + 7200 }), access({ expires: now + 1800, to_label: "claude agents" })] });
  assert.equal(run('folderYolos("stripe").length'), 2);
  assert.equal(run('soonestYolo("stripe").to_label'), "claude agents");
});
test("yoloTag never tags Public and yoloAdded requires coverage", () => {
  const run = ui({ stripe: [access()] });
  assert.equal(run('yoloTag({ name: "stripe/key", public: true })'), null);
  assert.equal(run('yoloTag({ name: "stripe/key" }).textContent'), "YOLO · no prompt");
  assert.equal(run(`yoloAdded({ name: "stripe/key", created: ${now} }).textContent`), "Added while YOLO is on");
  assert.equal(run(`yoloAdded({ name: "stripe/unobserved", created: ${now} })`), null);
  const overlap = ui({ stripe: [access({ expires: now + 60, added: [] }), access()] });
  assert.equal(overlap('yoloAdded({ name: "stripe/key" }).textContent'), "Added while YOLO is on");
});
test("the shipped document does not load the prototype backend", () => {
  const html = fs.readFileSync(require.resolve("../ui/index.html"), "utf8");
  assert.doesNotMatch(html, /mock-tauri/);
  assert.match(html, /Agent access does not end on screen lock\./);
});

// Exercise the inspector's actual row renderer and End callbacks without shipping a mock backend.
function inspector(yolos, extra = {}) {
  const requests = [];
  let refreshes = 0;
  const context = vm.createContext({
    yolos, yoloError: "", Date,
    el: (tag, attrs = {}, ...children) => ({ tag, ...attrs, children }),
    fullTime: (ts) => `time:${ts}`, endsAt: (ts) => `ends time:${ts}`,
    granteeName: (to) => to.value || "Any agent",
    durShort: () => "1h", scopeLabel: () => "", leasesOf: (s) => s.leases || [],
    call: async (command, args) => { requests.push({ command, args }); },
    loadSecrets: async () => { refreshes++; },
    endYolo: async (path, ctl, to) => { requests.push({ command: "yolo_end", args: { path, to } }); refreshes++; },
    ...extra,
  });
  vm.runInContext(source.slice(source.indexOf("const folderYolos ="), source.indexOf("function renderYoloBanner()")), context);
  vm.runInContext(source.slice(source.indexOf("function inspectorTemporaryAccess("), source.indexOf("function renderInspector()")), context);
  return { run: (expr) => vm.runInContext(expr, context), requests, refreshes: () => refreshes };
}
const treeText = (node) => typeof node === "string" ? node : [node.textContent || "", ...(node.children || []).map(treeText)].join(" ");
const yoloRecord = () => access({ path: "stripe", to: { type: "kind", value: "claude" } });
test("renderInspector YOLO-only rows name folder, agent, end time and scoped End", async () => {
  const fixture = inspector({ stripe: [yoloRecord()] });
  const rows = fixture.run('inspectorTemporaryAccess({ name: "stripe/key" })');
  assert.equal(rows.length, 1);
  assert.match(treeText(rows[0]), /YOLO.*stripe\/ · claude.*No prompt · ends time:/);
  assert.doesNotMatch(treeText(rows[0]), /No temporary access/);
  const end = rows[0].children[1];
  assert.equal(end["aria-label"], "End YOLO for claude to stripe/");
  await end.onclick();
  assert.equal(JSON.stringify(fixture.requests), JSON.stringify([{ command: "yolo_end", args: { path: "stripe", to: { type: "kind", value: "claude" } } }]));
  assert.equal(fixture.refreshes(), 1);
  assert.match(fixture.run('yoloOverride({ name: "stripe/key" })'), /YOLO on stripe\/ · claude: no prompt · ends time:/);
});
test("renderInspector mixed rows retain YOLO after ending per-key access", async () => {
  const fixture = inspector({ stripe: [yoloRecord()] });
  const rows = fixture.run(`inspectorTemporaryAccess({ name: "stripe/key", leases: [{ to: { type: "kind", value: "pi" }, remaining: 3600 }] })`);
  assert.equal(rows.length, 2);
  const end = rows[0].children[1];
  assert.equal(end["aria-label"], "End temporary access for pi to stripe/key");
  await end.onclick();
  assert.equal(fixture.requests[0].command, "lease_revoke");
  assert.equal(fixture.refreshes(), 1);
  const after = fixture.run('inspectorTemporaryAccess({ name: "stripe/key", leases: [] })');
  assert.match(treeText(after[0]), /YOLO.*stripe\/ · claude/);
  assert.doesNotMatch(after.map(treeText).join(" "), /No temporary access/);
});
test("renderInspector ignores expired, unverified and Public YOLO coverage", () => {
  const fixture = inspector({ stripe: [yoloRecord(), access({ path: "stripe", expires: now - 1 }), access({ path: "stripe", covered: [] })] });
  assert.equal(fixture.run('inspectorTemporaryAccess({ name: "stripe/key" }).length'), 1);
  assert.equal(fixture.run('yolosFor({ name: "stripe/key", public: true }).length'), 0);
  assert.match(treeText(fixture.run('inspectorTemporaryAccess({ name: "stripe/missing" })')[0]), /No temporary access/);
});
test("failed YOLO listing shows unknown, never an empty-access claim", async () => {
  const fixture = inspector({ stripe: [yoloRecord()] }, { invoke: async () => { throw new Error("offline"); } });
  await fixture.run("loadYolos()");
  const rows = fixture.run('inspectorTemporaryAccess({ name: "stripe/key" })');
  assert.match(treeText(rows[0]), /YOLO status unknown: Error: offline/);
  assert.equal(rows[0].role, "alert");
  assert.doesNotMatch(rows.map(treeText).join(" "), /No temporary access/);
  assert.match(fixture.run('yoloOverride({ name: "stripe/key" })'), /unknown/);
});

test("renderInspector lists every live verified ancestor and grantee separately", () => {
  const fixture = inspector({
    stripe: [yoloRecord(), access({ path: "stripe", to: { type: "kind", value: "pi" } })],
    "stripe/sub": [access({ path: "stripe/sub", to: { type: "any" }, covered: ["stripe/key"] })],
  });
  const rows = fixture.run('inspectorTemporaryAccess({ name: "stripe/key" })');
  assert.equal(rows.length, 3);
  assert.deepEqual(Array.from(rows, row => row.children[1]["aria-label"]).sort(), [
    "End YOLO for Any agent to stripe/sub/", "End YOLO for claude to stripe/", "End YOLO for pi to stripe/",
  ]);
});
test("loadStatusPage replaces stale access rows with an unknown state on failure", async () => {
  const nodes = new Map();
  const fixture = inspector({}, {
    $: (id) => { if (!nodes.has(id)) nodes.set(id, { replaceChildren(...children) { this.children = children; } }); return nodes.get(id); },
    call: async () => { throw new Error("offline"); }, refreshSso: async () => {},
  });
  fixture.run(source.slice(source.indexOf("async function loadStatusPage()"), source.indexOf("function renderLeases(")));
  await fixture.run("loadStatusPage()");
  assert.equal(nodes.get("status-leases-count").textContent, "Unknown");
  assert.match(treeText(nodes.get("status-leases").children[0]), /Temporary access status unknown/);
});

test("YOLO override and access tooltips use the same endsAt time as rows", () => {
  const fixture = inspector({ stripe: [yoloRecord()] }, {
    fullTime: () => { throw new Error("Access end times must use endsAt"); },
    clock: (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  });
  fixture.run(source.slice(source.indexOf("function endsAt("), source.indexOf("function clockGlyph(")));
  fixture.run(source.slice(source.indexOf("function leaseTag("), source.indexOf("// YOLO:")));
  const expected = fixture.run(`endsAt(${yoloRecord().expires})`);
  assert.match(expected, /^ends /);
  assert.ok(fixture.run('yoloOverride({ name: "stripe/key" })').endsWith(expected));
  assert.ok(fixture.run('yoloTag({ name: "stripe/key" }).title').endsWith(expected));
  assert.ok(treeText(fixture.run('yoloAccessRow(yolos.stripe[0])')).includes(expected));
  assert.ok(fixture.run(`leaseTag({ leases: [{ to_label: "claude", remaining: 3600, expires: ${yoloRecord().expires} }] }).title`).endsWith(expected));
  const title = fixture.run(`leaseTag({ leases: [
    { to: { type: "kind", value: "claude" }, expires: ${yoloRecord().expires} },
    { to: { type: "kind", value: "pi" }, expires: ${yoloRecord().expires} }
  ] }).title`);
  assert.equal(title, `claude · ${expected}\npi · ${expected}`);
  assert.doesNotMatch(source, /fullTime\([^\n]*(?:\.expires|\.remaining)/);
  assert.match(source, /\$\("detail-access"\)\.textContent = yoloOverride\(s\)/);
});

function endAllFixture(yolos, extra = {}) {
  const nodes = new Map();
  const fixture = inspector(yolos, {
    $: (id) => {
      if (!nodes.has(id)) nodes.set(id, {
        attributes: {},
        setAttribute(name, value) { this.attributes[name] = value; },
        addEventListener(type, handler) { this[type] = handler; },
        replaceChildren(...children) { this.children = children; },
      });
      return nodes.get(id);
    },
    MAX_LEASES_PER_SECRET: 8, plural: (n, name) => `${n} ${name}s`,
    granteeValue: (to) => to.value,
    leaseRow: () => ({ textContent: "Temporary access" }),
    ...extra,
  });
  fixture.run(source.slice(source.indexOf("function renderLeaseRows("), source.indexOf("// Button and help for the agent chosen")));
  return { ...fixture, nodes };
}

test("renderLeaseRows warns End all affects every key in each covering YOLO folder", () => {
  const covered = ["stripe/sub/key"];
  const fixture = endAllFixture({
    stripe: [access({ path: "stripe", covered, to: { type: "kind", value: "claude" } }), access({ path: "stripe", covered, to: { type: "kind", value: "pi" } })],
    "stripe/sub": [access({ path: "stripe/sub", covered, to: { type: "any" } })],
    other: [access({ path: "other", covered: ["other/key"] })],
  });
  fixture.run('renderLeaseRows([{ name: "stripe/sub/key" }], false)');
  const note = "End all also ends YOLO on stripe/, stripe/sub/ for every key in those folders.";
  assert.equal(fixture.nodes.get("lease-end-all-note").textContent, note);
  assert.equal(fixture.nodes.get("lease-end-all-note").hidden, false);
  assert.equal(fixture.nodes.get("lease-end-all").hidden, false);
  assert.equal(fixture.nodes.get("lease-end-all").attributes["aria-label"], `End all. ${note}`);
  // A folder selection targets keys too, and must carry the same warning.
  fixture.run('renderLeaseRows([{ name: "stripe/sub/key" }], true)');
  assert.equal(fixture.nodes.get("lease-end-all-note").textContent, note);
  const html = fs.readFileSync(require.resolve("../ui/index.html"), "utf8");
  assert.match(html, /id="lease-end-all-note" class="hint" hidden><\/p>\s*<div class="actions"><button[^>]*id="lease-end-all"/);
});

test("renderLeaseRows removes the End all warning without live verified coverage", () => {
  const fixture = endAllFixture({ stripe: [yoloRecord()] });
  fixture.run('renderLeaseRows([{ name: "stripe/key" }], false)');
  assert.equal(fixture.nodes.get("lease-end-all-note").textContent, "End all also ends YOLO on stripe/ for every key in that folder.");
  for (const item of [
    '{ name: "other/key", leases: [{ to: { type: "kind", value: "pi" }, expires: 1 }] }',
    '{ name: "stripe/key", public: true }',
  ]) {
    fixture.run(`renderLeaseRows([${item}], false)`);
    assert.equal(fixture.nodes.get("lease-end-all-note").hidden, true);
    assert.equal(fixture.nodes.get("lease-end-all-note").textContent, "");
    assert.equal(fixture.nodes.get("lease-end-all").attributes["aria-label"], "End all");
  }
  fixture.run('yolos.stripe[0].expires = 1; renderLeaseRows([{ name: "stripe/key" }], false)');
  assert.equal(fixture.nodes.get("lease-end-all-note").hidden, true);
  assert.equal(fixture.nodes.get("lease-end-all").hidden, true);
});

test("global End all confirmation lists every live YOLO folder", async () => {
  const confirmations = [];
  const fixture = endAllFixture({ stripe: [yoloRecord()], other: [access({ path: "other" })] }, {
    secrets: [],
    confirmDialog: async (...args) => { confirmations.push(args); return false; },
  });
  fixture.run(source.slice(source.indexOf('$("leases-end-all").addEventListener("click"'), source.indexOf('$("lease-end-all").addEventListener("click"')));
  await fixture.nodes.get("leases-end-all").click();
  assert.match(confirmations[0][1], /End all also ends YOLO on other\/, stripe\/ for every key in those folders\./);
  assert.equal(fixture.requests.length, 0);
});
