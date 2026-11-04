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
const treeText = (node) => !node ? "" : typeof node === "string" ? node : [node.textContent || "", ...(node.children || []).map(treeText)].join(" ");
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
  fixture.run(`
    let detail = null, secrets = [];
    ${source.slice(source.indexOf("function detailTargets()"), source.indexOf("// One secret holds at most"))}
    const renderRows = renderLeaseRows;
    renderLeaseRows = (items, isFolder) => {
      secrets = items;
      detail = { kind: isFolder ? "folder" : "secret", name: isFolder ? "stripe" : items[0]?.name };
      renderRows(items, isFolder);
    };
  `);
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

test("renderLeaseRows removes the End all warning without an affected live folder", () => {
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

test("End all warns about uncovered ancestor YOLO without adding access rows", () => {
  const fixture = endAllFixture({ stripe: [access({ path: "stripe", covered: ["stripe/other"], to: { type: "any" } })] });
  fixture.run('renderLeaseRows([{ name: "stripe/key", leases: [{ to: { type: "kind", value: "pi" }, expires: 1 }] }], false)');
  assert.equal(fixture.nodes.get("lease-end-all-note").textContent, "End all also ends YOLO on stripe/ for every key in that folder.");
  assert.equal(fixture.nodes.get("lease-rows").children.length, 1);
  fixture.run('renderLeaseRows([{ name: "stripe" }], false)');
  assert.equal(fixture.nodes.get("lease-end-all-note").hidden, true);
  fixture.run('renderLeaseRows([{ name: "stripe/key" }], true)');
  assert.equal(fixture.nodes.get("lease-end-all-note").hidden, false);
  assert.equal(fixture.nodes.get("lease-end-all").hidden, false);
  assert.deepEqual(Array.from(fixture.run("detailEndPatterns()")), ["stripe/key", "stripe/"]);
});

test("End all folder matching distinguishes exact keys and includes uncovered ancestors and descendants", () => {
  const run = ui({
    stripe: [access({ path: "stripe", covered: [] })],
    "stripe/sub": [access({ path: "stripe/sub", covered: [] })],
    stripe2: [access({ path: "stripe2", covered: [] })],
  });
  assert.deepEqual(Array.from(run('endAllYolosFor(["stripe"]).map(y => y.path)')), []);
  assert.deepEqual(Array.from(run('endAllYolosFor(["stripe/sub/key"]).map(y => y.path)')), ["stripe", "stripe/sub"]);
  assert.deepEqual(Array.from(run('endAllYolosFor(["stripe/"]).map(y => y.path)')), ["stripe", "stripe/sub"]);
  assert.equal(run('endAllYolosFor(["*"]).length'), 3);
});

test("End all warns that folder scope is unknown when YOLO listing fails", () => {
  const fixture = endAllFixture({}, { yoloError: "YOLO status unknown: offline" });
  fixture.run('renderLeaseRows([{ name: "stripe/key", leases: [{ to: { type: "kind", value: "pi" }, expires: 1 }] }], false)');
  const note = fixture.nodes.get("lease-end-all-note").textContent;
  assert.match(note, /Folder YOLO scope is unknown/);
  assert.match(note, /every key in those folders/);
  assert.equal(fixture.nodes.get("lease-end-all").attributes["aria-label"], `End all. ${note}`);
});

// Run the real dialog renderer with draft controls that fail if a refresh rebuilds them.
function detailRefreshFixture(kind, activity) {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {
      value: "", hidden: false,
      replaceChildren() { throw new Error(`Refresh rebuilt ${id}`); },
    });
    return nodes.get(id);
  };
  const context = vm.createContext({
    $: node, document: { querySelector: node },
    detail: { kind, name: kind === "folder" ? "stripe" : "stripe/key" },
    detailTargets: () => [{ name: "stripe/key", tier: "bio", agent_allowed: true }],
    accessOf: () => "agents-touch", accessLevel: () => ({ label: "Agents · Touch ID" }),
    accessDetail: () => "Stored access", yoloOverride: () => "YOLO override updated",
    isAws: () => false, relTime: () => "now", renderLeaseRows: () => {},
    leasesOf: () => [], MAX_LEASES_PER_SECRET: 8, granteeValue: (to) => to.value,
    granteeName: (to) => to.value || "Any agent", joinNames: (names) => names.join(", "),
    plural: (n, name) => `${n} ${name}s`,
    syncDetailPrimary: () => {},
    call: activity, renderActivity: () => {},
  });
  vm.runInContext(source.slice(source.indexOf("function chosenGrantee()"), source.indexOf('// "pi", "pi and claude"')), context);
  vm.runInContext(source.slice(source.indexOf("function syncLeaseControls()"), source.indexOf("function renderActivity(")), context);
  for (const [id, value] of Object.entries({ "lease-to": "session:chosen", "lease-hours": "3", "lease-cwd": "/project", "lease-cmds": "/usr/bin/true", "lease-uses": "3" })) node(id).value = value;
  return { nodes, run: (expr) => vm.runInContext(expr, context) };
}
for (const kind of ["secret", "folder"]) {
  for (const failure of [false, true]) {
    test(`renderDetail ${kind} refresh preserves draft after activity ${failure ? "failure" : "session churn"}`, async () => {
      const fixture = detailRefreshFixture(kind, async () => {
        if (failure) throw new Error("offline");
        return Array.from({ length: 8 }, (_, i) => ({ session: `new-${i}`, kind: "pi", ts: i }));
      });
      const before = [...fixture.nodes].map(([id, node]) => [id, node.value]);
      await fixture.run("renderDetail()");
      assert.deepEqual(before.map(([id]) => [id, fixture.nodes.get(id).value]), before);
      assert.equal(fixture.nodes.get("lease-to").value, "session:chosen");
      assert.equal(fixture.nodes.get("lease-grant").disabled, false);
      assert.doesNotMatch(fixture.nodes.get("lease-help").textContent, /Any agent/);
      assert.equal(fixture.nodes.get("detail-access").textContent, kind === "secret" ? "YOLO override updated" : undefined);
      // Submission still sends the exact draft, never Any agent, after the refresh.
      fixture.nodes.get("lease-uses").reportValidity = () => true;
      fixture.run(`
        toast = () => {}; plural = () => "items"; durShort = () => "1h";
        loadSecrets = async () => {};
        ${source.slice(source.indexOf("async function grantLease()"), source.indexOf('// "Agents · no prompt"'))}
      `);
      fixture.run("call = async (command, args) => { if (command === 'lease_grant') submitted = { command, args }; return []; }");
      await fixture.run("grantLease()");
      const submitted = fixture.run("submitted");
      assert.equal(submitted.args.to, "session:chosen");
      assert.equal(submitted.args.cwd, "/project");
      assert.equal(submitted.args.hours, 3);
      assert.equal(submitted.args.maxUses, 3);
      assert.deepEqual(Array.from(submitted.args.cmds), ["/usr/bin/true"]);
      fixture.nodes.get("lease-to").value = "";
      fixture.run("syncLeaseControls()");
      assert.equal(fixture.nodes.get("lease-grant").disabled, true);
      fixture.run("submitted = null");
      await fixture.run("grantLease()");
      assert.equal(fixture.run("submitted"), null);
    });
  }
}

test("rendered Activity strings use temporary access, never lease", () => {
  const rows = { children: [], replaceChildren() { this.children = []; }, append(row) { this.children.push(row); } };
  const context = vm.createContext({
    $: () => rows, whoLabel: () => ({ text: "pi", agent: true }), actionLabel: () => "Secret used",
    eventSummary: () => "", relTime: () => "now", fullTime: () => "now",
    el: (tag, attrs = {}, ...children) => ({ tag, ...attrs, children, addEventListener() {} }),
  });
  vm.runInContext(source.slice(source.indexOf("let evMoreSeq ="), source.indexOf("async function grantLease()")), context);
  vm.runInContext('renderActivityInto($("rows"), [{ action: "use", ok: true, detail: { via_lease: ["stripe/key"] } }], false)', context);
  assert.match(rows.children.map(treeText).join(" "), /via temporary access/);
  assert.doesNotMatch(rows.children.map(treeText).join(" "), /\blease\b/i);
  const html = fs.readFileSync(require.resolve("../ui/index.html"), "utf8");
  assert.doesNotMatch(html.replace(/<!--[\s\S]*?-->/g, "").replace(/<[^>]*>/g, ""), /\bleases?\b/i);
});
