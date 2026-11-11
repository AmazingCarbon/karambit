// Live metadata refresh: mocked Tauri invoke and fake timers, no real backend.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(require.resolve("../ui/app.js"), "utf8");
const start = source.indexOf("// ---------- live metadata refresh ----------");
const end = source.indexOf("// ---------- access levels ----------");
const METADATA_SOURCE = source.slice(start, end);
const LISTENER_SOURCE = source.slice(
  source.indexOf("// ---------- foreground refresh listeners (regression-tested) ----------"),
  source.indexOf("// ---------- audit filter ----------"),
);

const clone = (value) => JSON.parse(JSON.stringify(value));
const secret = (name, extra = {}) => ({ name, tier: "bio", agent_allowed: true, public: false, has_backup: true, created: 1, updated: 10, ...extra });

function fixture({ initial = [], list = null, active = true, hidden = false } = {}) {
  const nodes = new Map();
  const timers = [];
  const invoked = [];
  const renders = { lists: [], inspector: [], detail: [] };
  let listFn = list || (() => initial);
  const makeNode = (id) => {
    const node = {
      id, hidden: false, value: "", textContent: "", open: false, scrollTop: 0, children: [],
      attributes: {},
      getAttribute(name) { return this.attributes[name] ?? null; },
      setAttribute(name, value) { this.attributes[name] = value; },
      replaceChildren(...children) { this.children = children; },
      close() { this.open = false; },
      querySelector() { return null; },
      querySelectorAll() { return []; },
    };
    if (id === "rows") {
      node.folderList = { scrollTop: 120, isConnected: true };
      node.closest = (sel) => (sel === ".folder-list" ? node.folderList : null);
    }
    if (id === "aws-groups") {
      node.folderList = { scrollTop: 7, isConnected: true };
      node.closest = (sel) => (sel === ".folder-list" ? node.folderList : null);
    }
    if (id === "inspector") {
      node.panelBody = { scrollTop: 44, isConnected: true };
      node.querySelector = (sel) => (sel === ".panel-body" ? node.panelBody : null);
    }
    return node;
  };
  const nodeFor = (id) => { if (!nodes.has(id)) nodes.set(id, makeNode(id)); return nodes.get(id); };
  nodeFor("view-init").hidden = true;
  nodeFor("metadata-stale").hidden = true;
  nodeFor("detail-dialog").open = false;

  const props = {
    appInitialized: active,
    secrets: clone(initial), selectedSecret: null, detail: null, sources: [], sourceKinds: [],
    currentFolder: "", yoloError: "", yolos: {}, awsDetailTarget: null,
    document: {
      hidden, body: { tagName: "BODY" }, activeElement: null,
      getElementById: (id) => nodes.get(id) || null,
      querySelectorAll: () => [],
    },
    $: nodeFor,
    invoke: async (cmd) => { invoked.push(cmd); return clone(listFn()); },
    call: async (cmd) => {
      invoked.push(cmd);
      if (cmd === "list") return clone(listFn());
      return { sources: [] };
    },
    refreshSso: async () => {},
    loadYolos: async () => {},
    renderLists: (options) => renders.lists.push(options),
    renderInspector: (options) => renders.inspector.push(options),
    renderDetail: async (options) => renders.detail.push(options),
    detailTargets: () => {
      if (!props.detail) return [];
      return props.detail.kind === "secret"
        ? props.secrets.filter((s) => s.name === props.detail.name)
        : props.secrets.filter((s) => s.name.startsWith(props.detail.name + "/"));
    },
    fetchPublicValues: () => { renders.publicReads = (renders.publicReads || 0) + 1; },
    fetchAwsMeta: () => { renders.awsReads = (renders.awsReads || 0) + 1; },
    setTimeout: (fn, delay) => { timers.push({ fn, delay }); return timers.length; },
    clearTimeout: () => {},
    Promise,
  };
  const context = vm.createContext(props);
  vm.runInContext(METADATA_SOURCE, context);
  vm.runInContext("lastMetadataSignature = secretMetadataSignature(secrets)", context);
  return {
    context, props, nodes, timers, invoked, renders,
    setList(fn) { listFn = fn; },
    run: (expr) => vm.runInContext(expr, context),
    async flush() { await new Promise((resolve) => setImmediate(resolve)); },
  };
}

test("unchanged metadata is compared before render; lease countdown is ignored", async () => {
  const initial = [secret("stripe/key", { leases: [{ to: { type: "kind", value: "pi" }, to_label: "pi agents", granted: 1, expires: 1000, remaining: 900, by: "synthetic", scope: {} }] })];
  const f = fixture({ initial, list: () => {
    const next = clone(initial);
    next[0].leases[0].remaining = 800;
    return next;
  } });
  await f.run("requestSecretMetadata()");
  assert.deepEqual(f.invoked, ["list"]);
  assert.equal(f.renders.lists.length, 0);
  assert.equal(f.nodes.get("metadata-stale").hidden, true);
});

test("external add, remove, rename and policy changes update metadata and counts", async () => {
  const initial = [secret("stripe/keep"), secret("stripe/gone"), secret("stripe/renamed"), secret("stripe/policy")];
  const changed = [
    secret("stripe/keep"),
    secret("stripe/renamed-from"), // rename: old name disappears, new name appears
    secret("stripe/policy", { tier: "software", agent_allowed: false, updated: 11 }),
    secret("stripe/added", { updated: 12 }),
  ];
  const f = fixture({ initial, list: () => changed });
  f.props.selectedSecret = "stripe/policy";
  await f.run("requestSecretMetadata()");
  assert.equal(f.run("secrets.length"), 4);
  assert.equal(f.run('secrets.some((s) => s.name === "stripe/gone")'), false);
  assert.equal(f.run('secrets.some((s) => s.name === "stripe/added")'), true);
  assert.equal(f.run("secrets.find((s) => s.name === \"stripe/policy\").agent_allowed"), false);
  assert.equal(JSON.stringify(f.renders.lists), JSON.stringify([{ background: true }]));
  assert.equal(JSON.stringify(f.renders.inspector), JSON.stringify([{ background: true }]));
  assert.equal(f.nodes.get("metadata-stale").hidden, true);
});

test("deleting the selected secret clears the selection and hides its controls", async () => {
  const initial = [secret("stripe/gone"), secret("stripe/keep")];
  const f = fixture({ initial, list: () => [secret("stripe/keep")] });
  f.props.selectedSecret = "stripe/gone";
  await f.run("requestSecretMetadata()");
  assert.equal(f.run("selectedSecret"), null);
  assert.equal(JSON.stringify(f.renders.inspector), JSON.stringify([{ background: true }])); // renderInspector sees no selection and hides
  assert.equal(JSON.stringify(f.renders.lists), JSON.stringify([{ background: true }]));
});

test("the real inspector drops stale controls when the selected secret is gone", () => {
  const panel = {
    hidden: false, children: ["stale controls"], contains: () => false,
    replaceChildren(...children) { this.children = children; },
  };
  const aws = [];
  const context = vm.createContext({
    $: (id) => (id === "inspector" ? panel : {}),
    secrets: [], selectedSecret: "stripe/gone",
    renderAwsDetail: (s) => aws.push(s),
  });
  const prefix = source.slice(
    source.indexOf("function renderInspector()"),
    source.indexOf('  const close = el("button"', source.indexOf("function renderInspector()")),
  );
  vm.runInContext(`${prefix}\n}`, context);
  vm.runInContext("renderInspector()", context);
  assert.equal(panel.hidden, true);
  assert.deepEqual(panel.children, []);
  assert.deepEqual(aws, [null]);
});

test("open detail metadata refresh is metadata-only and keeps drafts", async () => {
  const initial = [secret("stripe/gone"), secret("stripe/keep")];
  const f = fixture({ initial, list: () => [secret("stripe/keep")] });
  f.props.detail = { kind: "secret", name: "stripe/gone" };
  f.nodes.get("detail-dialog").open = true;
  await f.run("requestSecretMetadata()");
  assert.equal(JSON.stringify(f.renders.detail), JSON.stringify([{ metadataOnly: true }]));
});

test("concurrent refreshes single-flight and coalesce one pending rerun", async () => {
  const initial = [secret("stripe/key")];
  const next = [secret("stripe/key"), secret("stripe/added")];
  let release;
  let calls = 0;
  const f = fixture({ initial });
  f.props.invoke = (cmd) => {
    f.invoked.push(cmd);
    calls += 1;
    if (calls === 1) return new Promise((resolve) => { release = resolve; });
    return Promise.resolve(clone(next));
  };
  const first = f.run("requestSecretMetadata()");
  const second = f.run("requestSecretMetadata()");
  assert.equal(calls, 1);
  release(clone(next));
  await Promise.all([first, second]);
  assert.equal(calls, 2);
  assert.equal(f.renders.lists.length, 1);
  assert.equal(f.run("secrets.length"), 2);
});

test("a stale poll cannot override newer loadSecrets state", async () => {
  const initial = [secret("stripe/key")];
  const newer = [secret("stripe/key", { updated: 20 }), secret("stripe/from-app", { updated: 21 })];
  let release;
  const f = fixture({ initial });
  f.props.invoke = () => new Promise((resolve) => { release = resolve; });
  f.setList(() => newer);
  const poll = f.run("requestSecretMetadata()");
  await f.run("loadSecrets()");
  assert.equal(f.run("secrets.length"), 2);
  release(clone(initial));
  await poll;
  assert.equal(f.run("secrets.length"), 2);
  assert.equal(f.run('secrets.some((s) => s.name === "stripe/key" && s.updated === 20)'), true);
});

test("failures keep last good metadata, mark quiet stale and back off to a cap", async () => {
  const initial = [secret("stripe/key")];
  const f = fixture({ initial });
  f.props.invoke = async () => { throw new Error("offline"); };
  for (let i = 0; i < 5; i += 1) await f.run("runSecretMetadataPoll()");
  assert.equal(f.run("secrets.length"), 1);
  assert.equal(f.run("secrets[0].name"), "stripe/key");
  assert.equal(f.nodes.get("metadata-stale").hidden, false);
  assert.deepEqual(f.timers.map((t) => t.delay).slice(-5), [2000, 4000, 8000, 16000, 30000]);
});

test("recovery clears stale indication and returns to the normal interval", async () => {
  const initial = [secret("stripe/key")];
  const fixed = [secret("stripe/key"), secret("stripe/added")];
  const f = fixture({ initial });
  f.props.invoke = async () => { throw new Error("offline"); };
  await f.run("runSecretMetadataPoll()");
  assert.equal(f.nodes.get("metadata-stale").hidden, false);
  f.props.invoke = async () => clone(fixed);
  await f.run("runSecretMetadataPoll()");
  assert.equal(f.nodes.get("metadata-stale").hidden, true);
  assert.equal(f.run("secrets.length"), 2);
  assert.equal(f.timers.at(-1).delay, 2000);
});

test("polling pauses while hidden or uninitialized and resumes immediately", async () => {
  const initial = [secret("stripe/key")];
  const f = fixture({ initial });
  f.run("startSecretMetadataPolling()");
  assert.equal(f.timers.at(-1).delay, 2000);
  assert.equal(f.invoked.length, 0);

  f.props.document.hidden = true;
  await f.run("handleSecretMetadataVisibility()");
  assert.equal(f.invoked.length, 0);

  f.props.document.hidden = false;
  await f.run("handleSecretMetadataVisibility()");
  assert.deepEqual(f.invoked.filter((cmd) => cmd === "list"), ["list"]);
  assert.equal(f.timers.at(-1).delay, 2000);

  f.props.appInitialized = false;
  const before = f.invoked.length;
  await f.run("handleSecretMetadataFocus()");
  assert.equal(f.invoked.length, before);
});

test("focus refreshes metadata immediately without waiting for the poll", async () => {
  const initial = [secret("stripe/key")];
  const f = fixture({ initial, list: () => [secret("stripe/key"), secret("stripe/added")] });
  await f.run("handleSecretMetadataFocus()");
  assert.deepEqual(f.invoked, ["list"]);
  assert.equal(f.run("secrets.length"), 2);
});

test("background renders never start public-value or AWS detail reads", () => {
  const f = fixture();
  f.run('fetchSecondaryMetadata([{ name: "stripe/public" }], { background: true })');
  f.run('fetchAwsPageMetadata([{ name: "aws/profile" }], { background: true })');
  assert.equal(f.renders.publicReads || 0, 0);
  assert.equal(f.renders.awsReads || 0, 0);
  f.run('fetchSecondaryMetadata([{ name: "stripe/public" }])');
  f.run('fetchAwsPageMetadata([{ name: "aws/profile" }])');
  assert.equal(f.renders.publicReads, 1);
  assert.equal(f.renders.awsReads, 2);
});

test("focus and list/inspector scroll survive a metadata replacement render", () => {
  const initial = [secret("stripe/key")];
  const f = fixture({ initial });
  const oldButton = {
    tagName: "BUTTON", id: "", textContent: "stripe/key", value: "", type: "", checked: false,
    getAttribute: (name) => (name === "aria-label" ? "Details for stripe/key" : null),
    focus() { this.focused = true; },
  };
  f.props.document.activeElement = oldButton;
  const view = f.run("captureRefreshView()");
  f.props.viewState = view;
  f.props.document.activeElement = f.props.document.body;
  const newButton = {
    tagName: "BUTTON", id: "", textContent: "stripe/key", value: "", type: "", checked: false,
    getAttribute: (name) => (name === "aria-label" ? "Details for stripe/key" : null),
    focus() { this.focused = true; },
  };
  f.props.document.querySelectorAll = (tag) => (tag === "BUTTON" ? [newButton] : []);
  f.nodes.get("rows").folderList.scrollTop = 0;
  f.nodes.get("inspector").panelBody.scrollTop = 0;
  f.run("restoreRefreshView(viewState)");
  assert.equal(newButton.focused, true);
  assert.equal(f.nodes.get("rows").folderList.scrollTop, 120);
  assert.equal(f.nodes.get("aws-groups").folderList.scrollTop, 7);
  assert.equal(f.nodes.get("inspector").panelBody.scrollTop, 44);
});

// Exercise the real registered focus / visibility / interval callbacks, not helpers.
function listenerFixture({ hidden = false, initialized = true } = {}) {
  const nodes = new Map();
  const timers = [];
  const intervals = [];
  const handlers = { window: {}, document: {} };
  const calls = [];
  const runtime = [];
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, { id, hidden: false, close() { this.closed = true; } });
    return nodes.get(id);
  };
  node("view-init").hidden = initialized;
  node("metadata-stale").hidden = true;
  const props = {
    appInitialized: initialized,
    secrets: [], selectedSecret: null, detail: null,
    document: {
      hidden, body: {}, activeElement: null,
      getElementById: () => null, querySelectorAll: () => [],
      addEventListener: (type, fn) => { handlers.document[type] = fn; },
    },
    window: { addEventListener: (type, fn) => { handlers.window[type] = fn; } },
    $: node,
    invoke: async (cmd) => { calls.push(cmd); return []; },
    renderLists: () => {}, renderInspector: () => {},
    renderDetail: async () => {}, detailTargets: () => [],
    refreshRuntimeAccess: () => { runtime.push("runtime"); return Promise.resolve(); },
    setTimeout: (fn, delay) => { timers.push({ fn, delay }); return timers.length; },
    clearTimeout: () => {},
    setInterval: (fn, delay) => { intervals.push({ fn, delay }); return intervals.length; },
    fetchPublicValues: () => {}, fetchAwsMeta: () => {},
    Promise,
  };
  const context = vm.createContext(props);
  vm.runInContext(METADATA_SOURCE, context);
  vm.runInContext("lastMetadataSignature = secretMetadataSignature(secrets)", context);
  vm.runInContext(LISTENER_SOURCE, context);
  return {
    nodes, timers, intervals, handlers, calls, runtime, props, context,
    run: (expr) => vm.runInContext(expr, context),
    async flush() { await new Promise((resolve) => setImmediate(resolve)); await new Promise((resolve) => setImmediate(resolve)); },
  };
}

test("registered focus listener refreshes metadata and runtime only for an initialized app", async () => {
  const f = listenerFixture();
  f.handlers.window.focus();
  await f.flush();
  assert.deepEqual(f.calls, ["list"]);
  assert.deepEqual(f.runtime, ["runtime"]);

  f.nodes.get("view-init").hidden = false; // setup screen
  f.handlers.window.focus();
  await f.flush();
  assert.deepEqual(f.calls, ["list"]); // no metadata refresh during setup
  assert.deepEqual(f.runtime, ["runtime"]); // and no runtime refresh either
});

test("registered visibility listener pauses hidden metadata and resumes when visible", async () => {
  const f = listenerFixture({ hidden: true });
  f.handlers.document.visibilitychange();
  await f.flush();
  assert.deepEqual(f.calls, []);

  f.props.document.hidden = false;
  f.handlers.document.visibilitychange();
  await f.flush();
  assert.deepEqual(f.calls, ["list"]);
});

test("hidden app focus does not start a metadata read", async () => {
  const f = listenerFixture({ hidden: true });
  f.handlers.window.focus();
  await f.flush();
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.runtime, ["runtime"]); // runtime keeps its existing focus behavior
});

test("rejected runtime refresh in focus and interval callbacks has no unhandled rejection", async () => {
  const unhandled = [];
  const onUnhandled = (err) => unhandled.push(err);
  process.on("unhandledRejection", onUnhandled);
  try {
    const f = listenerFixture();
    f.props.refreshRuntimeAccess = () => { f.runtime.push("runtime"); return Promise.reject(new Error("offline")); };
    f.handlers.window.focus();
    f.intervals[0].fn();
    await f.flush();
    assert.deepEqual(f.runtime, ["runtime", "runtime"]);
    assert.deepEqual(unhandled, []);
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
});

// The real detail renderer: metadataOnly must not load activity or rebuild drafts.
function detailFixture(targets = [{ name: "stripe/key", tier: "bio", agent_allowed: true }]) {
  const nodes = new Map();
  const calls = [];
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, {
      id, value: "", hidden: false, textContent: "", disabled: false,
      setAttribute() {},
      close() { this.closed = true; },
      replaceChildren() {
        if (["lease-to", "lease-hours", "lease-cwd", "lease-cmds", "lease-uses"].includes(id)) throw new Error(`draft rebuilt: ${id}`);
      },
    });
    return nodes.get(id);
  };
  const controls = { hidden: false };
  const props = {
    $: node,
    document: {
      querySelector: (sel) => (sel === "#lease-form .lease-controls" ? controls : node()),
      querySelectorAll: () => [],
      activeElement: null,
      body: {},
    },
    detail: { kind: "secret", name: "stripe/key" },
    detailTargets: () => targets,
    accessOf: () => "agents-touch", accessLevel: () => ({ label: "Agents · Touch ID" }),
    accessDetail: () => "Stored access", yoloOverride: () => "",
    isAws: () => false, relTime: () => "now", renderLeaseRows: () => {},
    leasesOf: () => [], yolosFor: () => [], MAX_LEASES_PER_SECRET: 8, granteeValue: (to) => to.value,
    endAllYolosFor: () => [], detailEndPatterns: () => [], endAllYoloNote: () => "", yoloError: "",
    yoloAccessRow: () => ({ replaceChildren() {} }),
    granteeName: (to) => to.value || "Any agent", joinNames: (names) => names.join(", "),
    plural: (n, name) => `${n} ${name}s`, syncDetailPrimary: () => {},
    call: async (command) => { calls.push(command); return []; },
    renderActivity: () => { throw new Error("activity must not render in metadata-only mode"); },
  };
  for (const [id, value] of Object.entries({ "lease-to": "session:chosen", "lease-hours": "3", "lease-cwd": "/project", "lease-cmds": "/usr/bin/true", "lease-uses": "3" })) node(id).value = value;
  const context = vm.createContext(props);
  vm.runInContext(source.slice(source.indexOf("function chosenGrantee()"), source.indexOf("function renderActivity(")), context);
  return { nodes, calls, run: (expr) => vm.runInContext(expr, context) };
}

test("metadata-only detail refresh loads no activity and leaves draft controls alone", async () => {
  const f = detailFixture();
  const before = [...f.nodes].map(([id, node]) => [id, node.value]);
  await f.run("renderDetail({ metadataOnly: true })");
  assert.deepEqual(f.calls, []);
  assert.deepEqual(before.map(([id]) => [id, f.nodes.get(id).value]), before);
  assert.equal(f.nodes.get("lease-to").value, "session:chosen");
});

test("metadata-only detail refresh closes when its target was deleted, without activity reads", async () => {
  const f = detailFixture([]);
  await f.run("renderDetail({ metadataOnly: true })");
  assert.equal(f.nodes.get("detail-dialog").closed, true);
  assert.deepEqual(f.calls, []);
});
