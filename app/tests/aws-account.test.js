// Source-named tests for AWS account names in the details panel and for action labels.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(require.resolve("../ui/app.js"), "utf8");
const html = fs.readFileSync(require.resolve("../ui/index.html"), "utf8");
const part = (from, to) => source.slice(source.indexOf(from), source.indexOf(to));

const ACCOUNT = "123456789012";
const OTHER = "210987654321";
const portal = (name, accounts) => ({ portal: name, start_url: `https://${name}.example/start`, region: "us-east-1", logged_in: true, profiles: [], accounts });

// Runs the shipped helpers, refreshSso and renderAwsDetail against a recording stub DOM.
function harness({ portals, status } = {}) {
  const nodes = {};
  const stub = (id) => (nodes[id] ??= {
    id, hidden: false, textContent: "", dataset: { profile: id }, kids: [], classList: { toggle() {} },
    setAttribute() {}, append() {}, querySelector: () => null,
    replaceChildren(...kids) { this.kids = kids; },
    get parentElement() { return this.parent ??= stub(`${id}:parent`); },
  });
  const calls = { fetchAwsMeta: 0, rendered: [] };
  const context = vm.createContext({
    $: stub, el: (tag, attrs = {}) => ({ tag, ...attrs }), isAws: (n) => n.startsWith("aws/"),
    cfg: {}, ssoBanner: null, awsMetas: {}, calls,
    freshMeta: (s) => context.awsMetas[s.name] || null,
    fetchAwsMeta: () => { calls.fetchAwsMeta += 1; },
    awsPortalFor: (s) => context.awsMetas[s.name]?.portal || null,
    portalUntil: () => "until later", shortClock: () => "now", endedWhy: () => "why", signOutPortal() {}, syncDetailPrimary() {},
    invoke: async () => status, toast() {}, awsDetailTarget: null,
    renderAwsDetail: (s) => { calls.rendered.push(s.name); },
  });
  const run = (code) => vm.runInContext(code, context);
  run(part("const groupAccount", "\nfunction splitName"));
  run(part("let ssoPortals", "async function loadSsoStatus"));
  run(`ssoPortals = ${JSON.stringify(portals || [])}`);
  // The refreshSso test needs the stub render; the detail tests need the real one.
  const stubRender = context.renderAwsDetail;
  vm.runInContext(part("function renderAwsDetail", "// One primary action"), context);
  const realRender = context.renderAwsDetail;
  context.renderAwsDetail = stubRender;
  return {
    run, nodes, calls, context,
    detail(secret, meta) {
      context.awsMetas = { [secret.name]: meta };
      realRender(secret);
      const kv = nodes["aws-detail-kv"];
      const rows = {};
      for (let i = 0; i < kv.kids.length; i += 2) rows[kv.kids[i].textContent] = kv.kids[i + 1].textContent;
      return { rows, kvHidden: kv.hidden, sub: nodes["aws-detail-sub"].textContent };
    },
  };
}

const profile = { name: "aws/prod", updated: 1, tier: "touch" };
const sso = (extra = {}) => ({ updated: 1, sso: true, portal: "corp", account: ACCOUNT, role: "Admin", region: "eu-west-1", ...extra });

test("awsAccountName reads only the named portal's stored account names", () => {
  const h = harness({ portals: [portal("corp", { [ACCOUNT]: "Production" }), portal("lab", { [ACCOUNT]: "Sandbox" }), portal("bare", undefined)] });
  assert.equal(h.run(`awsAccountName("corp", "${ACCOUNT}")`), "Production");
  assert.equal(h.run(`awsAccountName("lab", "${ACCOUNT}")`), "Sandbox");
  assert.equal(h.run(`awsAccountName("corp", "${OTHER}")`), "");
  assert.equal(h.run(`awsAccountName("bare", "${ACCOUNT}")`), "");
  assert.equal(h.run(`awsAccountName("gone", "${ACCOUNT}")`), "");
  assert.equal(h.run(`awsAccountName(null, "${ACCOUNT}")`), "");
});

test("awsAccountText shows the name beside the grouped number, or the number alone", () => {
  const h = harness({ portals: [portal("corp", { [ACCOUNT]: "Production" }), portal("bare", {})] });
  assert.equal(h.run(`awsAccountText("corp", "${ACCOUNT}")`), "Production · 1234 5678 9012");
  assert.equal(h.run(`awsAccountText("corp", "${OTHER}")`), "2109 8765 4321");
  assert.equal(h.run(`awsAccountText("bare", "${ACCOUNT}")`), "1234 5678 9012");
  assert.equal(h.run(`awsAccountText("gone", "${ACCOUNT}")`), "1234 5678 9012");
});

test("renderAwsDetail shows the stored name and number for a profile in that portal", () => {
  const h = harness({ portals: [portal("corp", { [ACCOUNT]: "Production" }), portal("lab", { [ACCOUNT]: "Sandbox" })] });
  const shown = h.detail(profile, sso());
  assert.equal(shown.rows.Account, "Production · 1234 5678 9012");
  assert.equal(shown.rows.Portal, "corp");
  const lab = h.detail(profile, sso({ portal: "lab" }));
  assert.equal(lab.rows.Account, "Sandbox · 1234 5678 9012");
});

test("renderAwsDetail falls back to the number for unknown accounts, empty maps and missing portals", () => {
  const unknown = harness({ portals: [portal("corp", { [OTHER]: "Other" })] });
  assert.equal(unknown.detail(profile, sso()).rows.Account, "1234 5678 9012");
  const missing = harness({ portals: [portal("corp", undefined)] });
  assert.equal(missing.detail(profile, sso()).rows.Account, "1234 5678 9012");
  const removed = harness({ portals: [] });
  assert.equal(removed.detail(profile, sso()).rows.Account, "1234 5678 9012");
});

test("renderAwsDetail shows names as text and keeps Touch ID profiles gated", () => {
  const h = harness({ portals: [portal("corp", { [ACCOUNT]: "<b>Prod</b>" })] });
  assert.equal(h.detail(profile, sso()).rows.Account, "<b>Prod</b> · 1234 5678 9012");
  const bio = { ...profile, tier: "bio" };
  const gated = h.detail(bio, null);
  assert.equal(gated.kvHidden, true);
  assert.deepEqual(gated.rows, {});
  assert.equal(gated.sub, "Show details asks for Touch ID once.");
  assert.equal(h.calls.fetchAwsMeta, 0);
  assert.equal(h.nodes["aws-detail-kind"].textContent, "Details protected by Touch ID");
});

test("refreshSso redraws an open AWS detail once stored account names load", async () => {
  const h = harness({ portals: [portal("corp", {})], status: { portals: [portal("corp", { [ACCOUNT]: "Production" })], registered: {} } });
  h.context.awsDetailTarget = profile;
  await h.run("refreshSso()");
  assert.deepEqual(h.calls.rendered, ["aws/prod"]);
  assert.equal(h.run(`awsAccountText("corp", "${ACCOUNT}")`), "Production · 1234 5678 9012");
  h.context.awsDetailTarget = null;
  await h.run("refreshSso()");
  assert.equal(h.calls.rendered.length, 1);
});

test("action labels end without an ellipsis while progress text and placeholders keep theirs", () => {
  const buttonText = [...html.matchAll(/<(button|summary)\b[^>]*>([^<]*)<\/\1>/g)].map((m) => m[2]);
  assert.ok(buttonText.includes("Block all agents") && buttonText.includes("Add portal"));
  assert.deepEqual(buttonText.filter((t) => /(…|\.\.\.)$/.test(t.trim())), []);
  const literals = [...source.matchAll(/"([^"\n]*(?:…|\.\.\.))"/g)].map((m) => m[1]);
  const notActions = new Set(["Waiting for Touch ID…", "Saving…", "Choose a portal…", "Loading…", "Contacting AWS…", "Cancelling…", "Checking…",
    "Checking… confirm with Touch ID", "typing…", "Saving · confirm with Touch ID when asked…", "Paste an age1… public key first"]);
  assert.deepEqual(literals.filter((t) => !notActions.has(t)), []);
  for (const label of ["Unblock agents", "Block all agents", "New portal", "Make a paper backup", "Delete profile", "Delete secret", "Edit", "Review", "Retarget / update credentials"]) {
    assert.ok(source.includes(`"${label}`), label);
  }
});

test("the folder menu keeps its plain Rename or move and Delete folder labels", () => {
  assert.match(source, /textContent: "Rename or move"/);
  assert.match(source, /textContent: "Delete folder"/);
});
