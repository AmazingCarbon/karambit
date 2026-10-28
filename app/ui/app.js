// Karambit GUI. Vanilla JS; talks to Rust only via Tauri IPC. Secret values are
// never returned to this page (Copy goes straight to the clipboard from Rust);
// only public (non-secret) values are, for display beside the name.
"use strict";

const invoke = window.__TAURI__.core.invoke;
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const $ = (id) => document.getElementById(id);

let secrets = [];
let cfg = null;

// ---------- helpers ----------

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("aria-") || k === "role" || k === "title" || k === "style") n.setAttribute(k, v);
    else n[k] = v;
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

const SVG_NS = document.querySelector("svg").namespaceURI;
function icon(paths) {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("viewBox", "0 0 16 16");
  s.setAttribute("aria-hidden", "true");
  for (const d of paths) {
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("d", d);
    s.append(p);
  }
  return s;
}
const ICON_COPY = ["M5.5 5.5h7v8h-7z", "M3.5 10.5v-8h7"];
const ICON_TRASH = ["M3 4.5h10", "M6.5 4.5V3h3v1.5", "M4.5 4.5l.6 9h5.8l.6-9", "M7 7v4.5M9 7v4.5"];
const ICON_FOLDER = ["M2 4.5a1 1 0 0 1 1-1h3.2l1.3 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"];
const ICON_CHEVRON = ["M6 3.5 10.5 8 6 12.5"];
const ICON_CLOSE = ["M4.5 4.5l7 7M11.5 4.5l-7 7"];
const ICON_ALERT = ["M8 2.2 14.6 13.5H1.4z", "M8 6.5v3.2", "M8 11.6v.01"];
const ICON_INFO = ["M8 1.5a6.5 6.5 0 1 0 0 13a6.5 6.5 0 1 0 0-13z", "M8 7.3v4", "M8 4.9v.01"];
// Leading icon for a .banner: alert triangle for "bad", info circle otherwise.
function bannerIcon(bad) {
  const s = icon(bad ? ICON_ALERT : ICON_INFO);
  s.setAttribute("class", "banner-icon");
  return s;
}

// Success/info goes to #toast (polite, auto-hides). Errors go to #toast-err: they stay
// until dismissed, stack newest first (max 3), and a success never replaces them.
function toast(msg, bad = false, title = "Something went wrong") {
  if (bad) { toastError(title, msg); return; }
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 3000);
}

const TOAST_ERR_MAX = 3;
function toastError(title, msg) {
  const box = $("toast-err");
  // The same failure again (e.g. a retry) moves to the top instead of stacking.
  for (const item of box.children) if (item.dataset.msg === msg) item.remove();
  const close = el("button", { type: "button", class: "ibtn", "aria-label": "Dismiss", title: "Dismiss" }, icon(ICON_CLOSE));
  const item = el("div", { class: "toast-err-item" },
    el("div", { class: "toast-err-text" }, el("b", { textContent: title }), el("p", { textContent: msg })), close);
  item.dataset.msg = msg;
  const dismiss = () => {
    const next = item.nextElementSibling || item.previousElementSibling;
    const hadFocus = item.contains(document.activeElement);
    item.remove();
    if (hadFocus && next) next.querySelector("button").focus();
  };
  close.addEventListener("click", dismiss);
  item.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); dismiss(); } });
  box.prepend(item);
  while (box.childElementCount > TOAST_ERR_MAX) box.lastElementChild.remove();
}

// Short title for an error toast, by IPC command. The backend text is shown in full below it.
const CMD_FAIL_TITLE = {
  add: "Couldn't save the secret", remove: "Couldn't delete", set_policy: "Couldn't change access", block_agents: "Couldn't change agent blocking", recover: "Couldn't restore", policy_explain: "Couldn't check the rules",
  set_config: "Couldn't save a setting", copy_secret: "Couldn't copy", keys_upgrade: "Couldn't add the agent key",
  lease_grant: "Couldn't give temporary access", lease_revoke: "Couldn't end temporary access", lease_revoke_all: "Couldn't end temporary access",
  aws_add: "Couldn't save the AWS profile", aws_add_sso: "Couldn't save the AWS profile", aws_show: "Couldn't read the AWS profile",
  sso_portal_add: "Couldn't add the AWS portal", sso_portal_remove: "Couldn't remove the AWS portal", sso_logout: "Couldn't sign out",
  sso_portal_limit: "Couldn't change the sign-in limit", init: "Couldn't set up Karambit",
  status_full: "Couldn't load status", profile_preview: "Couldn't read that file", profile_trust: "Couldn't trust the file", doctor: "Couldn't run the check", status: "Couldn't load", list: "Couldn't load", get_config: "Couldn't load", audit: "Couldn't load", activity: "Couldn't load",
};

// IPC with the triggering control disabled (Touch ID prompts can take a while).
async function call(cmd, args = {}, ctl = null) {
  if (ctl) ctl.disabled = true;
  try {
    return await invoke(cmd, args);
  } catch (err) {
    toast(String(err), true, CMD_FAIL_TITLE[cmd]);
    throw err;
  } finally {
    if (ctl) ctl.disabled = false;
  }
}

function setChip(node, kind, text) {
  node.className = `chip ${kind}`;
  node.querySelector(".chip-text").textContent = text;
}

function relTime(ts) {
  if (!ts) return "";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`;
  // Older: a short date ("Sep 29"), with the year only when it isn't this year.
  const d = new Date(ts * 1000);
  const opts = { month: "short", day: "numeric" };
  if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
  return d.toLocaleDateString(undefined, opts);
}
const fullTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "");
const groupAccount = (a) => String(a || "").replace(/^(\d{4})(\d{4})(\d{4})$/, "$1 $2 $3");

function splitName(name) {
  const i = name.lastIndexOf("/");
  return i < 0 ? ["", name] : [name.slice(0, i), name.slice(i + 1)];
}

// window.confirm() is a no-op in WKWebView, so use an in-page <dialog>.
function confirmDialog(title, msg, okLabel = "Delete", danger = true, noLabel = "Cancel") {
  return new Promise((resolve) => {
    const dlg = $("confirm-dialog");
    const yes = $("confirm-yes");
    $("confirm-title").textContent = title;
    // msg: one string, or an array of lines (one <p> each).
    $("confirm-msg").replaceChildren(...[].concat(msg).filter(Boolean).map((line) => el("p", { textContent: line })));
    $("confirm-no").textContent = noLabel;
    yes.textContent = okLabel;
    yes.className = danger ? "btn danger" : "btn primary";
    const done = (val) => {
      yes.onclick = null;
      $("confirm-no").onclick = null;
      dlg.oncancel = null;
      if (dlg.open) dlg.close();
      resolve(val);
    };
    yes.onclick = () => done(true);
    $("confirm-no").onclick = () => done(false);
    dlg.oncancel = (e) => { e.preventDefault(); done(false); };
    openDialog(dlg);
    $("confirm-no").focus();
  });
}

// ---------- navigation ----------

let currentView = "secrets";

function show(view) {
  if (view === "sources" && !sourceKinds.length) view = "secrets";
  currentView = view;
  for (const v of ["init", "secrets", "aws", "sources", "audit", "settings", "status"]) $(`view-${v}`).hidden = v !== view;
  for (const t of document.querySelectorAll(".tab")) {
    const active = t.dataset.view === view;
    t.classList.toggle("active", active);
    if (active) t.setAttribute("aria-current", "page");
    else t.removeAttribute("aria-current");
  }
  selectedSecret = null;
  document.querySelector(`#view-${view === "aws" ? "aws" : "secrets"} .secrets-body`).append($("inspector"));
  renderInspector();
  if (["secrets", "aws", "sources"].includes(view)) loadSecrets();
  if (view === "audit") loadAudit();
  if (view === "settings") loadSettings();
  if (view === "status") loadStatusPage();
}

async function loadStatus() {
  const s = await call("status");
  const h = $("health");
  const helper = s.helper || {};
  lastHealth = !s.initialized ? ["bad", "Not set up"]
    : helper.error || !helper.secure_enclave ? ["bad", "Secure Enclave unavailable"]
    : !helper.biometrics ? ["warn", "Touch ID unavailable"] : ["ok", "Touch ID ready"];
  setChip(h, lastHealth[0], lastHealth[1]);
  if (s.initialized && cfg) renderHealth();
  renderLockBanner(s);
  collapseAlerts();
  return s;
}

// Agent-enabled, no-prompt secrets still on the unlock-only key stop working when the
// screen locks. One click moves them to the lock-safe agent key (one Touch ID).
function renderLockBanner(s) {
  const n = s.initialized ? s.locked_screen_blocked || 0 : 0;
  const needKey = s.initialized && s.agent_key === false;
  $("lock-banner").hidden = !n && !needKey;
  $("lock-banner-text").textContent = n
    ? `${n} agent-enabled ${n === 1 ? "secret stops" : "secrets stop"} working when the screen locks.`
    : "Agent secrets you add won't work while the screen is locked until the agent key is created.";
}

async function fixLockKeys() {
  try {
    const r = await call("keys_upgrade", {}, $("lock-fix"));
    const n = (r.moved || []).length;
    toast(n ? `${n} ${n === 1 ? "secret now works" : "secrets now work"} for agents while locked` : "Agent key ready");
  } catch { /* toast shown */ }
  loadStatus();
  loadSecrets();
}

// ---------- secrets ----------

async function loadSecrets() {
  const [list, sourceResult] = await Promise.all([call("list"), sourceKinds.length ? call("source_list") : { sources: [] }, refreshSso()]);
  sources = sourceResult.sources || [];
  secrets = list;
  renderLists();
  renderInspector();
  if (awsDetailTarget) renderAwsDetail(secrets.find((s) => s.name === awsDetailTarget.name) || null);
}

// ---------- access levels ----------

// One setting per entry instead of three switches. Order mirrors the dependency:
// Public (overrides both) → Agents → Touch ID, most open first. Public stays on the
// open tier so it never prompts.
// Labels say who + whether Touch ID is needed. Hints must not overstate what's enforced
// (README Limits): no-prompt keys are usable by any process running as you, and agent
// detection is a heuristic, so only the Touch ID levels hold against a determined agent.
const ACCESS_LEVELS = [
  { id: "public", label: "Public · not secret", hint: "Not a secret: shown here, agents read it, never redacted",
    flags: { touch: "off", agentAllowed: true, public: true } },
  { id: "agents", label: "Agents · no prompt", hint: "You and your agents use it without asking; any program running as you could read it",
    flags: { touch: "off", agentAllowed: true, public: false } },
  { id: "agents-touch", label: "Agents · Touch ID", hint: "Agents may use it after your Touch ID, or freely while you give them temporary access",
    flags: { touch: "on", agentAllowed: true, public: false } },
  // Retired: no-prompt "Only me" doesn't stop a determined agent. Kept only so a
  // legacy secret still shows a label; never offered as a new choice.
  { id: "me", label: "Only me", hint: "Retired: pick Only me · Touch ID", retired: true,
    flags: { touch: "off", agentAllowed: false, public: false } },
  { id: "me-touch", label: "Only me · Touch ID", hint: "Detected agents are refused; you confirm with Touch ID",
    flags: { touch: "on", agentAllowed: false, public: false } },
];

// Long form for the detail dialog: what this level actually means, including the
// human Touch ID reuse window from config (0 = every time).
function accessDetail(id) {
  if (id !== "me-touch") return accessLevel(id).hint + ".";
  const h = cfg ? cfg.human_lease_hours : 3;
  const reuse = h > 0
    ? `After one Touch ID you aren't asked again for up to ${hoursLabel(h)}, or until the screen locks.`
    : "You're asked for Touch ID every time.";
  return `Agents are refused unless you give them temporary access. ${reuse} Agent detection can be fooled by a determined agent; the Touch ID prompt can't.`;
}
const hoursLabel = (h) => (h === 1 ? "1 hour" : `${h} hours`);

function accessOf(s) {
  if (s.public) return "public";
  if (s.tier === "bio") return s.agent_allowed ? "agents-touch" : "me-touch";
  return s.agent_allowed ? "agents" : "me";
}
const accessLevel = (id) => ACCESS_LEVELS.find((l) => l.id === id);
const levelFlags = (id) => ({ ...accessLevel(id).flags });
// Offered choices: never the retired level; AWS entries can't be public.
const levelsFor = (aws) => ACCESS_LEVELS.filter((l) => !l.retired && (!aws || l.id !== "public"));
const defaultLevel = () => (cfg && cfg.default_tier === "bio" ? "agents-touch" : "agents");

// Names with a policy change in flight → status text, so a re-render keeps the busy state.
const accessBusy = new Map();

// Level glyphs: colour comes from CSS (.lvl-<id>); meaning always also in text/aria-label.
const ICON_UNLOCKED = ["M4.5 7.5h7v6h-7z", "M6 7.5V5.5a2 2 0 0 1 3.9-.6"];
const ICON_LOCKED = ["M4.5 7.5h7v6h-7z", "M6 7.5V5.5a2 2 0 0 1 4 0v2"];
const ICON_FINGERPRINT = ["M3.5 10.5c.3-.7.5-1.4.5-2a4 4 0 0 1 8 0c0 .9-.1 1.8-.3 2.6", "M6 13.5c.6-1.5.9-3 .9-5a1.1 1.1 0 0 1 2.2 0c0 1.7-.2 3.2-.7 4.6"];
const ICON_EYE = ["M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8 12.1 12.5 8 12.5 1.5 8 1.5 8z", "M8 6.2a1.8 1.8 0 1 1 0 3.6 1.8 1.8 0 0 1 0-3.6z"];
const ICON_CLOCK = ["M8 2.5a5.5 5.5 0 1 1 0 11 5.5 5.5 0 0 1 0-11z", "M8 5v3l2 1.5"];
const LEVEL_ICON = { public: ICON_EYE, agents: ICON_UNLOCKED, "agents-touch": ICON_FINGERPRINT, me: ICON_LOCKED, "me-touch": ICON_LOCKED };
function levelGlyph(id) {
  const g = icon(LEVEL_ICON[id]);
  g.setAttribute("class", `lvl-glyph lvl-${id}`);
  return g;
}

function accessSelect(s, display, reload) {
  const cur = accessOf(s);
  const opts = levelsFor(isAws(s.name));
  const hintId = `acc-hint-${++accessHintSeq}`;
  const select = el("select", { "aria-label": `Access for ${s.name}`, "aria-describedby": hintId, title: accessLevel(cur).hint },
    ...opts.map((l) => el("option", { value: l.id, textContent: l.label, title: l.hint })));
  // Legacy "Only me" (retired): show it as a disabled current value so the row still renders.
  if (!opts.some((l) => l.id === cur)) {
    select.prepend(el("option", { value: cur, textContent: `${accessLevel(cur).label} (retired)`, disabled: true }));
  }
  select.value = cur;
  const status = el("span", { class: "access-status", role: "status" });
  const busy = accessBusy.get(s.name);
  if (busy) {
    select.disabled = true;
    select.setAttribute("aria-busy", "true");
    status.textContent = busy;
  } else if (accessError.has(s.name)) {
    showAccessError(status, s.name, accessError.get(s.name).text);
  }
  select.addEventListener("change", () => changeAccess(s, select, status, display, reload));
  // Screen readers don't reliably announce `title`; describe the current level too.
  return el("div", { class: `access lvl-${cur}` }, levelGlyph(cur), select, status, el("span", { id: hintId, class: "sr-only", textContent: accessLevel(cur).hint }));
}
let accessHintSeq = 0;

// A failed access change stays visible in its row for a few seconds (and survives the re-render).
const ACCESS_ERROR_MS = 8000;
const accessError = new Map(); // name -> { text, timer }

function showAccessError(status, name, text) {
  status.textContent = text;
  status.title = text;
  status.classList.add("error");
  status.dataset.errorFor = name;
}

function setAccessError(name, text) {
  clearTimeout(accessError.get(name)?.timer);
  const timer = setTimeout(() => {
    accessError.delete(name);
    for (const n of document.querySelectorAll(".access-status.error")) {
      if (n.dataset.errorFor !== name) continue;
      n.textContent = "";
      n.removeAttribute("title");
      n.classList.remove("error");
    }
  }, ACCESS_ERROR_MS);
  accessError.set(name, { text, timer });
}

async function changeAccess(s, select, status, display, reload) {
  const from = accessOf(s);
  const to = select.value;
  if (to === from || accessBusy.has(s.name)) { select.value = from; return; }
  const label = select.getAttribute("aria-label");
  const pubChange = from === "public" || to === "public";
  if (pubChange) {
    const on = to === "public";
    const ok = await confirmDialog(
      on ? "Make public?" : "Make secret?",
      on ? `Agents will be able to read ${display} and it won't be redacted. Use this only for identifiers like emails and URLs.`
         : `${display} will be hidden from agents and redacted again.`,
      on ? "Make public" : "Make secret",
      false,
    );
    if (!ok || accessBusy.has(s.name)) { select.value = from; return; }
  }
  // Public on/off sends the full target level; otherwise only the fields that differ.
  const want = levelFlags(to);
  const change = {};
  if (pubChange) Object.assign(change, want);
  else {
    if (want.touch !== (s.tier === "bio" ? "on" : "off")) change.touch = want.touch;
    if (want.agentAllowed !== s.agent_allowed) change.agentAllowed = want.agentAllowed;
  }
  // Mirrors the backend: Touch ID-tier entries and relaxing changes prompt.
  const relaxes = (change.touch === "off" && s.tier === "bio")
    || (change.agentAllowed === true && !s.agent_allowed)
    || (change.public === true && !s.public);
  const text = s.tier === "bio" || relaxes ? "Waiting for Touch ID…" : "Saving…";
  accessBusy.set(s.name, text);
  clearTimeout(accessError.get(s.name)?.timer);
  accessError.delete(s.name);
  status.classList.remove("error");
  select.disabled = true;
  select.setAttribute("aria-busy", "true");
  status.textContent = text;
  try {
    await call("set_policy", { names: [s.name], touch: null, agentAllowed: null, public: null, ...change });
    toast(`${display}: ${accessLevel(to).label}`);
  } catch (err) {
    setAccessError(s.name, `Not changed: ${err}`);
  }
  accessBusy.delete(s.name);
  select.disabled = false;
  select.removeAttribute("aria-busy");
  status.textContent = "";
  // The re-render replaces the row: put keyboard focus back on its select.
  await reload();
  const again = [...document.querySelectorAll("select")].find((n) => n.getAttribute("aria-label") === label);
  if (again && document.activeElement === document.body) again.focus();
}

// ---------- values beside the name ----------

// Public values are non-secret by definition; kept in memory only (never storage/console).
const publicValues = new Map(); // name -> { updated, value: string | null }
let publicValueBtns = new Map(); // name -> .val button in the current table render
let publicSeq = 0;
const MASK = "••••••••"; // fixed length: never hints at the real one

async function copyValue(name, btn) {
  try {
    const secs = await call("copy_secret", { name }, btn);
    toast(`Copied · clears in ${secs}s`);
  } catch { /* toast shown */ }
}

function showPublicValue(btn, value) {
  if (value == null) return;
  btn.firstChild.textContent = value;
  btn.title = value;
}

// Public rows show the value; others a fixed mask. Either way, click copies.
function valueButton(s) {
  const btn = el("button", { type: "button", class: s.public ? "val" : "val masked", "aria-label": `Copy ${s.name}`, title: "Copy value" },
    el("span", { class: "val-text", textContent: s.public ? "" : MASK }), icon(ICON_COPY));
  btn.addEventListener("click", () => copyValue(s.name, btn));
  if (s.public) {
    publicValueBtns.set(s.name, btn);
    const c = publicValues.get(s.name);
    if (c && c.updated === s.updated) showPublicValue(btn, c.value);
  }
  return btn;
}

// One batched fetch per render for visible public entries that are missing or stale.
function fetchPublicValues(shown) {
  const live = new Set(secrets.filter((s) => s.public).map((s) => s.name));
  for (const name of publicValues.keys()) if (!live.has(name)) publicValues.delete(name);
  const want = shown.filter((s) => s.public && publicValues.get(s.name)?.updated !== s.updated);
  if (!want.length) return;
  const seq = ++publicSeq;
  // Direct invoke, not call(): older backends lack this command; fail silently.
  invoke("public_values", { names: want.map((s) => s.name) }).then((vals) => {
    if (seq !== publicSeq) return;
    for (const s of want) {
      const v = vals && Object.prototype.hasOwnProperty.call(vals, s.name) && typeof vals[s.name] === "string" ? vals[s.name] : null;
      publicValues.set(s.name, { updated: s.updated, value: v });
      const btn = publicValueBtns.get(s.name);
      if (btn) showPublicValue(btn, v);
      if (selectedSecret === s.name && secrets.some((x) => x.name === s.name && x.public) && $("inspector-value") && v != null) $("inspector-value").textContent = v;
    }
  }, () => {
    if (seq !== publicSeq) return;
    for (const s of want) publicValues.set(s.name, { updated: s.updated, value: null });
  });
}

// ---------- the list ----------
// Folders are slash-delimited name prefixes; linked sources occupy a separate namespace.

let currentFolder = "";
let currentSource = null;
let selectedSecret = null;
let sources = [];
// Backend kinds this build registers. Linked sources are hidden while the list is empty.
let sourceKinds = [];
function applySourceKinds() {
  const on = sourceKinds.length > 0;
  $("source-kind").replaceChildren(...sourceKinds.map((k) => el("option", { value: k, textContent: k })));
  $("source-open-more").hidden = !on;
  // Keep ⌘1–⌘N matching the tabs that are shown.
  let n = 0;
  for (const t of document.querySelectorAll(".tab")) {
    t.hidden = t.dataset.view === "sources" && !on;
    if (t.hidden) { delete TAB_KEYS_BY_VIEW[t.dataset.view]; continue; }
    n += 1;
    TAB_KEYS_BY_VIEW[t.dataset.view] = n;
    t.setAttribute("aria-keyshortcuts", `Meta+${n}`);
    t.title = t.title.replace(/\(⌘\d\)/, `(⌘${n})`);
  }
}
const TAB_KEYS_BY_VIEW = {};

function deleteButton(s) {
  const aws = isAws(s.name);
  const display = aws ? s.name.slice(4) : s.name;
  const del = el("button", { class: "ibtn del", title: "Delete", "aria-label": `Delete ${aws ? "AWS profile " : ""}${display}` }, icon(ICON_TRASH));
  del.addEventListener("click", async () => {
    // The offline backup copy lives inside the secret file, so deleting removes it too.
    const lines = [
      aws
        ? `${display} will be removed from Karambit. ${awsMeta.get(s.name)?.sso ? "Your AWS access itself is unchanged." : "The keys themselves stay valid in AWS until they expire."}`
        : `${s.name} will be permanently removed.`,
      "This can't be undone: its offline backup copy is stored with it, so karambit recover can't bring it back.",
      s.lease ? `${s.lease.to_label} has temporary access until ${fullTime(s.lease.expires)}; that ends now.` : null,
    ];
    if (!(await confirmDialog(aws ? "Delete AWS profile?" : "Delete secret?", lines, aws ? "Delete profile" : "Delete secret"))) return;
    try {
      await call("remove", { names: [s.name] }, del);
      toast(`Deleted ${display}`);
    } catch { /* toast shown */ }
    loadSecrets();
  });
  return del;
}

function leaseTag(s) {
  return s.lease ? el("span", { class: "tag lease", textContent: `Temporary access · ${durShort(s.lease.remaining)}`,
    title: `Given to ${s.lease.to_label} until ${fullTime(s.lease.expires)}` }) : null;
}

function levelBadge(s, editable = false) {
  const id = accessOf(s);
  // Status only: the panel's "Who can use it" group is the one place to change access.
  return el(editable ? "button" : "span", { class: `level-badge lvl-${id}`, title: `Access: ${accessLevel(id).label}`,
    ...(editable ? { type: "button", "aria-label": `Access: ${accessLevel(id).label}. Show ${s.name} details`, onclick: (e) => { e.stopPropagation(); focusAccess(s.name); } } : {}) }, levelGlyph(id), accessLevel(id).label);
}

function secretRow(s, label) {
  const meta = freshMeta(s);
  const row = el("div", { class: `secret-row${selectedSecret === s.name ? " selected" : ""}` },
    el("span", { class: "tile" }, levelGlyph(accessOf(s))),
    el("div", { class: "row-name" },
      el("div", { class: "row-name-line" }, el("button", { type: "button", class: "leaf link", textContent: label, "aria-label": `Details for ${s.name}`, onclick: () => openDetail(s.name) }), isAws(s.name) ? null : valueButton(s)),
      el("span", { class: "muted small", textContent: isAws(s.name) ? (meta ? awsSummary(meta) : "AWS profile · open details") : s.public ? "Public · never redacted" : "" }), leaseTag(s)),
    levelBadge(s, true),
    el("span", { class: "when", textContent: relTime(s.updated), title: fullTime(s.updated) }));
  return wholeRow(row, () => openDetail(s.name));
}

function wholeRow(row, open) {
  row.addEventListener("click", (e) => {
    if (e.target.closest("button, a, input, select, summary, details.folder-menu, [role=dialog]")) return;
    if (!window.getSelection()?.toString()) open();
  });
  return row;
}

function renderLists() {
  renderSecrets();
  renderAwsPage();
  if (currentView === "sources") renderSources();
}

function goUp() {
  if (currentView === "sources") { currentSource = null; renderSources(); $("sources-title").focus(); }
  else navigateFolder(currentFolder.split("/").slice(0, -1).join("/"));
}

function navigateFolder(path = "", source = null) {
  if (source) { currentSource = source; show("sources"); renderSources(); $("sources-title").focus(); return; }
  // aws/ has exactly one view: the AWS page.
  if (path === "aws" || path.startsWith("aws/")) { currentFolder = ""; if (currentView !== "aws") show("aws"); return; }
  if (currentView !== "secrets") show("secrets");
  currentFolder = path;
  selectedSecret = null;
  renderSecrets();
  renderInspector();
  $("folder-title").focus();
  document.querySelectorAll(".folder-menu[open]").forEach((n) => { n.open = false; });
}

async function deleteFolder(path, items) {
  const names = items.map((s) => s.name);
  if (!(await confirmDialog(`Delete ${path}/?`, [`Permanently removes these ${names.length} local items and their offline backup copies:`, names.join(", "), "This cannot be undone. Linked sources and remote secrets are not affected."], "Delete folder"))) return;
  try { await call("remove", { names }); toast(`Deleted ${path}/`); }
  catch { /* toast shown; reload also reflects any partial deletion */ }
  await loadSecrets();
}

function folderRow(path, items, matches) {
  const levels = [...new Set(items.map(accessOf))];
  const menu = el("details", { class: "folder-menu" },
    el("summary", { "aria-label": `Actions for ${path}` }, "⋯"),
    el("div", { class: "menu-actions" },
      el("div", { class: "menu-heading" }, el("b", { textContent: path + "/" }), el("button", { type: "button", class: "ibtn", "aria-label": "Close folder menu", onclick: () => { menu.open = false; menu.querySelector("summary").focus(); } }, icon(ICON_CLOSE))),
      el("button", { class: "btn", textContent: "Open", onclick: () => navigateFolder(path) }),
      el("button", { class: "btn", textContent: "New secret here", onclick: () => openAdd(path) }),
      el("button", { class: "btn", textContent: "Temporary access for folder…", onclick: () => openFolderDetail(path) }),
      el("button", { class: "btn danger-text", textContent: "Delete folder…", onclick: () => deleteFolder(path, items) })));
  menu.addEventListener("toggle", () => {
    if (!menu.open) return;
    document.querySelectorAll(".folder-menu[open]").forEach((other) => { if (other !== menu) other.open = false; });
    const popup = menu.querySelector(".menu-actions"), rect = menu.getBoundingClientRect();
    popup.style.left = `${Math.max(8, Math.min(rect.right - popup.offsetWidth, innerWidth - popup.offsetWidth - 8))}px`;
    popup.style.top = `${Math.max(8, Math.min(rect.bottom, innerHeight - popup.offsetHeight - 8))}px`;
  });
  menu.querySelector(".menu-actions").addEventListener("click", (e) => { if (e.target.closest("button")) menu.open = false; });
  return wholeRow(el("div", { class: "secret-row folder-row" }, el("span", { class: "tile" }, icon(ICON_FOLDER)),
    el("div", { class: "row-name" }, el("button", { class: "group-toggle leaf", textContent: path.slice(currentFolder ? currentFolder.length + 1 : 0) + "/", onclick: () => navigateFolder(path) }),
      el("span", { class: "muted small", textContent: matches.length === items.length ? (path === "aws" ? `AWS profiles · ${items.length}` : "This Mac") : `${matches.length} of ${items.length} match` })),
    el("span", { class: "muted small", textContent: plural(matches.length, "item") }),
    levels.length === 1 ? levelBadge(items[0]) : el("span", { class: "muted small", textContent: `Mixed: ${levels.length} levels` }), menu), () => navigateFolder(path));
}

function signInButton(portal, aria) {
  const b = el("button", { type: "button", class: "btn sm signin", textContent: "Sign in", "aria-label": aria });
  b.addEventListener("click", () => startSignIn(portal));
  return b;
}

// Group header: disclosure button (aria-expanded), count, access summary, and the
// folder-wide temporary access action.
// ---------- exposure strip ----------
// The list leads with risk: what agents can read without asking, then the rest.
// Each chip filters the list to its level (toggle) and combines with the text filter.
const EXPOSURE = [
  // short = chip text; label = full meaning for title/aria-label and the "Showing only" line.
  { id: "agents", short: "No prompt", label: "Agents, no prompt", glyph: "agents", test: (s) => accessOf(s) === "agents" },
  { id: "agents-touch", short: "Touch ID", label: "Agents with Touch ID", glyph: "agents-touch", test: (s) => accessOf(s) === "agents-touch" },
  { id: "me", short: "Only me", label: "Only me", glyph: "me-touch", test: (s) => accessOf(s) === "me-touch" || accessOf(s) === "me" },
  { id: "public", short: "Public", label: "Public", glyph: "public", test: (s) => accessOf(s) === "public" },
  { id: "lease", short: "Temporary", label: "Temporary access", glyph: null, test: (s) => !!s.lease, optional: true },
];
// One short line per level for the legend (condensed from the ACCESS_LEVELS hints).
const LEVEL_LEGEND = [
  ["agents", "Agents · no prompt", "any program running as you can read it"],
  ["agents-touch", "Agents · Touch ID", "agents use it after your Touch ID"],
  ["me-touch", "Only me · Touch ID", "detected agents are refused"],
  ["public", "Public", "not secret, never redacted"],
];
let exposureFilter = null; // EXPOSURE id or null

function renderExposure() {
  // Counts are scoped to the current folder; the top level counts the vault.
  const prefix = currentFolder ? currentFolder + "/" : "";
  const scope = secrets.filter((s) => s.name.startsWith(prefix));
  const any = secrets.length > 0;
  $("exposure").hidden = !any;
  $("exposure-legend").hidden = !any;
  if (!any) { exposureFilter = null; return; }
  const counts = new Map(EXPOSURE.map((x) => [x.id, scope.filter(x.test).length]));
  if (exposureFilter && !counts.get(exposureFilter)) exposureFilter = null;
  const chips = EXPOSURE.filter((x) => !x.optional || counts.get(x.id) > 0).map((x) => {
    const n = counts.get(x.id);
    const glyph = x.glyph ? levelGlyph(x.glyph) : icon(ICON_CLOCK);
    if (!x.glyph) glyph.setAttribute("class", "lvl-glyph lvl-lease");
    const b = el("button", { type: "button", class: `exp-chip exp-${x.id}`, "aria-pressed": String(exposureFilter === x.id), disabled: n === 0,
      "aria-label": `${x.label}: ${n}`,
      title: `${x.label}: ${n}${n === 0 ? "" : exposureFilter === x.id ? " · click to show everything" : " · click to show only these"}` },
      glyph, el("span", { class: "exp-label", textContent: x.short }), el("span", { class: "exp-count", textContent: String(n) }));
    b.dataset.exposure = x.id;
    b.addEventListener("click", () => {
      exposureFilter = exposureFilter === x.id ? null : x.id;
      renderSecrets();
      const again = document.querySelector(`.exp-chip[data-exposure="${x.id}"]`);
      if (again) again.focus();
    });
    return b;
  });
  const all = el("button", { class: "exp-chip", "aria-pressed": String(!exposureFilter), textContent: `All ${scope.length}`, onclick: clearExposure });
  $("exposure-chips").replaceChildren(all, ...chips);
  const cur = EXPOSURE.find((x) => x.id === exposureFilter);
  $("exposure-state").hidden = !cur;
  $("exposure-showing").textContent = cur ? `Showing only ${cur.label} items, still in their folders. ${sourceKinds.length ? "Linked sources have separate policies and are hidden." : ""}` : "";
  if (!$("exposure-legend").childElementCount) {
    $("exposure-legend").append(...LEVEL_LEGEND.map(([id, label, what]) =>
      el("span", { class: "legend-item" }, levelGlyph(id), el("span", { textContent: `${label} = ${what}` }))));
  }
}

function clearExposure() {
  const was = exposureFilter;
  exposureFilter = null;
  renderSecrets();
  const chip = document.querySelector(`.exp-chip[data-exposure="${was}"]`);
  if (chip) chip.focus();
}

// ---------- search (rules and tests: search.js, app/tests/search.test.js) ----------
// Fields a query word may match. Only the name (first field) is highlighted.
function searchFields(s) {
  const fields = [{ text: s.name }, { text: accessLevel(accessOf(s)).label, weight: 0.5 }];
  if (s.public) fields.push({ text: "public", weight: 0.5 });
  if (s.lease) fields.push({ text: "temporary access lease", weight: 0.5 });
  if (isAws(s.name)) {
    const m = freshMeta(s), r = ssoRegistered[s.name], portal = r?.portal || awsPortalFor(s);
    const account = r?.account || (m && m.sso ? m.account : "");
    const accountName = ssoPortals.find((p) => p.portal === portal)?.accounts?.[account] || "";
    fields.push({ text: ["aws", portal, account, accountName, r?.role, m && !m.error ? awsSummary(m) : ""].filter(Boolean).join(" "), weight: 0.6 });
  }
  return fields;
}
// Score map for one query over a list of secrets: name -> { score, ranges }; null when no query.
function searchSecrets(query, list) {
  const m = KarambitSearch.compile(query);
  if (!m.active) return null;
  const hits = new Map();
  for (const s of list) { const r = m.score(searchFields(s)); if (r) hits.set(s.name, r); }
  return hits;
}
// Text nodes with <mark> on matched ranges, plus <wbr> after / and - so long names wrap.
function highlightNodes(text, ranges = []) {
  const out = [];
  const push = (part, hit) => {
    for (const piece of part.split(/(?<=[\/-])/)) {
      if (!piece) continue;
      out.push(hit ? el("mark", { class: "hit", textContent: piece }) : document.createTextNode(piece));
      if (/[\/-]$/.test(piece)) out.push(el("wbr"));
    }
  };
  let at = 0;
  for (const [a, b] of ranges) { if (a > at) push(text.slice(at, a), false); push(text.slice(a, b), true); at = b; }
  if (at < text.length) push(text.slice(at), false);
  return out;
}
// Highlight a row's name; `label` is the displayed suffix of the full name.
function markRow(row, s, label, hit) {
  if (!hit) return row;
  const leaf = row.querySelector(".leaf");
  if (leaf) leaf.replaceChildren(...highlightNodes(label, KarambitSearch.shift(hit.ranges, s.name.length - label.length, label.length)));
  return row;
}
const byScore = (hits) => (a, b) => (hits.get(b.name)?.score ?? 0) - (hits.get(a.name)?.score ?? 0) || a.name.localeCompare(b.name);

function renderSecrets() {
  const q = $("filter").value;
  const rows = $("rows");
  rows.replaceChildren();
  publicValueBtns = new Map();
  renderExposure();
  const exposure = EXPOSURE.find((x) => x.id === exposureFilter);
  const hits = searchSecrets(q, secrets);
  const match = (s) => (!hits || hits.has(s.name)) && (!exposure || exposure.test(s));
  const prefix = currentFolder ? currentFolder + "/" : "";
  const contents = secrets.filter((s) => s.name.startsWith(prefix));
  const shown = [];
  const groups = new Map();
  const loose = [];
  for (const s of contents) {
    const rest = s.name.slice(prefix.length);
    const slash = rest.indexOf("/");
    if (slash < 0) loose.push(s);
    else {
      const path = prefix + rest.slice(0, slash);
      if (!groups.has(path)) groups.set(path, []);
      groups.get(path).push(s);
    }
  }
  const hidden = [];
  $("breadcrumbs").replaceChildren(el("button", { class: "link", textContent: "All secrets", onclick: () => navigateFolder() }));
  if (currentFolder) $("breadcrumbs").prepend(el("button", { class: "btn sm", textContent: "← Back", "aria-keyshortcuts": "Meta+[ Backspace", onclick: goUp }));
  currentFolder.split("/").filter(Boolean).forEach((part, i, parts) => {
    $("breadcrumbs").append(" / ", el("button", { class: "link", textContent: part, onclick: () => navigateFolder(parts.slice(0, i + 1).join("/")) }));
  });
  $("folder-title").textContent = currentFolder ? currentFolder + "/" : "Secrets";
  $("breadcrumbs").hidden = !currentFolder; // top level is the root: no "All secrets" crumb
  // With a query, folders holding the best match come first; otherwise alphabetical.
  const best = (items) => Math.max(0, ...items.filter(match).map((s) => hits?.get(s.name)?.score ?? 0));
  const ordered = [...groups].sort(([a, x], [b, y]) => (hits ? best(y) - best(x) : 0) || a.localeCompare(b));
  for (const [path, items] of ordered) {
    const matches = items.filter(match);
    if (!matches.length) { hidden.push(path + "/"); continue; }
    rows.append(folderRow(path, items, matches));
    if (hits || exposure) for (const item of hits ? matches.sort(byScore(hits)) : matches) {
      const label = item.name.slice(path.length + 1);
      const row = markRow(secretRow(item, label), item, label, hits?.get(item.name));
      row.classList.add("child"); rows.append(row); shown.push(item);
    }
  }
  const looseShown = loose.filter(match);
  if (hits) looseShown.sort(byScore(hits));
  for (const item of looseShown) { const label = item.name.slice(prefix.length); rows.append(markRow(secretRow(item, label), item, label, hits?.get(item.name))); shown.push(item); }
  const unmatched = contents.length - contents.filter(match).length;
  $("hidden-folders").textContent = [hidden.length ? `${hidden.join(", ")} have no matching items and are hidden for now.` : "", unmatched ? `${unmatched} other items do not match. Clear the filters to show all.` : ""].filter(Boolean).join(" ");
  // Inside a folder, never hide matches elsewhere silently.
  const elsewhere = hits && currentFolder ? secrets.filter((s) => !s.name.startsWith(prefix) && match(s)).length : 0;
  if (elsewhere) $("hidden-folders").append(" ", el("button", { type: "button", class: "link", id: "search-everywhere",
    textContent: `${plural(elsewhere, "more match", "more matches")} in other folders · Show`, onclick: () => { navigateFolder(); $("filter").focus(); } }));
  $("count").textContent = (hits || exposure) ? `Filtered: ${contents.filter(match).length} of ${plural(contents.length, "item")}`
    : groups.size > 0 && contents.length > 0 ? `${plural(groups.size, "folder")} · ${plural(contents.length, "item")}` : plural(contents.length, "item");
  fetchPublicValues(shown);
  fetchAwsMeta(shown);
  $("empty").hidden = rows.childElementCount > 0;
  $("empty-text").textContent = secrets.length ? "Nothing matches the filter." : "Your folders will live here";
  $("empty-hint").hidden = secrets.length > 0;
  $("leases-end-all").hidden = !secrets.some((s) => s.lease);
  $("more-title").textContent = `More · ${currentFolder ? currentFolder + "/" : "Secrets"}`;
  const unbacked = secrets.filter((s) => !s.has_backup).length;
  const banner = $("backup-banner");
  banner.hidden = unbacked === 0 || !!currentFolder; // inside folders: Settings › Backup carries it
  if (unbacked) {
    banner.replaceChildren(bannerIcon(false), el("span", {},
      `${unbacked} of ${secrets.length} secrets have no offline backup. If Touch ID keys are lost, they can't be recovered. Run `,
      el("code", { textContent: "karambit backup rotate" }),
      " in a terminal to fix.",
    ));
  }
  renderSsoBanner();
  renderBlock();
  collapseAlerts();
}

// ---------- block agents (CLI block/unblock) ----------
// cfg.killed = { all, agents: [...], sessions: [...] } or absent. Blocking refuses requests;
// it never stops processes, so the copy says so.
function blockedState() {
  const k = cfg && cfg.killed;
  if (!k) return null;
  const agents = k.agents || [], sessions = k.sessions || [];
  if (!k.all && !agents.length && !sessions.length) return null;
  return { all: !!k.all, agents, sessions };
}

function blockedWho(b) {
  if (b.all) return "All agents are blocked";
  const parts = [...b.agents, ...b.sessions.map((s) => `session ${s}`)];
  return `Blocked: ${parts.join(", ")}`;
}

function renderBlock() {
  const b = blockedState();
  // Blocked banner: one line at 1000 px. The "running programs keep what
  // they have" detail lives in the confirm dialog and on Status.
  const banner = $("block-banner");
  banner.hidden = !b;
  banner.className = "blockline";
  if (b) {
    const lead = b.all ? "All agents blocked." : `${blockedWho(b).replace(/^Blocked: /, "Blocked: ")}.`;
    banner.replaceChildren(
      el("span", { class: "txt" }, el("b", { textContent: lead }), " Every request is refused."),
      el("span", { class: "sp" }),
      el("button", { type: "button", class: "btn sm", textContent: "Unblock…", onclick: () => setBlocked(false, b) }));
  }
  for (const id of ["block-agents-menu", "block-agents-settings", "status-block"]) {
    const btn = $(id);
    if (!btn) continue;
    btn.textContent = b ? "Unblock agents…" : "Block all agents…";
    if (id === "block-agents-menu") btn.classList.toggle("danger-text", !b);
    else btn.classList.toggle("danger-ghost", !b);
  }
  if ($("block-state")) {
    $("block-state").textContent = b
      ? `${blockedWho(b)}. Unblocking needs Touch ID; ended temporary access stays ended.`
      : "Refuses every agent request until you unblock. Ends temporary access. Running programs aren’t stopped. Touch ID.";
  }
  // Every page: red sidebar chip + Status badge.
  $("status-badge").hidden = !b;
  renderHealth();
}

// Sidebar chip: blocked beats hardware state. loadStatus() keeps lastHealth up to date.
let lastHealth = null;
function renderHealth() {
  const h = $("health");
  if (blockedState()) { setChip(h, "bad", "Agents blocked"); h.title = "Agents are blocked · open Status"; return; }
  h.title = "Open Status";
  if (lastHealth) setChip(h, lastHealth[0], lastHealth[1]);
}

async function setBlocked(block, current = blockedState()) {
  const btn = document.activeElement instanceof HTMLButtonElement ? document.activeElement : null;
  if (block) {
    const ok = await confirmDialog("Block all agents?", [
      "Every agent request is refused from now on: run, AWS, temporary access. This stays until you unblock, even after a restart.",
      "All temporary access ends now and isn't restored when you unblock.",
      "Agents and programs that are already running aren't stopped and keep any secret they already received.",
    ], "Block agents");
    if (!ok) return;
  }
  try {
    // Unblock clears exactly what is set: --all, then each agent / session.
    if (block) await call("block_agents", { all: true, agent: null, session: null, unblock: false }, btn);
    else {
      if (current?.all) await call("block_agents", { all: true, agent: null, session: null, unblock: true }, btn);
      for (const a of current?.agents || []) await call("block_agents", { all: false, agent: a, session: null, unblock: true }, btn);
      for (const s of current?.sessions || []) await call("block_agents", { all: false, agent: null, session: s, unblock: true }, btn);
    }
    toast(block ? "Agents blocked" : "Agents unblocked");
  } catch { /* toast shown */ }
  cfg = await call("get_config").catch(() => cfg);
  renderBlock();
  collapseAlerts();
  loadSecrets();
  if (currentView === "status") loadStatusPage();
  if (currentView === "settings") renderBackupSettings();
}

// At most one alert line (most severe first: agents blocked, AWS signed out, lock key, backup); "+N more" expands.
let alertsExpanded = false;
const alertsMoreBtn = el("button", { type: "button", id: "alerts-more", class: "link small alerts-more", hidden: true,
  onclick: () => { alertsExpanded = !alertsExpanded; collapseAlerts(); } });
function collapseAlerts() {
  const lines = [$("block-banner"), ...$("sso-banner").querySelectorAll(".sso-line"), $("lock-banner"), $("backup-banner")]
    .filter((n) => !n.hidden && !(n.closest("#sso-banner")?.hidden));
  lines.forEach((n, i) => n.classList.toggle("alert-extra", i > 0 && !alertsExpanded));
  // Kept in JS: banners rebuild their children, which would otherwise drop the button.
  const more = alertsMoreBtn;
  more.hidden = lines.length < 2;
  // Keep "+N more" on the visible alert line instead of a row of its own.
  if (lines[0] && more.parentElement !== lines[0]) lines[0].append(more);
  else if (!lines[0] && more.parentElement !== $("alerts")) $("alerts").append(more);
  more.textContent = alertsExpanded ? "Show less" : `+${lines.length - 1} more`;
  more.setAttribute("aria-expanded", String(alertsExpanded));
}

// ---------- secret details: lease + activity ----------

const durShort = (secs) => {
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), d = Math.floor(secs / 86400);
  if (d >= 1) return `${d}d ${Math.floor((secs % 86400) / 3600)}h`;
  if (h >= 1) return `${h}h ${m}m`;
  return `${Math.max(1, m)}m`;
};

// Who did it. Short, but always unique: agent type + short session id, or "You".
function whoLabel(ev) {
  if (ev.kind) {
    let sess = "";
    if (ev.session) {
      const id = ev.session.includes(":") ? ev.session.slice(ev.session.indexOf(":") + 1) : ev.session;
      sess = ev.session.startsWith("pid:") ? `pid ${id.split("@")[0]}` : id.slice(0, 8);
    } else if (ev.pid) {
      sess = `pid ${ev.pid}`;
    }
    return { text: ev.kind, sess, agent: true };
  }
  if (ev.agent) {
    // Events logged before identity tracking: only the env marker was recorded.
    const m = ev.agent.replace(/^env:/, "");
    const kind = { PI_CODING_AGENT: "pi", CLAUDECODE: "claude", CLAUDE_CODE_ENTRYPOINT: "claude", CODEX_SANDBOX: "codex" }[m] || m.toLowerCase();
    return { text: kind, sess: "", agent: true, legacy: true };
  }
  const c = (ev.caller || [])[0];
  if (c === "karambit-gui") return { text: "You", sess: "app", agent: false };
  if (c === "karambit") return { text: "karambit", sess: "automatic", agent: false };
  return { text: "You", sess: c || "terminal", agent: false };
}

const ACTION_LABEL = {
  run: "Used", get: "Revealed", copy: "Copied", view: "Viewed (public)", add: "Saved", policy: "Access changed", rm: "Deleted",
  lease: "Temporary access given", revoke: "Temporary access ended", "lease-ended": "Temporary access ended (access changed)",
  "lease-used-up": "Temporary access used up", "lease-expired": "Temporary access expired", "aws-describe": "AWS profile details read",
  "backup-rotate": "Backup re-made", recover: "Recovered", config: "Settings changed", init: "Set up", "keys-upgrade": "Agent key added",
  "sso-login": "AWS sign-in", "sso-logout": "AWS sign-out", "sso-portal": "AWS portal saved", "sso-portal-rm": "AWS portal removed",
  "sso-ended": "AWS sign-in ended", "sso-limit": "AWS sign-in limit changed",
};

// Refused events headline the attempted verb, not the success label.
const REFUSED_VERB = { get: "reveal", run: "use", copy: "copy", view: "view", add: "save", policy: "access change", rm: "delete",
  lease: "temporary access", revoke: "end temporary access", "aws-describe": "AWS details", "sso-login": "AWS sign-in", config: "settings change" };
function actionLabel(ev) {
  if (ev.ok === false) return `Refused: ${REFUSED_VERB[ev.action] || ev.action}`;
  return ACTION_LABEL[ev.action] || ev.action;
}
// "in 1h 40m" / "2h ago", for lease end times.
function relUntil(ts) {
  const d = ts - Date.now() / 1000;
  return d > 0 ? `in ${durShort(d)}` : relTime(ts);
}

// What the event was about, in words: the command an agent ran, lease terms, etc.
function eventSummary(ev) {
  const d = ev.detail || {};
  if (ev.action === "run" && d.context) return d.context;
  if (ev.action === "lease") { const l = scopeLabel(d.scope); return `to ${d.to || "?"} for ${d.hours}h · ${d.expires > Date.now() / 1000 ? "until" : "ended"} ${relUntil(d.expires)}${l ? " · " + l : ""}`; }
  if (ev.action === "lease-ended") return d.why || "";
  if (ev.action === "policy") {
    const parts = [];
    if (d.tier) parts.push(`Touch ID ${d.tier === "bio" ? "on" : "off"}`);
    if (d.agent_allowed != null) parts.push(`agents ${d.agent_allowed ? "allowed" : "blocked"}`);
    if (d.public != null) parts.push(d.public ? "made public" : "made secret");
    return parts.join(", ");
  }
  if (ev.action === "add") return d.overwrite ? "replaced value" : "new";
  if (ev.action.startsWith("sso-")) {
    const where = d.portal ? `portal ${d.portal}` : ev.action === "sso-logout" ? "every portal" : "";
    const limit = "limit_minutes" in d && (ev.action === "sso-limit" || d.limit_minutes != null)
      ? `stay signed in ${limitPhrase(d.limit_minutes)}` : "";
    return [where, d.start_url, d.profiles != null ? `${d.profiles} profiles` : "", limit, d.why].filter(Boolean).join(" · ");
  }
  if (ev.action === "config" && d.key) return `${d.key} = ${d.value}`;
  return "";
}

function scopeLabel(sc) {
  if (!sc) return "";
  const v = [];
  if (sc.cwd) v.push(`only in ${sc.cwd.replace(/^\/Users\/[^/]+/, "~")}`);
  if (sc.cmds && sc.cmds.length) v.push(`only ${sc.cmds.map(c => typeof c === "string" ? c : c.path).join("/")}`);
  if (sc.max_uses) v.push(`${sc.max_uses} uses max`);
  return v.join(", ");
}

// Details dialog target: one secret, or a whole folder (prefix, no trailing slash).
let detail = null; // { kind: "secret" | "folder", name }

function focusAccess(name) {
  if (selectedSecret !== name) { selectedSecret = name; renderLists(); renderInspector(); }
  $("inspector").querySelector(".compact-access input:checked, .compact-access input")?.focus();
}
async function openDetail(name) { selectedSecret = name; renderLists(); renderInspector(); $("inspector").querySelector("button")?.focus(); }
async function openFolderDetail(path) { detail = { kind: "folder", name: path }; await showDetail(); }

async function showDetail() {
  const dlg = $("detail-dialog");
  $("lease-cwd").value = "";
  $("lease-cmds").value = "";
  $("lease-uses").value = "";
  $("lease-hours").value = "2";
  $("lease-to").replaceChildren(el("option", { value: "claude", textContent: "claude · any session" }));
  if (!dlg.open) openDialog(dlg);
  await renderDetail();
}

function detailTargets() {
  if (!detail) return [];
  return detail.kind === "secret"
    ? secrets.filter((s) => s.name === detail.name)
    : secrets.filter((s) => s.name.startsWith(detail.name + "/"));
}

async function renderDetail() {
  const d = detail;
  if (!d) return;
  const items = detailTargets();
  if (!items.length) { $("detail-dialog").close(); return; }
  const isFolder = d.kind === "folder";
  $("lease-target-name").textContent = isFolder ? `everything in ${d.name}/` : d.name;
  $("detail-title").textContent = isFolder ? `Give temporary access · ${d.name}/` : `Change temporary access · ${d.name}`;
  if (isFolder) {
    const leasable = items.filter((s) => !s.public).length;
    $("detail-sub").textContent = `Folder · ${items.length} ${items.length === 1 ? "item" : "items"} · ${leasable} can get temporary access (public ones don't need it)`;
    $("detail-access").hidden = true;
  } else {
    const s = items[0];
    const id = accessOf(s);
    $("detail-sub").textContent = `${isAws(s.name) ? "AWS profile · " : ""}${accessLevel(id).label} · updated ${relTime(s.updated)}`;
    $("detail-access").textContent = accessDetail(id);
    $("detail-access").hidden = false;
  }


  // Lease state. Any non-public secret can be leased; for a folder it's every one inside.
  const leasable = items.filter((s) => !s.public);
  const leased = leasable.filter((s) => s.lease);
  $("lease-active").hidden = leased.length === 0;
  if (leased.length) {
    const soonest = leased.reduce((a, b) => (a.lease.expires < b.lease.expires ? a : b)).lease;
    const whom = [...new Set(leased.map((s) => s.lease.to_label))].join(", ");
    $("lease-active-text").textContent = isFolder
      ? `${leased.length} of ${leasable.length} given to ${whom}`
      : `Given to ${whom} · ${durShort(soonest.remaining)} left`;
    const lim = scopeLabel(leased[0].lease.scope);
    const uses = leased.reduce((n, s) => n + (s.lease.uses || 0), 0);
    $("lease-active-sub").textContent = `${isFolder ? "First ends" : "Until"} ${fullTime(soonest.expires)}${lim ? ` \u00b7 ${lim}` : ""} \u00b7 used ${uses}\u00d7. Ends early if you block agents, change the value, or the Karambit daemon restarts; then the access level applies again.`;
  }
  const controls = document.querySelector("#lease-form .lease-controls");
  // Agents · no prompt: a grant changes nothing, so offer the real fix instead.
  const noPrompt = !isFolder && accessOf(items[0]) === "agents";
  controls.hidden = leasable.length === 0 || noPrompt;
  $("lease-grant").hidden = controls.hidden;
  document.querySelector("#lease-form .lease-limits").hidden = noPrompt || leasable.length === 0;
  $("lease-require-touch").hidden = !noPrompt;
  syncDetailPrimary();
  $("lease-grant").textContent = leased.length ? (isFolder ? "Give all again" : "Replace temporary access") : isFolder ? `Give access to all ${leasable.length}` : "Give access";
  const cli = isFolder && leased.length ? ` Replaces ${leased.length} existing grants and resets their use counts.` : "";
  // The banner is only for a real warning or an explanation of why there is no form. The normal
  // Touch ID entry is covered by the sentence above plus the grey hint below, so it stays empty.
  const help = leasable.length === 0
    ? "Public entries are always available to agents; there's nothing to give."
    : isFolder
      ? `Lets the chosen agent use all ${leasable.length} non-public items in ${d.name}/ without Touch ID until it ends, including ones that normally refuse agents. Covers what's in the folder now, not items added later. One Touch ID approves it.${cli}`
      : !items[0].agent_allowed
        ? `This normally refuses agents. Temporary access lets the chosen agent use it anyway, without Touch ID, until it ends. Giving it asks for Touch ID once.${cli}`
        : items[0].tier === "bio"
          ? ""
          : `Agents can already use this without a prompt. Temporary access only records who it's for and until when; ending it doesn't block agents.${cli}`;
  $("lease-help").textContent = help;
  $("lease-help").hidden = help === "";
  $("lease-touch-note").hidden = controls.hidden || help !== ""; // warnings above already say Touch ID is asked once

  // Activity: per secret, or merged across the folder.
  const names = isFolder ? items.map((s) => s.name) : [d.name];
  let events = [];
  try {
    const all = await Promise.all(names.map((n) => call("activity", { name: n, limit: 40 })));
    const seen = new Set();
    events = all.flat().filter((e) => { const k = e.id || `${e.ts}/${e.action}/${(e.secrets || []).join()}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => b.ts - a.ts).slice(0, 60);
  } catch { /* toast shown */ }
  if (detail !== d) return;

  // Offer the recent agent sessions as lease targets ("only this session").
  const sessions = new Map();
  for (const ev of events) if (ev.session && ev.kind && !sessions.has(ev.session)) sessions.set(ev.session, ev);
  const to = $("lease-to");
  const base = ["pi", "claude", "codex", "kiro", "cursor"];
  const kinds = [...new Set(events.filter((e) => e.kind).map((e) => e.kind))].filter((k) => !base.includes(k));
  const typeOpts = [["any", "Any agent"], ...base.concat(kinds).map((k) => [k, `Any ${k} agent`])];
  const sessOpts = [...sessions.values()].slice(0, 6).map((e) => [`session:${e.session}`, `Only ${e.kind} ${whoLabel(e).sess} (${e.cwd ? e.cwd.split("/").slice(-1)[0] + ", " : ""}${relTime(e.ts)})`]);
  const opts = [...typeOpts, ...sessOpts];
  const prev = to.value;
  const optGroup = (label, list) => el("optgroup", { label }, ...list.map(([v, l]) => el("option", { value: v, textContent: l })));
  to.replaceChildren(optGroup("Agent type", typeOpts), ...(sessOpts.length ? [optGroup("Recent sessions", sessOpts)] : []));
  if (opts.some(([v]) => v === prev)) to.value = prev;

  renderActivity(events, isFolder);
}

function renderActivity(events, showSecret) {
  renderActivityInto($("activity-rows"), events, showSecret);
  $("activity-empty").hidden = events.length > 0;
}

let evMoreSeq = 0;

// onSecret (Audit tab only): each secret name becomes a button that calls onSecret(name).
function renderActivityInto(rows, events, showSecret, onSecret = null) {
  rows.replaceChildren();
  for (const ev of events) {
    const who = whoLabel(ev);
    const label = actionLabel(ev);
    const via = ev.detail && Array.isArray(ev.detail.via_lease) ? " via lease" : "";
    const summary = eventSummary(ev);
    const where = [ev.cwd, ev.branch && `\u2387 ${ev.branch}`].filter(Boolean).join("  ");
    const names = ev.secrets || [];
    const secretEl = !showSecret ? null : !onSecret
      ? el("span", { class: "ev-secret", textContent: names.join(", ") })
      : el("span", { class: "ev-secret" }, ...names.map((n) => {
        const b = el("button", { type: "button", class: "ev-secret-btn", textContent: n, "aria-label": `Filter audit by ${n}`, title: `Filter audit by ${n}` });
        b.addEventListener("click", (e) => { e.stopPropagation(); onSecret(n); });
        return b;
      }));
    // Disclosure for the row's details; the row itself also toggles on mouse click.
    const moreId = `ev-more-${++evMoreSeq}`;
    const toggle = el("button", { type: "button", class: "ev-toggle", textContent: `${label}${via}`, "aria-expanded": "false", "aria-controls": moreId });
    const what = el("div", { class: "ev-main" },
      el("div", { class: `ev ${ev.ok ? "" : "denied"}` }, el("span", { class: "dot" }), toggle, secretEl),
      summary ? el("code", { class: "ev-cmd", textContent: summary, title: ev.action === "lease" && ev.detail?.expires ? `${summary}\nEnds ${fullTime(ev.detail.expires)}` : summary }) : null,
      ev.ok ? null : el("span", { class: "err", textContent: ev.err || "denied" }),
      where ? el("span", { class: "cwd", textContent: where, title: "Working directory and git branch" }) : null);

    const whoCell = el("div", { class: "who" },
      el("span", { class: `who-kind ${who.agent ? "agent" : ""}`, textContent: who.text }),
      who.sess ? el("span", { class: "who-sess", textContent: who.sess, title: ev.session || "" }) : null,
      who.legacy ? el("span", { class: "who-sess", textContent: "no session id", title: "Logged before karambit recorded agent sessions" }) : null,
      ev.model ? el("span", { class: "who-sess", textContent: ev.model }) : null);

    // Expandable: full identity + event id, so a row can be pointed at exactly.
    const more = el("div", { class: "ev-more", id: moreId, hidden: true },
      ...[["Event", ev.id || "(older event, no id)"], ["Time", fullTime(ev.ts)], ["Session", ev.session], ["Process", ev.pid && `pid ${ev.pid}`],
        ["Model", ev.model], ["Folder", ev.cwd], ["Branch", ev.branch], ["Chain", (ev.caller || []).join(" \u2190 ")]]
        .filter(([, v]) => v).map(([k, v]) => el("div", {}, el("span", { class: "k", textContent: k }), el("span", { class: "v", textContent: v }))));
    const tr = el("tr", { class: "item ev-row" },
      el("td", {}, what, more),
      el("td", {}, whoCell),
      el("td", { class: "r when", textContent: relTime(ev.ts), title: fullTime(ev.ts) }));
    const toggleMore = () => { more.hidden = !more.hidden; toggle.setAttribute("aria-expanded", String(!more.hidden)); };
    toggle.addEventListener("click", toggleMore);
    tr.addEventListener("click", (e) => { if (!e.target.closest("button")) toggleMore(); });
    rows.append(tr);
  }
}

async function grantLease() {
  if (!$("lease-uses").reportValidity()) return;
  const hours = Number($("lease-hours").value);
  const to = $("lease-to").value;
  const names = detailTargets().filter((s) => !s.public).map((s) => s.name);
  const cwd = $("lease-cwd").value.trim() || null;
  const cmds = $("lease-cmds").value.split(",").map((x) => x.trim()).filter(Boolean);
  const maxUses = Number($("lease-uses").value) || null;
  try {
    const r = await call("lease_grant", { names, to, hours, cwd, cmds, maxUses }, $("lease-grant"));
    toast(r.length ? `Temporary access to ${plural(r.length, "item")} for ${r[0].to_label}: ${durShort(r[0].remaining)}` : "No eligible secrets");
  } catch { return; }
  await loadSecrets();
  renderDetail();
}

// "Agents · no prompt" → "Agents · Touch ID" for the open secret (same set_policy call as the row select).
async function requireTouchInstead() {
  const name = detail.name;
  if (accessBusy.has(name)) return;
  const display = isAws(name) ? name.slice(4) : name;
  accessBusy.set(name, "Saving…");
  try {
    await call("set_policy", { names: [name], touch: "on", agentAllowed: null, public: null }, $("lease-require-touch"));
    toast(`${display}: ${accessLevel("agents-touch").label}`);
  } catch { /* toast shown */ }
  accessBusy.delete(name);
  await loadSecrets();
  renderDetail();
}

async function revokeLease() {
  const names = detailTargets().filter((s) => !s.public).map((s) => s.name);
  try {
    const r = await call("lease_revoke", { names }, $("lease-revoke"));
    toast(r.length === 1 ? "Temporary access ended" : `Ended temporary access to ${r.length} items`);
  } catch { return; }
  await loadSecrets();
  renderDetail();
}

// ---------- AWS profiles ----------

const isAws = (name) => /^aws\/[^/]+$/.test(name);

// Non-secret profile details (SSO portal/account/role, or key type + masked key id).
// Reading them decrypts the entry (an audited "details read"), so: never for Touch ID
// profiles unless asked, and cached per name + updated time.
const awsMeta = new Map(); // name -> { updated, sso, portal, account, role, region, temporary, key } | { updated, error }
const awsMetaBusy = new Set();

function fetchAwsMeta(shown) {
  const want = shown.filter((s) => isAws(s.name) && s.tier !== "bio" && awsMeta.get(s.name)?.updated !== s.updated && !awsMetaBusy.has(s.name));
  if (!want.length) return;
  for (const s of want) awsMetaBusy.add(s.name);
  Promise.all(want.map((s) => invoke("aws_show", { profile: s.name.slice(4) })
    .then((d) => awsMeta.set(s.name, { ...d, updated: s.updated }), () => awsMeta.set(s.name, { updated: s.updated, error: true }))
    .finally(() => awsMetaBusy.delete(s.name))))
    .then(() => {
      if (!$("view-secrets").hidden && !$("rows").contains(document.activeElement)) renderSecrets();
      renderAwsPage();
      if (awsDetailTarget) renderAwsDetail(awsDetailTarget);
    });
}

function freshMeta(s) {
  const m = awsMeta.get(s.name);
  return m && m.updated === s.updated ? m : null;
}

function awsSummary(m) {
  if (m.error) return "AWS profile · couldn't read its details";
  if (m.sso) return `AWS SSO · ${m.portal} · ${m.account} / ${m.role} · ${m.region}`;
  return [`Access keys · ${m.temporary ? "temporary" : "long-term"}`, m.region, m.key].filter(Boolean).join(" · ");
}

// Report which fields the pasted text contains, by NAME only. Values stay in the
// textarea until submit and are never parsed or echoed by this page.
function detectAws() {
  const t = $("aws-paste").value.toUpperCase();
  const out = $("aws-detected");
  if (!t.trim()) { out.textContent = ""; out.className = "hint"; return; }
  const has = (k) => new RegExp(`\\b${k}\\b`).test(t);
  const id = has("AWS_ACCESS_KEY_ID");
  const sk = has("AWS_SECRET_ACCESS_KEY");
  const tok = has("AWS_SESSION_TOKEN");
  const temp = /AWS_ACCESS_KEY_ID\s*[= ]\s*["']?ASIA/.test(t);
  const missing = [!id && "access key", !sk && "secret key", temp && !tok && "session token"].filter(Boolean);
  if (missing.length) {
    out.textContent = `Missing: ${missing.join(", ")}`;
    out.className = "hint detected-bad";
  } else {
    out.textContent = `✓ Found access key, secret key${tok ? ", session token (temporary credentials)" : " (long-term key)"}`;
    out.className = "hint detected-ok";
  }
}

function openAwsDialog(profile = "", existing = null) {
  $("aws-form").reset();
  setFormError("aws-error", "");
  $("aws-profile").value = profile;
  $("aws-profile").readOnly = !!profile;
  $("aws-title").textContent = profile ? `Edit ${profile}` : "Add AWS profile";
  $("aws-access").querySelector(".legacy-access")?.remove();
  if (existing && accessOf(existing) === "me") {
    $("aws-access").append(el("label", { class: "legacy-access hint" }, el("input", { type: "radio", name: "aws-level", value: "me", hidden: true }), "Only me (retired) · current access"));
  }
  $("aws-form").elements["aws-level"].value = existing ? accessOf(existing) : defaultLevel();
  syncAccessHint($("aws-access"));
  // Prefill from the saved profile. New profiles default to SSO (no keys stored).
  const meta = existing ? freshMeta(existing) : null;
  const sso = meta && meta.sso ? meta : null;
  $("aws-form").elements["aws-kind"].value = meta && !meta.error && !meta.sso ? "keys" : "sso";
  $("aws-account").value = sso ? sso.account : "";
  $("aws-role").value = sso ? sso.role : "";
  renderPortalOptions(sso ? sso.portal : null);
  syncAwsKind();
  detectAws();
  openDialog($("aws-dialog"));
  (profile ? (awsKind() === "sso" ? $("aws-account") : $("aws-paste")) : $("aws-profile")).focus();
}

const NEW_PORTAL = "__new__";

// Portal dropdown: every configured portal (with sign-in state), plus "New portal…".
function renderPortalOptions(selected) {
  const sel = $("aws-portal");
  const opts = ssoPortals.map((p) => el("option", { value: p.portal,
    textContent: `${p.portal} · ${p.start_url.replace(/^https:\/\//, "")} (${p.region})${p.logged_in ? "" : " · signed out"}` }));
  sel.replaceChildren(el("option", { value: "", textContent: "Choose a portal…", disabled: true }), ...opts, el("option", { value: NEW_PORTAL, textContent: "+ New portal…" }));
  const keep = selected && ssoPortals.some((p) => p.portal === selected);
  sel.value = keep ? selected : (ssoPortals[0]?.portal ?? NEW_PORTAL);
}

function syncPortal() {
  const isNew = $("aws-portal").value === NEW_PORTAL && awsKind() === "sso";
  $("aws-new-portal").hidden = !isNew;
  for (const id of ["aws-portal-name", "aws-start-url", "aws-sso-region"]) $(id).required = isNew;
}

const awsKind = () => $("aws-form").elements["aws-kind"].value;

// Show the SSO fields or the paste box; only the visible ones are required.
function syncAwsKind() {
  const sso = awsKind() === "sso";
  $("aws-sso-fields").hidden = !sso;
  $("aws-key-fields").hidden = sso;
  $("aws-verify-row").hidden = sso;
  for (const id of ["aws-account", "aws-role"]) $(id).required = sso;
  $("aws-paste").required = !sso;
  syncPortal();
}

async function submitAws(ev) {
  ev.preventDefault();
  const profile = $("aws-profile").value.trim();
  const flags = levelFlags($("aws-form").elements["aws-level"].value);
  const common = { profile, region: $("aws-region").value.trim() || null, touch: flags.touch, agentAllowed: flags.agentAllowed, overwrite: $("aws-profile").readOnly };
  setFormError("aws-error", "");
  let portalAdded = "";
  try {
    if (awsKind() === "sso") {
      let portal = $("aws-portal").value;
      if (portal === NEW_PORTAL) {
        portal = $("aws-portal-name").value.trim();
        await call("sso_portal_add", { name: portal, startUrl: $("aws-start-url").value.trim(), region: $("aws-sso-region").value.trim() }, $("aws-submit"));
        // The portal now exists: select it, so a retry doesn't try to add it again.
        portalAdded = portal;
        await refreshSso();
        renderPortalOptions(portal);
        syncPortal();
      }
      await call("aws_add_sso", { ...common, portal, account: $("aws-account").value.trim(), role: $("aws-role").value.trim() }, $("aws-submit"));
      $("aws-dialog").close();
      await afterAwsSave();
      // Saving isn't done until agents can use it: offer the sign-in right here.
      const p = ssoPortals.find((x) => x.portal === portal);
      if (p && p.logged_in && p.profiles.includes(`aws/${profile}`)) {
        toast(`Saved ${profile} · agents can use it now`);
      } else if (await confirmDialog(`Sign in to ${portal}?`,
        p && p.logged_in
          ? `${profile} is saved but not active yet. Sign in to ${portal} again to activate it (browser approval, then Touch ID).`
          : `${profile} is saved. Agents can use it once you sign in to the ${portal} portal: approve in your browser, then confirm with Touch ID.`,
        "Sign in now", false, "Later")) {
        startSignIn(portal);
      } else {
        toast(`Saved ${profile} · sign in to ${portal} when you're ready`);
      }
    } else {
      const r = await call("aws_add", { ...common, pasted: $("aws-paste").value, verify: $("aws-verify").checked }, $("aws-submit"));
      $("aws-paste").value = "";
      $("aws-dialog").close();
      toast(r.identity ? `Saved ${profile} · ${r.identity.split(" · ")[0]}` : `Saved ${profile}`);
      await afterAwsSave();
    }
  } catch (err) {
    // Toast shown too; keep the dialog open with the reason beside the form.
    if ($("aws-dialog").open) {
      setFormError("aws-error", portalAdded ? `Portal ${portalAdded} was added, but ${profile} wasn't saved: ${err}` : String(err));
    }
  }
}

async function afterAwsSave() {
  await loadSecrets();
  if (detail) renderDetail();
}

// ---------- AWS profile in the detail dialog ----------

let awsDetailTarget = null; // the secret meta shown in the AWS section

function renderAwsDetail(s) {
  const box = $("aws-detail");
  awsDetailTarget = s && isAws(s.name) ? s : null;
  box.hidden = !awsDetailTarget;
  if (!awsDetailTarget) return;
  const profile = s.name.slice(4);
  const m = freshMeta(s);
  if (!m && s.tier !== "bio") fetchAwsMeta([s]);
  $("aws-detail-cmd").textContent = `karambit aws ${profile} -- aws sts get-caller-identity`;
  $("aws-detail-default").setAttribute("aria-checked", String(cfg?.default_profile === profile));
  if ($("aws-detail-test-result").dataset.profile !== profile) {
    $("aws-detail-test-result").replaceChildren(); $("aws-detail-test-result").hidden = true; $("aws-detail-test-result").className = "tsr";
    $("aws-detail-test").textContent = "Test sign-in";
  }
  $("aws-detail-reveal").hidden = !!(m && !m.error) || s.tier !== "bio";
  let kind, sub, state = "";
  if (m && m.sso) {
    kind = `AWS SSO · portal ${m.portal}`;
    sub = `Account ${m.account} · role ${m.role} · region ${m.region}`;
  } else if (m && !m.error) {
    kind = `Access keys (${m.temporary ? "temporary" : "long-term"})`;
    sub = [m.region, m.key].filter(Boolean).join(" · ");
    state = m.temporary ? "Temporary keys stop working when they expire: paste fresh ones with Edit, or switch to AWS SSO." : "Long-term keys never expire on their own. AWS SSO is safer: nothing is stored.";
  } else if (s.tier === "bio") {
    kind = "Details protected by Touch ID";
    sub = "Show details asks for Touch ID once.";
  } else {
    kind = "AWS profile";
    sub = m && m.error ? "Couldn't read its details." : "Loading…";
  }
  const p = ssoPortals.find((x) => x.portal === awsPortalFor(s));
  const active = !!(p && p.logged_in && p.profiles.includes(s.name));
  if (m && m.sso) {
    if (!p) state = `Portal ${m.portal} is missing: add it again on the AWS page.`;
    else if (active) state = `Signed in · agents can use it · ${portalUntil(p)}`;
    else if (p.logged_in) state = `Not active yet: sign in to ${m.portal} again to activate it.`;
    else state = p.ended
      ? `Signed out at ${shortClock(p.ended.at)} (${endedWhy(p)}): agents can't use it until you sign in to ${m.portal} again.`
      : `Signed out: agents can't use it until you sign in to ${m.portal}.`;
  }
  $("aws-detail-kind").textContent = kind;
  $("aws-detail-sub").textContent = sub;
  const fields = m && !m.error ? (m.sso
    ? [["Portal", m.portal], ["Account", String(m.account).replace(/^(\d{4})(\d{4})(\d{4})$/, "$1 $2 $3")], ["Role", m.role], ["Region", m.region]]
    : [["Key type", m.temporary ? "Temporary" : "Long-term"], ["Key ID", m.key], ["Region", m.region]]) : [];
  $("aws-detail-kv").replaceChildren(...fields.filter(([, value]) => value).flatMap(([label, value]) => [el("dt", { textContent: label }), el("dd", { textContent: value })]));
  $("aws-detail-kv").hidden = !fields.length;
  $("aws-detail-sub").hidden = !!fields.length;
  if (p && !p.logged_in) state = `Signed out of ${p.portal}. Agents can’t use this profile.`;
  $("aws-detail-state").parentElement.classList.toggle("warn", !!p && !p.logged_in);
  $("aws-detail-state").parentElement.hidden = !state;
  if (active) state = `Signed in · ${p.portal} · ${portalUntil(p)}`;
  $("aws-detail-state").textContent = state;
  $("aws-detail-state").parentElement.querySelector(".detail-signout")?.remove();
  if (active) {
    const out = el("button", { class: "btn sm detail-signout", textContent: "Sign out", onclick: () => signOutPortal(p, out) });
    $("aws-detail-state").parentElement.append(out);
  }
  $("aws-detail-state").hidden = !state;
  $("aws-detail-state").classList.toggle("signed-in", active);
  $("aws-detail-signin").hidden = !(p && !active);
  syncDetailPrimary();
}

// One primary action in the details dialog: Sign in when shown, else the lease action.
function syncDetailPrimary() {
  const signin = !$("detail-dialog").open && !$("aws-detail").hidden && !$("aws-detail-signin").hidden;
  $("lease-grant").classList.toggle("primary", !signin);
  $("lease-require-touch").classList.toggle("primary", !signin);
}

async function revealAwsDetail() {
  const s = awsDetailTarget;
  if (!s) return;
  try {
    const d = await call("aws_show", { profile: s.name.slice(4) }, $("aws-detail-reveal"));
    awsMeta.set(s.name, { ...d, updated: s.updated });
  } catch { return; }
  renderAwsDetail(s);
  renderLists();
}

// Copy non-secret text (an example command, the sign-in code) via the web clipboard.
async function copyText(text, container = document.body) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch { /* fall back below */ }
  // Inside the open dialog: a modal makes the rest of the page inert.
  const ta = el("textarea", { value: text, readOnly: true, class: "sr-only", "aria-hidden": "true" });
  container.append(ta);
  ta.select();
  const ok = document.execCommand("copy");
  ta.remove();
  return ok;
}

// ---------- AWS sign-in (SSO) ----------

let ssoPortals = []; // [{portal, start_url, region, limit_minutes, accounts, logged_in, can_refresh, access_expires_at, signed_in_at, renew_until, renew_error, ended, profiles}]
let ssoRegistered = {}; // aws/name -> {portal, account, role}: daemon registrations, no secrets
const ssoBannerHidden = new Set(); // portals whose signed-out banner was dismissed (this run only)
let ssoEndedSeen = null; // portal -> ended.at already announced (null until the first status read)
const quietNextEnd = new Set(); // portals you just signed out via a shorter limit (already told)

async function refreshSso() {
  try {
    const st = await invoke("sso_status");
    ssoPortals = st.portals || [];
    ssoRegistered = st.registered || {};
  } catch { return; /* keep the last known state */ }
  // A sign-in that ended by itself (AWS stopped renewing it, or its limit passed): say so once.
  const first = ssoEndedSeen === null;
  ssoEndedSeen = ssoEndedSeen || new Map();
  for (const p of ssoPortals) {
    if (!p.ended || ssoEndedSeen.get(p.portal) === p.ended.at) continue;
    ssoEndedSeen.set(p.portal, p.ended.at);
    ssoBannerHidden.delete(p.portal);
    if (quietNextEnd.delete(p.portal)) continue;
    if (!first) toast(`AWS portal ${p.portal} signed out: ${endedWhy(p)}`, true, "AWS sign-in ended");
  }
}

async function loadSsoStatus() {
  await refreshSso();
  renderSsoBanner();
  renderAwsPage();
  if (awsDetailTarget) renderAwsDetail(awsDetailTarget);
}

// Sign-in limits, in minutes (null = as long as AWS allows). AWS's own session
// duration still applies on top: a limit can only end a sign-in sooner.
const LIMIT_CHOICES = [null, 60, 240, 480, 720, 1440, 10080];
function limitLabel(m) {
  if (m == null) return "As long as AWS allows";
  const n = (v, one) => `${v} ${one}${v === 1 ? "" : "s"}`;
  if (m >= 1440 && m % 1440 === 0) return n(m / 1440, "day");
  if (m >= 60 && m % 60 === 0) return n(m / 60, "hour");
  if (m < 60) return n(m, "minute");
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}
// In a sentence: "for up to 8 hours" / "while AWS allows".
const limitPhrase = (m) => (m == null ? "while AWS allows" : `for up to ${limitLabel(m)}`);

// Short reason for a sign-in that ended by itself.
const endedWhy = (p) => (p.ended.limit ? "its sign-in limit was reached" : "AWS stopped renewing it");

// The access token renews by itself while the AWS session lasts (and, with a limit,
// until then); only show a clock time when it can't renew.
// "renews until 22:47". Never print a bare "until" when the
// expiry is unknown; the full timestamp goes in the caller's title where it has one.
function portalUntil(p) {
  if (!p.can_refresh) return p.access_expires_at ? `until ${shortClock(p.access_expires_at)}` : "expiry unknown";
  if (p.renew_until) return `renews until ${shortClock(p.renew_until)}`;
  return "renews while AWS allows";
}

// SSO profiles we know (from cached details) that use this portal.
const portalProfiles = (portal) => [...awsMeta.entries()].filter(([, m]) => m.sso && m.portal === portal).map(([n]) => n.slice(4));

// "Agents stopped working" is a signed-out portal: say so above the list, one click to fix.
function renderSsoBanner() {
  const box = $("sso-banner");
  const unknown = secrets.some((s) => isAws(s.name) && s.tier === "bio" && !freshMeta(s));
  const out = ssoPortals.filter((p) => !p.logged_in && !ssoBannerHidden.has(p.portal) && (portalProfiles(p.portal).length > 0 || unknown));
  box.hidden = out.length === 0;
  box.replaceChildren(...out.map((p) => {
    const names = portalProfiles(p.portal);
    const what = names.length ? (names.length <= 2 ? names.join(" and ") : `${names.length} profiles`) : "its profiles";
    const later = el("button", { type: "button", class: "btn sm ghost", textContent: "Not now", "aria-label": `Hide the ${p.portal} sign-in reminder` });
    later.addEventListener("click", () => { ssoBannerHidden.add(p.portal); renderSsoBanner(); collapseAlerts(); });
    const why = p.ended ? `signed out at ${shortClock(p.ended.at)}: ${endedWhy(p)}` : "is signed out";
    // Signed out means agents are broken right now: the most severe alert.
    return el("div", { class: "banner bad sso-line" }, bannerIcon(true),
      el("span", { class: "txt", textContent: `AWS portal ${p.portal} ${why}, so agents can't use ${what}.`, title: p.ended ? p.ended.why : "" }),
      signInButton(p.portal, `Sign in to AWS portal ${p.portal}`), later);
  }));
}

// "14:05" today, else a full date + time.
function shortClock(ts) {
  const d = new Date(ts * 1000);
  return d.toDateString() === new Date().toDateString() ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : fullTime(ts);
}

// Active registrations also identify protected profiles without decrypting them.
const awsPortalMembership = new Map();
function awsPortalFor(s) {
  const m = freshMeta(s);
  if (m && !m.error) return m.sso ? m.portal : null;
  const known = awsPortalMembership.get(s.name);
  return known?.updated === s.updated ? known.portal : null;
}
let awsExposureFilter = null;
function renderAwsPage() {
  const profiles = secrets.filter((s) => isAws(s.name));
  for (const p of ssoPortals) for (const name of p.profiles) {
    const s = profiles.find((s) => s.name === name);
    if (s) awsPortalMembership.set(name, { portal: p.portal, updated: s.updated });
  }
  const portalFor = awsPortalFor;
  const signedOut = ssoPortals.filter((p) => !p.logged_in && profiles.some((s) => portalFor(s) === p.portal));
  $("aws-count").textContent = `${profiles.length} profiles · ${profiles.filter((s) => signedOut.some((p) => p.portal === portalFor(s))).length} signed out`;
  let badge = document.querySelector(".tab[data-view=aws] .aws-nav-count");
  if (!badge) { badge = el("span", { class: "aws-nav-count" }); document.querySelector(".tab[data-view=aws]").append(badge); }
  badge.textContent = signedOut.length; badge.hidden = !signedOut.length; badge.title = `${signedOut.length} portals signed out`;
  $("aws-exposure").replaceChildren(...[[null, "All"], ["agents", "No prompt"], ["agents-touch", "Touch ID"], ["me", "Only me"]].map(([id, label]) => {
    const test = EXPOSURE.find((x) => x.id === id)?.test || (() => true);
    return el("button", { class: "exp-chip", "aria-pressed": String(awsExposureFilter === id), textContent: `${label} ${profiles.filter(test).length}`, onclick: () => { awsExposureFilter = id; renderAwsPage(); } });
  }));
  $("portal-items").replaceChildren(...ssoPortals.map((p) => portalItem(p)));
  $("portals-btn").textContent = `Portals (${ssoPortals.length})`;
  $("aws-warnings").replaceChildren(...signedOut.map((p) => el("div", { class: "banner warn sso-line" }, el("span", { class: "txt", textContent: `Signed out of ${p.portal}. Agents can’t use its profiles.` }), signInButton(p.portal, `Sign in to ${p.portal}`))));
  const exposure = EXPOSURE.find((x) => x.id === awsExposureFilter);
  const hits = searchSecrets($("aws-filter").value, profiles);
  const shown = profiles.filter((s) => (!exposure || exposure.test(s)) && (!hits || hits.has(s.name)));
  if (hits) shown.sort(byScore(hits));
  $("aws-groups").replaceChildren(...awsTree(shown, hits, signedOut));
  $("aws-empty").hidden = shown.length > 0;
  fetchAwsMeta(profiles);
}

// ---------- AWS page tree: portal → account → role (like the AWS access portal) ----------
// Where a profile sits: registration (no decrypt) or fetched details, else unknown.
function awsPlace(s) {
  const r = ssoRegistered[s.name], m = freshMeta(s);
  if (m && !m.error && !m.sso) return { kind: "keys" };
  const portal = (m && m.sso && m.portal) || r?.portal || awsPortalFor(s);
  const account = (m && m.sso && m.account) || r?.account || null;
  const role = (m && m.sso && m.role) || r?.role || null;
  if (portal) return { kind: "sso", portal, account, role };
  return { kind: "unknown" };
}
const awsOpen = new Map(); // group key -> open? (remembered while the app runs)
function awsGroup(key, defaultOpen, summary, children, cls = "") {
  const open = awsOpen.has(key) ? awsOpen.get(key) : defaultOpen;
  const d = el("details", { class: `aws-tree ${cls}`, open });
  d.addEventListener("toggle", () => awsOpen.set(key, d.open));
  d.append(el("summary", {}, ...summary), ...children);
  return d;
}
function awsProfileRow(s, hits, signedOut, label) {
  const m = freshMeta(s), place = awsPlace(s);
  const row = secretRow(s, s.name.slice(4));
  const sub = place.kind === "keys" ? `Access keys · ${m.region || "default region"}`
    : place.kind === "sso" ? (place.role ? label : "account after unlock")
    : "Touch ID profile · details after unlock";
  const nameNodes = () => highlightNodes(s.name.slice(4), hits?.get(s.name) ? KarambitSearch.shift(hits.get(s.name).ranges, 4, s.name.length - 4) : []);
  const small = row.querySelector(".row-name > .small"), leaf = row.querySelector(".leaf");
  // SSO roles read like the AWS portal (role first); the profile name you type is underneath.
  if (place.kind === "sso" && place.role) { leaf.replaceChildren(document.createTextNode(place.role)); small.replaceChildren(...nameNodes()); small.classList.add("mono"); }
  else { leaf.replaceChildren(...nameNodes()); small.textContent = sub; }
  leaf.setAttribute("aria-label", `Details for ${s.name}`);
  // "Signed out" lives on the portal header, not on every role under it.
  return row;
}
function awsTree(shown, hits, signedOut) {
  const filtering = !!hits || !!awsExposureFilter;
  const byPortal = new Map(), keys = [], unknown = [];
  for (const s of shown) {
    const place = awsPlace(s);
    if (place.kind === "keys") keys.push(s);
    else if (place.kind === "unknown") unknown.push(s);
    else {
      if (!byPortal.has(place.portal)) byPortal.set(place.portal, new Map());
      const accounts = byPortal.get(place.portal), id = place.account || "?";
      if (!accounts.has(id)) accounts.set(id, []);
      accounts.get(id).push(s);
    }
  }
  const out = [];
  const portalNames = [...new Set([...ssoPortals.map((p) => p.portal), ...byPortal.keys()])].filter((n) => byPortal.has(n));
  for (const name of portalNames) {
    const p = ssoPortals.find((x) => x.portal === name), accounts = byPortal.get(name);
    const host = p ? p.start_url.replace(/^https:\/\//, "").replace(/\/.*$/, "") : "portal removed";
    const count = [...accounts.values()].reduce((n, a) => n + a.length, 0);
    const out2 = signedOut.some((x) => x.portal === name);
    const accountNodes = [...accounts].sort(([a], [b]) => (p?.accounts?.[a] || a).localeCompare(p?.accounts?.[b] || b)).map(([id, items]) => {
      const label = p?.accounts?.[id];
      items.sort((a, b) => (awsPlace(a).role || a.name).localeCompare(awsPlace(b).role || b.name));
      const rows = items.map((s) => awsProfileRow(s, hits, signedOut, label || id));
      return awsGroup(`acct:${name}:${id}`, filtering || accounts.size === 1, [
        el("span", { class: "aws-acct-name", textContent: label || (id === "?" ? "Account after unlock" : groupAccount(id)) }),
        id !== "?" ? el("span", { class: "aws-acct-id mono", textContent: label ? `${groupAccount(id)}` : "" }) : null,
        el("span", { class: "aws-count-pill", textContent: plural(items.length, "role") }),
      ].filter(Boolean), [el("div", { class: "aws-tree-body" }, ...rows)], "aws-account");
    });
    out.push(awsGroup(`portal:${name}`, true, [
      el("span", { class: "aws-portal-name", textContent: name }),
      el("span", { class: "aws-portal-host", textContent: host, title: p?.start_url || "" }),
      el("span", { class: "aws-count-pill", textContent: `${plural(accounts.size, "account")} · ${plural(count, "role")}` }),
      out2 ? el("span", { class: "tag warn", textContent: "Signed out" }) : null,
    ].filter(Boolean), accountNodes, "aws-portal"));
  }
  if (keys.length) out.push(awsGroup("keys", true, [el("span", { class: "aws-portal-name", textContent: "Access keys" }), el("span", { class: "aws-count-pill", textContent: plural(keys.length, "profile") })],
    [el("div", { class: "aws-tree-body" }, ...keys.map((s) => awsProfileRow(s, hits, signedOut)))], "aws-portal"));
  if (unknown.length) out.push(awsGroup("unknown", true, [el("span", { class: "aws-portal-name", textContent: "Not grouped yet" }), el("span", { class: "aws-portal-host", textContent: "Touch ID profiles: sign in or open one to place it" }), el("span", { class: "aws-count-pill", textContent: plural(unknown.length, "profile") })],
    [el("div", { class: "aws-tree-body" }, ...unknown.map((s) => awsProfileRow(s, hits, signedOut)))], "aws-portal"));
  return out;
}

async function signOutPortal(p, action) {
  if (!(await confirmDialog(`Sign out of ${p.portal}?`,
    `Agents stop getting new credentials for ${p.portal}'s profiles. Credentials already handed to a running command keep working until they expire. Other portals stay signed in.`, "Sign out", true))) return;
  try { await call("sso_logout", { portal: p.portal }, action); toast(`Signed out of ${p.portal}`); } catch { /* toast shown */ }
  loadSsoStatus();
}

function portalItem(p) {
  const host = p.start_url.replace(/^https:\/\//, "").replace(/\/.*$/, "");
  const chip = el("span", { class: "chip", role: "status" }, el("span", { class: "dot" }), el("span", { class: "chip-text" }));
  if (p.logged_in && p.renew_error) setChip(chip, "warn", "Can't renew · retrying");
  else if (p.logged_in) setChip(chip, "ok", `Signed in · ${p.profiles.length} active`);
  else setChip(chip, "warn", "Signed out");
  if (p.renew_error) chip.title = p.renew_error;
  let state = "";
  if (p.logged_in) state = portalUntil(p);
  else if (p.ended) state = `Signed out ${shortClock(p.ended.at)}: ${endedWhy(p)}`;
  // Host line may truncate; the state line wraps so its time is always readable.
  const text = el("span", { class: "row-text" }, el("b", { textContent: p.portal }),
    el("small", { class: "host", textContent: `${host} · ${p.region}`, title: p.start_url }),
    state ? el("small", { class: "state", textContent: state, title: p.ended && !p.logged_in ? p.ended.why : "" }) : null);
  let action;
  if (p.logged_in) {
    action = el("button", { type: "button", class: "btn sm", textContent: "Sign out", "aria-label": `Sign out of AWS portal ${p.portal}` });
    action.addEventListener("click", () => signOutPortal(p, action));
  } else {
    action = signInButton(p.portal, `Sign in to AWS portal ${p.portal}`);
    action.classList.add("primary");
  }
  const rm = el("button", { type: "button", class: "ibtn del", title: "Remove portal", "aria-label": `Remove AWS portal ${p.portal}` }, icon(ICON_TRASH));
  rm.addEventListener("click", async () => {
    const names = portalProfiles(p.portal);
    if (!(await confirmDialog(`Remove portal ${p.portal}?`,
      `This signs it out. ${names.length ? names.join(", ") : "Profiles saved on it"} stay in Karambit but stop working until a portal named ${p.portal} with the same URL and region is added again.`,
      "Remove"))) return;
    try { await call("sso_portal_remove", { name: p.portal }, rm); toast(`Removed portal ${p.portal}`); } catch { /* toast shown */ }
    loadSsoStatus();
  });
  const importRoles = el("button", { type: "button", class: "btn sm", textContent: "Import all roles", disabled: !p.logged_in, title: p.logged_in ? "Import accounts and roles" : "Sign in first" });
  importRoles.onclick = () => openSsoImport(p.portal, importRoles);
  return el("div", { class: "portal-management" }, el("div", { class: "sso-main" }, text, chip),
    el("div", { class: "portal-actions" }, action, importRoles, rm), limitPicker(p));
}

async function openSsoImport(portal, trigger) {
  let rows;
  try { rows = await call("sso_discover", { portal }, trigger); } catch { return; }
  const dlg = el("dialog", { class: "sso-import-dialog" });
  const filter = el("input", { type: "search", placeholder: "Filter accounts, roles or names", "aria-label": "Filter roles" });
  const list = el("div", { class: "sso-import-list" });
  const choices = rows.map((r) => {
    const input = el("input", { type: "checkbox", checked: true });
    const label = el("label", {}, input, el("span", {}, `${r.name} · ${r.account_name} / ${r.role} · ${r.account_id} · ${r.action}`));
    list.append(label);
    return { r, input, label };
  });
  filter.oninput = () => {
    const text = filter.value.toLowerCase();
    for (const c of choices) c.label.hidden = !`${c.r.name} ${c.r.account_name} ${c.r.account_id} ${c.r.role}`.toLowerCase().includes(text);
  };
  const access = el("div", { class: "compact-access" });
  accessPicker(access, "import-level", levelsFor(true));
  access.querySelector('input[value="me-touch"]').checked = true;
  syncAccessHint(access);
  const submit = el("button", { type: "button", class: "btn primary", textContent: "Import · Touch ID" });
  let busy = false;
  dlg.addEventListener("cancel", (e) => { if (busy) e.preventDefault(); });
  submit.onclick = async () => {
    const items = choices.filter((c) => c.input.checked && !c.label.hidden).map(({ r }) => ({ account_id: r.account_id, role: r.role, name: r.name, account_label: r.account_name || undefined }));
    if (!items.length) { toast("Select at least one role"); return; }
    busy = true;
    dlg.querySelectorAll("button, input").forEach((n) => { n.disabled = true; });
    try {
      const result = await call("aws_import_sso", { portal, items, access: access.querySelector("input:checked").value }, submit);
      toast(`added ${result.added}, skipped ${result.skipped}`);
      dlg.close(); loadSecrets(); loadSsoStatus();
    } catch { /* keep selection for retry */ }
    finally { busy = false; dlg.querySelectorAll("button, input").forEach((n) => { n.disabled = false; }); }
  };
  const close = el("button", { type: "button", class: "ibtn dialog-close", "aria-label": "Close import", onclick: () => dismissDialog(dlg) }, icon(ICON_CLOSE));
  dlg.append(close, el("h2", {}, `Import roles · ${portal}`), filter,
    el("p", { class: "hint" }, "Imports checked, visible roles only. Existing profiles stay unchanged."), list, access, submit);
  dlg.addEventListener("close", () => dlg.remove(), { once: true });
  document.body.append(dlg); openDialog(dlg);
  dlg.querySelector(".dialog-back").hidden = false;
  filter.focus();
}

// "Stay signed in for": a per-portal cap on how long one sign-in lasts. Shorter applies
// right away (may sign out now); longer or none asks for Touch ID.
function limitPicker(p) {
  const id = `sso-limit-${p.portal}`;
  const cur = p.limit_minutes ?? null;
  const choices = LIMIT_CHOICES.includes(cur) ? LIMIT_CHOICES : [...LIMIT_CHOICES, cur].sort((a, b) => (a ?? -1) - (b ?? -1));
  const sel = el("select", { id }, ...choices.map((m) => el("option", { value: m == null ? "" : String(m), textContent: limitLabel(m), selected: m === cur })));
  sel.addEventListener("change", async () => {
    const minutes = sel.value === "" ? null : Number(sel.value);
    const started = p.logged_in && p.signed_in_at ? p.signed_in_at : null;
    if (started && minutes != null && started + minutes * 60 <= Date.now() / 1000
      && !(await confirmDialog(`Sign out of ${p.portal} now?`,
        `This sign-in started at ${shortClock(started)}, more than ${limitLabel(minutes)} ago, so the new limit signs it out now. Agents stop getting new credentials for its profiles.`,
        "Sign out now", true))) {
      sel.value = cur == null ? "" : String(cur);
      return;
    }
    try {
      const r = await call("sso_portal_limit", { name: p.portal, minutes }, sel);
      toast(r.ended ? `Signed out of ${p.portal}: its sign-in was older than the new limit` : `${p.portal}: stays signed in ${limitPhrase(minutes)}`);
      // You signed it out yourself: don't also announce it as an unexpected sign-out.
      if (r.ended) quietNextEnd.add(p.portal);
    } catch { sel.value = cur == null ? "" : String(cur); }
    loadSsoStatus();
  });
  return el("div", { class: "sso-limit" },
    el("span", { class: "row-text" }, el("label", { htmlFor: id, textContent: "Stay signed in for" }),
      el("small", { textContent: "Karambit stops renewing after this, even if AWS would go on. Your organization's AWS session length still applies. A longer limit asks for Touch ID." })),
    sel);
}

function openPortalDialog() {
  $("portal-form").reset();
  setFormError("portal-error", "");
  openDialog($("portal-dialog"));
  $("portal-name").focus();
}

async function submitPortal(ev) {
  ev.preventDefault();
  const name = $("portal-name").value.trim();
  setFormError("portal-error", "");
  try {
    await call("sso_portal_add", { name, startUrl: $("portal-url").value.trim(), region: $("portal-region").value.trim() }, $("portal-submit"));
  } catch (err) {
    setFormError("portal-error", String(err));
    return;
  }
  $("portal-dialog").close();
  await loadSsoStatus();
  startSignIn(name);
}

// One sign-in at a time (the backend enforces it too). Phases:
// starting → code (waiting for browser approval; Cancel works) → approved (Touch ID;
// only the OS prompt's own Cancel stops it) → done | error | cancelled.
let signIn = null;

async function startSignIn(portal) {
  const dlg = $("signin-dialog");
  if (signIn && signIn.running) { if (!dlg.open) openDialog(dlg); return; }
  const before = ssoPortals.find((x) => x.portal === portal);
  const me = { portal, running: true, phase: "starting", code: "", expiresAt: 0, timer: 0,
    wasLive: !!(before && before.logged_in), beforeExpiry: before ? before.access_expires_at : null };
  signIn = me;
  $("signin-title").textContent = `Sign in to AWS · ${portal}`;
  $("signin-portal").textContent = before ? `${before.start_url} (${before.region})` : "";
  setSignIn("starting");
  if (!dlg.open) openDialog(dlg);

  const ch = new window.__TAURI__.core.Channel();
  ch.onmessage = (m) => {
    if (signIn !== me || !me.running) return;
    if (m.phase === "code") {
      me.code = m.userCode;
      me.expiresAt = Date.now() + (m.expiresIn || 600) * 1000;
      if (me.phase !== "cancelling") setSignIn("code");
    } else if (m.phase === "approved") {
      setSignIn("approved");
    }
  };
  let result = null, err = null;
  try {
    result = await invoke("sso_login", { portal, onEvent: ch });
  } catch (e) {
    err = String(e);
  }
  me.running = false;
  await loadSecrets().catch(() => {});
  if (signIn !== me) return;
  const now = ssoPortals.find((x) => x.portal === portal);
  if (!err) {
    me.profiles = result.profiles;
    setSignIn("done");
  } else if (err === "cancelled") {
    setSignIn("closed");
    toast("Sign-in cancelled");
  } else if (me.phase === "approved" && now && now.logged_in && (!me.wasLive || now.access_expires_at !== me.beforeExpiry)) {
    // Karambit stopped waiting, but the daemon finished the sign-in anyway.
    me.profiles = now.profiles.length;
    setSignIn("done");
  } else {
    me.error = err;
    setSignIn("error");
  }
}

function setSignIn(phase) {
  const me = signIn;
  if (!me) return;
  me.phase = phase;
  const dlg = $("signin-dialog");
  clearInterval(me.timer);
  const show = (id, on) => { $(id).hidden = !on; };
  const msg = $("signin-msg");
  msg.className = "";
  show("signin-code-box", phase === "code");
  show("signin-copy", phase === "code");
  show("signin-browser", phase === "code");
  show("signin-retry", phase === "error");
  show("signin-done", phase === "done");
  show("signin-cancel", phase !== "approved" && phase !== "done");
  $("signin-cancel").disabled = phase === "cancelling";
  $("signin-cancel").textContent = phase === "error" ? "Close" : "Cancel";
  if (phase === "starting") msg.textContent = "Contacting AWS…";
  if (phase === "code") {
    msg.textContent = "Your browser opened AWS's sign-in page. Check it shows this code, approve, then come back here.";
    $("signin-code").textContent = me.code;
    const tick = () => {
      const left = Math.max(0, Math.round((me.expiresAt - Date.now()) / 1000));
      $("signin-expiry").textContent = left ? `Code expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "Code expired";
    };
    tick();
    me.timer = setInterval(tick, 1000);
  }
  if (phase === "cancelling") msg.textContent = "Cancelling…";
  if (phase === "approved") msg.textContent = "Approved in your browser. Now confirm with Touch ID to finish. If some AWS profiles use Touch ID, macOS asks once more. To stop, use Cancel on the Touch ID prompt.";
  if (phase === "done") {
    const n = me.profiles || 0;
    msg.textContent = n
      ? `Signed in to ${me.portal}. ${n} ${n === 1 ? "profile is" : "profiles are"} active for agents; the sign-in renews automatically ${limitWords(me.portal)}.`
      : `Signed in to ${me.portal}. No profiles use this portal yet: add one with Add AWS profile.`;
    msg.className = "ok";
    $("signin-done").focus();
  }
  if (phase === "error") {
    msg.textContent = me.error;
    msg.className = "bad";
    $("signin-retry").focus();
  }
  if (phase === "closed" && dlg.open) dlg.close();
  if (phase === "code" && document.activeElement === document.body) $("signin-copy").focus();
}

// "until 18:13 (sign-in limit)" / "while your organization's AWS session lasts".
function limitWords(portal) {
  const p = ssoPortals.find((x) => x.portal === portal);
  if (p && p.renew_until) return `until ${fullTime(p.renew_until)} (sign-in limit)`;
  if (p && p.limit_minutes) return limitPhrase(p.limit_minutes);
  return "while your organization's AWS session lasts";
}

async function cancelSignIn() {
  const me = signIn;
  if (!me) return;
  if (!me.running) { setSignIn("closed"); return; }
  if (me.phase === "approved" || me.phase === "cancelling") return;
  try {
    const r = await invoke("sso_login_cancel");
    if (signIn !== me || !me.running) return;
    if (r.cancelling) setSignIn("cancelling");
    else if (r.approved) setSignIn("approved");
  } catch (e) { toast(String(e), true); }
}

// ---------- audit ----------

const AUDIT_LIMIT = 300;
const ACTIVITY_LIMIT = 200; // main.rs `activity` caps limit at 200

async function loadAudit() {
  const a = await call("audit", { limit: AUDIT_LIMIT });
  // The chain is unkeyed: it catches edits inside the log, not a rewrite of the whole file.
  if (a.broken_at) setChip($("chain"), "bad", `Log altered at line ${a.broken_at}`);
  else setChip($("chain"), "ok", `Log chain OK · ${a.checked} events`);
  $("chain").title = "Each event is chained to the one before, so edited or deleted lines show up here. A program running as you could still rewrite the whole log.";
  auditEvents = a.events;
  renderAuditSecretNames();
  applyAuditFilter();
}

let auditEvents = [];
let auditSeq = 0; // bumped per filter run; stale `activity` responses are dropped
let auditTimer = 0;

// Names seen in the loaded window plus every vault secret.
function auditKnownNames() {
  const names = new Set(secrets.map((s) => s.name));
  for (const ev of auditEvents) for (const n of ev.secrets || []) names.add(n);
  return names;
}

function renderAuditSecretNames() {
  $("audit-secret-names").replaceChildren(...[...auditKnownNames()].sort().map((n) => el("option", { value: n })));
}

// Exact name, folder prefix ("aws" or "aws/" matches "aws/x"), or case-insensitive substring.
function auditSecretMatch(q) {
  const prefix = q.replace(/\/+$/, "") + "/";
  const lq = q.toLowerCase();
  return (ev) => (ev.secrets || []).some((n) => n === q || n.startsWith(prefix) || n.toLowerCase().includes(lq));
}

async function applyAuditFilter() {
  clearTimeout(auditTimer);
  const seq = ++auditSeq;
  const q = $("audit-secret").value.trim();
  if (!q) return showAuditEvents(auditEvents, q, "");
  const windowed = () => showAuditEvents(auditEvents.filter(auditSecretMatch(q)), q, `Searching the last ${AUDIT_LIMIT} events`);
  // The window is only the newest events; an exact secret name gets its full history.
  if (!auditKnownNames().has(q)) return windowed();
  let evs;
  try {
    evs = await call("activity", { name: q, limit: ACTIVITY_LIMIT });
  } catch {
    if (seq === auditSeq) windowed();
    return;
  }
  if (seq !== auditSeq) return;
  showAuditEvents(evs, q, evs.length >= ACTIVITY_LIMIT ? `All events for ${q} · capped at the newest ${ACTIVITY_LIMIT}` : `All events for ${q}`);
}

// Triage view: "Denied only" keeps the refused events (ev.ok === false).
const auditDeniedOnly = () => document.querySelector('input[name="audit-only"]:checked')?.value === "denied";

function showAuditEvents(events, q, scope) {
  const denied = auditDeniedOnly();
  const shown = denied ? events.filter((ev) => ev.ok === false) : events;
  renderActivityInto($("audit-rows"), shown, true, setAuditSecret);
  $("audit-empty").hidden = shown.length > 0;
  $("audit-empty-text").textContent = denied ? (q ? "No denied events for this secret." : "No denied events.")
    : q ? "No events match this secret." : "No events yet.";
  $("audit-scope").textContent = scope;
  $("audit-scope").hidden = !scope;
  $("audit-count").textContent = denied ? `${shown.length} denied${q ? ` for ${q}` : ""}`
    : !q ? ""
    : shown.length ? `${shown.length} ${shown.length === 1 ? "event" : "events"} for ${q}` : "No events match";
}

function setAuditSecret(name) {
  $("audit-secret").value = name;
  $("audit-secret").focus();
  applyAuditFilter();
}

// ---------- settings ----------

let detectionDraft;
const chipKey = (id) => id === "cfg-procs" ? "agent_process_names" : "agent_env_markers";
const chipDefaults = (id) => cfg[id === "cfg-procs" ? "default_agent_process_names" : "default_agent_env_markers"] || [];
const detectionFromConfig = () => ({ agent_process_names: [...cfg.agent_process_names], agent_env_markers: [...cfg.agent_env_markers], removed_defaults: [...(cfg.removed_defaults || [])] });
function detectionRelaxes(next) {
  return cfg.agent_process_names.some((n) => !next.agent_process_names.some((v) => v.toLowerCase() === n.toLowerCase()))
    || cfg.agent_env_markers.some((n) => !next.agent_env_markers.includes(n));
}
function loadDetectionChips() {
  detectionDraft = detectionFromConfig();
  for (const id of ["cfg-procs", "cfg-env"]) $(id).value = "";
  renderDetectionChips();
}
function renderDetectionChips() {
  for (const id of ["cfg-procs", "cfg-env"]) {
    const box = $(id + "-box"), input = $(id);
    box.querySelectorAll(".token").forEach((n) => n.remove());
    detectionDraft[chipKey(id)].forEach((name) => {
      const builtin = chipDefaults(id).some((v) => v.toLowerCase() === name.toLowerCase());
      const button = el("button", { type: "button", class: `token${builtin ? " token-default" : ""}`, "aria-label": `Remove ${name}`, onclick: () => removeChip(id, name) },
        el("span", {}, name), builtin ? el("small", {}, "default") : null, el("span", { "aria-hidden": "true" }, "×"));
      box.insertBefore(button, input);
    });
  }
  $("cfg-detection").value = JSON.stringify(detectionDraft);
  renderSettingsNote();
}
function removeChip(id, name) {
  detectionDraft[chipKey(id)] = detectionDraft[chipKey(id)].filter((v) => v !== name);
  const builtin = chipDefaults(id).find((v) => v.toLowerCase() === name.toLowerCase());
  if (builtin && !detectionDraft.removed_defaults.includes(builtin)) detectionDraft.removed_defaults.push(builtin);
  renderDetectionChips(); $(id).focus();
}
function addChips(id, text) {
  const names = text.split(/[,\s]+/).filter(Boolean);
  const pattern = id === "cfg-env" ? /^[A-Za-z_][A-Za-z0-9_]*$/ : /^[A-Za-z0-9_.-]+$/;
  if (names.some((n) => n.length > 128 || !pattern.test(n))) {
    $(id).setAttribute("aria-invalid", "true");
    settingsResult("Invalid detection token. Use letters, numbers, underscores" + (id === "cfg-procs" ? ", dots or hyphens." : "; start with a letter or underscore."), "error");
    $(id).focus(); return false;
  }
  const next = [...detectionDraft[chipKey(id)]];
  for (let name of names) {
    name = chipDefaults(id).find((v) => v.toLowerCase() === name.toLowerCase()) || name;
    if (!next.some((v) => v.toLowerCase() === name.toLowerCase())) next.push(name);
  }
  if (next.length > 256) { settingsResult("At most 256 detection tokens per field.", "error"); return false; }
  detectionDraft[chipKey(id)] = next;
  detectionDraft.removed_defaults = detectionDraft.removed_defaults.filter((v) => !next.some((n) => n.toLowerCase() === v.toLowerCase()));
  $(id).value = ""; $(id).removeAttribute("aria-invalid");
  renderDetectionChips(); return true;
}
for (const id of ["cfg-procs", "cfg-env"]) {
  $(id).addEventListener("keydown", (event) => {
    if (["Enter", ",", "Tab"].includes(event.key) && $(id).value.trim()) {
      if (event.key !== "Tab") event.preventDefault();
      if (!addChips(id, $(id).value)) event.preventDefault();
    } else if (event.key === "Enter" || event.key === ",") event.preventDefault();
    else if (event.key === "Backspace" && !$(id).value) {
      const last = detectionDraft[chipKey(id)].at(-1);
      if (last) { event.preventDefault(); removeChip(id, last); }
    }
  });
  $(id).addEventListener("paste", (event) => {
    const text = event.clipboardData.getData("text");
    event.preventDefault(); addChips(id, $(id).value + text);
  });
}
$("detect-agents").onclick = async (event) => {
  let rows;
  try { rows = await call("agents_discover", {}, event.currentTarget); } catch { return; }
  const dlg = el("dialog", { class: "sso-import-dialog", "aria-label": "Installed agent suggestions" });
  const list = el("div", { class: "sso-import-list" });
  const choices = rows.map((row) => {
    const input = el("input", { type: "checkbox", checked: !row.already_configured, disabled: row.already_configured });
    list.append(el("label", { class: row.already_configured ? "discovery-configured" : "" }, input,
      el("span", {}, el("b", {}, row.kind + (row.already_configured ? " · configured" : " · new")),
        el("div", {}, [...row.process_names, ...row.env_markers].join(", ")),
        el("small", {}, row.evidence.join(" · ")))));
    return { row, input };
  });
  const add = el("button", { type: "button", class: "btn primary", textContent: "Add selected", onclick: () => {
    for (const { row, input } of choices) if (input.checked && !input.disabled) {
      if (!addChips("cfg-procs", row.process_names.join(",")) || !addChips("cfg-env", row.env_markers.join(","))) return;
    }
    dismissDialog(dlg); settingsResult("Suggestions added. Save changes to apply.", "muted");
  } });
  dlg.append(el("button", { type: "button", class: "ibtn dialog-close", "aria-label": "Close discovery", onclick: () => dismissDialog(dlg) }, icon(ICON_CLOSE)),
    el("h2", {}, "Installed agents"), el("p", { class: "hint" }, "Filesystem hints only. Nothing is executed. Selected names stay pending until Save."),
    rows.length ? list : el("p", {}, "No installed agents found."), add);
  dlg.addEventListener("close", () => dlg.remove(), { once: true });
  document.body.append(dlg); openDialog(dlg); dlg.querySelector(".dialog-back").hidden = false;
};

async function loadSettings() {
  cfg = await call("get_config");
  if (!secrets.length) secrets = await call("list").catch(() => secrets);
  renderBlock();
  renderBackupSettings();
  loadProfiles();
  trackSettingsSection();
  $("cfg-default-tier").checked = cfg.default_tier === "bio";
  $("cfg-clip").value = cfg.clip_seconds;
  $("cfg-backup").value = cfg.backup_recipient || "";
  loadDetectionChips();
  $("cfg-human-lease").value = cfg.human_lease_hours;
  settingsResult("", "");
  renderSettingsNote();

  const s = await call("status");
  const h = s.helper || {};
  const about = [
    ["Vault location", s.root],
    ["Secure Enclave", h.secure_enclave ? "available" : "unavailable"],
    ["Touch ID", h.biometrics ? "ready" : h.biometrics_error || "unavailable"],
    ["Secrets", String(s.secrets)],
    ["Without backup", String(s.without_backup)],
  ];
  $("about").replaceChildren(...about.flatMap(([k, v]) => [el("dt", { textContent: k }),
    el("dd", { textContent: v, class: k === "Without backup" && s.without_backup > 0 ? "warn" : "" })]));
}

// ---------- status page ----------
// Plain-language names for `karambit doctor` checks. Unknown names show as-is.
const DOCTOR_NAMES = {
  "sibling-env-ps": "Other programs' environment variables",
  "vault-token": "Vault token file (~/.vault-token)",
  "key-blob-use": "No-prompt key usable without Karambit",
  "daemon-socket": "Karambit daemon socket",
  "audit-config-pin-writable": "Audit log, config and trust pins writable",
  "redaction": "Output redaction (encoded forms)",
  "caller-agent": "Agent detection for this check",
  "jail-availability": "Sandbox (run --jail)",
};
const CHECK_WORD = { pass: "OK", fail: "Reachable", inconclusive: "Unclear", unsupported: "Not checked" };

// Status rows: label, then dot + value next to it.
// kind: "" (ok), "warn", "bad", "off" (neutral fact). mono only for paths.
function kvRows(target, rows) {
  $(target).replaceChildren(...rows.map(([k, v, kind = "", mono = false]) => el("div", { class: "r2" },
    el("span", { class: "k3", textContent: k }),
    el("span", { class: `v ${kind === "off" ? "" : kind}` }, el("i", { class: `dot3 ${kind}` }), mono ? el("span", { class: "mono", textContent: v, title: v }) : v))));
}

// Needs attention, most severe first. Each: [severity, bold, rest, button?].
function attentionItems(d) {
  const s = d.status || {}, items = [], ok = [];
  const b = blockedState();
  if (b) items.push(["bad", b.all ? "All agents are blocked." : `${blockedWho(b)}.`, " Every agent request is refused.",
    el("button", { type: "button", class: "btn sm", textContent: "Unblock…", onclick: () => setBlocked(false, b) })]);
  for (const p of ssoPortals.filter((x) => !x.logged_in)) {
    const names = portalProfiles(p.portal);
    const what = names.length ? (names.length <= 2 ? names.join(" and ") : `${names.length} profiles`) : "its profiles";
    const btn = el("button", { type: "button", class: "btn sm primary", textContent: "Sign in", onclick: () => startSignIn(p.portal) });
    items.push(["warn", `AWS portal ${p.portal} is signed out.`, ` Agents can’t use ${what}.`, btn]);
  }
  const unbacked = secrets.filter((x) => !x.has_backup);
  if (unbacked.length) {
    const list = unbacked.length <= 2 ? ` (${unbacked.map((x) => x.name).join(", ")})` : "";
    items.push(["warn", `${plural(unbacked.length, "secret has", "secrets have")} no backup copy`, `${list}.`,
      el("button", { type: "button", class: "btn sm", textContent: "Back it up", onclick: backItUp })]);
  }
  if (s.initialized && s.agent_key === false) items.push(["warn", "No lock-safe agent key.", " No-prompt secrets stop working while the screen is locked.",
    el("button", { type: "button", class: "btn sm", textContent: "Fix now", onclick: fixLockKeys })]);
  const h = s.helper || {};
  if (!h.secure_enclave) items.unshift(["bad", "Secure Enclave unavailable.", " Touch ID secrets can't be opened on this Mac.", null]);
  else ok.push("Secure Enclave");
  if (h.secure_enclave && !h.biometrics) items.push(["warn", "Touch ID unavailable.", ` ${h.biometrics_error || "Touch ID secrets can't be used until it works again."}`, null]);
  else if (h.biometrics) ok.push("Touch ID");
  if (s.agent_key) ok.push("no-prompt key");
  if (cfg?.backup_recipient) ok.push("paper backup"); else items.push(["bad", "No backup.", " If this Mac's keys are lost, every secret is unrecoverable.",
    el("button", { type: "button", class: "btn sm", textContent: "Set up backup", onclick: () => openSettingsSection("settings-backup") })]);
  if ((d.pins?.daemon ?? 0) > 0 && (d.pins?.helper ?? 0) > 0) ok.push("trusted binaries");
  if (d.daemon?.running) ok.push("daemon");
  return { items, ok };
}

// No backup_rotate IPC yet: go to Settings › Backup, which says
// how to write the missing copies from a terminal.
function backItUp() { openSettingsSection("settings-backup", true); }

function renderAttention(d) {
  const { items, ok } = attentionItems(d);
  const okText = ok.length ? `${items.length ? "Everything else is OK" : "Everything is OK"}: ${ok.join(", ")}.` : (items.length ? "" : "Everything is OK.");
  $("status-attention").replaceChildren(
    ...items.map(([sev, bold, rest, btn]) => el("div", { class: "it2", role: "listitem" },
      el("span", { class: `sev ${sev}`, "aria-hidden": "true" }), el("span", {}, el("b", { textContent: bold }), rest), el("span", { class: "sp" }), btn)),
    ...(okText ? [el("div", { class: "it2 okrow", role: "listitem" }, el("span", { class: "sev ok", "aria-hidden": "true" }), el("span", { textContent: okText }))] : []));
}

function clock(t = Date.now()) { return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }

async function loadStatusPage() {
  let d;
  try { [d, cfg] = await Promise.all([call("status_full", {}, $("status-refresh")), call("get_config"), refreshSso()]); } catch { return; }
  if (!secrets.length) secrets = await call("list").catch(() => secrets);
  const s = d.status || {}, h = s.helper || {}, c = s.caller || {};
  $("status-when").textContent = "Checked just now";
  renderAttention(d);
  const total = secrets.length || s.secrets || 0, unbacked = secrets.filter((x) => !x.has_backup).length;
  const pinned = (d.pins?.daemon ?? 0) > 0 && (d.pins?.helper ?? 0) > 0;
  kvRows("status-mac", [
    ["Secure Enclave", h.secure_enclave ? "Available" : "Unavailable", h.secure_enclave ? "" : "bad"],
    ["Touch ID", h.biometrics ? "Ready" : h.biometrics_error || "Unavailable", h.biometrics ? "" : "warn"],
    ["No-prompt key", s.agent_key ? "Ready, works while locked" : "Not created: stops when the screen locks", s.agent_key ? "" : "warn"],
    ["Backup", cfg?.backup_recipient ? `Paper backup · ${total - unbacked} of ${total} secrets` : "None", !cfg?.backup_recipient ? "bad" : unbacked ? "warn" : ""],
    ["Trusted binaries", pinned ? "CLI and helper pinned" : "Not pinned: run ./install.sh", pinned ? "" : "warn"],
    ["Daemon", d.daemon?.running ? "Running" : "Not running (starts when needed)", d.daemon?.running ? "" : "off"],
    ["Vault", s.root || "?", "off", true],
  ]);
  const b = blockedState();
  renderBlock();
  kvRows("status-agents", [
    ["Blocking", b ? blockedWho(b).replace("All agents are blocked", "All agents blocked") : "Not blocked", b ? "bad" : ""],
    ["Detected by", `${plural((cfg?.agent_process_names || []).length, "program name")} · ${plural((cfg?.agent_env_markers || []).length, "env marker")}`, "off"],
    ["Refused while locked", s.locked_screen_blocked ? plural(s.locked_screen_blocked, "use") : "None", s.locked_screen_blocked ? "warn" : "off"],
    ["This app", c.agent ? `Seen as agent (${c.kind || "?"})` : "Seen as you (human)", c.agent ? "warn" : "off"],
  ]);
  renderPolicy();
  renderLeases(d.leases || []);
}

function renderLeases(leases) {
  $("status-leases-count").textContent = leases.length ? `${leases.length} active` : "";
  $("status-leases").replaceChildren(...(leases.length ? leases.map((l) => {
    const meta = secrets.find((x) => x.name === l.name);
    const end = el("button", { type: "button", class: "btn sm danger-ghost", textContent: "End", "aria-label": `End temporary access to ${l.name}` });
    end.addEventListener("click", async () => {
      try { await call("lease_revoke", { names: [l.name] }, end); toast("Temporary access ended"); } catch { return; }
      await loadSecrets(); loadStatusPage();
    });
    return el("div", { class: "lrow" },
      el("span", { class: "gly", "aria-hidden": "true" }, levelGlyph(meta ? accessOf(meta) : "agents-touch")),
      el("span", { class: "t2" }, el("span", { class: "mono", style: "font-size:13px", textContent: l.name }),
        el("small", { textContent: [l.to_label, l.uses ? `used ${l.uses}×` : "", leaseScopeText(l.scope || {})].filter(Boolean).join(" · ") })),
      el("span", { class: "hint", textContent: `${durShort(l.remaining)} left` }), end);
  }) : [el("div", { class: "lrow empty", textContent: "No temporary access right now." })]));
}

// Read-only view of cfg.policy: { rules: [{subject:{secret|tool|egress}, action, who, effect}], tags: {pattern: tier} }.
// Status checks: one sentence per rule, who underneath, no indices.
const EFFECT_WORD = { deny: "Deny", approve: "Ask", allow: "Allow" };
const EFFECT_CLASS = { deny: "deny", approve: "ask", allow: "allow" };
function ruleWho(w) {
  if (w === "any") return "Everyone";
  if (w === "agent") return "Any agent";
  if (w && typeof w === "object") {
    if (w.kind) return `${w.kind[0].toUpperCase()}${w.kind.slice(1)} agents`;
    if (w.session) return `Session ${w.session}`;
  }
  return String(w);
}
const whoShort = (w) => w === "any" ? "Everyone" : w === "agent" ? "Agents" : w?.kind ? `${w.kind[0].toUpperCase()}${w.kind.slice(1)}` : w?.session ? "That session" : "Someone";
const VERB = {
  run: ["can’t run with", "asks before running with", "may run with"],
  get: ["can’t reveal", "asks before revealing", "may reveal"],
  copy: ["can’t copy", "asks before copying", "may copy"],
  view: ["can’t view", "asks before viewing", "may view"],
  export: ["can’t export", "asks before exporting", "may export"],
  call: ["can’t call", "asks before calling", "may call"],
  egress: ["can’t connect to", "asks before connecting to", "Network allowed to"],
};
function ruleSentence(r) {
  const [name] = Object.values(r.subject || {});
  const i = r.effect === "deny" ? 0 : r.effect === "approve" ? 1 : 2;
  const verbs = VERB[r.action] || [`can’t ${r.action}`, `asks before ${r.action}`, `may ${r.action}`];
  // "Network allowed to host" reads without a subject.
  const lead = r.action === "egress" && r.effect === "allow" ? verbs[2] : `${whoShort(r.who)} ${verbs[i]}`;
  return { lead, name: String(name ?? "?") };
}
function ruleText(r) { const { lead, name } = ruleSentence(r); return `${lead} ${name}`; }

function renderPolicy() {
  const pol = (cfg && cfg.policy) || { rules: [], tags: {} };
  const rules = pol.rules || [], tags = Object.entries(pol.tags || {});
  const effect = (e) => el("b", { class: `e ${EFFECT_CLASS[e] || ""}`, textContent: EFFECT_WORD[e] || e });
  const name = (n) => el("span", { class: "mono", style: "font-size:13px", textContent: n });
  const rows = [
    ...rules.map((r) => {
      const { lead, name: n } = ruleSentence(r);
      const who = ruleWho(r.who) + (r.effect === "allow" ? " · never loosens a secret’s own level" : "");
      return el("div", { class: "lrow rule" }, el("span", { class: "t2" }, effect(r.effect), ` · ${lead} `, name(n), el("small", { textContent: who })));
    }),
    ...tags.map(([pat, tier]) => el("div", { class: "lrow rule" }, el("span", { class: "t2" },
      tier === "prod" ? effect("deny") : el("b", { textContent: "Tag" }),
      ` · ${tier === "prod" ? "Production" : tier === "preprod" ? "Pre-production" : "Development"}: `, name(pat),
      el("small", { textContent: tier === "prod" ? "Agents denied unless a rule above allows" : "Label only" })))),
  ];
  $("policy-rules").replaceChildren(...(rows.length ? rows : [el("div", { class: "lrow empty", textContent: "No rules. Only each secret’s access level applies." })]));
  const kinds = [...new Set(cfg?.agent_process_names || [])];
  const keep = $("policy-who").value;
  $("policy-who").replaceChildren(el("option", { value: "", textContent: "you" }), el("option", { value: "agent:unknown", textContent: "an unknown agent" }),
    ...kinds.map((k) => el("option", { value: `agent:${k}`, textContent: `${k}` })));
  if ([...$("policy-who").options].some((o) => o.value === keep)) $("policy-who").value = keep;
}

async function explainPolicy() {
  const out = $("policy-result");
  const subject = $("policy-subject").value.trim();
  out.className = "res";
  if (!subject) { out.hidden = false; out.textContent = "Type a secret name, tool or host."; return; }
  try {
    const r = await call("policy_explain", { action: $("policy-action").value, subject, asWho: $("policy-who").value || null }, $("policy-explain"));
    const rule = r.rule_index != null ? (cfg?.policy?.rules || [])[r.rule_index] : null;
    const by = rule ? ` by the rule “${ruleText(rule)}”` : r.reason_code === "policy.prod_agent" ? " by the Production tag" : "";
    const word = { deny: "Denied", approve: "Asks first", allow: r.reason_code === "policy.rule_allow" ? "Allowed" : "Not limited by rules" }[r.effect] || r.effect;
    out.className = `res ${EFFECT_CLASS[r.effect] || ""}`;
    out.title = r.reason_code;
    out.replaceChildren(el("span", {}, el("b", { textContent: word }), `${by}. The secret’s own access level still applies on top.`));
    out.hidden = false;
  } catch { out.hidden = true; }
}

function leaseScopeText(sc) {
  const v = [];
  if (sc.cwd) v.push(`only in ${sc.cwd.replace(/^\/Users\/[^/]+/, "~")}`);
  if (sc.cmds?.length) v.push(`only ${sc.cmds.map((c) => (c.path || c).split("/").pop()).join(", ")}`);
  if (sc.max_uses) v.push(`${sc.max_uses} uses max`);
  return v.join(" · ");
}

// Pills: OK green, Reachable amber, Unclear amber outline, Not checked grey.
const CHECK_PILL = { pass: "ok", fail: "warn", inconclusive: "unclear", unsupported: "off" };
async function runDoctor() {
  $("doctor-run").textContent = "Run check";
  $("doctor-result").replaceChildren(el("div", { class: "lrow empty", textContent: "Checking…" }));
  let r;
  try { r = await call("doctor", {}, $("doctor-run")); } catch { $("doctor-result").replaceChildren(); return; }
  const checks = r.checks || [];
  const reach = checks.filter((x) => x.status === "fail").length;
  $("doctor-when").textContent = `Checked ${clock()} with a fake test secret`;
  $("doctor-run").textContent = "Run again";
  $("doctor-intro").hidden = true;
  $("doctor-result").replaceChildren(
    el("div", { class: "sum", style: "margin-bottom:6px" }, el("div", { class: "it2" },
      el("span", { class: `sev ${reach ? "warn" : "ok"}`, "aria-hidden": "true" }),
      reach ? el("span", {}, el("b", { textContent: `${reach} of ${plural(checks.length, "check")} ${reach === 1 ? "is" : "are"} reachable` }), " by any program running as you. Expected on macOS; Touch ID secrets stay protected.")
        : el("span", { textContent: `Nothing reachable in ${plural(checks.length, "check")}.` }))),
    el("div", { class: "lrows" }, ...checks.map((x) => el("div", { class: "lrow" },
      el("span", { class: "t2", textContent: DOCTOR_NAMES[x.name] || x.name }, el("small", { textContent: x.why || "" })),
      el("span", { class: `pill2 ${CHECK_PILL[x.status] || "off"}`, textContent: CHECK_WORD[x.status] || x.status })))));
}

// ---------- settings section nav ----------
// Click scrolls the body to the section; the current section follows the scroll.
function openSettingsSection(id, flash = false) {
  if (currentView !== "settings") show("settings");
  requestAnimationFrame(() => {
    const target = $(id);
    if (!target) return;
    target.scrollIntoView({ block: "start", behavior: "smooth" });
    trackSettingsSection(id);
    if (flash && id === "settings-backup") $("backup-missing-row").classList.add("flash");
  });
}
function trackSettingsSection(force) {
  const body = document.querySelector("#view-settings .settings-body");
  const links = [...document.querySelectorAll("#settings-nav a")];
  let cur = force;
  if (!cur) {
    const top = body.getBoundingClientRect().top + 24;
    for (const a of links) { const t = $(a.dataset.sec); if (t && t.getBoundingClientRect().top <= top) cur = a.dataset.sec; }
    if (!cur) cur = links[0]?.dataset.sec;
    // At the bottom, the last short section is current.
    if (body.scrollTop + body.clientHeight >= body.scrollHeight - 4) cur = links.at(-1).dataset.sec;
  }
  for (const a of links) {
    const on = a.dataset.sec === cur;
    a.classList.toggle("on", on);
    if (on) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
  }
}
document.querySelectorAll("#settings-nav a").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); openSettingsSection(a.dataset.sec); }));
document.querySelector("#view-settings .settings-body").addEventListener("scroll", () => trackSettingsSection(), { passive: true });

function setNavCount(id, n, bad = false) {
  $(id).hidden = !n;
  $(id).textContent = n ? String(n) : "";
  $(id).classList.toggle("bad", bad);
}

// Backup section, paper first. "Back it up" needs a backup_rotate IPC, which is not
// implemented yet: until then it points at the CLI.
function renderBackupSettings() {
  const total = secrets.length, unbacked = secrets.filter((x) => !x.has_backup);
  const has = !!cfg?.backup_recipient;
  $("backup-gly").replaceChildren(levelGlyph(has ? "me-touch" : "me"));
  $("backup-gly").style.color = has ? "var(--ok)" : "var(--bad)";
  $("backup-state").textContent = has
    ? `Set up · ${total - unbacked.length} of ${plural(total, "secret")} ${total === 1 ? "has" : "have"} a backup copy`
    : "Not set up: if this Mac's keys are lost, every secret is unrecoverable.";
  $("backup-verify-open").hidden = !has;
  $("backup-rotate-open").textContent = has ? "New paper key…" : "Make a paper backup…";
  $("backup-rotate-open").classList.toggle("primary", !has);
  const row = $("backup-missing-row");
  row.hidden = !has || unbacked.length === 0;
  if (!row.hidden) {
    $("backup-missing-title").textContent = `${plural(unbacked.length, "secret has", "secrets have")} no backup copy`;
    const names = unbacked.length <= 3 ? unbacked.map((x) => x.name).join(", ") : `${unbacked.slice(0, 3).map((x) => x.name).join(", ")} and ${unbacked.length - 3} more`;
    $("backup-missing-sub").replaceChildren(`${names}. To write the missing copies, run `, el("code", { textContent: "karambit backup rotate" }), " in a terminal (one Touch ID).");
  }
  setNavCount("snav-backup-n", has ? unbacked.length : 1, !has);
}
$("backup-missing-btn").textContent = "Copy command";
$("backup-missing-btn").addEventListener("click", async (ev) => {
  // Fallback until there is a backup_rotate IPC: copy the command and say where to run it.
  try { await navigator.clipboard.writeText("karambit backup rotate"); toast("Copied: karambit backup rotate. Run it in a terminal."); }
  catch { toast("Run karambit backup rotate in a terminal", true); }
  ev.currentTarget.blur();
});

// ---------- project files (.karambit.env trust) ----------
// One flat row per trusted file; a review block opens inline under the row it's about.
// Old VAR = ref lines are not shown yet: a changed file shows its current
// lines and was/now hashes. Untrust is not implemented yet: Missing has no Remove.
let profiles = [];          // [{ path, sha256, state }]
let profileReview = null;   // { key: path or "new", r: profile_preview result, oldSha? }

const shortSha = (h) => (h && h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-6)}` : h || "");
const tildePath = (p) => p.replace(/^\/Users\/[^/]+/, "~");
const FILE_ICON = ["M4 1.5h5l3 3v10H4z", "M9 1.5v3h3"];

function profileRow(p) {
  const state = { trusted: "Trusted", changed: "Changed", missing: "Missing" }[p.state] || p.state;
  const pill = { trusted: "ok", changed: "warn", missing: "off" }[p.state] || "off";
  const sub = { trusted: "Trusted: agents can use it", changed: "Changed since you trusted it · agents are refused", missing: "File no longer exists" }[p.state] || "";
  const row = el("div", { class: `lrow profile-row${p.state === "missing" ? " gone" : ""}` },
    el("span", { class: "gly", "aria-hidden": "true" }, icon(FILE_ICON)),
    el("span", { class: "t2" }, el("span", { class: "mono", style: "font-size:13px", textContent: tildePath(p.path), title: p.path }), el("small", { textContent: sub })),
    el("span", { class: `pill2 ${pill}`, textContent: state }));
  if (p.state === "changed" && profileReview?.key !== p.path) {
    row.append(el("button", { type: "button", class: "btn sm", textContent: "Review…", onclick: () => reviewProfile(p.path, p.sha256) }));
  }
  return row;
}

function reviewBlock() {
  const { r, oldSha, key } = profileReview;
  const changed = !!oldSha && oldSha !== r.sha256;
  const lines = r.specs.length ? r.specs : [];
  const width = Math.max(4, ...lines.map(([k]) => k.length));
  const trust = el("button", { type: "button", class: "btn sm primary", textContent: r.trusted ? "Trusted" : changed ? "Trust new version" : "Trust this file", disabled: r.trusted, onclick: trustProfile });
  return el("div", { class: "review", role: "region", "aria-label": `Review ${tildePath(r.path)}` },
    el("b", { style: "font-size:13.5px", textContent: changed ? "What it says now" : key === "new" ? `Review ${tildePath(r.path)}` : "Contents" }),
    el("p", { class: "hint", style: "margin:0", textContent: changed
      ? "Karambit doesn't keep the old lines, so it can't show what was removed. Check these are the names you expect before trusting."
      : r.trusted ? "Already trusted." : `Agents get ${plural(lines.length, "variable")} from this file once you trust it.` }),
    el("div", { class: "diff" }, ...(lines.length ? lines.map(([k, v]) => el("div", { class: "same", textContent: `  ${k.padEnd(width)} = ${v}` })) : [el("div", { class: "same", textContent: "  (no VAR = name lines)" })])),
    el("span", { class: "hint mono", style: "font-size:11.5px", textContent: changed ? `SHA-256 ${shortSha(r.sha256)} (was ${shortSha(oldSha)})` : `SHA-256 ${shortSha(r.sha256)}`, title: r.sha256 }),
    el("div", { class: "review-actions" },
      el("button", { type: "button", class: "btn sm", textContent: "Not now", onclick: () => { profileReview = null; renderProfiles(); } }), trust));
}

function renderProfiles() {
  const rows = [];
  if (profileReview?.key === "new") rows.push(reviewBlock());
  for (const p of profiles) {
    rows.push(profileRow(p));
    if (profileReview?.key === p.path) rows.push(reviewBlock());
  }
  $("profile-list").replaceChildren(...(rows.length ? rows : [el("div", { class: "lrow empty", textContent: "No project files trusted yet." })]));
  setNavCount("snav-projects-n", profiles.filter((p) => p.state === "changed").length);
}

async function reviewProfile(path = $("profile-path").value.trim(), oldSha = null) {
  if (!path) { $("profile-path").focus(); return; }
  let r;
  try { r = await call("profile_preview", { path }, $("profile-check")); } catch { return; }
  const known = profiles.find((p) => p.path === r.path);
  profileReview = { key: known ? r.path : "new", r, oldSha: oldSha || (known && known.sha256 !== r.sha256 ? known.sha256 : null) };
  renderProfiles();
}

async function trustProfile(ev) {
  if (!profileReview) return;
  const path = profileReview.r.path;
  try {
    await call("profile_trust", { path }, ev.currentTarget);
    toast(`Trusted ${tildePath(path)}`);
  } catch { return; /* toast shown (e.g. changed during approval) */ }
  profileReview = null;
  $("profile-path").value = "";
  toggleProfileAdd(false);
  await loadProfiles();
}

async function loadProfiles() {
  try { profiles = await call("profile_list"); } catch { return; }
  renderProfiles();
}

function toggleProfileAdd(open = $("profile-add-box").hidden) {
  $("profile-add-box").hidden = !open;
  $("profile-add").setAttribute("aria-expanded", String(open));
  if (open) $("profile-path").focus();
  else if (profileReview?.key === "new") { profileReview = null; renderProfiles(); }
}

// Settings keys (as the backend names them) → field id and the label shown on the page.
const SETTING_FIELDS = {
  "default-tier": { id: "cfg-default-tier", label: "Touch ID for new secrets" },
  "clip-seconds": { id: "cfg-clip", label: "Clear clipboard after" },
  "backup-recipient": { id: "cfg-backup", label: "Backup recipient" },
  "agent-detection": { id: "cfg-detection", label: "Agent detection" },
  "human-lease-hours": { id: "cfg-human-lease", label: "Reuse your Touch ID for" },
};
const SETTINGS_NOTE = "Relaxing a setting asks for Touch ID.";

function settingsWant() {
  return {
    "default-tier": $("cfg-default-tier").checked ? "on" : "off",
    "clip-seconds": String($("cfg-clip").value),
    "backup-recipient": $("cfg-backup").value.trim() || "none",
    "agent-detection": $("cfg-detection").value,
    "human-lease-hours": $("cfg-human-lease").value === "" ? String(cfg.human_lease_hours) : String(Number($("cfg-human-lease").value)),
  };
}

function settingsHave() {
  return {
    "default-tier": cfg.default_tier === "bio" ? "on" : "off",
    "clip-seconds": String(cfg.clip_seconds),
    "backup-recipient": cfg.backup_recipient || "none",
    "agent-detection": JSON.stringify(detectionFromConfig()),
    "human-lease-hours": String(cfg.human_lease_hours),
  };
}

// Changed keys, in save order.
function settingsChanged() {
  const want = settingsWant(), have = settingsHave();
  return Object.keys(want).filter((k) => want[k] !== have[k]).map((k) => [k, want[k]]);
}

// Mirrors the backend's set_config: these ask for Touch ID, one prompt per key.
function settingRelaxes(key, value) {
  return (key === "default-tier" && value === "off")
    || (key === "backup-recipient" && value === "none")
    || (key === "agent-detection" && detectionRelaxes(JSON.parse(value)))
    || (key === "human-lease-hours" && Number(value) > cfg.human_lease_hours);
}

// Before saving: say so when more than one change will ask for Touch ID.
function renderSettingsNote() {
  if (!cfg) return;
  const n = settingsChanged().filter(([k, v]) => settingRelaxes(k, v)).length;
  const note = $("settings-note");
  note.textContent = n > 1 ? `${n} of these changes relax a setting, so Touch ID asks up to ${n} times.` : SETTINGS_NOTE;
  note.classList.toggle("warn-note", n > 1);
}

function settingsResult(text, kind) {
  const r = $("settings-result");
  r.textContent = text;
  r.className = `small ${kind}`;
}

// Saves changed keys one by one and stops at the first failure. Every outcome is said
// inline next to Save; fields that weren't saved keep what you typed.
async function saveSettings(ev) {
  ev.preventDefault();
  const btn = ev.submitter;
  for (const id of ["cfg-procs", "cfg-env"]) if (!addChips(id, $(id).value)) return;
  const changed = settingsChanged();
  for (const { id } of Object.values(SETTING_FIELDS)) $(id).removeAttribute("aria-invalid");
  if (!changed.length) { settingsResult("Nothing to save", "muted"); return; }
  settingsResult(changed.some(([k, v]) => settingRelaxes(k, v)) ? "Saving · confirm with Touch ID when asked…" : "Saving…", "muted");
  if (btn) btn.disabled = true;
  let saved = 0, failed = null;
  for (const [k, v] of changed) {
    try {
      await call("set_config", { key: k, value: v });
      saved++;
    } catch (err) {
      failed = { key: k, err: String(err) };
      break;
    }
  }
  // Keep the unsaved inputs (the failed key and any not tried) across the re-read.
  const unsaved = changed.slice(saved).map(([k]) => SETTING_FIELDS[k].id);
  const kept = unsaved.map((id) => [id, $(id).type === "checkbox" ? $(id).checked : $(id).value]);
  try { await loadSettings(); } catch { /* toast shown */ }
  for (const [id, v] of kept) { if ($(id).type === "checkbox") $(id).checked = v; else $(id).value = v; }
  detectionDraft = JSON.parse($("cfg-detection").value); renderDetectionChips();
  renderSettingsNote();
  if (btn) btn.disabled = false;
  if (failed) {
    const field = $(SETTING_FIELDS[failed.key].id);
    field.setAttribute("aria-invalid", "true");
    const rest = changed.slice(saved + 1).map(([k]) => SETTING_FIELDS[k].label);
    settingsResult(`Saved ${saved} of ${changed.length} · not saved: ${SETTING_FIELDS[failed.key].label} (${failed.err})${rest.length ? ` · not tried: ${rest.join(", ")}` : ""}`, "error");
  } else {
    settingsResult(`Saved ${saved} ${saved === 1 ? "setting" : "settings"}`, "ok");
  }
  loadStatus();
}

// ---------- add dialog ----------

// The same least-to-most restrictive control is used in sheets, panels and row menus.
function accessPicker(box, group, levels) {
  // Public is a separate final choice: own radio name so the 3 levels announce "1 of 3".
  const step = (l) => el("label", { class: `access-step lvl-${l.id}` },
    el("input", { type: "radio", name: l.id === "public" ? `${group}-public` : group, value: l.id }),
    el("span", {}, levelGlyph(l.id), l.id === "public" ? "Mark as public (not a secret)…" : l.label));
  box.replaceChildren(el("div", { class: "access-segments" }, ...levels.filter((l) => l.id !== "public").map(step)),
    el("p", { class: "hint access-hint" }));
  const pub = levels.find((l) => l.id === "public");
  if (pub) box.append(step(pub));
  box.addEventListener("change", () => syncAccessHint(box));
}
const COMPACT_ACCESS_HINT = {
  agents: "Any program running as you could read it.",
  "agents-touch": "Agents use it after your Touch ID, or freely during temporary access.",
  "me-touch": "Detected agents refused; Touch ID for you.",
  public: "Not secret: visible and never redacted.",
  me: "Only me (retired) · choose a new level.",
};
function syncAccessHint(box) {
  const id = box.querySelector("input:checked")?.value;
  const hint = box.querySelector(".access-hint");
  if (hint) hint.textContent = COMPACT_ACCESS_HINT[id || "me"];
}
// Radio + glyph + label rows; only the selected row shows its one-line explanation.
function compactAccessRows(box) {
  box.querySelectorAll(".access-step").forEach((step) => {
    const input = step.querySelector("input"), span = step.querySelector("span");
    const label = input.value === "public" ? "Mark as public…" : accessLevel(input.value).label;
    const glyph = span.firstElementChild;
    span.replaceChildren(el("i", { class: "access-radio", "aria-hidden": "true" }), glyph, el("span", { class: "access-label" }, el("b", { textContent: label }), el("small", { class: "access-explain", textContent: COMPACT_ACCESS_HINT[input.value] })));
  });
  box.querySelector(".access-hint")?.remove(); // the selected option carries its own one-line explanation
}
function policyPicker(s) {
  const box = el("div", { class: "compact-access", role: "radiogroup", "aria-label": "Who can use it" });
  accessPicker(box, `policy-${++accessHintSeq}`, levelsFor(isAws(s.name)));
  const selected = box.querySelector(`input[value="${accessOf(s)}"]`);
  if (selected) selected.checked = true;
  syncAccessHint(box);
  compactAccessRows(box);
  const status = el("p", { class: "access-status small", role: "status", textContent: accessBusy.get(s.name) || accessError.get(s.name)?.text || "" });
  box.append(status);
  box.querySelectorAll("input").forEach((n) => { n.disabled = accessBusy.has(s.name); });
  // Arrows only move a focus ring (roving tabindex); Space/Enter/click commits once.
  // The saved level stays checked until changeAccess succeeds; cancel/fail restores it.
  box.setAttribute("aria-description", "Arrow keys to choose, Space to apply");
  const inputs = [...box.querySelectorAll(".access-step input")];
  const saved = () => inputs.find((n) => n.value === accessOf(s)) || inputs[0];
  const restore = () => { inputs.forEach((n) => { n.checked = n === saved(); }); };
  const keys = el("p", { class: "access-keys small", hidden: true }, el("kbd", { textContent: "↑" }), " ", el("kbd", { textContent: "↓" }), " choose · ",
    el("kbd", { textContent: "Space" }), " apply · ", el("kbd", { textContent: "Esc" }), " cancel");
  box.append(keys);
  const rove = (target) => {
    inputs.forEach((n) => { n.tabIndex = n === target ? 0 : -1; n.closest(".access-step").classList.toggle("kbd-focus", n === target); });
    keys.hidden = target === saved(); // legend only while a different option is focused
    target.focus();
  };
  inputs.forEach((n) => { n.tabIndex = n === saved() ? 0 : -1; });
  let committing = false;
  const commit = async (input) => {
    if (committing || input.disabled) return;
    if (input.value === accessOf(s)) { restore(); return; }
    committing = true;
    restore(); // the dot moves only after success
    const select = accessSelect(s, s.name, loadSecrets).querySelector("select");
    select.value = input.value;
    inputs.forEach((n) => { n.disabled = true; });
    try { await changeAccess(s, select, status, s.name, loadSecrets); }
    finally { committing = false; }
    renderInspector();
    $("inspector").querySelector(".compact-access input:checked")?.focus();
  };
  box.addEventListener("keydown", (e) => {
    const cur = inputs.indexOf(document.activeElement);
    if (cur < 0) return;
    const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[e.key];
    if (step) { e.preventDefault(); rove(inputs[(cur + step + inputs.length) % inputs.length]); return; }
    if (e.key === " " || e.key === "Enter") { e.preventDefault(); commit(inputs[cur]); return; }
    // Esc first cancels a pending choice (focus back on the saved level); a second Esc closes the panel.
    if (e.key === "Escape" && inputs[cur] !== saved()) { e.preventDefault(); e.stopPropagation(); restore(); rove(saved()); }
  });
  // Native radio activation (click on label/dot) still commits in one step; keyboard-driven
  // changes are already prevented above, so a "change" here is a pointer action.
  box.addEventListener("change", (e) => { if (e.target.matches(".access-step input")) commit(e.target); });
  box.addEventListener("focusout", (e) => { if (!box.contains(e.relatedTarget)) { keys.hidden = true; inputs.forEach((n) => { n.closest(".access-step").classList.remove("kbd-focus"); n.tabIndex = n === saved() ? 0 : -1; }); } });
  return box;
}

// Inline failure above a dialog's buttons; "" clears it.
function setFormError(id, text) {
  $(id).textContent = text;
}

function openAdd(folder = currentFolder, fromFolder = false) {
  $("add-back").hidden = !fromFolder;
  if (typeof folder !== "string") folder = currentFolder;
  $("add-form").reset();
  $("add-name").value = folder ? folder + "/" : "";
  $("add-name").placeholder = folder ? "name" : "folder/name";
  $("add-form").querySelectorAll("input.touched").forEach((n) => n.classList.remove("touched"));
  setFormError("add-error", "");
  $("add-form").elements["add-level"].value = defaultLevel();
  syncAccessHint($("add-access"));
  openDialog($("add-dialog"));
  $("add-name").focus();
  const end = $("add-name").value.length;
  $("add-name").setSelectionRange(end, end); // caret after "stripe/"
}
// Mark fields touched on first blur or a submit attempt, so empty fields aren't red on open.
$("add-form").addEventListener("focusout", (e) => { if (e.target.matches("input")) e.target.classList.add("touched"); });
$("add-form").addEventListener("invalid", (e) => e.target.classList.add("touched"), true);

async function submitAdd(ev) {
  ev.preventDefault();
  const level = $("add-access").querySelector('input[value="public"]:checked') ? "public" : $("add-form").elements["add-level"].value;
  const flags = levelFlags(level);
  const args = {
    name: $("add-name").value.trim(),
    value: $("add-value").value,
    touch: flags.touch,
    agentAllowed: flags.agentAllowed,
    public: flags.public,
    overwrite: $("add-force").checked,
  };
  setFormError("add-error", "");
  try {
    await call("add", args, $("add-submit"));
    $("add-value").value = "";
    $("add-dialog").close();
    toast(`Saved ${args.name}`);
    loadSecrets();
  } catch (err) {
    setFormError("add-error", String(err)); // toast shown too; keep dialog open
  }
}

// ---------- A+ details panel ----------
function wrapName(name) { return name.split(/(?<=[\/-])/).flatMap((part) => [document.createTextNode(part), el("wbr")]); }
function renderInspector() {
  const panel = $("inspector");
  // Keep the existing AWS controls and their event listeners when rebuilding the panel.
  const aws = $("aws-detail");
  if (panel.contains(aws)) $("detail-dialog").querySelector("form").prepend(aws);
  const s = secrets.find((x) => x.name === selectedSecret);
  panel.hidden = !s;
  panel.replaceChildren();
  if (!s) { renderAwsDetail(null); return; }
  const close = el("button", { class: "ibtn", "aria-label": "Close details", onclick: () => { selectedSecret = null; renderLists(); renderInspector(); } }, icon(ICON_CLOSE));
  const slash = s.name.lastIndexOf("/");
  panel.append(el("div", { class: "panel-heading" }, el("h2", { class: "mono-title panel-name" },
    el("span", { class: "panel-crumb" }, ...wrapName(slash < 0 ? "" : s.name.slice(0, slash) + " /")),
    ...wrapName(s.name.slice(slash + 1))), close),
    el("p", { class: "muted small", textContent: `${isAws(s.name) ? "AWS profile · updated" : "Updated"} ${relTime(s.updated)}` }));
  if (isAws(s.name)) { panel.append(aws); renderAwsDetail(s); }
  else {
    const copy = el("button", { class: "btn primary", textContent: "Copy", onclick: () => copyValue(s.name, copy) });
    panel.append(el("h3", { class: "sec", textContent: "Value" }),
      el("div", { class: "panel-value" }, el("code", { id: "inspector-value", textContent: s.public ? (publicValues.get(s.name)?.value ?? "Public value · copy to read") : MASK }), copy),
      el("p", { class: "hint", textContent: `Copying never reveals a secret here. Clipboard clears in ${cfg?.clip_seconds ?? 30}s.` }));
  }
  panel.append(el("h3", { class: "sec", textContent: "Who can use it" }));
  panel.append(policyPicker(s));
  if (accessError.has(s.name)) panel.append(el("p", { class: "form-error", role: "alert", textContent: accessError.get(s.name).text }));
  if (!s.public) {
    panel.append(el("h3", { class: "sec", textContent: "Temporary access" }),
      el("p", { class: "small", textContent: s.lease ? `${s.lease.to_label} · ${durShort(s.lease.remaining)} left · used ${s.lease.uses || 0} times` : "No temporary access" }),
      // DOM append() would print a null child as the text "null"; add the hint only when there is a lease.
      ...(s.lease ? [el("p", { class: "hint", textContent: scopeLabel(s.lease.scope) || "No program or folder limits" })] : []),
      el("button", { class: "btn sm", textContent: s.lease ? "Change…" : "Give access…", onclick: () => { detail = { kind: "secret", name: s.name }; showDetail(); } }));
    if (s.lease) {
      const end = el("button", { class: "btn sm", textContent: "End", onclick: async () => {
        try { await call("lease_revoke", { names: [s.name] }, end); await loadSecrets(); } catch { /* toast shown */ }
      } });
      panel.append(end);
    }
  }
  if (!isAws(s.name)) {
    const cmd = `karambit run -e VAR=${s.name} -- command`;
    panel.append(el("h3", { class: "sec", textContent: "Agents use it with" }), el("div", { class: "cmd-copy" },
      el("code", { textContent: cmd }), el("button", { class: "ibtn", "aria-label": "Copy command", onclick: () => copyText(cmd) }, icon(ICON_COPY))));
  }
  panel.append(el("button", { class: "link panel-activity", textContent: "View activity →", onclick: () => { show("audit"); setAuditSecret(s.name); } }));
  const leaseHeading = [...panel.querySelectorAll("h3")].find((n) => n.textContent === "Temporary access");
  if (leaseHeading) {
    const leaseBox = el("div", { class: "panel-lease" });
    while (leaseHeading.nextElementSibling && !leaseHeading.nextElementSibling.matches("h3, .panel-activity")) leaseBox.append(leaseHeading.nextElementSibling);
    leaseHeading.after(leaseBox);
  }
  const del = deleteButton(s); del.className = "btn danger-text"; del.append(isAws(s.name) ? "Delete profile…" : "Delete secret…");
  panel.append(el("div", { class: "panel-footer" }, del, el("span", { class: "hint", textContent: "Asks for Touch ID" })));
  const heading = panel.firstElementChild;
  const title = heading.firstElementChild;
  const titleBlock = el("div", { class: "panel-title-block" });
  title.before(titleBlock);
  titleBlock.append(title, panel.children[1]);
  const body = el("div", { class: "panel-body" });
  while (heading.nextElementSibling && !heading.nextElementSibling.classList.contains("panel-footer")) body.append(heading.nextElementSibling);
  heading.after(body);
}

// ---------- G: linked sources (metadata and offline reference checks only) ----------
function sourceRow(source) {
  return wholeRow(el("div", { class: "secret-row folder-row" }, el("span", { class: "tile" }, icon(ICON_FOLDER)),
    el("div", { class: "row-name" }, el("button", { class: "group-toggle leaf", textContent: source.name + "/", onclick: () => navigateFolder("", source.name) }),
      el("span", { class: "muted small", textContent: source.endpoint })),
    el("span", { class: "tag pub", textContent: source.kind }),
    el("button", { class: "btn sm", textContent: "Manage", "aria-label": `Manage linked source ${source.name}`, onclick: () => navigateFolder("", source.name) })), () => navigateFolder("", source.name));
}
function renderSources() {
  if (currentSource && !sources.some((s) => s.name === currentSource)) currentSource = null;
  const rows = $("source-rows");
  rows.replaceChildren();
  $("sources-title").textContent = currentSource ? currentSource + "/" : "Linked sources";
  $("sources-breadcrumbs").replaceChildren();
  $("sources-filter").disabled = !!currentSource;
  if (currentSource) {
    $("sources-breadcrumbs").append(el("button", { class: "btn sm", textContent: "← Back", "aria-keyshortcuts": "Meta+[ Backspace", onclick: goUp }), el("button", { class: "link", textContent: "Linked sources", onclick: goUp }));
    renderSourceFolder(rows);
  } else {
    const m = KarambitSearch.compile($("sources-filter").value);
    const scored = sources.map((s) => ({ s, r: m.active ? m.score([{ text: s.name }, { text: `${s.kind} ${s.endpoint}`, weight: 0.6 }]) : { score: 0 } }))
      .filter((x) => x.r).sort((a, b) => b.r.score - a.r.score);
    rows.append(...scored.map(({ s, r }) => {
      const row = sourceRow(s);
      if (r.ranges?.length) row.querySelector(".leaf").replaceChildren(...highlightNodes(s.name, r.ranges), "/");
      return row;
    }));
  }
  // Empty states: "none yet" vs "filter matches none".
  const none = !currentSource && sources.length === 0;
  const q = $("sources-filter").value.trim();
  $("sources-filter").closest(".search").hidden = none;
  const empty = $("sources-empty");
  empty.hidden = rows.childElementCount > 0;
  if (!empty.hidden) {
    if (none) {
      const link = el("button", { class: "btn primary", textContent: "Link source", onclick: () => openSource() });
      empty.replaceChildren(el("h2", { textContent: "No linked sources yet" }),
        el("p", { textContent: "Link a source to use its secrets by reference; only the connection credential is stored here." }), link);
    } else {
      const clear = el("button", { class: "btn", textContent: "Clear filter", onclick: () => { $("sources-filter").value = ""; renderSources(); $("sources-filter").focus(); } });
      empty.replaceChildren(el("p", { textContent: `No linked sources match “${q}”` }), clear);
    }
  }
}
function renderSourceFolder(rows) {
  const source = sources.find((x) => x.name === currentSource);
  if (!source) { currentSource = null; renderSources(); return; }
  const ref = el("input", { id: "source-ref", placeholder: `${source.name}:mount/path#field`, autocomplete: "off", spellcheck: false, required: true });
  const result = el("p", { class: "hint", role: "status" });
  const check = el("button", { class: "btn primary", textContent: "Check reference", type: "submit" });
  const form = el("form", { class: "source-check", onsubmit: async (e) => {
    e.preventDefault(); result.textContent = "";
    if (!ref.value.trim().startsWith(source.name + ":")) { result.textContent = `Use the ${source.name}: prefix for this source.`; return; }
    try { await call("classify_reference", { reference: ref.value.trim() }, check); result.textContent = "Configured backend reference. Offline classification only: existence, permissions and native backend syntax have not been checked."; }
    catch { result.textContent = "Reference not accepted. Check the source prefix and syntax."; }
  } }, el("label", { class: "lbl", htmlFor: "source-ref", textContent: "Paste a reference to check" }), ref, check, result);
  const remove = el("button", { class: "btn danger-text", textContent: "Remove source", onclick: async () => {
    if (!(await confirmDialog(`Remove ${source.name}?`, "This removes the local connection and invalidates grants. Remote secrets are not deleted.", "Remove source"))) return;
    try { await call("source_remove", { name: source.name }, remove); currentSource = null; await loadSecrets(); } catch { /* toast shown */ }
  } });
  rows.append(el("div", { class: "source-page" }, el("h2", { textContent: source.name }), el("span", { class: "tag pub", textContent: source.kind }),
    el("p", { class: "mono", textContent: source.endpoint }),
    el("p", { class: "muted", textContent: "Remote listing is not available. Karambit resolves references when used, not while browsing. Source policy is independent of local-secret access filters." }), form,
    el("div", { class: "actions" }, el("button", { class: "btn", textContent: "Retarget / update credentials…", onclick: () => openSource(source) }), remove)));
}
let editingSource = null;
async function openSource(source = null) {
  editingSource = source;
  $("source-form").reset();
  $("source-title").textContent = source ? `Retarget ${source.name}` : "Link source";
  $("source-save").textContent = source ? "Save binding" : "Link source";
  $("source-error").textContent = "";
  $("source-name").value = source?.name || "";
  $("source-name").readOnly = !!source;
  $("source-kind").disabled = !!source;
  $("source-auth").readOnly = !!source;
  $("source-credential").required = !source;
  if (source) {
    $("source-kind").value = source.kind;
    $("source-endpoint").value = source.endpoint;
    $("source-auth").value = source.auth_method;
    try { const config = await call("get_config"); $("source-policy").value = JSON.stringify(config.sources[source.name].policy, null, 2); }
    catch { return; }
  }
  openDialog($("source-dialog"));
  (source ? $("source-endpoint") : $("source-name")).focus();
}
async function submitSource(e) {
  e.preventDefault();
  $("source-error").textContent = "";
  let policy;
  try { policy = JSON.parse($("source-policy").value); }
  catch { $("source-error").textContent = "Policy must be valid JSON. Do not put credentials here."; return; }
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) { $("source-error").textContent = "Policy must be a JSON object."; return; }
  const args = { name: $("source-name").value.trim(), endpoint: $("source-endpoint").value.trim(), policy,
    credential: $("source-credential").value || (editingSource ? null : "") };
  $("source-credential").value = "";
  const save = $("source-save"); save.disabled = true;
  try {
    // Deliberately no call()/raw error toast here: never echo credential-bearing errors.
    if (editingSource) await invoke("source_retarget", args);
    else await invoke("source_add", { ...args, kind: $("source-kind").value, authMethod: $("source-auth").value.trim() });
    $("source-dialog").close();
    toast("Source binding saved");
    await loadSecrets();
  } catch { $("source-error").textContent = "Source was not saved. Check metadata, authentication method, policy and credentials; confirm Touch ID when asked. Re-enter credentials to retry."; }
  finally { args.credential = null; save.disabled = false; }
}

// ---------- D: command palette ----------
let paletteItems = [];
let paletteIndex = 0;
function openPalette() {
  $("palette-query").value = ""; paletteIndex = 0;
  renderPalette(); openDialog($("palette-dialog")); $("palette-query").focus();
}
function renderPalette() {
  const q = $("palette-query").value;
  const folders = new Set();
  for (const s of secrets) { const parts = s.name.split("/"); parts.pop(); while (parts.length) { folders.add(parts.join("/")); parts.pop(); } }
  paletteItems = [
    ...[...folders].sort().map((name) => ({ name: name + "/", kind: "Folder", run: () => navigateFolder(name) })),
    ...sources.map((s) => ({ name: s.name + "/", kind: s.kind + " · linked source", run: () => navigateFolder("", s.name) })),
    ...secrets.map((s) => ({ name: s.name, kind: isAws(s.name) ? "AWS profile" : accessLevel(accessOf(s)).label, secret: s.name,
      run: () => isAws(s.name) ? openDetail(s.name) : copyValue(s.name, null) })),
    { name: `New secret${currentFolder ? " in " + currentFolder + "/" : ""}`, kind: "Action", run: () => openAdd() },
    ...(sourceKinds.length ? [{ name: "Link source", kind: "Action", run: () => openSource() }] : []),
  ];
  // Ranked fuzzy match on name (highlighted) and kind; no query keeps the list order.
  const m = KarambitSearch.compile(q);
  if (m.active) paletteItems = paletteItems.map((x, i) => ({ x, i, r: m.score([{ text: x.name }, { text: x.kind, weight: 0.5 }]) }))
    .filter((y) => y.r).sort((a, b) => b.r.score - a.r.score || a.i - b.i).map((y) => ({ ...y.x, ranges: y.r.ranges }));
  paletteIndex = Math.min(paletteIndex, Math.max(0, paletteItems.length - 1));
  $("palette-results").replaceChildren(...paletteItems.map((x, i) => el("button", { id: `palette-option-${i}`, role: "option", tabIndex: -1, "aria-selected": String(i === paletteIndex), class: "palette-result" + (i === paletteIndex ? " selected" : ""),
    onclick: () => runPalette(i), onfocus: () => { paletteIndex = i; markPalette(); } }, el("span", { class: "mono" }, ...highlightNodes(x.name, x.ranges)), el("span", { class: "muted small", textContent: x.kind }))));
  markPalette();
  if (!paletteItems.length) $("palette-results").append(el("p", { class: "muted", textContent: "No results" }));
}
function markPalette() {
  [...$("palette-results").children].forEach((b, i) => { b.classList.toggle("selected", i === paletteIndex); b.setAttribute("aria-selected", String(i === paletteIndex)); });
  if (paletteItems.length) $("palette-query").setAttribute("aria-activedescendant", `palette-option-${paletteIndex}`);
  else $("palette-query").removeAttribute("aria-activedescendant");
}
function runPalette(i, details = false) {
  const x = paletteItems[i]; if (!x) return;
  $("palette-dialog").close();
  if (x.kind !== "Action") show("secrets");
  if (x.secret && (details || isAws(x.secret))) { navigateFolder(isAws(x.secret) ? "aws" : splitName(x.secret)[0]); openDetail(x.secret); } else x.run();
}

// ---------- boot ----------

document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => show(t.dataset.view)));
$("filter").addEventListener("input", renderSecrets);
$("aws-filter").addEventListener("input", renderAwsPage);
$("sources-filter").addEventListener("input", renderSources);
// Arrow keys move between rows' primary buttons (item names and folder toggles).
$("rows").addEventListener("keydown", (e) => {
  if ((e.key !== "ArrowDown" && e.key !== "ArrowUp") || e.altKey || e.metaKey || e.ctrlKey) return;
  const sel = ".leaf.link, .group-toggle";
  if (!e.target.matches(sel)) return;
  const all = [...$("rows").querySelectorAll(sel)];
  const next = all[all.indexOf(e.target) + (e.key === "ArrowDown" ? 1 : -1)];
  e.preventDefault();
  if (next) next.focus();
});
$("add-open").addEventListener("click", openAdd);
$("lock-fix").addEventListener("click", fixLockKeys);
accessPicker($("add-access"), "add-level", levelsFor(false));
compactAccessRows($("add-access"));
// Public has its own radio name (the three levels announce "1 of 3"); keep the two groups exclusive.
$("add-access").addEventListener("change", (e) => {
  const isPublic = e.target.value === "public";
  $("add-access").querySelectorAll("input").forEach((n) => { if ((n.value === "public") !== isPublic) n.checked = false; });
});
accessPicker($("aws-access"), "aws-level", levelsFor(true));
$("add-cancel").addEventListener("click", () => $("add-dialog").close());
$("add-dialog").addEventListener("close", () => ($("add-value").value = ""));
$("add-form").addEventListener("submit", submitAdd);
$("add-form").addEventListener("input", () => setFormError("add-error", ""));
$("aws-form").addEventListener("input", () => setFormError("aws-error", ""));
$("portal-form").addEventListener("input", () => setFormError("portal-error", ""));
$("aws-open").addEventListener("click", () => openAwsDialog());
$("aws-paste").addEventListener("input", detectAws);
for (const r of document.querySelectorAll('input[name="aws-kind"]')) r.addEventListener("change", syncAwsKind);
$("aws-portal").addEventListener("change", syncPortal);
$("aws-cancel").addEventListener("click", () => $("aws-dialog").close());
$("aws-dialog").addEventListener("close", () => ($("aws-paste").value = ""));
$("aws-form").addEventListener("submit", submitAws);
$("aws-detail-edit").addEventListener("click", () => {
  const s = awsDetailTarget;
  if (!s) return;
  $("detail-dialog").close();
  openAwsDialog(s.name.slice(4), s);
});
$("aws-detail-signin").addEventListener("click", () => {
  const portal = awsDetailTarget && awsPortalFor(awsDetailTarget);
  if (portal) startSignIn(portal);
});
$("aws-detail-reveal").addEventListener("click", revealAwsDetail);
// AWS result block "Signed in" + "<role> · <account 4-4-4>".
function roleFromArn(arn) {
  const assumed = arn.split(":assumed-role/")[1];
  if (assumed) {
    const raw = assumed.split("/")[0];
    // IAM Identity Center: AWSReservedSSO_<PermissionSet>_<hash>.
    const m = /^AWSReservedSSO_(.+)_[0-9a-f]+$/i.exec(raw);
    return m ? m[1] : raw;
  }
  return arn.split(":user/")[1] || arn;
}
$("aws-detail-test").addEventListener("click", async (ev) => {
  const s = awsDetailTarget;
  if (!s) return;
  const profile = s.name.slice(4), out = $("aws-detail-test-result");
  out.dataset.profile = profile;
  out.className = "tsr pending"; out.hidden = false;
  out.textContent = s.tier === "bio" ? "Checking… confirm with Touch ID" : "Checking…";
  const btn = ev.currentTarget;
  btn.disabled = true;
  try {
    const id = await invoke("aws_whoami", { profile });
    out.className = "tsr ok";
    out.replaceChildren(el("span", {}, el("b", { textContent: "Signed in" }), el("br"),
      el("span", { class: "mono", style: "font-size:12.5px", textContent: `${roleFromArn(String(id.Arn || ""))} · ${groupAccount(id.Account)}`, title: String(id.Arn || "") })));
  } catch (err) {
    out.className = "tsr bad";
    out.replaceChildren(el("span", {}, el("b", { textContent: "Couldn’t sign in" }), el("br"), String(err).replace(/^Error:\s*/, "")));
  } finally { btn.disabled = false; btn.textContent = "Test again"; }
});
$("aws-detail-default").addEventListener("click", async (ev) => {
  const s = awsDetailTarget, sw = ev.currentTarget;
  if (!s) return;
  const on = sw.getAttribute("aria-checked") !== "true";
  const value = on ? s.name.slice(4) : "none";
  sw.setAttribute("aria-checked", String(on));
  try { cfg = await call("set_config", { key: "default-profile", value }, sw); toast(on ? `${value} is the default AWS profile` : "No default AWS profile"); }
  catch { sw.setAttribute("aria-checked", String(!on)); }
});
$("aws-detail-copy").append(icon(ICON_COPY));
$("aws-detail-copy").addEventListener("click", async () => {
  toast((await copyText($("aws-detail-cmd").textContent, $("aws-detail"))) ? "Command copied" : "Couldn't copy", false);
});
$("sso-add").addEventListener("click", openPortalDialog);
$("portal-form").addEventListener("submit", submitPortal);
$("portal-cancel").addEventListener("click", () => $("portal-dialog").close());
$("signin-cancel").addEventListener("click", cancelSignIn);
$("signin-done").addEventListener("click", () => setSignIn("closed"));
$("signin-retry").addEventListener("click", () => { if (signIn) startSignIn(signIn.portal); });
$("signin-copy").addEventListener("click", async () => {
  if (signIn && signIn.code) toast((await copyText(signIn.code, $("signin-dialog"))) ? "Code copied" : "Couldn't copy");
});
$("signin-browser").addEventListener("click", () => invoke("sso_open_browser").catch((e) => toast(String(e), true)));
// Closing the sheet never claims to cancel a macOS Touch ID prompt.
$("signin-dialog").addEventListener("cancel", (e) => {
  e.preventDefault();
  if (signIn?.phase === "approved") toast("Sign-in continues. To stop, cancel the macOS Touch ID prompt.");
  cancelSignIn();
  $("signin-dialog").close();
});
// Sign-in state changes outside this window (CLI, expiry): re-read on focus and every minute.
window.addEventListener("focus", () => { if (!$("view-init").hidden) return; loadSsoStatus().then(() => { if (!$("view-secrets").hidden) renderSecrets(); }); });
setInterval(() => { if (document.hidden || !$("view-init").hidden) return; loadSsoStatus().then(() => { if (!$("view-secrets").hidden && !$("rows").contains(document.activeElement)) renderSecrets(); }); }, 60000);
$("audit-secret").addEventListener("input", () => { auditSeq++; clearTimeout(auditTimer); auditTimer = setTimeout(applyAuditFilter, 150); });
for (const r of document.querySelectorAll('input[name="audit-only"]')) r.addEventListener("change", applyAuditFilter);
$("audit-secret").addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  e.preventDefault();
  e.target.value = "";
  applyAuditFilter();
});
$("lease-grant").addEventListener("click", grantLease);
$("leases-end-all").addEventListener("click", async () => {
  const n = secrets.filter((s) => s.lease).length;
  if (!(await confirmDialog("End all temporary access?", `Temporary access to ${n} ${n === 1 ? "item" : "items"} ends now. Each one's access level applies again: Touch ID where it's on, refused where agents are blocked.`, "End all"))) return;
  try {
    const r = await call("lease_revoke_all", {}, $("leases-end-all"));
    toast(`Ended temporary access to ${r.length} ${r.length === 1 ? "item" : "items"}`);
  } catch { /* toast shown */ }
  loadSecrets();
});
$("lease-revoke").addEventListener("click", revokeLease);
$("status-refresh").addEventListener("click", loadStatusPage);
$("more-close").append(icon(ICON_CLOSE));
$("more-close").addEventListener("click", () => { $("more-menu").open = false; $("more-menu").querySelector("summary").focus(); });
$("status-block").addEventListener("click", () => setBlocked(!blockedState()));
$("profile-check").addEventListener("click", () => reviewProfile());
$("profile-add").addEventListener("click", () => toggleProfileAdd());
$("profile-path").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); reviewProfile(); }
  if (e.key === "Escape") { e.preventDefault(); toggleProfileAdd(false); $("profile-add").focus(); }
});
$("doctor-run").addEventListener("click", runDoctor);
$("policy-explain").addEventListener("click", explainPolicy);
$("policy-subject").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); explainPolicy(); } });
$("health").addEventListener("click", () => { if ($("view-init").hidden) show("status"); });
for (const id of ["block-agents-menu", "block-agents-settings"]) {
  $(id).addEventListener("click", () => { $("more-menu").open = false; setBlocked(!blockedState()); });
}
$("lease-require-touch").addEventListener("click", requireTouchInstead);
$("exposure-clear").addEventListener("click", clearExposure);
$("detail-close").addEventListener("click", () => $("detail-dialog").close());
$("detail-dialog").addEventListener("close", () => { detail = null; renderInspector(); });
$("settings-form").addEventListener("submit", saveSettings);
$("settings-form").addEventListener("input", (e) => {
  e.target.removeAttribute("aria-invalid");
  if ($("settings-result").classList.contains("ok") || $("settings-result").classList.contains("muted")) settingsResult("", "");
  renderSettingsNote();
});
// ---------- paper backup (init / rotate / verify) ----------
// The secret key is generated and kept in the Rust side; the page only displays its
// rows once and sends back what was typed. Inputs are cleared as soon as we're done.
const PAPER_ROWS = 3;
let paperFlow = null; // { purpose: "init"|"rotate"|"verify"|"recover", id?, rows? }

function paperInputs() { return [...$("paper-inputs").querySelectorAll("input")]; }

function clearPaper() {
  paperInputs().forEach((i) => { i.value = ""; });
  $("paper-rows").replaceChildren();
  if (paperFlow) paperFlow.rows = null;
}

// Paper key typing: mono uppercase rows with group-shaped placeholders,
// a check mark + code on valid rows, Confirm disabled until every row checks.
const NO_LOOKALIKES = "Only 0 is used for zero: there is no O, 1, B or I.";
const groupShape = (len) => Array.from({ length: Math.ceil(len / 4) }, (_, g) => "X".repeat(Math.min(4, len - g * 4))).join(" ");
let paperRowOk = [];

function syncPaperSubmit() {
  const ready = paperRowOk.length > 0 && paperRowOk.every(Boolean);
  $("paper-submit").disabled = !ready;
  $("paper-submit").title = ready ? "" : `Type all ${paperRowOk.length} rows first`;
}

function paperTypeStep() {
  const lens = paperFlow.rows ? paperFlow.rows.map((r) => r.len) : [20, 20, 18];
  paperRowOk = lens.map(() => false);
  $("paper-inputs").replaceChildren(...lens.map((len, i) => {
    const input = el("input", { id: `paper-in-${i}`, autocomplete: "off", spellcheck: false, autocapitalize: "characters", placeholder: groupShape(len) });
    input.setAttribute("autocorrect", "off");
    const st = el("span", { class: "st hint", id: `paper-st-${i}`, "aria-live": "polite" });
    const msg = el("span", { class: "row-msg", id: `paper-msg-${i}` });
    input.setAttribute("aria-describedby", `${st.id} ${msg.id}`);
    let seq = 0;
    const check = async (final) => {
      const value = input.value.toUpperCase();
      const mine = ++seq;
      if (!value.trim()) { msg.textContent = ""; st.textContent = ""; input.classList.remove("ok"); input.removeAttribute("aria-invalid"); paperRowOk[i] = false; syncPaperSubmit(); return; }
      const r = await invoke("paper_check_row", { index: i, row: value }).catch(() => ({ ok: false, error: "Couldn't check this row." }));
      if (mine !== seq) return; // a newer keystroke won
      paperRowOk[i] = !!r.ok;
      input.classList.toggle("ok", !!r.ok);
      if (r.ok) {
        input.removeAttribute("aria-invalid"); msg.textContent = "";
        st.className = "st ok"; st.textContent = r.check ? `✓ check ${r.check}` : "✓";
      } else {
        st.className = "st hint"; st.textContent = final ? "" : "typing…";
        // Only complain once the row is complete or the user leaves it.
        if (final || value.replace(/[\s-]/g, "").length >= len) { msg.textContent = r.error; input.setAttribute("aria-invalid", "true"); }
        else { msg.textContent = ""; input.removeAttribute("aria-invalid"); }
      }
      syncPaperSubmit();
    };
    input.addEventListener("input", () => check(false));
    input.addEventListener("change", () => check(true));
    return el("div", { class: "prow" }, el("label", { class: "hint", for: input.id, textContent: `Row ${i + 1}` }), input, st, msg);
  }));
  $("paper-show").hidden = true;
  $("paper-type").hidden = false;
  const typeOnly = paperFlow.purpose === "verify" || paperFlow.purpose === "recover";
  $("paper-back").hidden = typeOnly;
  $("paper-error").textContent = "";
  $("paper-type-intro").textContent = ({
    verify: "Type each row from your paper sheet. Spaces and case don’t matter; the check code is optional. Nothing is saved.",
    recover: "Type each row from your paper sheet. Karambit first checks it opens your backup copies, then asks for Touch ID, creates new keys for this Mac and restores every secret that has a backup.",
  }[paperFlow.purpose] || "Type each row from your sheet to prove it’s written correctly. Spaces and case don’t matter.") + " " + NO_LOOKALIKES;
  $("paper-submit").textContent = { init: "Confirm and set up", rotate: "Confirm and re-encrypt", verify: "Check", recover: "Restore" }[paperFlow.purpose];
  if (paperFlow.purpose !== "verify" && paperFlow.purpose !== "recover") $("paper-title").textContent = "Type your paper key";
  syncPaperSubmit();
  paperInputs()[0].focus();
}

function paperShowStep() {
  $("paper-rows").replaceChildren(...paperFlow.rows.map((r) => el("li", {}, el("span", { textContent: r.text }), el("span", { class: "check", textContent: `check ${r.check}` }))));
  $("paper-show").hidden = false;
  $("paper-type").hidden = true;
  $("paper-written").focus();
}

async function openPaper(purpose) {
  paperFlow = { purpose };
  $("paper-title").textContent = { init: "Make a paper backup", rotate: "New paper key", verify: "Check your paper key", recover: "Restore from paper backup" }[purpose];
  if (purpose === "verify" || purpose === "recover") {
    paperFlow.rows = null;
    openDialog($("paper-dialog"));
    paperTypeStep();
    return;
  }
  if (purpose === "rotate" && !(await confirmDialog("Make a new paper key?", [
    "Every secret's backup copy is re-encrypted to a new key, with Touch ID.",
    "After this, your old sheet no longer works: destroy it.",
  ], "Continue", false))) return;
  try {
    const r = await call("paper_new", {});
    paperFlow.id = r.id; paperFlow.rows = r.rows;
  } catch { paperFlow = null; return; }
  openDialog($("paper-dialog"));
  paperShowStep();
}

async function closePaper() {
  clearPaper();
  if (paperFlow && (paperFlow.purpose === "init" || paperFlow.purpose === "rotate")) await invoke("paper_cancel", {}).catch(() => {});
  paperFlow = null;
  if ($("paper-dialog").open) $("paper-dialog").close();
}

async function submitPaper(ev) {
  ev.preventDefault();
  const rows = paperInputs().map((i) => i.value.toUpperCase());
  if (rows.some((r) => !r.trim()) || !paperRowOk.every(Boolean)) { $("paper-error").textContent = "Every row has to check first."; return; }
  $("paper-error").textContent = "";
  const flow = paperFlow;
  try {
    if (flow.purpose === "recover") {
      const r = await call("recover", { rows }, $("paper-submit"));
      await closePaper();
      const miss = r.missing || [];
      toast(`Restored ${plural(r.restored, "secret")}${miss.length ? `. ${miss.length} had no backup copy and can't be restored` : ""}`, miss.length > 0);
      if (miss.length) await confirmDialog("Some secrets couldn't be restored", ["These had no backup copy:", miss.join(", "), "Add them again with new values."], "OK", false, "Close");
      boot();
      return;
    }
    if (flow.purpose === "verify") {
      const r = await call("backup_verify", { rows }, $("paper-submit"));
      if (r.matches) { await closePaper(); toast("Paper key matches your backup"); }
      else $("paper-error").textContent = "That's a valid key, but not this vault's backup. Wrong sheet?";
      return;
    }
    const r = await call("paper_confirm", { id: flow.id, rows, purpose: flow.purpose }, $("paper-submit"));
    paperFlow = null; clearPaper(); $("paper-dialog").close();
    if (flow.purpose === "init") { toast("Karambit is set up with a paper backup"); boot(); }
    else { toast(`Backup re-encrypted for ${plural(r.rotated, "secret")}. Destroy your old sheet.`); loadSecrets(); loadSettings(); }
  } catch (err) {
    // Wrong key / typo: say it inline; keep what was typed so it can be fixed.
    $("paper-error").textContent = String(err).replace(/^Error:\s*/, "");
  }
}

$("init-recover").addEventListener("click", async () => {
  if (!(await confirmDialog("Restore from paper backup", [
    "Copy the secrets folder from your old Mac's ~/.local/share/karambit to the same place on this Mac first.",
    "Then type your paper key: Karambit creates new keys for this Mac and restores every secret that has a backup copy.",
  ], "Continue", false))) return;
  openPaper("recover");
});
$("backup-recover-open").addEventListener("click", async () => {
  if (!(await confirmDialog("Restore from paper backup?", [
    "Use this only if your secrets no longer open. Karambit checks your paper key first; nothing changes if it's wrong.",
    "Then it creates new keys for this Mac, retires the old ones and restores every secret from its backup copy. Secrets without a backup copy can't be restored.",
  ], "Continue", true))) return;
  openPaper("recover");
});
$("backup-verify-open").addEventListener("click", () => {
  if (!cfg?.backup_recipient) { toast("No backup is set up yet", true); return; }
  openPaper("verify");
});
$("backup-rotate-open").addEventListener("click", () => openPaper("rotate"));
// Leave the key off-screen while typing (rows stay in memory until the flow ends, for "show again").
$("paper-written").addEventListener("click", () => { $("paper-rows").replaceChildren(); paperTypeStep(); });
$("paper-back").addEventListener("click", () => { if (paperFlow?.rows) paperShowStep(); });
$("paper-cancel").addEventListener("click", closePaper);
$("paper-type-cancel").addEventListener("click", closePaper);
$("paper-type").addEventListener("submit", submitPaper);
$("paper-dialog").addEventListener("cancel", (e) => { e.preventDefault(); closePaper(); });

// First run: the primary button follows the backup choice; "no backup" is a quiet
// link whose confirm carries the "No backup = no recovery" warning.
const initChoice = () => document.querySelector('input[name="init-backup"]:checked')?.value || "paper";
function syncInitButton() {
  const age = initChoice() === "age";
  $("init-recip-box").hidden = !age;
  $("init-btn").textContent = age ? "Continue with this age key" : "Continue: make a paper backup";
  $("init-btn").disabled = age && !/^age1[0-9a-z]{20,}$/.test($("init-recip").value.trim());
  $("init-btn").title = $("init-btn").disabled ? "Paste an age1… public key first" : "";
}
document.querySelectorAll('input[name="init-backup"]').forEach((r) => r.addEventListener("change", () => { syncInitButton(); if (initChoice() === "age") $("init-recip").focus(); }));
$("init-recip").addEventListener("input", syncInitButton);
syncInitButton();

async function initWith(recipient) {
  try {
    await call("init", { backupRecipient: recipient }, $("init-btn"));
    toast("Karambit is set up");
    boot();
  } catch { /* toast shown */ }
}
$("init-btn").addEventListener("click", () => {
  if (initChoice() === "paper") { openPaper("init"); return; }
  initWith($("init-recip").value.trim());
});
$("init-skip").addEventListener("click", async () => {
  if (!(await confirmDialog("Set up without a backup?", [
    "No backup = no recovery.",
    "If this Mac is lost or your enrolled fingerprints change, every secret becomes unrecoverable. You can add a paper backup later in Settings › Backup.",
  ], "Set up without a backup", true))) return;
  initWith("");
});
// Cmd+1–5 switch tabs, Cmd+F focuses the filter (secret filter on Activity), Cmd+N opens Add.
const tabForKey = (key) => Object.keys(TAB_KEYS_BY_VIEW).find((v) => String(TAB_KEYS_BY_VIEW[v]) === key);
document.addEventListener("keydown", (e) => {
  if (!e.metaKey || document.querySelector("dialog[open]")) return;
  if (tabForKey(e.key)) {
    e.preventDefault();
    if ($("view-init").hidden) show(tabForKey(e.key));
    return;
  }
  if (e.key === "f" && !$("view-audit").hidden) { e.preventDefault(); $("audit-secret").focus(); return; }
  if (e.key === "f" && ["aws", "sources"].includes(currentView)) { e.preventDefault(); $(`${currentView}-filter`).focus(); return; }
  if ($("view-secrets").hidden) return;
  if (e.key === "f") { e.preventDefault(); $("filter").focus(); }
  if (e.key === "n") { e.preventDefault(); openAdd(); }
});

$("folder-title").tabIndex = -1;
$("folder-open").addEventListener("click", () => { $("folder-name").value = ""; openDialog($("folder-dialog")); $("folder-name").focus(); });
$("folder-cancel").addEventListener("click", () => $("folder-dialog").close());
$("folder-form").addEventListener("submit", (e) => { e.preventDefault(); const path = [currentFolder, $("folder-name").value.trim()].filter(Boolean).join("/"); $("folder-dialog").close(); openAdd(path, true); });
$("source-open").addEventListener("click", () => openSource());
$("source-open-more").addEventListener("click", () => openSource());
// ⋯ More: close after choosing, on Escape, and on outside click.
$("more-menu").addEventListener("click", (e) => { if (e.target.closest(".menu-item")) $("more-menu").open = false; });
$("more-menu").addEventListener("keydown", (e) => { if (e.key === "Escape" && $("more-menu").open) { $("more-menu").open = false; $("more-menu").querySelector("summary").focus(); e.stopPropagation(); } });
document.addEventListener("click", (e) => { if ($("more-menu").open && !$("more-menu").contains(e.target)) $("more-menu").open = false; });
$("source-form").addEventListener("submit", submitSource);
$("source-cancel").addEventListener("click", () => $("source-dialog").close());
$("source-dialog").addEventListener("close", () => { $("source-credential").value = ""; });
$("empty-add").addEventListener("click", () => openAdd());
$("empty-aws").addEventListener("click", () => openAwsDialog());
$("palette-open").addEventListener("click", openPalette);
$("palette-query").addEventListener("input", () => { paletteIndex = 0; renderPalette(); });
$("palette-dialog").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault(); paletteIndex = Math.max(0, Math.min(paletteItems.length - 1, paletteIndex + (e.key === "ArrowDown" ? 1 : -1)));
    markPalette(); $("palette-results").children[paletteIndex]?.scrollIntoView({ block: "nearest" });
  } else if (e.key === "Enter") { e.preventDefault(); runPalette(paletteIndex); }
  else if ((e.metaKey || e.ctrlKey) && e.key === "i") { e.preventDefault(); runPalette(paletteIndex, true); }
});
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "k" && $("view-init").hidden && !document.querySelector("dialog[open]")) { e.preventDefault(); openPalette(); }
  if (document.querySelector("dialog[open]")) return;
  if (e.key === "Escape") {
    const menu = document.querySelector(".folder-menu[open]");
    if (menu) { menu.open = false; menu.querySelector("summary").focus(); return; }
  }
  const editing = e.target.closest("input, textarea, select, [contenteditable]");
  if (((currentView === "secrets" && currentFolder) || (currentView === "sources" && currentSource)) && !editing && ((e.metaKey && e.key === "[") || e.key === "Backspace")) { e.preventDefault(); goUp(); }
  if (selectedSecret && e.key === "Escape") {
    e.preventDefault();
    const name = selectedSecret;
    selectedSecret = null; renderLists(); renderInspector();
    [...document.querySelectorAll(`#view-${currentView} .leaf.link`)].find((n) => n.getAttribute("aria-label") === `Details for ${name}`)?.focus();
  }
});

function dismissDialog(dlg) {
  if (dlg.dispatchEvent(new Event("cancel", { cancelable: true }))) dlg.close();
}
function openDialog(dlg) {
  const parent = [...document.querySelectorAll("dialog[open]")].filter((n) => n !== dlg).pop();
  // A dialog with its own step-back (data-own-back) shows only that one.
  if (dlg.querySelector("[data-own-back]")) { dlg.querySelector(":scope > .dialog-back")?.remove(); dlg.showModal(); return; }
  let back = dlg.querySelector(":scope > .dialog-back");
  if (!back) {
    back = el("button", { type: "button", class: "btn sm step-back dialog-back", textContent: "← Back", onclick: () => dismissDialog(dlg) });
    dlg.insertBefore(back, dlg.querySelector(".dialog-close")?.nextSibling || dlg.firstChild);
  }
  back.hidden = !parent;
  dlg.showModal();
}

// Visible close controls reuse each dialog's cancel path (not its submit action).
for (const dlg of document.querySelectorAll("dialog")) {
  const close = el("button", { type: "button", class: "ibtn dialog-close", "aria-label": "Close " + (dlg.querySelector("h2")?.textContent || "dialog"), title: "Close (Esc)", onclick: () => dismissDialog(dlg) }, icon(ICON_CLOSE));
  dlg.prepend(close);
}
$("add-back").onclick = () => { $("add-dialog").close(); openDialog($("folder-dialog")); };
$("aws-portal-back").onclick = () => {
  const option = [...$("aws-portal").options].find((o) => o.value && o.value !== NEW_PORTAL);
  $("aws-portal").value = option?.value || ""; syncPortal(); $("aws-portal").focus();
};

async function boot() {
  try {
    const s = await loadStatus();
    if (!s.initialized) {
      show("init");
      return;
    }
    cfg = await call("get_config");
    sourceKinds = await call("source_kinds");
    applySourceKinds();
    renderBlock(); // chip + Status badge on every page, from the first paint
    show("secrets");
  } catch { /* toast shown */ }
}

boot();

$("aws-find").onclick = openPalette;
$("portals-close").onclick = () => { $("aws-portals").open = false; };
$("aws-portals").addEventListener("keydown", (e) => { if (e.key === "Escape") { $("aws-portals").open = false; e.stopPropagation(); } });
