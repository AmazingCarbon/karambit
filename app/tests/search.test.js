// Run: node --test app/tests/
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { compile, shift, editDistance } = require("../ui/search.js");

// Example names in the shape AWS SSO imports produce (names only, no values).
const NAMES = [
  "aws/demoapp-staging-administratoraccess",
  "aws/demoapp-production-administratoraccess",
  "aws/platform-production-operations-admin",
  "aws/platform-shared-staging-administratoraccess",
  "aws/website-staging-administratoraccess",
  "aws/globex-staging-administratoraccess",
  "aws/qa-staging",
  "ops/gitops-staging-token",
  "deploy/admin-token",
];

function find(q, names = NAMES) {
  const m = compile(q);
  return names.map((name) => ({ name, r: m.score([{ text: name }]) }))
    .filter((x) => x.r).sort((a, b) => b.r.score - a.r.score).map((x) => x.name);
}

test("'demoapp staging' finds the profile, first", () => {
  assert.equal(find("demoapp staging")[0], "aws/demoapp-staging-administratoraccess");
  assert.ok(!find("demoapp staging").includes("aws/demoapp-production-administratoraccess"));
});

test("word order, separators and spacing do not matter", () => {
  for (const q of ["staging demoapp", "demo app staging", "demoapp-staging", "demoappstaging",
    "DemoApp_Staging", "aws/demoapp stag", "  demoapp   staging  "]) {
    assert.equal(find(q)[0], "aws/demoapp-staging-administratoraccess", q);
  }
});

test("partial words", () => {
  assert.equal(find("app stag")[0], "aws/demoapp-staging-administratoraccess");
  assert.equal(find("prod admin")[0], "aws/platform-production-operations-admin");
});

test("initials", () => {
  assert.equal(find("ppoa")[0], "aws/platform-production-operations-admin");
});

test("typos in longer words", () => {
  assert.equal(find("demapp staging")[0], "aws/demoapp-staging-administratoraccess");
  assert.equal(find("demoapp stagign")[0], "aws/demoapp-staging-administratoraccess");
  assert.equal(find("delpoy")[0], "deploy/admin-token");
});

test("short words are exact: no typo noise", () => {
  assert.deepEqual(find("qa"), ["aws/qa-staging"].concat(find("qa").slice(1)));
  assert.deepEqual(find("zz"), []);
  assert.deepEqual(find("xyzzyplugh"), []);
});

test("every word must match", () => {
  assert.deepEqual(find("demoapp deploy"), []);
});

test("empty query is inactive", () => {
  assert.equal(compile("  ").active, false);
  assert.equal(compile("-/").active, false);
});

test("secondary fields match but are not highlighted", () => {
  const m = compile("touch");
  const r = m.score([{ text: "github/deploy-token" }, { text: "Agents · Touch ID", weight: 0.5 }]);
  assert.ok(r && r.ranges.length === 0);
});

test("highlight ranges point at the original text", () => {
  const name = "aws/demoapp-staging-administratoraccess";
  const r = compile("app stag").score([{ text: name }]);
  assert.deepEqual(r.ranges.map(([a, b]) => name.slice(a, b)), ["app", "stag"]);
  assert.deepEqual(shift(r.ranges, 4, name.length - 4).map(([a, b]) => name.slice(4).slice(a, b)), ["app", "stag"]);
});

test("accents fold", () => {
  assert.equal(find("cafe", ["notes/café-wifi"])[0], "notes/café-wifi");
});

test("edit distance counts a swap as one edit", () => {
  assert.equal(editDistance("stagign", "staging", 2), 1);
  assert.equal(editDistance("abc", "abc", 1), 0);
});
