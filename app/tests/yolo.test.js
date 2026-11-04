// Source-named tests for YOLO metadata selection. No mock backend ships in the app.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const source = fs.readFileSync(require.resolve("../ui/app.js"), "utf8");
function ui(yolos) {
  const context = vm.createContext({ yolos, Date, el: (tag, attrs) => ({ tag, ...attrs }), fullTime: String });
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
