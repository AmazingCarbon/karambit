const fs = require('fs'), C = require('./corpus.json');
const sort = (v) => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sort(v[k])])) : v;
// Varlock reports a bare `@x` as the static value true; Karambit as a bare flag. Same meaning.
const norm = (o) => JSON.stringify(sort(o), (k, v) => (k === 'value' && v === true ? 'true' : v));
// Varlock turns `${X}` / `$X` into concat(ref(X)) at parse time; Karambit keeps text and
// expands at run time. Expand both to the same flat string to compare meaning.
const flat = (v) => v && typeof v === 'object' && v.call === 'concat' ? v.args.map(flat).join('') : v && typeof v === 'object' && v.call === 'ref' ? '${' + v.args[0] + '}' : v;
const a = fs.readFileSync('varlock.out', 'utf8').trim().split('\n').map(JSON.parse);
const b = fs.readFileSync('karambit.out', 'utf8').trim().split('\n').map(JSON.parse);
const expandText = (s) => typeof s === 'string' ? s.replace(/(?<!\\)\$([A-Za-z_][A-Za-z0-9_]*)/g, '${$1}') : s;
let same = 0; const diff = [];
for (let i = 0; i < a.length; i++) {
  const x = a[i], y = b[i];
  if (x.ok && y.ok) for (const [it, jt] of x.items.map((it, j) => [it, y.items[j]])) { if (it && jt) { it.value = flat(it.value); jt.value = expandText(jt.value); } }
  if (norm(x) === norm(y)) same++; else diff.push({ i, input: C[i], varlock: x, karambit: y });
}
console.log(`same meaning: ${same} of ${a.length}`);
process.on("exit", () => { if (diff.length) process.exitCode = 1; });
for (const d of diff) console.log(`\n#${d.i} ${JSON.stringify(d.input)}\n  varlock : ${norm(d.varlock)}\n  karambit: ${norm(d.karambit)}`);
