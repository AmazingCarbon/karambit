// Evaluate varlock's parsed + expanded tree to final strings (static text, ref,
// concat, fallback). AMBIENT simulates the shell; like varlock and Karambit, an
// already-set variable wins over the file.
const p = require('@env-spec/parser');
const AMBIENT = { SHELLVAR: 'from-shell' };
for (const [i, text] of require('./files.json').entries()) {
  const f = p.parseEnvSpecDotEnvFile(text);
  const items = Object.fromEntries(f.configItems.map((it) => [it.key, it]));
  const cache = {};
  const unesc = (v) => v.data.quote === "'" ? String(v.value) : String(v.value).replaceAll('\\$', '$').replace(/\\n/g, (m) => (v.data.quote === '"' || v.data.quote === '`') ? '\n' : m);
  const evalNode = (n) => {
    if (!n) return undefined;
    const c = n.constructor.name;
    if (c === 'ParsedEnvSpecStaticValue') return n.value === undefined ? undefined : unesc(n);
    if (c === 'ParsedEnvSpecFunctionCall') {
      const args = n.data.args.values;
      if (n.name === 'ref') return get(String(args[0].value));
      if (n.name === 'concat') return args.map((a) => evalNode(a) ?? '').join('');
      if (n.name === 'fallback') { const v = evalNode(args[0]); return v === undefined || v === '' ? evalNode(args[1]) : v; }
    }
    throw new Error('unsupported ' + c + ' ' + n.name);
  };
  const get = (k) => {
    if (k in AMBIENT) return AMBIENT[k];
    if (!(k in items)) return undefined;
    if (!(k in cache)) cache[k] = evalNode(items[k].value);
    return cache[k];
  };
  const env = {};
  for (const k of Object.keys(items)) if (!(k in AMBIENT)) { const v = get(k); if (v !== undefined) env[k] = v; }
  console.log(JSON.stringify({ i, env }));
}
