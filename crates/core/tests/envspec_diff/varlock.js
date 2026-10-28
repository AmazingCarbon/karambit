// Differential test: varlock's real @env-spec parser (npm @env-spec/parser 0.6.2)
// vs Karambit's Rust port. Prints one JSON line per case: a normalized view of keys,
// values, function calls and decorators. Synthetic inputs only.
const p = require('@env-spec/parser');
const cases = require('./corpus.json');

const val = (v) => {
  if (!v) return null;
  const c = v.constructor.name;
  if (c === 'ParsedEnvSpecFunctionCall') {
    return { call: v.name, args: v.data.args.values.map((a) => a.constructor.name === 'ParsedEnvSpecKeyValuePair'
      ? { k: a.key, v: val(a.value) } : val(a)) };
  }
  if (c === 'ParsedEnvSpecStaticValue') {
    // Raw text after quote removal, before number/bool coercion (Karambit keeps text).
    if (v.data.quote) return String(v.value);
    const raw = String(v.data.rawValue).trim();
    return raw === '' ? null : raw;
  }
  return { unsupported: c };
};
const dec = (d) => ({ name: d.name, value: d.isBareFnCall ? { args: d.bareFnArgs?.data?.values?.map(val) ?? [] } : (d.value ? val(d.value) : true) });

for (const [i, text] of cases.entries()) {
  let out;
  try {
    const f = p.parseEnvSpecDotEnvFile(text);
    out = {
      ok: true,
      header: f.decoratorsArray.map(dec),
      items: f.configItems.map((it) => ({ key: it.key, value: val(it.value), decorators: it.decoratorsArray.map(dec) })),
    };
  } catch (e) { out = { ok: false }; }
  console.log(JSON.stringify({ i, ...out }));
}
