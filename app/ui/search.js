// Karambit GUI search: forgiving, ranked matching for names like
// "aws/demoapp-staging-administratoraccess".
//
// - Query words match in any order; every word must match somewhere.
// - Separators (/ - _ . space) are ignored: "demoapp staging", "demo app",
//   "demoapp-stag" and "demoappstaging" all find the name above.
// - Initials work across words: "ppoa" finds platform-production-operations-admin.
// - Small typos are forgiven in longer words: one edit for 5+ letters, two for 9+.
// - Results are ranked: exact word > word start > anywhere > initials > typo.
//
// Pure functions, no DOM: app.js renders highlights from `ranges`. Loaded as a plain
// script (window.KarambitSearch) and by Node tests (module.exports).
"use strict";
(function (root) {
  const SEP = /[^a-z0-9]+/;

  // Lowercase + strip accents, one source char at a time so every normalized char
  // maps back to its original index (for highlighting).
  function normalize(text) {
    let out = "";
    const map = [];
    for (let i = 0; i < text.length; i++) {
      const n = text[i].normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
      for (const c of n) { out += c; map.push(i); }
    }
    return { text: out, map };
  }

  function words(text) { return normalize(text).text.split(SEP).filter(Boolean); }

  // Index one field: its words (with original start/end) and the separator-free form.
  function indexField(text) {
    const n = normalize(text);
    const tokens = [];
    let compact = "";
    const compactMap = [];
    const re = /[a-z0-9]+/g;
    let m;
    while ((m = re.exec(n.text))) {
      const start = m.index, end = m.index + m[0].length;
      tokens.push({ word: m[0], compactStart: compact.length, from: n.map[start], to: n.map[end - 1] + 1 });
      for (let i = start; i < end; i++) { compact += n.text[i]; compactMap.push(n.map[i]); }
    }
    return { tokens, compact, compactMap, initials: tokens.map((t) => t.word[0]).join("") };
  }

  // Optimal string alignment distance (adjacent swaps count as one edit), capped.
  function editDistance(a, b, cap) {
    if (Math.abs(a.length - b.length) > cap) return cap + 1;
    let prev2 = null, prev = Array.from({ length: b.length + 1 }, (_, j) => j);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      let rowMin = i;
      for (let j = 1; j <= b.length; j++) {
        let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        if (prev2 && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2] + 1);
        cur.push(v);
        rowMin = Math.min(rowMin, v);
      }
      if (rowMin > cap) return cap + 1;
      prev2 = prev; prev = cur;
    }
    return prev[b.length];
  }

  const typoBudget = (w) => (w.length >= 9 ? 2 : w.length >= 5 ? 1 : 0);

  // Best way one query word matches one indexed field: { score, ranges } or null.
  function matchWord(w, f) {
    const span = (from, len) => [[f.compactMap[from], f.compactMap[from + len - 1] + 1]];
    let best = null;
    const take = (score, ranges) => { if (!best || score > best.score) best = { score, ranges }; };
    for (const t of f.tokens) {
      if (t.word === w) take(100, [[t.from, t.to]]);
      else if (t.word.startsWith(w)) take(80, span(t.compactStart, w.length));
    }
    if (best) return best;
    // Anywhere, including across separators ("demoapp" in "demo-app").
    const at = f.compact.indexOf(w);
    if (at >= 0) {
      const wordStart = f.tokens.some((t) => t.compactStart === at);
      return { score: wordStart ? 70 : 50, ranges: span(at, w.length) };
    }
    if (w.length >= 2) {
      const i = f.initials.indexOf(w);
      if (i >= 0) return { score: 40, ranges: f.tokens.slice(i, i + w.length).map((t) => [t.from, t.from + 1]) };
    }
    const cap = typoBudget(w);
    if (cap) {
      for (const t of f.tokens) {
        // Compare with the whole word and with its same-length start ("stagng" ~ "staging").
        const candidates = [t.word, t.word.slice(0, w.length), t.word.slice(0, w.length + 1)];
        const d = Math.min(...candidates.map((c) => editDistance(w, c, cap)));
        if (d <= cap) take(20 - 5 * d, [[t.from, t.to]]);
      }
    }
    return best;
  }

  // Build a reusable matcher for one query string.
  // fields: [{ text, weight = 1 }]; the first field is the one highlights refer to.
  function compile(query) {
    const qWords = words(query || "");
    const qCompact = qWords.join("");
    function score(fields) {
      if (!qWords.length) return { score: 0, ranges: [] };
      const indexed = fields.map((x) => ({ f: indexField(x.text || ""), weight: x.weight ?? 1 }));
      let total = 0;
      const ranges = [];
      for (const w of qWords) {
        let best = null, bestField = -1;
        indexed.forEach(({ f, weight }, i) => {
          const m = matchWord(w, f);
          if (m && (!best || m.score * weight > best.score)) { best = { score: m.score * weight, ranges: m.ranges }; bestField = i; }
        });
        if (!best) return null;
        total += best.score;
        if (bestField === 0) ranges.push(...best.ranges);
      }
      // Whole query as one run in the primary field ranks above scattered words.
      if (qWords.length > 1 && indexed[0].f.compact.includes(qCompact)) total += 30;
      return { score: total, ranges: merge(ranges) };
    }
    return { active: qWords.length > 0, score };
  }

  function merge(ranges) {
    const sorted = ranges.slice().sort((a, b) => a[0] - b[0]);
    const out = [];
    for (const r of sorted) {
      const last = out[out.length - 1];
      if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
      else out.push([r[0], r[1]]);
    }
    return out;
  }

  // Shift ranges from a full name onto a displayed suffix (e.g. "aws/x" shown as "x").
  function shift(ranges, offset, length) {
    return ranges.map(([a, b]) => [Math.max(0, a - offset), Math.min(length, b - offset)]).filter(([a, b]) => b > a);
  }

  const api = { compile, shift, normalize, editDistance };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.KarambitSearch = api;
})(typeof window !== "undefined" ? window : globalThis);
