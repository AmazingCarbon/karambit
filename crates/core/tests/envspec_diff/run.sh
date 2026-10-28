#!/bin/sh
# Differential test: Karambit's @env-spec port vs varlock's real parser.
# Needs node + network once (npm). Synthetic inputs only. Usage: sh run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cp "$here"/*.js "$here"/*.json "$work"/
(cd "$work" && npm init -y >/dev/null && npm install -s --no-audit --no-fund --ignore-scripts --save-exact @env-spec/parser@0.6.2 dotenv@16.4.7 >/dev/null)
(cd "$work" && node varlock.js > varlock.out && node vexpand.js > vexpand.out)
(cd "$root" && cargo run -q --offline -p karambit-core --example envspec_dump < "$work/corpus.json" > "$work/karambit.out")
(cd "$root" && cargo run -q --offline -p karambit-core --example envspec_env < "$work/files.json" > "$work/kexpand.out")
(cd "$work" && node compare.js && node -e "
const fs=require('fs'); const s=(o)=>JSON.stringify(Object.fromEntries(Object.entries(o).sort()));
const a=fs.readFileSync('vexpand.out','utf8').trim().split('\n').map(JSON.parse), b=fs.readFileSync('kexpand.out','utf8').trim().split('\n').map(JSON.parse);
const bad=a.filter((x,i)=>s(x.env)!==s(b[i].env)); console.log('same env:', a.length-bad.length, 'of', a.length); process.exit(bad.length?1:0);")
echo "node+dotenv end to end: KARAMBIT_TEST_NODE_APP=<dir with node_modules/dotenv> KARAMBIT_TEST_CLI_CASE=schema-node cargo test -p karambit-core --lib production_cli_bound_run_contract"
