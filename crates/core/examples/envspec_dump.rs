//! Differential-test helper: parse each JSON string from stdin (an array) with
//! Karambit's @env-spec port and print one normalized JSON line per case, in the same
//! shape as the varlock-side script. Not shipped; `cargo run --example envspec_dump`.
use karambit_core::envspec::{Arg, Decorator, Value, parse};
use serde_json::{Value as J, json};

fn val(v: &Option<Value>) -> J {
    match v {
        None => J::Null,
        Some(Value::Static { text, quote, .. }) => if quote.is_none() && text.trim().is_empty() { J::Null } else { J::String(text.clone()) },
        Some(Value::Call { name, args, .. }) => json!({"call": name, "args": args.iter().map(arg).collect::<Vec<_>>()}),
    }
}
fn arg(a: &Arg) -> J {
    match a {
        Arg::Pos(v) => val(&Some(v.clone())),
        Arg::Kw(k, v) => json!({"k": k, "v": val(&Some(v.clone()))}),
    }
}
fn dec(d: &Decorator) -> J {
    let value = match (&d.args, &d.value) {
        (Some(a), _) => json!({"args": a.iter().map(arg).collect::<Vec<_>>()}),
        (None, Some(_)) => val(&d.value),
        (None, None) => J::Bool(true),
    };
    json!({"name": d.name, "value": value})
}

fn main() {
    let cases: Vec<String> = serde_json::from_reader(std::io::stdin()).expect("JSON array of strings");
    for (i, text) in cases.iter().enumerate() {
        let out = match parse(text) {
            Ok(f) => json!({"i": i, "ok": true, "header": f.header.iter().map(dec).collect::<Vec<_>>(),
                "items": f.items.iter().map(|it| json!({"key": it.key, "value": val(&it.value), "decorators": it.decorators.iter().map(dec).collect::<Vec<_>>()})).collect::<Vec<_>>()}),
            Err(_) => json!({"i": i, "ok": false}),
        };
        println!("{out}");
    }
}
