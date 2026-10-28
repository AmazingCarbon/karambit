//! Differential-test helper: run Karambit's real schema evaluation (`compile` +
//! `plain`) over each file in a JSON array on stdin, with a fixed simulated shell
//! environment. Prints `{i, env}` per case. Not shipped.
use karambit_core::envspec::{compile, parse};

fn main() {
    let files: Vec<String> = serde_json::from_reader(std::io::stdin()).expect("JSON array of strings");
    let ambient = |k: &str| (k == "SHELLVAR").then(|| "from-shell".to_owned());
    for (i, text) in files.iter().enumerate() {
        let env = compile(&parse(text).expect("parse")).expect("compile").plain(&ambient).expect("plain");
        let env: serde_json::Map<String, serde_json::Value> = env.into_iter().map(|(k, v)| (k, v.into())).collect();
        println!("{}", serde_json::json!({"i": i, "env": env}));
    }
}
