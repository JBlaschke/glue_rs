//! Retain and export only the reviewed API of the experimental native profile.
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=../glue-runtime-lua/native-exports.txt");
    if env::var_os("CARGO_FEATURE_LINUX_NATIVE").is_none() {
        return;
    }
    let target = env::var("TARGET").expect("Cargo target missing");
    if target != "aarch64-unknown-linux-gnu" {
        return;
    }
    for symbol in include_str!("../glue-runtime-lua/native-exports.txt").lines() {
        assert!(
            symbol
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        println!("cargo:rustc-link-arg-bin=glue=-Wl,--export-dynamic-symbol={symbol}");
        println!("cargo:rustc-link-arg-bin=glue=-Wl,-u,{symbol}");
    }
}
