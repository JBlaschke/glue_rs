fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-undefined,dynamic_lookup");
        println!(
            "cargo:rustc-link-arg-cdylib=-Wl,-install_name,@rpath/glue-node-archive-bridge.node"
        );
    }
}
