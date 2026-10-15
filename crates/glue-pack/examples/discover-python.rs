#[cfg(feature = "python")]
fn main() -> Result<(), String> {
    use glue_pack::python::discovery::{DiscoveryOptions, discover};
    let mut args = std::env::args_os().skip(1);
    let environment = args
        .next()
        .ok_or("usage: discover-python ENV [RUNTIME]")?
        .into();
    let runtime = args.next().map(Into::into);
    let result = discover(&DiscoveryOptions {
        environment,
        runtime,
        python_version: None,
        target: None,
        inspect_only: false,
    })?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}

#[cfg(not(feature = "python"))]
fn main() {
    eprintln!("requires --features python");
    std::process::exit(2);
}
