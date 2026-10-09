use std::{
    fs::File,
    io::{self, Read, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("glue-pbs-inspect: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) {
        return Err("usage: glue-pbs-inspect PINS.json FULL.tar.zst [INSTALL_ONLY.tar.gz]".into());
    }
    let mut bytes = Vec::new();
    File::open(&arguments[0])
        .map_err(|error| format!("open PBS pins: {error}"))?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let pins = glue_pbs::pins::Pins::from_json(&bytes)?;
    let mut full =
        File::open(&arguments[1]).map_err(|error| format!("open PBS full input: {error}"))?;
    let mut install = arguments
        .get(2)
        .map(File::open)
        .transpose()
        .map_err(|error| format!("open PBS install-only input: {error}"))?;
    let report = glue_pbs::inspect(&pins, &mut full, install.as_mut())?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer_pretty(&mut output, &report).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}
