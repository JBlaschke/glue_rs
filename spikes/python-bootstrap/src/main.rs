//! Experimental fixture CLI over the shared controlled Python executor.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    match glue_runtime_python::experimental::dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("glue-python-bootstrap-probe: {error}");
            ExitCode::from(if error.is_unsupported() { 2 } else { 1 })
        }
    }
}
