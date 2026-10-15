//! Run the portable ELF admission check on arbitrary images and report the
//! first rejection reason. This is a survey tool for the native capability
//! contract (decision 0032); it loads nothing and changes no policy.
//!
//! Usage:
//!   elf-survey [--soname NAME] [--allow-file PATH] [--data-import-file PATH] IMAGE
//!
//! `--soname` is the SONAME the inspector is told to expect (default: the file
//! name). `--allow-file` lists undefined symbol names to admit, one per line;
//! `--data-import-file` lists the subset that may bind as data imports.
//! Output is one line: `ok`, `invalid: ...` or `unsupported: ...`.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use glue_native::elf::{ElfError, inspect_with_data_imports};

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("elf-survey: {message}");
            ExitCode::FAILURE
        }
    }
}

fn names(path: &Path) -> Result<BTreeSet<String>, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

fn run() -> Result<String, String> {
    let mut arguments = std::env::args_os().skip(1);
    let mut soname: Option<String> = None;
    let mut allow_file: Option<PathBuf> = None;
    let mut data_file: Option<PathBuf> = None;
    let mut image: Option<PathBuf> = None;
    while let Some(argument) = arguments.next() {
        let mut value = |name: &str| -> Result<OsString, String> {
            arguments
                .next()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match argument.to_str() {
            Some("--soname") => {
                soname = Some(
                    value("--soname")?
                        .into_string()
                        .map_err(|_| "--soname must be UTF-8".to_owned())?,
                )
            }
            Some("--allow-file") => allow_file = Some(PathBuf::from(value("--allow-file")?)),
            Some("--data-import-file") => {
                data_file = Some(PathBuf::from(value("--data-import-file")?))
            }
            Some(flag) if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => {
                if image.replace(PathBuf::from(argument)).is_some() {
                    return Err("exactly one image path is required".into());
                }
            }
        }
    }
    let image = image.ok_or(
        "usage: elf-survey [--soname NAME] [--allow-file PATH] [--data-import-file PATH] IMAGE",
    )?;
    let bytes = fs::read(&image).map_err(|error| format!("read {}: {error}", image.display()))?;
    let soname = match soname {
        Some(name) => name,
        None => image
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("image path has no UTF-8 file name")?
            .to_owned(),
    };
    let allowed = allow_file
        .as_deref()
        .map(names)
        .transpose()?
        .unwrap_or_default();
    let data = data_file
        .as_deref()
        .map(names)
        .transpose()?
        .unwrap_or_default();
    Ok(
        match inspect_with_data_imports(&bytes, &soname, &allowed, &data) {
            Ok(facts) => format!(
                "ok: soname={} needed={} symbols={} relocations={} constructors={}",
                facts.soname,
                facts.needed.len(),
                facts.symbols.len(),
                facts.relocations.len(),
                facts.has_constructors
            ),
            Err(ElfError::Invalid(message)) => format!("invalid: {message}"),
            Err(ElfError::Unsupported(message)) => format!("unsupported: {message}"),
        },
    )
}
