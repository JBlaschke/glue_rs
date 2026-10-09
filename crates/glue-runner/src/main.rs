//! Packaging, inspection and explicit linked Lua execution entry points.

use glue_format::{Archive, Manifest, Provisioning, RuntimeAbi, digest};
use glue_resources::Resources;
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const HELP: &str = "glue — experimental archive packager

Usage:
  glue build --manifest MANIFEST --root INPUT_DIR --output APP.glue
  glue inspect APP.glue [--json]
  glue verify APP.glue
  glue cat APP.glue RESOURCE
  glue explain-size APP.glue
  glue doctor [APP.glue]
  glue run APP.glue

A linked Lua 5.4 or 5.5 build can run source and resources from a matching archive.
Native modules, host/archived runtimes, other languages and standalone executables
remain pending. The resource fixture is packaging-only; see fixtures/lua-linked.
Existing build outputs are never overwritten.
";

enum Command {
    Help,
    Version,
    Build {
        manifest: PathBuf,
        root: PathBuf,
        output: PathBuf,
    },
    Standalone,
    Inspect {
        path: PathBuf,
        json: bool,
    },
    Verify(PathBuf),
    Cat {
        path: PathBuf,
        resource: String,
    },
    ExplainSize(PathBuf),
    Doctor(Option<PathBuf>),
    Run(PathBuf),
}

fn main() -> ExitCode {
    let result = parse(std::env::args_os().skip(1).collect()).and_then(execute);
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("glue: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse(args: Vec<OsString>) -> Result<Command> {
    let Some(name) = args.first() else {
        return Ok(Command::Help);
    };
    if name == "--help" || name == "-h" || name == "help" {
        return Ok(Command::Help);
    }
    if name == "--version" || name == "-V" {
        return Ok(Command::Version);
    }
    let name = name.to_str().ok_or("command name must be UTF-8")?;
    let args = &args[1..];
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    match name {
        "build" => parse_build(args),
        "inspect" => {
            let mut path = None;
            let mut json = false;
            for arg in args {
                if arg == "--json" && !json {
                    json = true;
                } else if !is_option(arg) && path.is_none() {
                    path = Some(PathBuf::from(arg));
                } else {
                    return Err(format!("unexpected inspect argument {arg:?}").into());
                }
            }
            Ok(Command::Inspect {
                path: path.ok_or("inspect requires an archive path")?,
                json,
            })
        }
        "verify" => Ok(Command::Verify(one_path(args, "verify")?)),
        "explain-size" => Ok(Command::ExplainSize(one_path(args, "explain-size")?)),
        "run" => Ok(Command::Run(one_path(args, "run")?)),
        "doctor" if args.is_empty() => Ok(Command::Doctor(None)),
        "doctor" => Ok(Command::Doctor(Some(one_path(args, "doctor")?))),
        "cat" if args.len() == 2 && !is_option(&args[0]) && !is_option(&args[1]) => {
            Ok(Command::Cat {
                path: PathBuf::from(&args[0]),
                resource: args[1]
                    .to_str()
                    .ok_or("resource identity must be UTF-8")?
                    .to_owned(),
            })
        }
        "cat" => Err("cat requires an archive path and a resource identity".into()),
        _ => Err(format!("unknown command {name:?}; use glue --help").into()),
    }
}

fn parse_build(args: &[OsString]) -> Result<Command> {
    let mut manifest = None;
    let mut root = None;
    let mut output = None;
    let mut standalone = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--standalone" && !standalone {
            standalone = true;
            continue;
        }
        let slot = match arg.to_str() {
            Some("--manifest") => &mut manifest,
            Some("--root") => &mut root,
            Some("--output") => &mut output,
            _ => return Err(format!("unexpected build argument {arg:?}").into()),
        };
        if slot.is_some() {
            return Err(format!("duplicate build option {arg:?}").into());
        }
        let value = args
            .next()
            .filter(|value| !is_option(value))
            .ok_or_else(|| format!("{arg:?} requires a path"))?;
        *slot = Some(PathBuf::from(value));
    }
    if standalone {
        return Ok(Command::Standalone);
    }
    Ok(Command::Build {
        manifest: manifest.ok_or("build requires --manifest")?,
        root: root.ok_or("build requires --root")?,
        output: output.ok_or("build requires --output")?,
    })
}

fn is_option(value: &OsStr) -> bool {
    value.to_str().is_some_and(|value| value.starts_with('-'))
}

fn one_path(args: &[OsString], command: &str) -> Result<PathBuf> {
    if args.len() != 1 || is_option(&args[0]) {
        return Err(format!("{command} requires exactly one archive path").into());
    }
    Ok(PathBuf::from(&args[0]))
}

fn execute(command: Command) -> Result<ExitCode> {
    match command {
        Command::Help => print!("{HELP}"),
        Command::Version => println!("glue {} (experimental schema 0)", env!("CARGO_PKG_VERSION")),
        Command::Build {
            manifest,
            root,
            output,
        } => {
            let report = glue_pack::build(&manifest, &root, &output)?;
            println!(
                "Built {}: {} resources, {} archive bytes, {} uncompressed bytes",
                output.display(),
                report.resource_count,
                report.archive_bytes,
                report.uncompressed_bytes,
            );
            println!("Archive SHA-256: {}", report.archive_sha256);
        }
        Command::Standalone => {
            eprintln!(
                "glue: standalone packaging is unavailable; executable layout and signing require G6 evidence"
            );
            return Ok(ExitCode::from(2));
        }
        Command::Inspect { path, json } => {
            let archive = open(&path)?;
            if json {
                let mut stdout = io::stdout().lock();
                stdout.write_all(&archive.manifest().to_json()?)?;
                stdout.write_all(b"\n")?;
            } else {
                inspect(&archive)?;
            }
        }
        Command::Verify(path) => {
            let mut archive = open(&path)?;
            archive.verify_all()?;
            println!(
                "Verified {} resources ({} uncompressed bytes)",
                archive.entries().len(),
                archive
                    .entries()
                    .values()
                    .map(|entry| entry.size)
                    .sum::<u64>(),
            );
        }
        Command::Cat { path, resource } => {
            let mut resources = Resources::with_default_cache(open(&path)?);
            // `read` verifies the complete member before any output is published.
            io::stdout().lock().write_all(&resources.read(&resource)?)?;
        }
        Command::ExplainSize(path) => explain_size(&path)?,
        Command::Doctor(path) => {
            println!(
                "Launcher: glue {} on {}/{}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
            );
            println!(
                "Linked Lua: {} (int64, float64)",
                glue_runtime_lua::profile::LUA_RELEASE,
            );
            println!(
                "Available: archive packaging, inspection, verification, read-only resources, linked Lua source profile"
            );
            println!(
                "Pending: native backends, host/archived runtime providers, Python/Node adapters, workers, standalone signing"
            );
            if let Some(path) = path {
                let archive = open(&path)?;
                println!("Validated metadata for {}", archive.manifest().app_id);
                match glue_runtime_lua::profile::validate(archive.manifest()) {
                    Ok(entry) => println!(
                        "Ready: linked Lua {} source profile, entry {entry}",
                        glue_runtime_lua::profile::LUA_RELEASE,
                    ),
                    Err(glue_runtime_lua::profile::CapabilityError::Unsupported(reason)) => {
                        execution_unavailable(archive.manifest());
                        eprintln!("glue: {reason}");
                        return Ok(ExitCode::from(2));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Command::Run(path) => {
            let archive = open(&path)?;
            let entry = match glue_runtime_lua::profile::validate(archive.manifest()) {
                Ok(entry) => entry,
                Err(glue_runtime_lua::profile::CapabilityError::Unsupported(reason)) => {
                    execution_unavailable(archive.manifest());
                    eprintln!("glue: {reason}");
                    return Ok(ExitCode::from(2));
                }
                Err(error) => return Err(error.into()),
            };
            if let Err(error) =
                glue_runtime_lua::execute(Resources::with_default_cache(archive), &entry)
            {
                if error.is_unsupported() {
                    eprintln!("glue: {error}");
                    return Ok(ExitCode::from(2));
                }
                return Err(error.into());
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn open(path: &Path) -> Result<Archive<File>> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open archive {}: {error}", path.display()))?;
    Ok(Archive::open(file)?)
}

fn inspect(archive: &Archive<File>) -> Result<()> {
    let manifest = archive.manifest();
    println!(
        "App: {} (schema {})",
        manifest.app_id, manifest.schema_version
    );
    println!("Entrypoint: {}", manifest.entrypoint);
    println!("Manifest SHA-256: {}", digest(&manifest.to_json()?));
    println!("Resources: {}", archive.entries().len());
    for (id, target) in &manifest.targets {
        println!(
            "Target {id}: {:?}/{:?}, minimum OS {}",
            target.os, target.arch, target.minimum_os_version
        );
    }
    for (id, runtime) in &manifest.runtimes {
        let provisioning = match &runtime.provisioning {
            Provisioning::Linked { provider, source } => {
                format!(
                    "linked {provider:?} {} ({})",
                    source.release, source.variant
                )
            }
            Provisioning::Bundled { provider, .. } => format!("bundled {provider:?}"),
            Provisioning::Host {
                runtime_library,
                stdlib,
                ..
            } => {
                format!("host library {runtime_library}, stdlib {stdlib}")
            }
        };
        println!(
            "Runtime {id}: {} on {}, {provisioning}",
            runtime_name(&runtime.abi),
            runtime.target
        );
    }
    for (id, import) in &manifest.host_imports {
        println!("Host import {id}: {import:?}");
    }
    println!("Payload verification: use glue verify");
    println!("Execution support: use glue doctor to check the selected runtime and target");
    Ok(())
}

fn runtime_name(abi: &RuntimeAbi) -> String {
    let (name, version) = match abi {
        RuntimeAbi::Python { version, .. } => ("Python", version),
        RuntimeAbi::Node { version, .. } => ("Node", version),
        RuntimeAbi::Lua { version, .. } => ("Lua", version),
    };
    format!(
        "{name} {}.{}.{}",
        version.major, version.minor, version.patch
    )
}

fn execution_unavailable(manifest: &Manifest) {
    let component = &manifest.components[&manifest.entrypoint];
    let runtime = &manifest.runtimes[&component.runtime];
    eprintln!(
        "glue: execution is unavailable for {} ({}); the selected provider or execution profile is unsupported. See fixtures/lua-linked for the linked Lua source profile",
        manifest.app_id,
        runtime_name(&runtime.abi),
    );
}

fn explain_size(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    let archive_bytes = file.metadata()?.len();
    let archive = Archive::open(file)?;
    let compressed = archive
        .entries()
        .values()
        .map(|entry| entry.compressed_size)
        .sum::<u64>();
    let uncompressed = archive
        .entries()
        .values()
        .map(|entry| entry.size)
        .sum::<u64>();
    println!("Archive: {archive_bytes} bytes");
    println!("Payload: {compressed} compressed bytes, {uncompressed} uncompressed bytes");
    println!(
        "Locator and metadata overhead: {} bytes",
        archive_bytes - compressed
    );
    println!("compressed\tuncompressed\tresource");
    let mut entries: Vec<_> = archive.entries().iter().collect();
    entries.sort_unstable_by(|(left_path, left), (right_path, right)| {
        right
            .compressed_size
            .cmp(&left.compressed_size)
            .then_with(|| left_path.cmp(right_path))
    });
    for (path, entry) in entries {
        println!("{}\t{}\t{path}", entry.compressed_size, entry.size);
    }
    Ok(())
}
