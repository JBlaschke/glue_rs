//! Packaging, inspection and explicit runtime profile execution entry points.

mod compact;

use glue_format::{
    Archive, ArchiveLimits, BufferedReader, Manifest, Provisioning, RuntimeAbi, digest,
};
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
  glue build lua PROJECT --lua 5.4|5.5 --output DIR [--entry FILE] [--config FILE]
  glue build python --env ENV --entry FILE --output DIR
  glue build node PROJECT --node EXECUTABLE --entry FILE --output DIR
  glue run APP.glue -- [ARGUMENTS...]
  glue rebuild glue.lock.json --output NEW_DIR [--json]
  glue build --manifest MANIFEST --root INPUT_DIR --output APP.glue
  glue python-template --provider bundled --pbs-full FULL.tar.zst
    --frozen-bootstrap BUNDLE.json --output DIR [--json]
  glue python-template --provider (host-full | host-install | host-install-stripped)
    --host-prefix PREFIX --output DIR [--json]
  glue python-host --provider host-full --pbs-full FULL.tar.zst
    --output PREFIX [--json]
  glue python-host --provider (host-install | host-install-stripped) --pbs-install-only INSTALL.tar.gz
    --output PREFIX [--json]
  glue python-host --provider (host-install | host-install-stripped) --runtime-tree ROOT
    --output PREFIX [--json]
  glue build-python --provider-template MANIFEST --provider-root DIR --app DIR
    (--venv VENV | --site-packages DIR) --output APP.glue
    [--app-id ID] [--entry app/main.py] [--json]
  glue inspect APP.glue [--json]
  glue verify APP.glue
  glue cat APP.glue RESOURCE
  glue explain-size APP.glue
  glue doctor [APP.glue]
  glue run APP.glue

Compact builders consume existing Lua projects, Python environments and installed
Node projects. Install glue, both Lua helpers and the archive bridge together with
scripts/install-glue.sh PREFIX. Runtime versions must pass capability/ABI checks.
Memory delivery remains limited to proven low-level profiles. Existing outputs
are never overwritten. The legacy build-python command retains its separate
python-pack feature; the high-level build python command is included normally.
";

enum Command {
    Help,
    Version,
    Build {
        manifest: PathBuf,
        root: PathBuf,
        output: PathBuf,
    },
    BuildPython {
        provider_template: PathBuf,
        provider_root: PathBuf,
        application: PathBuf,
        packages: PathBuf,
        venv: bool,
        app_id: String,
        entry: String,
        output: PathBuf,
        json: bool,
    },
    PythonTemplate {
        input: TemplateOptions,
        output: PathBuf,
        json: bool,
    },
    PythonHost {
        input: HostOptions,
        output: PathBuf,
        json: bool,
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

enum TemplateOptions {
    Bundled { full: PathBuf, frozen: PathBuf },
    HostFull(String),
    HostInstall(String),
    HostInstallStripped(String),
}

enum HostOptions {
    Full(PathBuf),
    Install(PathBuf),
    InstallTree(PathBuf),
    InstallStripped(PathBuf),
    InstallStrippedTree(PathBuf),
}

enum Selection {
    Lua(String),
    #[cfg(feature = "python-pbs")]
    Python(glue_runtime_python::profile::ControlledProfile),
}

enum SelectionError {
    Unsupported(String),
    Invalid(Box<dyn Error>),
}

fn select(manifest: &Manifest) -> std::result::Result<Selection, SelectionError> {
    // Schema validation has already established these references. Dispatch
    // solely by the selected component's declared ABI, without provider retry.
    let runtime = &manifest.runtimes[&manifest.components[&manifest.entrypoint].runtime];
    match runtime.abi {
        RuntimeAbi::Lua { .. } => glue_runtime_lua::profile::validate(manifest)
            .map(Selection::Lua)
            .map_err(|error| match error {
                glue_runtime_lua::profile::CapabilityError::Unsupported(reason) => {
                    SelectionError::Unsupported(reason)
                }
                error => SelectionError::Invalid(error.into()),
            }),
        RuntimeAbi::Python { .. } => {
            #[cfg(feature = "python-pbs")]
            {
                glue_runtime_python::profile::validate(manifest)
                    .map(Selection::Python)
                    .map_err(|error| {
                        if error.is_unsupported() {
                            SelectionError::Unsupported(error.to_string())
                        } else {
                            SelectionError::Invalid(error.into())
                        }
                    })
            }
            #[cfg(not(feature = "python-pbs"))]
            {
                Err(SelectionError::Unsupported(
                    "Python execution requires a build with --features python-pbs".to_owned(),
                ))
            }
        }
        RuntimeAbi::Node { .. } => Err(SelectionError::Unsupported(
            "the Node runtime adapter is unavailable".to_owned(),
        )),
    }
}

fn execution_result(result: Result<()>, unsupported: bool) -> Result<ExitCode> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) if unsupported => {
            eprintln!("glue: {error}");
            Ok(ExitCode::from(2))
        }
        Err(error) => Err(error),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if let Some(result) = compact::handle(&arguments) {
        return match result {
            Ok(code) => code,
            Err(error) => {
                if arguments.iter().any(|a| a == "--json") {
                    eprintln!(
                        "{}",
                        serde_json::to_string(&error).expect("serializable diagnostic")
                    );
                } else {
                    eprintln!("glue: {error}");
                }
                ExitCode::FAILURE
            }
        };
    }
    let result = parse(arguments).and_then(execute);
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
        "build-python" => parse_build_python(args),
        "python-template" => parse_python_template(args),
        "python-host" => parse_python_host(args),
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

fn parse_build_python(args: &[OsString]) -> Result<Command> {
    let mut provider_template = None;
    let mut provider_root = None;
    let mut application = None;
    let mut packages = None;
    let mut venv = false;
    let mut app_id = None;
    let mut entry = None;
    let mut output = None;
    let mut json = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            if json {
                return Err("duplicate build-python option --json".into());
            }
            json = true;
            continue;
        }
        let slot = match arg.to_str() {
            Some("--provider-template") => &mut provider_template,
            Some("--provider-root") => &mut provider_root,
            Some("--app") => &mut application,
            Some("--venv") => {
                venv = true;
                &mut packages
            }
            Some("--site-packages") => &mut packages,
            Some("--app-id") => &mut app_id,
            Some("--entry") => &mut entry,
            Some("--output") => &mut output,
            _ => return Err(format!("unexpected build-python argument {arg:?}").into()),
        };
        if slot.is_some() {
            return Err(format!("duplicate or conflicting build-python option {arg:?}").into());
        }
        *slot = Some(
            args.next()
                .filter(|value| !is_option(value))
                .ok_or_else(|| format!("{arg:?} requires a value"))?
                .clone(),
        );
    }
    Ok(Command::BuildPython {
        provider_template: PathBuf::from(
            provider_template.ok_or("build-python requires --provider-template")?,
        ),
        provider_root: PathBuf::from(provider_root.ok_or("build-python requires --provider-root")?),
        application: PathBuf::from(application.ok_or("build-python requires --app")?),
        packages: PathBuf::from(packages.ok_or("build-python requires --venv or --site-packages")?),
        venv,
        app_id: app_id
            .unwrap_or_else(|| OsString::from("python.application"))
            .into_string()
            .map_err(|_| "application identity must be UTF-8")?,
        entry: entry
            .unwrap_or_else(|| OsString::from("app/main.py"))
            .into_string()
            .map_err(|_| "entry identity must be UTF-8")?,
        output: PathBuf::from(output.ok_or("build-python requires --output")?),
        json,
    })
}

fn parse_python_template(args: &[OsString]) -> Result<Command> {
    let mut provider = None;
    let mut full = None;
    let mut frozen = None;
    let mut prefix = None;
    let mut output = None;
    let mut json = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            if json {
                return Err("duplicate python-template option --json".into());
            }
            json = true;
            continue;
        }
        let slot = match arg.to_str() {
            Some("--provider") => &mut provider,
            Some("--pbs-full") => &mut full,
            Some("--frozen-bootstrap") => &mut frozen,
            Some("--host-prefix") => &mut prefix,
            Some("--output") => &mut output,
            _ => return Err(format!("unexpected python-template argument {arg:?}").into()),
        };
        if slot.is_some() {
            return Err(format!("duplicate python-template option {arg:?}").into());
        }
        *slot = Some(
            args.next()
                .filter(|value| !is_option(value))
                .ok_or_else(|| format!("{arg:?} requires a value"))?
                .clone(),
        );
    }
    let provider = provider.ok_or("python-template requires --provider")?;
    let input = match provider.to_str() {
        Some("bundled") => {
            if prefix.is_some() {
                return Err("bundled python-template does not accept --host-prefix".into());
            }
            TemplateOptions::Bundled {
                full: PathBuf::from(full.ok_or("bundled python-template requires --pbs-full")?),
                frozen: PathBuf::from(
                    frozen.ok_or("bundled python-template requires --frozen-bootstrap")?,
                ),
            }
        }
        Some("host-full" | "host-install" | "host-install-stripped") => {
            if full.is_some() || frozen.is_some() {
                return Err("host python-template does not accept PBS or frozen inputs".into());
            }
            let prefix = prefix
                .ok_or("host python-template requires --host-prefix")?
                .into_string()
                .map_err(|_| "host prefix must be UTF-8")?;
            if provider == "host-full" {
                TemplateOptions::HostFull(prefix)
            } else if provider == "host-install-stripped" {
                TemplateOptions::HostInstallStripped(prefix)
            } else {
                TemplateOptions::HostInstall(prefix)
            }
        }
        _ => {
            return Err(
                "python-template provider must be bundled, host-full, host-install or host-install-stripped".into(),
            );
        }
    };
    Ok(Command::PythonTemplate {
        input,
        output: PathBuf::from(output.ok_or("python-template requires --output")?),
        json,
    })
}

fn parse_python_host(args: &[OsString]) -> Result<Command> {
    let mut provider = None;
    let mut full = None;
    let mut install = None;
    let mut tree = None;
    let mut output = None;
    let mut json = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            if json {
                return Err("duplicate python-host option --json".into());
            }
            json = true;
            continue;
        }
        let slot = match arg.to_str() {
            Some("--provider") => &mut provider,
            Some("--pbs-full") => &mut full,
            Some("--pbs-install-only") => &mut install,
            Some("--runtime-tree") => &mut tree,
            Some("--output") => &mut output,
            _ => return Err(format!("unexpected python-host argument {arg:?}").into()),
        };
        if slot.is_some() {
            return Err(format!("duplicate python-host option {arg:?}").into());
        }
        *slot = Some(
            args.next()
                .filter(|value| !is_option(value))
                .ok_or_else(|| format!("{arg:?} requires a value"))?
                .clone(),
        );
    }
    let provider = provider.ok_or("python-host requires --provider")?;
    let input = match provider.to_str() {
        Some("host-full") => {
            if install.is_some() || tree.is_some() {
                return Err(
                    "host-full python-host does not accept --pbs-install-only or --runtime-tree"
                        .into(),
                );
            }
            HostOptions::Full(PathBuf::from(
                full.ok_or("host-full python-host requires --pbs-full")?,
            ))
        }
        Some("host-install" | "host-install-stripped") => {
            if full.is_some() {
                return Err("host-install python-host does not accept --pbs-full".into());
            }
            match (install, tree) {
                (Some(artifact), None) => if provider == "host-install-stripped" {
                    HostOptions::InstallStripped(PathBuf::from(artifact))
                } else { HostOptions::Install(PathBuf::from(artifact)) },
                (None, Some(root)) => if provider == "host-install-stripped" {
                    HostOptions::InstallStrippedTree(PathBuf::from(root))
                } else { HostOptions::InstallTree(PathBuf::from(root)) },
                _ => return Err("host-install python-host requires exactly one of --pbs-install-only or --runtime-tree".into()),
            }
        }
        _ => {
            return Err(
                "python-host provider must be host-full, host-install or host-install-stripped"
                    .into(),
            );
        }
    };
    Ok(Command::PythonHost {
        input,
        output: PathBuf::from(output.ok_or("python-host requires --output")?),
        json,
    })
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
            #[cfg(feature = "python-pbs")]
            let report = glue_pack::build_with_policy(&manifest, &root, &output, |manifest| {
                let Some(archive_limits) = glue_runtime_python::profile::packaging_limits(manifest)
                    .map_err(|error| error.to_string())?
                else {
                    return Ok(glue_pack::PackLimits::default());
                };
                Ok(glue_pack::PackLimits {
                    max_input_bytes: archive_limits.max_total_uncompressed_bytes,
                    archive_limits,
                })
            })?;
            #[cfg(not(feature = "python-pbs"))]
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
        Command::BuildPython {
            provider_template,
            provider_root,
            application,
            packages,
            venv,
            app_id,
            entry,
            output,
            json,
        } => {
            #[cfg(feature = "python-pack")]
            {
                use glue_pack::python::{PackageInput, PythonBuildOptions};
                let report = glue_pack::python::build(
                    PythonBuildOptions {
                        provider_template: &provider_template,
                        provider_root: &provider_root,
                        application: &application,
                        packages: if venv {
                            PackageInput::Venv(&packages)
                        } else {
                            PackageInput::SitePackages(&packages)
                        },
                        app_id: &app_id,
                        entry: &entry,
                    },
                    &output,
                )?;
                if json {
                    let mut stdout = io::stdout().lock();
                    serde_json::to_writer(&mut stdout, &report)?;
                    stdout.write_all(b"\n")?;
                } else {
                    println!(
                        "Built {}: {} resources, {} archive bytes, {} uncompressed bytes",
                        output.display(),
                        report.build.resource_count,
                        report.build.archive_bytes,
                        report.build.uncompressed_bytes,
                    );
                    println!("Archive SHA-256: {}", report.build.archive_sha256);
                    println!(
                        "Normalized installed Python packages; use --json for the transformation report"
                    );
                }
            }
            #[cfg(not(feature = "python-pack"))]
            {
                let _ = (
                    provider_template,
                    provider_root,
                    application,
                    packages,
                    venv,
                    app_id,
                    entry,
                    output,
                    json,
                );
                eprintln!("glue: installed Python package builds require --features python-pack");
                return Ok(ExitCode::from(2));
            }
        }
        Command::PythonTemplate {
            input,
            output,
            json,
        } => {
            #[cfg(feature = "python-pack")]
            {
                use glue_pack::python_template::TemplateInput;
                let selected = match &input {
                    TemplateOptions::Bundled { full, frozen } => {
                        TemplateInput::Bundled { full, frozen }
                    }
                    TemplateOptions::HostFull(prefix) => TemplateInput::HostFull { prefix },
                    TemplateOptions::HostInstall(prefix) => TemplateInput::HostInstall { prefix },
                    TemplateOptions::HostInstallStripped(prefix) => {
                        TemplateInput::HostInstallStripped { prefix }
                    }
                };
                let report = glue_pack::python_template::prepare(selected, &output)?;
                if json {
                    let mut stdout = io::stdout().lock();
                    serde_json::to_writer(&mut stdout, &report)?;
                    stdout.write_all(b"\n")?;
                } else {
                    println!("Prepared Python runtime template at {}", output.display());
                    println!("Use its manifest.json and root/ with glue build-python");
                }
            }
            #[cfg(not(feature = "python-pack"))]
            {
                match input {
                    TemplateOptions::Bundled { full, frozen } => {
                        let _ = (full, frozen);
                    }
                    TemplateOptions::HostFull(prefix)
                    | TemplateOptions::HostInstall(prefix)
                    | TemplateOptions::HostInstallStripped(prefix) => {
                        let _ = prefix;
                    }
                }
                let _ = (output, json);
                eprintln!("glue: Python runtime templates require --features python-pack");
                return Ok(ExitCode::from(2));
            }
        }
        Command::PythonHost {
            input,
            output,
            json,
        } => {
            #[cfg(feature = "python-pack")]
            {
                use glue_pack::python_host::HostInput;
                let selected = match &input {
                    HostOptions::Full(artifact) => HostInput::Full { artifact },
                    HostOptions::Install(artifact) => HostInput::Install { artifact },
                    HostOptions::InstallTree(root) => HostInput::InstallTree { root },
                    HostOptions::InstallStripped(artifact) => {
                        HostInput::InstallStripped { artifact }
                    }
                    HostOptions::InstallStrippedTree(root) => {
                        HostInput::InstallStrippedTree { root }
                    }
                };
                let report = glue_pack::python_host::prepare(selected, &output)?;
                if json {
                    let mut stdout = io::stdout().lock();
                    serde_json::to_writer(&mut stdout, &report)?;
                    stdout.write_all(b"\n")?;
                } else {
                    println!(
                        "Prepared pinned host Python prerequisites at {}",
                        output.display()
                    );
                    println!("Use this prefix with glue python-template for its host provider");
                }
            }
            #[cfg(not(feature = "python-pack"))]
            {
                match input {
                    HostOptions::Full(artifact)
                    | HostOptions::Install(artifact)
                    | HostOptions::InstallTree(artifact)
                    | HostOptions::InstallStripped(artifact)
                    | HostOptions::InstallStrippedTree(artifact) => {
                        let _ = artifact;
                    }
                }
                let _ = (output, json);
                eprintln!(
                    "glue: host Python prerequisite preparation requires --features python-pack"
                );
                return Ok(ExitCode::from(2));
            }
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
                "Pending: general runtime/package compatibility, Node adapters, workers, standalone signing"
            );
            #[cfg(feature = "python-pbs")]
            println!(
                "Python: controlled CPython 3.13.16 / PBS 20261009 profiles; {}",
                glue_runtime_python::profile::execution_cell()
            );
            #[cfg(not(feature = "python-pbs"))]
            println!(
                "Python: disabled; build with --features python-pbs for controlled PBS profiles"
            );
            if let Some(path) = path {
                let archive = open(&path)?;
                println!("Validated metadata for {}", archive.manifest().app_id);
                match select(archive.manifest()) {
                    Ok(Selection::Lua(entry)) => {
                        archive.check_limits(ArchiveLimits::default())?;
                        println!(
                            "Ready: linked Lua {} source profile, entry {entry}",
                            glue_runtime_lua::profile::LUA_RELEASE,
                        );
                    }
                    #[cfg(feature = "python-pbs")]
                    Ok(Selection::Python(selected)) => {
                        if let Err(error) = glue_runtime_python::profile::readiness(&selected) {
                            let unsupported = error.is_unsupported();
                            return execution_result(Err(error.into()), unsupported);
                        }
                        println!(
                            "Ready: {} build/target prerequisites, CPython 3.13.16 / PBS 20261009",
                            selected.name()
                        );
                        println!(
                            "Run checks profile archive limits, contents and explicit host prerequisites before loading Python"
                        );
                    }
                    Err(SelectionError::Unsupported(reason)) => {
                        execution_unavailable(archive.manifest());
                        eprintln!("glue: {reason}");
                        return Ok(ExitCode::from(2));
                    }
                    Err(SelectionError::Invalid(error)) => return Err(error),
                }
            }
        }
        Command::Run(path) => {
            let archive = open(&path)?;
            let selected = match select(archive.manifest()) {
                Ok(selected) => selected,
                Err(SelectionError::Unsupported(reason)) => {
                    execution_unavailable(archive.manifest());
                    eprintln!("glue: {reason}");
                    return Ok(ExitCode::from(2));
                }
                Err(SelectionError::Invalid(error)) => return Err(error),
            };
            match selected {
                Selection::Lua(entry) => {
                    archive.check_limits(ArchiveLimits::default())?;
                    if let Err(error) =
                        glue_runtime_lua::execute(Resources::with_default_cache(archive), &entry)
                    {
                        let unsupported = error.is_unsupported();
                        return execution_result(Err(error.into()), unsupported);
                    }
                }
                #[cfg(feature = "python-pbs")]
                Selection::Python(selected) => {
                    if let Err(error) = glue_runtime_python::execute(archive, selected) {
                        let unsupported = error.is_unsupported();
                        return execution_result(Err(error.into()), unsupported);
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn open(path: &Path) -> Result<Archive<BufferedReader<File>>> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open archive {}: {error}", path.display()))?;
    Ok(Archive::open_with_limits(
        BufferedReader::new(file),
        inspection_limits(),
    )?)
}

fn inspection_limits() -> ArchiveLimits {
    // The stock pinned libpython is 73,563,968 bytes. Inspection must work even
    // when Python execution is disabled; each executor enforces its own policy.
    ArchiveLimits {
        max_entry_bytes: 80 * 1024 * 1024,
        ..ArchiveLimits::default()
    }
}

fn inspect(archive: &Archive<BufferedReader<File>>) -> Result<()> {
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
        "glue: execution is unavailable for {} ({}); the selected provider or execution profile is unsupported. Use glue doctor to check compiled capabilities",
        manifest.app_id,
        runtime_name(&runtime.abi),
    );
}

fn explain_size(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    let archive_bytes = file.metadata()?.len();
    let archive = Archive::open_with_limits(BufferedReader::new(file), inspection_limits())?;
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
