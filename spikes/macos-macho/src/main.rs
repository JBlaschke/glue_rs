//! Controlled signed macOS arm64 mapping experiment, not a product native loader.

use glue_format::{
    Architecture, ComponentSpec, Compression, DependencySpec, HostDiscovery, HostImportSpec,
    LoaderFeature, LuaNumber, Manifest, NativeFormat, NativeModuleSpec, OperatingSystem,
    Provisioning, ResourceSpec, RuntimeAbi, RuntimeSpec, RuntimeVersion, SCHEMA_VERSION, TargetAbi,
    TargetProfile, digest, write_archive,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use glue_format::{Archive, ArchiveLimits};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{self, Read},
    path::Path,
    process::ExitCode,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(unsafe_code)]
mod macos;

mod macho;

type ProbeResult<T> = Result<T, Box<dyn Error>>;
const SYSTEM: &str = "/usr/lib/libSystem.B.dylib";
const DEP: &str = "@loader_path/libglue_probe_dep.dylib";
const MODULE: &str = "@loader_path/libglue_probe_module.dylib";
const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
const DEPENDENCY_RESOURCE: &str = "native/libglue_probe_dep.dylib";
const MODULE_RESOURCE: &str = "native/libglue_probe_module.dylib";
const SCAFFOLD_RESOURCE: &str = "scaffold/main.lua";
const SCAFFOLD_BYTES: &[u8] = b"-- Unacquired schema scaffold; the mapping probe never runs Lua.\n";

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let action = arguments.get(1).and_then(|argument| argument.to_str());
    let result = match (action, arguments.len()) {
        (Some("prepare"), 5) => prepare_archive(
            Path::new(&arguments[2]),
            Path::new(&arguments[3]),
            Path::new(&arguments[4]),
        ),
        (Some("run"), 3 | 4) if arguments.len() == 3 || arguments[3] == "--hold" => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            {
                run_archive(Path::new(&arguments[2]), arguments.len() == 4)
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                eprintln!(
                    "macOS arm64 mapping execution is unavailable on this target; no fallback exists"
                );
                return ExitCode::from(2);
            }
        }
        _ => Err(failure(
            "usage: glue-macos-macho-probe prepare ARCHIVE DEP_DYLIB MODULE_DYLIB | run ARCHIVE [--hold]",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn prepare_archive(output: &Path, dependency_path: &Path, module_path: &Path) -> ProbeResult<()> {
    let arch = host_architecture()?;
    let dependency = read_image(dependency_path)?;
    let module = read_image(module_path)?;
    let images = [
        macho::parse(&dependency).map_err(|error| failure(&error))?,
        macho::parse(&module).map_err(|error| failure(&error))?,
    ];
    validate_closure(&images)?;
    let manifest = fixture_manifest(&dependency, &module, arch);
    let resources = BTreeMap::from([
        (DEPENDENCY_RESOURCE.to_owned(), dependency),
        (MODULE_RESOURCE.to_owned(), module),
        (SCAFFOLD_RESOURCE.to_owned(), SCAFFOLD_BYTES.to_vec()),
    ]);
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(output)?;
    write_archive(file, &manifest, &resources)?.sync_all()?;
    println!("prepared controlled native fixture; Lua scaffold remains unacquired");
    Ok(())
}

fn read_image(path: &Path) -> ProbeResult<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_IMAGE_BYTES {
        return Err(failure(
            "fixture input must be a regular file no larger than 16 MiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_IMAGE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_IMAGE_BYTES {
        return Err(failure("fixture input grew beyond 16 MiB"));
    }
    Ok(bytes)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_archive(path: &Path, hold: bool) -> ProbeResult<()> {
    let limits = ArchiveLimits {
        max_manifest_bytes: 128 * 1024,
        max_archive_bytes: 2 * MAX_IMAGE_BYTES + 256 * 1024,
        max_entry_bytes: MAX_IMAGE_BYTES,
        max_total_uncompressed_bytes: 2 * MAX_IMAGE_BYTES + 1024,
        max_central_directory_bytes: 64 * 1024,
        max_entries: 3,
        ..ArchiveLimits::default()
    };
    let mut archive = Archive::open_with_limits(File::open(path)?, limits)?;
    let dependency = archive.read_resource(DEPENDENCY_RESOURCE)?;
    let module = archive.read_resource(MODULE_RESOURCE)?;
    let scaffold = archive.read_resource(SCAFFOLD_RESOURCE)?;
    let arch = host_architecture()?;
    if archive.manifest() != &fixture_manifest(&dependency, &module, arch)
        || scaffold != SCAFFOLD_BYTES
    {
        return Err(failure(
            "archive does not match the controlled, unacquired-runtime fixture contract",
        ));
    }
    // Preflight both complete images before allocating executable memory.
    let images = [
        macho::parse(&dependency).map_err(|error| failure(&error))?,
        macho::parse(&module).map_err(|error| failure(&error))?,
    ];
    validate_closure(&images)?;
    let report = macos::execute(&dependency, &module)?;
    println!(
        "PASS answer={} data={} constructors={} pid={}",
        report.answer, report.data, report.constructors, report.pid,
    );
    if hold {
        use std::io::Write;
        std::io::stdout().flush()?;
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    Ok(())
}

fn fixture_manifest(dependency: &[u8], module: &[u8], arch: Architecture) -> Manifest {
    let target_id = "macos-aarch64".to_owned();
    Manifest {
        schema_version: SCHEMA_VERSION,
        app_id: "macos.macho.probe".to_owned(),
        entrypoint: "fixture".to_owned(),
        targets: BTreeMap::from([(
            target_id.clone(),
            TargetProfile {
                os: OperatingSystem::Macos,
                arch,
                minimum_os_version: "13.0".to_owned(),
                abi: TargetAbi::Darwin,
                page_sizes: BTreeSet::from([16384]),
                cpu_features: BTreeSet::new(),
            },
        )]),
        resources: BTreeMap::from([
            (DEPENDENCY_RESOURCE.to_owned(), resource_spec(dependency)),
            (MODULE_RESOURCE.to_owned(), resource_spec(module)),
            (SCAFFOLD_RESOURCE.to_owned(), resource_spec(SCAFFOLD_BYTES)),
        ]),
        // The native-only probe does not acquire this runtime. It exists solely
        // because provisional schema zero requires a language component.
        runtimes: BTreeMap::from([(
            "scaffold".to_owned(),
            RuntimeSpec {
                target: target_id.clone(),
                build_id: "unacquired-fixture-scaffold".to_owned(),
                abi: RuntimeAbi::Lua {
                    version: RuntimeVersion {
                        major: 5,
                        minor: 4,
                        patch: 9,
                    },
                    integer_bits: 64,
                    number: LuaNumber::Float64,
                },
                provisioning: Provisioning::Host {
                    runtime_library: "/unacquired-fixture-scaffold/liblua.dylib".to_owned(),
                    stdlib: "/unacquired-fixture-scaffold/stdlib".to_owned(),
                    discovery: HostDiscovery::ExplicitPaths,
                },
                required_features: BTreeSet::new(),
            },
        )]),
        components: BTreeMap::from([(
            "fixture".to_owned(),
            ComponentSpec {
                runtime: "scaffold".to_owned(),
                entry_point: SCAFFOLD_RESOURCE.to_owned(),
                native_modules: BTreeSet::from(["module".to_owned()]),
            },
        )]),
        native_modules: BTreeMap::from([
            (
                "dependency".to_owned(),
                NativeModuleSpec {
                    target: target_id.clone(),
                    resource: DEPENDENCY_RESOURCE.to_owned(),
                    format: NativeFormat::MachO,
                    namespace: "probe".to_owned(),
                    runtime: None,
                    dependencies: vec![DependencySpec::OperatingSystem {
                        import: "libsystem".to_owned(),
                    }],
                    required_features: BTreeSet::from([LoaderFeature::FunctionExports]),
                },
            ),
            (
                "module".to_owned(),
                NativeModuleSpec {
                    target: target_id.clone(),
                    resource: MODULE_RESOURCE.to_owned(),
                    format: NativeFormat::MachO,
                    namespace: "probe".to_owned(),
                    runtime: None,
                    dependencies: vec![
                        DependencySpec::ArchivedModule {
                            module: "dependency".to_owned(),
                        },
                        DependencySpec::OperatingSystem {
                            import: "libsystem".to_owned(),
                        },
                    ],
                    required_features: BTreeSet::from([
                        LoaderFeature::FunctionExports,
                        LoaderFeature::DataExports,
                        LoaderFeature::Constructors,
                    ]),
                },
            ),
        ]),
        host_imports: BTreeMap::from([(
            "libsystem".to_owned(),
            HostImportSpec::OperatingSystem {
                target: target_id,
                library: "/usr/lib/libSystem.B.dylib".to_owned(),
                symbols: BTreeSet::from(["getpid".to_owned()]),
            },
        )]),
    }
}

fn resource_spec(bytes: &[u8]) -> ResourceSpec {
    ResourceSpec {
        size: bytes.len() as u64,
        sha256: digest(bytes),
        compression: Compression::Stored,
    }
}

fn host_architecture() -> ProbeResult<Architecture> {
    if std::env::consts::ARCH == "aarch64" {
        Ok(Architecture::Aarch64)
    } else {
        Err(failure("this fixture requires arm64"))
    }
}

fn failure(message: &str) -> Box<dyn Error> {
    Box::new(io::Error::other(message.to_owned()))
}

fn validate_closure(images: &[macho::Image; 2]) -> ProbeResult<()> {
    let total_vm = images
        .iter()
        .try_fold(0u64, |total, image| total.checked_add(image.vm_size));
    if total_vm.is_none_or(|size| size == 0 || size > 64 * 1024 * 1024)
        || images
            .iter()
            .flat_map(|image| &image.segments)
            .any(|segment| segment.read_only_after_fixups && segment.initial_protection != 3)
    {
        return Err(failure(
            "unsupported closure memory or constant-data layout",
        ));
    }
    if images
        .iter()
        .any(|image| image.minimum_os_version != 13 << 16)
    {
        return Err(failure("fixture images must declare macOS 13.0 exactly"));
    }
    if images.iter().any(|image| {
        image.code_signature.is_none()
            || image
                .segments
                .iter()
                .any(|segment| segment.initial_protection & !segment.maximum_protection != 0)
    }) {
        return Err(failure(
            "require bounded signature metadata and consistent segment permissions",
        ));
    }
    if images[0].install_name != DEP
        || images[1].install_name != MODULE
        || images[0].dependencies != [SYSTEM]
        || images[1].dependencies != [DEP, SYSTEM]
    {
        return Err(failure(
            "image install names or dependencies differ from the controlled closure",
        ));
    }
    let expected = [
        BTreeSet::from(["_glue_probe_dep"]),
        BTreeSet::from([
            "_glue_answer",
            "_glue_probe_constructor_count",
            "_glue_probe_data",
            "_glue_probe_pid",
        ]),
    ];
    for (index, image) in images.iter().enumerate() {
        if image
            .exports
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected[index]
        {
            return Err(failure("exports differ from the controlled fixture"));
        }
        for (name, &offset) in &image.exports {
            if name == "_glue_probe_data" {
                let segment = image
                    .segment_containing(offset, 4)
                    .ok_or_else(|| failure("exported data exceeds its segment"))?;
                if segment.initial_protection != 3 || offset % 4 != 0 {
                    return Err(failure("data export requires aligned non-executable data"));
                }
            } else if !image.is_executable(offset) || offset % 4 != 0 {
                return Err(failure("function export requires aligned executable code"));
            }
        }
        let bindings = image
            .binds
            .iter()
            .map(|bind| (bind.library_ordinal, bind.symbol.as_str(), bind.addend))
            .collect::<BTreeSet<_>>();
        let expected_bindings = if index == 0 {
            BTreeSet::new()
        } else {
            BTreeSet::from([(1, "_glue_probe_dep", 0), (2, "_getpid", 0)])
        };
        if bindings != expected_bindings || image.constructors.len() != index {
            return Err(failure(
                "imports or constructors differ from the controlled fixture",
            ));
        }
    }
    Ok(())
}
