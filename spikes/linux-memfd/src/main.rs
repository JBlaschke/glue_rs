//! Controlled Linux memfd feasibility fixture, not a product native loader.

use glue_format::{
    Architecture, ComponentSpec, Compression, DependencySpec, HostDiscovery, HostImportSpec,
    LoaderFeature, LuaNumber, Manifest, NativeFormat, NativeModuleSpec, OperatingSystem,
    Provisioning, ResourceSpec, RuntimeAbi, RuntimeSpec, RuntimeVersion, SCHEMA_VERSION, TargetAbi,
    TargetProfile, digest, write_archive,
};
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux;

type ProbeResult<T> = Result<T, Box<dyn Error>>;
const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
const DEPENDENCY_RESOURCE: &str = "native/libglue_probe_dep.so";
const MODULE_RESOURCE: &str = "native/libglue_probe_module.so";
const SCAFFOLD_RESOURCE: &str = "scaffold/main.lua";
const SCAFFOLD_BYTES: &[u8] =
    b"-- Schema fixture only: this Lua scaffold is never acquired or executed.\n";

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().collect();
    let action = arguments.get(1).and_then(|argument| argument.to_str());
    let result = match (action, arguments.len()) {
        (Some("prepare"), 5) => prepare_archive(
            Path::new(&arguments[2]),
            Path::new(&arguments[3]),
            Path::new(&arguments[4]),
        ),
        (Some("run"), 3) => {
            #[cfg(target_os = "linux")]
            {
                run_archive(Path::new(&arguments[2]))
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!(
                    "Linux memfd execution is unavailable on this operating system; no fallback exists"
                );
                return ExitCode::from(2);
            }
        }
        _ => Err(failure(
            "usage: glue-linux-memfd-probe prepare ARCHIVE DEP_SO MODULE_SO | run ARCHIVE",
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
    validate_elf(&dependency, arch)?;
    validate_elf(&module, arch)?;
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

#[cfg(target_os = "linux")]
fn run_archive(path: &Path) -> ProbeResult<()> {
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
    // Preflight both images before the first dlopen can execute a constructor.
    validate_elf(&dependency, arch)?;
    validate_elf(&module, arch)?;
    let report = linux::execute(&dependency, &module)?;
    println!(
        "PASS answer=42 data=7 constructors=1 machine={} dependency_seals={:#x} module_seals={:#x} mechanism=sealed-memfd+/proc/self/fd runtime=unacquired-fixture-scaffold",
        architecture_name(arch),
        report.dependency_seals,
        report.module_seals,
    );
    Ok(())
}

fn fixture_manifest(dependency: &[u8], module: &[u8], arch: Architecture) -> Manifest {
    let target_id = format!("linux-{}-glibc", architecture_name(arch));
    Manifest {
        schema_version: SCHEMA_VERSION,
        app_id: "linux.memfd.probe".to_owned(),
        entrypoint: "fixture".to_owned(),
        targets: BTreeMap::from([(
            target_id.clone(),
            TargetProfile {
                os: OperatingSystem::Linux,
                arch,
                minimum_os_version: "6.3".to_owned(),
                abi: TargetAbi::Glibc {
                    minimum_version: "2.36".to_owned(),
                },
                page_sizes: BTreeSet::from([4096]),
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
                        patch: 8,
                    },
                    integer_bits: 64,
                    number: LuaNumber::Float64,
                },
                provisioning: Provisioning::Host {
                    runtime_library: "/unacquired-fixture-scaffold/liblua.so".to_owned(),
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
                    format: NativeFormat::Elf,
                    namespace: "probe".to_owned(),
                    runtime: None,
                    dependencies: vec![],
                    required_features: BTreeSet::from([LoaderFeature::FunctionExports]),
                },
            ),
            (
                "module".to_owned(),
                NativeModuleSpec {
                    target: target_id.clone(),
                    resource: MODULE_RESOURCE.to_owned(),
                    format: NativeFormat::Elf,
                    namespace: "probe".to_owned(),
                    runtime: None,
                    dependencies: vec![
                        DependencySpec::ArchivedModule {
                            module: "dependency".to_owned(),
                        },
                        DependencySpec::OperatingSystem {
                            import: "libc".to_owned(),
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
            "libc".to_owned(),
            HostImportSpec::OperatingSystem {
                target: target_id,
                library: "libc.so.6".to_owned(),
                symbols: BTreeSet::from(["strlen".to_owned()]),
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
    match std::env::consts::ARCH {
        "aarch64" => Ok(Architecture::Aarch64),
        "x86_64" => Ok(Architecture::X86_64),
        _ => Err(failure(
            "this fixture implements ELF preflight only for aarch64 and x86_64",
        )),
    }
}

fn architecture_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::Aarch64 => "aarch64",
        Architecture::X86_64 => "x86_64",
    }
}

/// Narrow structural preflight, not an ELF verifier or a compatibility claim.
fn validate_elf(bytes: &[u8], arch: Architecture) -> ProbeResult<()> {
    if bytes.len() < 64 || bytes[..4] != *b"\x7fELF" {
        return Err(failure("truncated or non-ELF image"));
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 || !matches!(bytes[7], 0 | 3) {
        return Err(failure(
            "fixture requires ELF64, little-endian, version 1, System V/GNU ABI",
        ));
    }
    let machine = match arch {
        Architecture::Aarch64 => 183,
        Architecture::X86_64 => 62,
    };
    if u16_at(bytes, 16) != 3
        || u16_at(bytes, 18) != machine
        || u32_at(bytes, 20) != 1
        || u16_at(bytes, 52) != 64
    {
        return Err(failure(
            "fixture requires an ET_DYN image with the host machine and standard ELF64 header",
        ));
    }
    let ph_offset = u64_at(bytes, 32);
    let ph_count = u16_at(bytes, 56);
    if u16_at(bytes, 54) != 56 || ph_count == 0 || ph_count == u16::MAX {
        return Err(failure("unsupported or missing ELF program header table"));
    }
    let end = ph_offset
        .checked_add(u64::from(ph_count) * 56)
        .ok_or_else(|| failure("ELF program header range overflow"))?;
    if end > bytes.len() as u64 {
        return Err(failure("ELF program headers exceed image bytes"));
    }
    let mut load = false;
    let mut dynamic = false;
    for index in 0..u64::from(ph_count) {
        let offset = (ph_offset + index * 56) as usize;
        let kind = u32_at(bytes, offset);
        let flags = u32_at(bytes, offset + 4);
        let file_offset = u64_at(bytes, offset + 8);
        let file_size = u64_at(bytes, offset + 32);
        let memory_size = u64_at(bytes, offset + 40);
        let segment_end = file_offset
            .checked_add(file_size)
            .ok_or_else(|| failure("ELF segment range overflow"))?;
        if segment_end > bytes.len() as u64 {
            return Err(failure("ELF segment exceeds image bytes"));
        }
        match kind {
            1 => {
                load = true;
                if memory_size < file_size || flags & 3 == 3 {
                    return Err(failure(
                        "unsupported ELF load segment size or writable executable mapping",
                    ));
                }
            }
            2 => dynamic = true,
            3 => {
                return Err(failure(
                    "ELF interpreter segments are outside this shared-library fixture profile",
                ));
            }
            _ => {}
        }
    }
    if !load || !dynamic {
        return Err(failure(
            "fixture requires both PT_LOAD and PT_DYNAMIC segments",
        ));
    }
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn failure(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(arch: Architecture) -> Vec<u8> {
        let mut bytes = vec![0; 64 + 2 * 56];
        bytes[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(
            &(if arch == Architecture::Aarch64 {
                183_u16
            } else {
                62_u16
            })
            .to_le_bytes(),
        );
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[96..104].copy_from_slice(&176_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&176_u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&2_u32.to_le_bytes());
        bytes
    }

    #[test]
    fn narrow_header_preflight_checks_class_endianness_type_and_machine() {
        for arch in [Architecture::Aarch64, Architecture::X86_64] {
            validate_elf(&header(arch), arch).unwrap();
        }
        for (offset, value) in [
            (0, 0),
            (4, 1),
            (5, 2),
            (6, 0),
            (7, 9),
            (16, 2),
            (18, 0),
            (20, 0),
            (52, 0),
        ] {
            let mut bytes = header(Architecture::Aarch64);
            bytes[offset] = value;
            assert!(
                validate_elf(&bytes, Architecture::Aarch64).is_err(),
                "offset {offset}"
            );
        }
        assert!(validate_elf(&header(Architecture::X86_64), Architecture::Aarch64).is_err());
        assert!(validate_elf(&[0; 63], Architecture::Aarch64).is_err());
    }

    #[test]
    fn program_headers_reject_ranges_and_unsupported_mapping_shapes() {
        for (offset, value) in [(32, u64::MAX), (96, u64::MAX), (104, 1)] {
            let mut bytes = header(Architecture::Aarch64);
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(validate_elf(&bytes, Architecture::Aarch64).is_err());
        }
        for (offset, value) in [(64, 3_u32), (68, 7), (120, 0)] {
            let mut bytes = header(Architecture::Aarch64);
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(validate_elf(&bytes, Architecture::Aarch64).is_err());
        }
    }

    #[test]
    fn scaffold_manifest_validates_without_claiming_runtime_acquisition() {
        let manifest = fixture_manifest(b"dependency", b"module", Architecture::Aarch64);
        manifest.validate().unwrap();
        assert_eq!(
            manifest.runtimes["scaffold"].build_id,
            "unacquired-fixture-scaffold"
        );
        assert!(
            manifest
                .native_modules
                .values()
                .all(|module| module.runtime.is_none())
        );
    }

    #[test]
    fn matching_archive_hashes_do_not_let_corrupted_or_truncated_elf_pass_preflight() {
        use std::io::Cursor;

        let dependency = header(Architecture::Aarch64);
        let mut corrupted = header(Architecture::Aarch64);
        corrupted[4] = 1; // ELF32 declaration is outside this profile.
        let truncated = header(Architecture::Aarch64)[..63].to_vec();
        for module in [corrupted, truncated] {
            let manifest = fixture_manifest(&dependency, &module, Architecture::Aarch64);
            let resources = BTreeMap::from([
                (DEPENDENCY_RESOURCE.to_owned(), dependency.clone()),
                (MODULE_RESOURCE.to_owned(), module.clone()),
                (SCAFFOLD_RESOURCE.to_owned(), SCAFFOLD_BYTES.to_vec()),
            ]);
            let output = write_archive(Cursor::new(Vec::new()), &manifest, &resources).unwrap();
            let mut archive = glue_format::Archive::open(Cursor::new(output.into_inner())).unwrap();
            let verified = archive.read_resource(MODULE_RESOURCE).unwrap();
            assert_eq!(verified, module);
            assert_eq!(
                archive.manifest().resources[MODULE_RESOURCE].sha256,
                digest(&verified)
            );
            // Structural preflight remains mandatory even though archive length,
            // CRC32 and SHA-256 checks all passed. No native loader is called.
            assert!(validate_elf(&verified, Architecture::Aarch64).is_err());
        }
    }
}
