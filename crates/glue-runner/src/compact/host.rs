//! Check declared host requirements before entering application code.
use super::{Result, error};
use glue_format::{DiagnosticCode, DistributionSpec, NativeInventory};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Default)]
struct Capabilities {
    version: Option<String>,
    cpu: BTreeSet<String>,
    versions: BTreeMap<String, BTreeSet<String>>,
}
fn numeric(value: &str) -> Result<Vec<u32>> {
    let mut result = Vec::new();
    for part in value.split('.').take(3) {
        let number: String = part.chars().take_while(char::is_ascii_digit).collect();
        if number.is_empty() {
            return Err(error(
                DiagnosticCode::InvalidConfiguration,
                format!("invalid OS requirement {value:?}"),
            ));
        }
        result.push(
            number
                .parse()
                .map_err(|_| error(DiagnosticCode::InvalidConfiguration, "OS version overflow"))?,
        );
    }
    while result.len() < 3 {
        result.push(0);
    }
    Ok(result)
}
fn bounded_read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(max + 1).read_to_end(&mut bytes))
        .map_err(|e| {
            error(
                DiagnosticCode::MissingDependency,
                format!("host prerequisite {}: {e}", path.display()),
            )
        })?;
    if bytes.len() as u64 > max {
        return Err(error(
            DiagnosticCode::ResourceLimit,
            "host prerequisite exceeds inspection bound",
        ));
    }
    Ok(bytes)
}
fn macos_version() -> Result<String> {
    glue_runtime_lua::profile::macos_product_version().map_err(|query_error| {
        let (glue_runtime_lua::profile::CapabilityError::Unsupported(message)
        | glue_runtime_lua::profile::CapabilityError::Invalid(message)) = query_error;
        error(DiagnosticCode::MissingDependency, message)
    })
}
fn required_versions(inventory: &NativeInventory) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut result = BTreeMap::<String, BTreeSet<String>>::new();
    for r in &inventory.host_requirements {
        if let Some(spec) = r.strip_prefix("elf-version:") {
            let (library, version) = spec.rsplit_once(':').ok_or_else(|| {
                error(
                    DiagnosticCode::InvalidConfiguration,
                    "invalid ELF version requirement",
                )
            })?;
            if library.is_empty() || library.contains('/') || version.is_empty() {
                return Err(error(
                    DiagnosticCode::InvalidConfiguration,
                    "invalid host ELF library/version requirement",
                ));
            }
            result
                .entry(library.into())
                .or_default()
                .insert(version.into());
        }
    }
    Ok(result)
}
fn inspect(target: &str, inventory: &NativeInventory) -> Result<Capabilities> {
    let mut result = Capabilities::default();
    if inventory
        .host_requirements
        .iter()
        .any(|r| r.starts_with("linux>="))
    {
        result.version = Some(
            String::from_utf8(bounded_read(Path::new("/proc/sys/kernel/osrelease"), 4096)?)
                .map_err(|e| error(DiagnosticCode::MissingDependency, e.to_string()))?
                .trim()
                .to_owned(),
        );
    }
    if inventory
        .host_requirements
        .iter()
        .any(|r| r.starts_with("macos>="))
    {
        result.version = Some(macos_version()?);
    }
    if target.starts_with("x86_64-") {
        result.cpu.insert("x86_64_isa_v1".into());
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // Only the first processor's flags are needed. Large HPC hosts can
            // expose megabytes of processor records; inspect a bounded prefix.
            let mut prefix = Vec::new();
            File::open("/proc/cpuinfo")
                .and_then(|f| f.take(64 * 1024).read_to_end(&mut prefix))
                .map_err(|e| error(DiagnosticCode::MissingDependency, e.to_string()))?;
            let text = String::from_utf8_lossy(&prefix);
            let flags: BTreeSet<_> = text
                .lines()
                .find_map(|l| {
                    l.strip_prefix("flags")
                        .and_then(|s| s.split_once(':'))
                        .map(|(_, s)| s.split_whitespace().collect())
                })
                .unwrap_or_default();
            if [
                "cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3",
            ]
            .iter()
            .all(|f| flags.contains(f))
            {
                result.cpu.insert("x86_64_isa_v2".into());
                if [
                    "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "movbe", "xsave",
                ]
                .iter()
                .all(|f| flags.contains(f))
                    && std::is_x86_feature_detected!("avx")
                    && std::is_x86_feature_detected!("lzcnt")
                {
                    result.cpu.insert("x86_64_isa_v3".into());
                    if ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"]
                        .iter()
                        .all(|f| flags.contains(f))
                    {
                        result.cpu.insert("x86_64_isa_v4".into());
                    }
                }
            }
        }
    }
    let triplet = if target.starts_with("aarch64-") {
        "aarch64-linux-gnu"
    } else {
        "x86_64-linux-gnu"
    };
    for (library, _) in required_versions(inventory)? {
        let candidates = [
            format!("/lib/{triplet}/{library}"),
            format!("/usr/lib/{triplet}/{library}"),
            format!("/lib64/{library}"),
            format!("/usr/lib64/{library}"),
            format!("/lib/{library}"),
            format!("/usr/lib/{library}"),
        ];
        let path=candidates.into_iter().map(PathBuf::from).find(|p|p.is_file()).ok_or_else(||error(DiagnosticCode::MissingDependency,format!("declared OS library {library} was not found in target system library directories")))?;
        let facts = glue_pack::native::linux::inspect_link_contract(&bounded_read(
            &path,
            64 * 1024 * 1024,
        )?)?;
        result.versions.insert(library, facts.version_definitions);
    }
    Ok(result)
}
fn validate(inventory: &NativeInventory, caps: &Capabilities) -> Result<()> {
    for requirement in &inventory.host_requirements {
        if let Some(floor) = requirement
            .strip_prefix("linux>=")
            .or_else(|| requirement.strip_prefix("macos>="))
        {
            let actual = caps.version.as_ref().ok_or_else(|| {
                error(
                    DiagnosticCode::MissingDependency,
                    "host OS version could not be established",
                )
            })?;
            if numeric(actual)? < numeric(floor)? {
                return Err(error(
                    DiagnosticCode::TargetMismatch,
                    format!("host OS {actual} does not satisfy {requirement}"),
                ));
            }
        }
    }
    for feature in &inventory.features {
        if feature.starts_with("x86_64_unknown_isa_mask:") {
            return Err(error(
                DiagnosticCode::UnsupportedCapability,
                format!("cannot establish CPU compatibility for {feature}"),
            ));
        }
        if feature.starts_with("x86_64_isa_v") && !caps.cpu.contains(feature) {
            return Err(error(
                DiagnosticCode::TargetMismatch,
                format!("host CPU does not satisfy {feature}"),
            ));
        }
    }
    for (library, required) in required_versions(inventory)? {
        let supplied = caps.versions.get(&library).ok_or_else(|| {
            error(
                DiagnosticCode::MissingDependency,
                format!("host library {library} is unavailable"),
            )
        })?;
        let missing: Vec<_> = required.difference(supplied).collect();
        if !missing.is_empty() {
            return Err(error(
                DiagnosticCode::RuntimeAbiMismatch,
                format!("host library {library} lacks required versions {missing:?}"),
            ));
        }
    }
    Ok(())
}
pub(super) fn check(spec: &DistributionSpec) -> Result<()> {
    let caps = inspect(&spec.runtime.target, &spec.native)?;
    validate(&spec.native, &caps)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn macos_floor_keeps_numeric_ordering_zero_padding_and_error_codes() {
        let mut inventory = NativeInventory::default();
        inventory.host_requirements.insert("macos>=26.7.0".into());
        for actual in ["26.7", "26.7.0", "26.7.1", "26.10", "27"] {
            let caps = Capabilities {
                version: Some(actual.into()),
                ..Capabilities::default()
            };
            validate(&inventory, &caps).unwrap();
        }
        for actual in ["26.6.99", "26", "25.99"] {
            let caps = Capabilities {
                version: Some(actual.into()),
                ..Capabilities::default()
            };
            assert_eq!(
                validate(&inventory, &caps).unwrap_err().code,
                DiagnosticCode::TargetMismatch
            );
        }
        assert_eq!(
            validate(&inventory, &Capabilities::default())
                .unwrap_err()
                .code,
            DiagnosticCode::MissingDependency
        );
        inventory.host_requirements = BTreeSet::from(["macos>=4294967296.0".into()]);
        let caps = Capabilities {
            version: Some("26.7".into()),
            ..Capabilities::default()
        };
        assert_eq!(
            validate(&inventory, &caps).unwrap_err().code,
            DiagnosticCode::InvalidConfiguration
        );
    }

    #[test]
    fn rejects_missing_versions_os_floor_and_cpu_before_application() {
        let mut i = NativeInventory::default();
        let mut caps = Capabilities {
            version: Some("6.1.0-test".into()),
            cpu: BTreeSet::from(["x86_64_isa_v1".into()]),
            versions: BTreeMap::from([("libc.so.6".into(), BTreeSet::from(["GLIBC_2.17".into()]))]),
        };
        i.host_requirements.insert("linux>=6.2.0".into());
        assert_eq!(
            validate(&i, &caps).unwrap_err().code,
            DiagnosticCode::TargetMismatch
        );
        i.host_requirements.clear();
        i.features.insert("x86_64_isa_v3".into());
        assert_eq!(
            validate(&i, &caps).unwrap_err().code,
            DiagnosticCode::TargetMismatch
        );
        caps.cpu.insert("x86_64_isa_v3".into());
        i.host_requirements
            .insert("elf-version:libc.so.6:GLIBC_2.38".into());
        assert_eq!(
            validate(&i, &caps).unwrap_err().code,
            DiagnosticCode::RuntimeAbiMismatch
        );
        caps.versions
            .get_mut("libc.so.6")
            .unwrap()
            .insert("GLIBC_2.38".into());
        validate(&i, &caps).unwrap();
    }
}
