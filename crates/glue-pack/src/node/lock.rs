//! Lockfiles are provenance, never an instruction to install or replace bytes.
use super::{PackageRecord, error};
use crate::distribution::Result;
use glue_format::{DiagnosticCode, InputIdentity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::parser::{Event, Parser};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockDifference {
    pub package: String,
    pub installed: Option<String>,
    pub recorded: Option<String>,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockProvenance {
    pub input: InputIdentity,
    pub format: String,
    pub comparison: String,
    pub differences: Vec<LockDifference>,
}
fn invalid(message: impl Into<String>) -> glue_format::Diagnostic {
    error(DiagnosticCode::InvalidConfiguration, message)
}
enum Frame {
    Map(Map<String, Value>, Option<String>),
    Array(Vec<Value>),
}
fn append(value: Value, stack: &mut [Frame], root: &mut Option<Value>) -> Result<()> {
    if let Some(frame) = stack.last_mut() {
        match frame {
            Frame::Array(items) => items.push(value),
            Frame::Map(map, key) => {
                if let Some(key) = key.take() {
                    if map.insert(key, value).is_some() {
                        return Err(invalid("duplicate YAML lock key"));
                    }
                } else {
                    *key = Some(
                        value
                            .as_str()
                            .ok_or_else(|| invalid("YAML lock mapping keys must be strings"))?
                            .into(),
                    );
                }
            }
        }
    } else if root.replace(value).is_some() {
        return Err(invalid("multiple YAML lock roots"));
    }
    Ok(())
}
/// Iterate tokens instead of recursive document loading. Never expand aliases.
fn yaml(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("pnpm lock is not UTF-8"))?;
    let mut parser = Parser::new_from_str(text);
    let mut stack = Vec::new();
    let mut root = None;
    let mut documents = 0;
    for _ in 0..500_000 {
        let (event, _) = parser
            .next_token()
            .map_err(|e| invalid(format!("pnpm lock: {e}")))?;
        match event {
            Event::StreamStart | Event::DocumentEnd | Event::Nothing => (),
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(invalid("pnpm lock must have one YAML document"));
                }
            }
            Event::Scalar(value, _, anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(invalid("pnpm lock anchors and tags are unsupported"));
                }
                append(Value::String(value), &mut stack, &mut root)?;
            }
            Event::Alias(_) => return Err(invalid("pnpm lock aliases are unsupported")),
            Event::MappingStart(anchor, ref tag) | Event::SequenceStart(anchor, ref tag) => {
                if stack.len() >= 64 {
                    return Err(error(
                        DiagnosticCode::ResourceLimit,
                        "pnpm lock exceeds 64 levels",
                    ));
                }
                if anchor != 0 || tag.is_some() {
                    return Err(invalid("pnpm lock anchors and tags are unsupported"));
                }
                stack.push(if matches!(event, Event::MappingStart(..)) {
                    Frame::Map(Map::new(), None)
                } else {
                    Frame::Array(Vec::new())
                });
            }
            Event::MappingEnd => {
                let Some(Frame::Map(map, None)) = stack.pop() else {
                    return Err(invalid("invalid pnpm mapping"));
                };
                append(Value::Object(map), &mut stack, &mut root)?;
            }
            Event::SequenceEnd => {
                let Some(Frame::Array(items)) = stack.pop() else {
                    return Err(invalid("invalid pnpm sequence"));
                };
                append(Value::Array(items), &mut stack, &mut root)?;
            }
            Event::StreamEnd => {
                return root
                    .filter(|_| stack.is_empty())
                    .ok_or_else(|| invalid("incomplete pnpm lock"));
            }
        }
    }
    Err(error(
        DiagnosticCode::ResourceLimit,
        "pnpm lock exceeds 500,000 tokens",
    ))
}
fn difference(
    out: &mut Vec<LockDifference>,
    package: String,
    installed: Option<&str>,
    recorded: Option<&str>,
    reason: &str,
) {
    out.push(LockDifference {
        package,
        installed: installed.map(str::to_owned),
        recorded: recorded.map(str::to_owned),
        reason: reason.into(),
    });
}
fn npm(
    lock: &Value,
    installed: &BTreeMap<String, Value>,
    out: &mut Vec<LockDifference>,
) -> Result<bool> {
    let Some(records) = lock.get("packages").and_then(Value::as_object) else {
        return Ok(false);
    };
    for (path, metadata) in installed {
        if path.is_empty() {
            continue;
        }
        let actual = metadata.get("version").and_then(Value::as_str);
        let expected = records
            .get(path)
            .and_then(|v| v.get("version"))
            .and_then(Value::as_str);
        if expected != actual {
            difference(
                out,
                path.clone(),
                actual,
                expected,
                if expected.is_some() {
                    "installed_version_differs"
                } else {
                    "installed_package_not_locked"
                },
            );
        }
    }
    for (path, value) in records {
        if path.is_empty() || value.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if !installed.contains_key(path) {
            difference(
                out,
                path.clone(),
                None,
                value.get("version").and_then(Value::as_str),
                "locked_package_not_installed",
            );
        }
    }
    Ok(true)
}
fn pnpm(
    lock: &Value,
    installed: &BTreeMap<String, Value>,
    packages: &BTreeMap<String, PackageRecord>,
    out: &mut Vec<LockDifference>,
) -> Result<bool> {
    let Some(importers) = lock.get("importers").and_then(Value::as_object) else {
        return Ok(false);
    };
    for (owner, importer) in importers {
        let owner = if owner == "." { "" } else { owner.as_str() };
        let Some(package) = packages.get(owner) else {
            difference(out, owner.into(), None, None, "locked_importer_not_present");
            continue;
        };
        let mut locked = BTreeSet::new();
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Some(deps) = importer.get(section).and_then(Value::as_object) else {
                continue;
            };
            for (name, record) in deps {
                locked.insert(name.clone());
                let expected = record
                    .as_str()
                    .or_else(|| record.get("version").and_then(Value::as_str));
                let actual = package
                    .dependencies
                    .get(name)
                    .and_then(|target| installed.get(target))
                    .and_then(|v| v.get("version"))
                    .and_then(Value::as_str);
                if expected.is_some_and(|v| {
                    v.starts_with("link:") || v.starts_with("file:") || v.starts_with("workspace:")
                }) {
                    continue;
                }
                let expected = expected.map(|v| v.split('(').next().unwrap());
                let expected =
                    expected.map(|v| v.rsplit_once('@').map_or(v, |(_, version)| version));
                if expected.is_some_and(|v| {
                    v.starts_with("link:") || v.starts_with("file:") || v.starts_with("workspace:")
                }) {
                    continue;
                }
                if actual != expected {
                    difference(
                        out,
                        format!("{owner}:{name}"),
                        actual,
                        expected,
                        if actual.is_none() {
                            "locked_dependency_not_installed"
                        } else {
                            "installed_version_differs"
                        },
                    );
                }
            }
        }
        for (name, target) in &package.dependencies {
            if !locked.contains(name) {
                difference(
                    out,
                    format!("{owner}:{name}"),
                    installed
                        .get(target)
                        .and_then(|v| v.get("version"))
                        .and_then(Value::as_str),
                    None,
                    "installed_dependency_not_locked",
                );
            }
        }
    }
    if let Some(records) = lock.get("packages").and_then(Value::as_object) {
        let locked: BTreeSet<_> = records
            .keys()
            .map(|k| {
                k.trim_start_matches('/')
                    .split('(')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        for (path, metadata) in installed {
            if !path.contains("node_modules/") {
                continue;
            }
            if let (Some(name), Some(version)) = (
                metadata.get("name").and_then(Value::as_str),
                metadata.get("version").and_then(Value::as_str),
            ) {
                if !locked.contains(&format!("{name}@{version}")) {
                    difference(
                        out,
                        path.clone(),
                        Some(version),
                        None,
                        "installed_package_version_not_in_lock_packages",
                    );
                }
            }
        }
    }
    Ok(true)
}
pub fn collect(
    files: &BTreeMap<String, Vec<u8>>,
    installed: &BTreeMap<String, Value>,
    packages: &BTreeMap<String, PackageRecord>,
) -> Result<BTreeMap<String, LockProvenance>> {
    let mut reports = BTreeMap::new();
    for name in [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    ] {
        let Some(bytes) = files.get(name) else {
            continue;
        };
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(error(
                DiagnosticCode::ResourceLimit,
                "Node lockfile exceeds 8 MiB",
            ));
        }
        let mut report = LockProvenance {
            input: InputIdentity::of(bytes),
            format: if name == "pnpm-lock.yaml" {
                "pnpm"
            } else if name == "yarn.lock" {
                "yarn"
            } else {
                "npm"
            }
            .into(),
            comparison: "unrecognized_lock_shape".into(),
            differences: vec![],
        };
        let compared = if name == "pnpm-lock.yaml" {
            pnpm(&yaml(bytes)?, installed, packages, &mut report.differences)?
        } else if name == "yarn.lock" {
            false
        } else {
            let value =
                serde_json::from_slice(bytes).map_err(|e| invalid(format!("{name}: {e}")))?;
            npm(&value, installed, &mut report.differences)?
        };
        if compared {
            report.comparison = if report.differences.is_empty() {
                "versions_and_presence_match"
            } else {
                "installed_graph_differs"
            }
            .into();
        }
        reports.insert(name.into(), report);
    }
    Ok(reports)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn yaml_token_bounds_and_unsupported_features() {
        assert_eq!(
            yaml(b"importers:\n  .:\n    dependencies: {}\n").unwrap()["importers"]["."]["dependencies"],
            serde_json::json!({})
        );
        assert!(yaml(b"a: &x value\nb: *x\n").is_err());
        assert!(yaml(b"a: x\na: y\n").is_err());
        let deep = format!("{}value{}", "[".repeat(65), "]".repeat(65));
        assert_eq!(
            yaml(deep.as_bytes()).unwrap_err().code,
            DiagnosticCode::ResourceLimit
        );
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    fn installed() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("".into(), serde_json::json!({"name":"app"})),
            (
                "node_modules/dep".into(),
                serde_json::json!({"name":"dep","version":"2.0.0"}),
            ),
        ])
    }
    fn packages() -> BTreeMap<String, PackageRecord> {
        BTreeMap::from([(
            "".into(),
            PackageRecord {
                name: "app".into(),
                package_type: "commonjs".into(),
                main: None,
                exports: None,
                imports: None,
                dependencies: BTreeMap::from([("dep".into(), "node_modules/dep".into())]),
            },
        )])
    }
    #[test]
    fn npm_and_pnpm_discrepancies_keep_installed_bytes_authoritative() {
        for(name,bytes)in[("package-lock.json",br#"{"lockfileVersion":3,"packages":{"node_modules/dep":{"version":"1.0.0"}}}"#.as_slice()),("pnpm-lock.yaml",b"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      dep:\n        specifier: ^1\n        version: 1.0.0\npackages:\n  dep@1.0.0: {}\n".as_slice())]{let reports=collect(&BTreeMap::from([(name.into(),bytes.to_vec())]),&installed(),&packages()).unwrap();let report=&reports[name];assert_eq!(report.input,InputIdentity::of(bytes));assert_eq!(report.comparison,"installed_graph_differs");assert!(report.differences.iter().any(|d|d.installed.as_deref()==Some("2.0.0")&&d.reason.contains("differs")));}
    }
    #[test]
    fn matching_modern_lock_graph_and_local_links() {
        let npm = br#"{"lockfileVersion":3,"packages":{"node_modules/dep":{"version":"2.0.0"}}}"#;
        let pnpm=b"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      dep:\n        version: 2.0.0(peer@1)\npackages:\n  dep@2.0.0: {}\n";
        for (name, bytes) in [
            ("package-lock.json", npm.as_slice()),
            ("pnpm-lock.yaml", pnpm.as_slice()),
        ] {
            let report = collect(
                &BTreeMap::from([(name.into(), bytes.to_vec())]),
                &installed(),
                &packages(),
            )
            .unwrap();
            assert_eq!(report[name].comparison, "versions_and_presence_match");
            assert!(report[name].differences.is_empty());
        }
    }
}
