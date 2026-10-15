//! Build-time inspection of pinned stock PBS inputs, without materialization.
//! This crate does not acquire or execute a Python runtime.

pub mod archive;
mod compression;
pub mod metadata;
pub mod pins;
mod projection;

use archive::{Entry, Inventory, Limits};
use metadata::MetadataReport;
use pins::{ArtifactPin, Pins};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::{Read, Seek},
};

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub schema_version: u32,
    pub pins: Pins,
    pub full: ArtifactReport,
    pub metadata: MetadataReport,
    pub install_only: Option<InstallReport>,
    pub bootstrap_observed: bool,
    pub loader_compatibility_validated: bool,
}

#[derive(Debug, Serialize)]
pub struct ArtifactReport {
    pub pin: ArtifactPin,
    pub decompressed_tar_bytes: u64,
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize)]
pub struct InstallReport {
    pub artifact: ArtifactReport,
    pub pairing: projection::PairReport,
}

#[derive(Debug)]
pub struct SelectedInspection {
    pub inspection: Inspection,
    /// Selected exact regular-file payloads, after complete artifact validation.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// An independently pinned install-only inventory and selected regular bytes.
/// This report makes no metadata-pairing or runtime-compatibility claim.
#[derive(Debug)]
pub struct SelectedInstallInspection {
    pub artifact: ArtifactReport,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Inspect the complete independently pinned install-only artifact while
/// retaining selected regular files in bounded memory. No full artifact or
/// target interpreter is consulted. The compressed identity, single gzip
/// stream, entire tar inventory and absence of full-distribution metadata
/// validate before any selected bytes are returned.
pub fn inspect_install_selected<R: Read + Seek>(
    pins: &Pins,
    install_input: &mut R,
    selection: &BTreeSet<String>,
    max_selected_bytes: u64,
) -> Result<SelectedInstallInspection, String> {
    pins.validate()?;
    inspect_install_pin_selected(
        &pins.install_only,
        install_input,
        selection,
        max_selected_bytes,
    )
}

/// Inspect a separately pinned stripped counterpart. This validates the same
/// complete gzip/tar contract without changing the unstripped pin or claiming
/// that stripping preserves runtime compatibility.
pub fn inspect_install_stripped_selected<R: Read + Seek>(
    pins: &Pins,
    stripped_pin: &ArtifactPin,
    install_input: &mut R,
    selection: &BTreeSet<String>,
    max_selected_bytes: u64,
) -> Result<SelectedInstallInspection, String> {
    pins.validate_stripped_install(stripped_pin)?;
    inspect_install_pin_selected(stripped_pin, install_input, selection, max_selected_bytes)
}

/// Inspect one independently pinned gzip install-only artifact for any
/// target and retain selected regular files. The caller validates the pin's
/// identity, URL and target; this checks the compressed bytes, single gzip
/// stream, complete tar inventory and absence of full-distribution metadata.
pub fn inspect_install_pin_selected<R: Read + Seek>(
    pin: &ArtifactPin,
    install_input: &mut R,
    selection: &BTreeSet<String>,
    max_selected_bytes: u64,
) -> Result<SelectedInstallInspection, String> {
    let selected = compression::inspect_selected(
        install_input,
        pin,
        compression::Compression::Gzip,
        &Limits::default(),
        selection,
        max_selected_bytes,
    )?;
    if selected
        .inventory
        .entries
        .contains_key("python/PYTHON.json")
    {
        return Err("install-only archive unexpectedly contains PYTHON.json".into());
    }
    Ok(SelectedInstallInspection {
        artifact: artifact_report(pin.clone(), selected.inventory),
        files: selected.files,
    })
}

/// Inspect the pinned full PBS artifact and retain selected regular-file bytes
/// in bounded memory. Selection never follows aliases or writes host files.
/// The compressed pin, complete tar inventory and stock metadata all validate
/// before any selected payload is returned to the caller.
pub fn inspect_full_selected<R: Read + Seek>(
    pins: &Pins,
    full_input: &mut R,
    selection: &BTreeSet<String>,
    max_selected_bytes: u64,
) -> Result<SelectedInspection, String> {
    pins.validate()?;
    let selected = compression::inspect_selected(
        full_input,
        &pins.full,
        compression::Compression::Zstd,
        &Limits::default(),
        selection,
        max_selected_bytes,
    )?;
    let metadata = metadata::inspect_metadata(
        &selected.inventory,
        &pins.python_version,
        &pins.target_triple,
        &pins.build_options,
    )?;
    Ok(SelectedInspection {
        inspection: Inspection {
            schema_version: 0,
            pins: pins.clone(),
            full: artifact_report(pins.full.clone(), selected.inventory),
            metadata,
            install_only: None,
            bootstrap_observed: false,
            loader_compatibility_validated: false,
        },
        files: selected.files,
    })
}

/// Inspect already downloaded inputs. No downloads, filesystem output, runtime
/// acquisition, Python execution or manifest conversion take place here.
pub fn inspect<R: Read + Seek>(
    pins: &Pins,
    full_input: &mut R,
    install_input: Option<&mut R>,
) -> Result<Inspection, String> {
    pins.validate()?;
    let limits = Limits::default();
    let full = compression::inspect(
        full_input,
        &pins.full,
        compression::Compression::Zstd,
        &limits,
    )?;
    let metadata = metadata::inspect_metadata(
        &full,
        &pins.python_version,
        &pins.target_triple,
        &pins.build_options,
    )?;
    let install_only = if let Some(input) = install_input {
        let install = compression::inspect(
            input,
            &pins.install_only,
            compression::Compression::Gzip,
            &limits,
        )?;
        if install.metadata.is_some() {
            return Err("install-only archive unexpectedly contains PYTHON.json".into());
        }
        let pairing = projection::compare(&full, &install, &metadata.stdlib, &pins.revision)?;
        Some(InstallReport {
            artifact: artifact_report(pins.install_only.clone(), install),
            pairing,
        })
    } else {
        None
    };
    Ok(Inspection {
        schema_version: 0,
        pins: pins.clone(),
        full: artifact_report(pins.full.clone(), full),
        metadata,
        install_only,
        bootstrap_observed: false,
        loader_compatibility_validated: false,
    })
}

fn artifact_report(pin: ArtifactPin, inventory: Inventory) -> ArtifactReport {
    ArtifactReport {
        pin,
        decompressed_tar_bytes: inventory.decompressed_bytes,
        entries: inventory.entries,
    }
}

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Reject duplicate object keys before typed deserialization. The JSON byte and
// recursion limits are enforced by each caller and serde_json respectively.
pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value, String> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value =
        UniqueValue::deserialize(&mut decoder).map_err(|error| format!("invalid JSON: {error}"))?;
    decoder
        .end()
        .map_err(|error| format!("invalid JSON tail: {error}"))?;
    Ok(value.0)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|v| UniqueValue(Value::Number(v)))
                    .ok_or_else(|| E::custom("nonfinite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Self::Value, A::Error> {
                let mut result = Vec::new();
                while let Some(value) = values.next_element::<UniqueValue>()? {
                    result.push(value.0);
                }
                Ok(UniqueValue(Value::Array(result)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<Self::Value, A::Error> {
                let mut result = serde_json::Map::new();
                let mut seen = BTreeSet::new();
                while let Some(key) = values.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
                    }
                    result.insert(key, values.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(result)))
            }
        }
        decoder.deserialize_any(UniqueVisitor)
    }
}

#[cfg(test)]
mod install_selected_tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Write};

    fn tar(entries: &[(&str, u8, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, kind, payload, link) in entries {
            let mut header = [0u8; 512];
            header[..path.len()].copy_from_slice(path.as_bytes());
            header[100..108].copy_from_slice(b"0000644\0");
            header[124..136].copy_from_slice(format!("{:011o}\0", payload.len()).as_bytes());
            header[148..156].fill(b' ');
            header[156] = *kind;
            if let Some(link) = link {
                header[157..157 + link.len()].copy_from_slice(link.as_bytes());
            }
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&header);
            tar.extend_from_slice(payload);
            tar.resize(tar.len() + (512 - payload.len() % 512) % 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        tar
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn pins(payload: &[u8]) -> Pins {
        let mut pins =
            Pins::from_json(include_bytes!("../../../fixtures/python-pbs/pins.json")).unwrap();
        pins.install_only.size = payload.len() as u64;
        pins.install_only.sha256 = hex_digest(&Sha256::digest(payload));
        pins
    }

    #[test]
    fn independently_pinned_install_selection_hashes_every_unselected_member() {
        let payload = gzip(&tar(&[
            ("python/a", b'0', b"selected", None),
            ("python/b", b'0', b"unselected", None),
        ]));
        let pins = pins(&payload);
        let selected = inspect_install_selected(
            &pins,
            &mut Cursor::new(payload),
            &BTreeSet::from(["python/a".into()]),
            8,
        )
        .unwrap();
        assert_eq!(
            selected.files,
            BTreeMap::from([("python/a".into(), b"selected".to_vec())])
        );
        assert_eq!(selected.artifact.entries.len(), 2);
        assert_eq!(
            selected.artifact.entries["python/b"].sha256,
            Some(hex_digest(&Sha256::digest(b"unselected")))
        );
        assert_eq!(selected.artifact.pin.sha256, pins.install_only.sha256);
        assert_eq!(selected.artifact.decompressed_tar_bytes, 3072);
    }

    #[test]
    fn stripped_selection_has_a_separate_pin_and_checks_complete_input() {
        let payload = gzip(&tar(&[
            ("python/a", b'0', b"selected", None),
            ("python/b", b'0', b"unselected", None),
        ]));
        let pins = pins(&payload);
        let mut stripped = pins.install_only.clone();
        stripped.filename = stripped
            .filename
            .replace("install_only", "install_only_stripped");
        stripped.url = stripped
            .url
            .replace("install_only", "install_only_stripped");
        let selected = inspect_install_stripped_selected(
            &pins,
            &stripped,
            &mut Cursor::new(&payload),
            &BTreeSet::from(["python/a".into()]),
            8,
        )
        .unwrap();
        assert_eq!(selected.artifact.pin.filename, stripped.filename);
        assert_eq!(selected.files["python/a"], b"selected");
        assert_eq!(
            selected.artifact.entries["python/b"].sha256,
            Some(hex_digest(&Sha256::digest(b"unselected")))
        );
        assert!(
            inspect_install_stripped_selected(
                &pins,
                &pins.install_only,
                &mut Cursor::new(&payload),
                &BTreeSet::new(),
                0,
            )
            .is_err()
        );
        stripped.sha256 = "0".repeat(64);
        assert!(
            inspect_install_stripped_selected(
                &pins,
                &stripped,
                &mut Cursor::new(&payload),
                &BTreeSet::new(),
                0,
            )
            .unwrap_err()
            .contains("SHA-256")
        );
    }

    #[test]
    fn unexpected_full_metadata_rejects_after_complete_install_inspection() {
        let payload = gzip(&tar(&[("python/PYTHON.json", b'0', b"{}", None)]));
        assert!(
            inspect_install_selected(
                &pins(&payload),
                &mut Cursor::new(payload),
                &BTreeSet::new(),
                0
            )
            .unwrap_err()
            .contains("unexpectedly contains PYTHON.json")
        );
    }

    #[test]
    fn nonregular_full_metadata_candidates_are_also_absent_from_install_inputs() {
        for (kind, link) in [
            (b'5', None),
            (b'2', Some("else.json")),
            (b'1', Some("python/else.json")),
        ] {
            let payload = gzip(&tar(&[
                ("python/PYTHON.json", kind, b"", link),
                ("python/else.json", b'0', b"{}", None),
            ]));
            assert!(
                inspect_install_selected(
                    &pins(&payload),
                    &mut Cursor::new(payload),
                    &BTreeSet::new(),
                    0
                )
                .unwrap_err()
                .contains("unexpectedly contains PYTHON.json")
            );
        }
    }

    #[test]
    fn compressed_identity_rejects_before_the_gzip_parser() {
        let payload = b"not a gzip stream".to_vec();
        let mut pins = pins(&payload);
        pins.install_only.sha256 = "0".repeat(64);
        assert!(
            inspect_install_selected(&pins, &mut Cursor::new(payload), &BTreeSet::new(), 0)
                .unwrap_err()
                .contains("differs from pin")
        );
    }

    #[test]
    fn trailing_compressed_data_and_second_members_cannot_return_selected_bytes() {
        let first = gzip(&tar(&[("python/a", b'0', b"a", None)]));
        let second = gzip(&tar(&[("python/b", b'0', b"b", None)]));
        for tail in [b"tail".to_vec(), second] {
            let mut payload = first.clone();
            payload.extend_from_slice(&tail);
            assert!(
                inspect_install_selected(
                    &pins(&payload),
                    &mut Cursor::new(payload),
                    &BTreeSet::from(["python/a".into()]),
                    1
                )
                .unwrap_err()
                .contains("trailing data")
            );
        }
    }

    #[test]
    fn selected_install_bytes_remain_bounded_and_never_follow_aliases() {
        let payload = gzip(&tar(&[
            ("python/a", b'0', b"aa", None),
            ("python/b", b'0', b"bb", None),
        ]));
        let pins = pins(&payload);
        let selection = BTreeSet::from(["python/a".into(), "python/b".into()]);
        assert!(
            inspect_install_selected(&pins, &mut Cursor::new(&payload), &selection, 3)
                .unwrap_err()
                .contains("selected")
        );
        assert!(
            inspect_install_selected(
                &pins,
                &mut Cursor::new(&payload),
                &selection,
                archive::MAX_SELECTED_BYTES + 1
            )
            .unwrap_err()
            .contains("128 MiB")
        );
        assert!(
            inspect_install_selected(
                &pins,
                &mut Cursor::new(&payload),
                &BTreeSet::from(["python/missing".into()]),
                1
            )
            .unwrap_err()
            .contains("absent")
        );
        let alias = gzip(&tar(&[
            ("python/a", b'2', b"", Some("b")),
            ("python/b", b'0', b"b", None),
        ]));
        assert!(
            inspect_install_selected(
                &self::pins(&alias),
                &mut Cursor::new(alias),
                &BTreeSet::from(["python/a".into()]),
                1
            )
            .unwrap_err()
            .contains("not a regular file")
        );
    }

    #[test]
    fn malformed_later_tar_members_prevent_returning_earlier_valid_selection() {
        let mut bytes = tar(&[("python/a", b'0', b"a", None)]);
        bytes.truncate(bytes.len() - 513);
        let payload = gzip(&bytes);
        assert!(
            inspect_install_selected(
                &pins(&payload),
                &mut Cursor::new(payload),
                &BTreeSet::from(["python/a".into()]),
                1
            )
            .is_err()
        );
    }
}
