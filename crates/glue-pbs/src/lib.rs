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
