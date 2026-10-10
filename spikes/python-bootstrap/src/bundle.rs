//! Portable identity and size checks for the fixed PBS bootstrap fixture.

use glue_pbs::{Inspection, archive::EntryKind};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_MARSHAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_APP_BYTES: usize = 64 * 1024;

pub(super) const PYTHON_VERSION: &str = "3.13.16";
pub(super) const TARGET_TRIPLE: &str = "aarch64-unknown-linux-gnu";
pub(super) const FULL_SHA256: &str =
    "8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca";
pub(super) const INSTALL_ONLY_SHA256: &str =
    "397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34";
pub(super) const METADATA_SHA256: &str =
    "2be93f8346d647c46a9c5133cddb403d757a564ce1ec4039239ce9008fd763dc";
pub(super) const RUNTIME_LIBRARY_SHA256: &str =
    "42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219";
pub(super) const EXECUTABLE_SHA256: &str =
    "1abe8738dd82558ba7884a0dd00bb8e9561ad0b85a3ddd3d755999c2dd878d45";
pub(super) const RUNTIME_LIBRARY_PATH: &str = "python/install/lib/libpython3.13.so.1.0";
const EXECUTABLE_PATH: &str = "python/install/bin/python3.13";
const APP_PATH: &str = "fixtures/python-bootstrap/app.py";

pub(super) struct ModuleSpec {
    pub name: &'static str,
    pub is_package: bool,
    pub source_path: &'static str,
    pub source_sha256: &'static str,
    pub source_size: u64,
}

// Captured independently from the exact full PBS artifact's regular members.
pub(super) const MODULE_SPECS: [ModuleSpec; 6] = [
    ModuleSpec {
        name: "codecs",
        is_package: false,
        source_path: "install/lib/python3.13/codecs.py",
        source_size: 36978,
        source_sha256: "2f278497548b8313580b247a1097a0a304e5087a355ebb11a92ec685fa9e63ff",
    },
    ModuleSpec {
        name: "encodings",
        is_package: true,
        source_path: "install/lib/python3.13/encodings/__init__.py",
        source_size: 6020,
        source_sha256: "3a8c3b489e90381552e06171f4a03e4097b77a675795974e9b0d10338729003e",
    },
    ModuleSpec {
        name: "encodings.aliases",
        is_package: false,
        source_path: "install/lib/python3.13/encodings/aliases.py",
        source_size: 16011,
        source_sha256: "368bf46e530f71d2defa1e2ff305f7d887584898e624cd36c75413fa23d5b333",
    },
    ModuleSpec {
        name: "encodings.ascii",
        is_package: false,
        source_path: "install/lib/python3.13/encodings/ascii.py",
        source_size: 1248,
        source_sha256: "578aa1173f7cc60dad2895071287fe6182bd14787b3fbf47a6c7983dfe3675e3",
    },
    ModuleSpec {
        name: "encodings.latin_1",
        is_package: false,
        source_path: "install/lib/python3.13/encodings/latin_1.py",
        source_size: 1264,
        source_sha256: "b75503e532a27c636477396c855209ff5f3036536d2a4bede0a576c89382b60c",
    },
    ModuleSpec {
        name: "encodings.utf_8",
        is_package: false,
        source_path: "install/lib/python3.13/encodings/utf_8.py",
        source_size: 1005,
        source_sha256: "ba0cac060269583523ca9506473a755203037c57d466a11aa89a30a5f6756f3d",
    },
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bundle {
    pub schema_version: u32,
    pub producer: Producer,
    pub modules: Vec<Module>,
    pub app: App,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Producer {
    pub python_version: String,
    pub target_triple: String,
    pub full_sha256: String,
    pub install_only_sha256: String,
    pub metadata_sha256: String,
    pub runtime_library_sha256: String,
    pub executable_sha256: String,
    pub bytecode_magic: String,
    pub cache_tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Module {
    pub name: String,
    pub is_package: bool,
    pub source_path: String,
    pub source_sha256: String,
    pub bytecode_sha256: String,
    pub bytecode_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct App {
    pub source_path: String,
    pub source_sha256: String,
    pub source_hex: String,
}

impl Bundle {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_JSON_BYTES {
            return Err("bootstrap bundle exceeds 4 MiB".into());
        }
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let value = UniqueValue::deserialize(&mut decoder)
            .map_err(|error| format!("invalid bootstrap bundle JSON: {error}"))?;
        decoder
            .end()
            .map_err(|error| format!("invalid bootstrap bundle JSON tail: {error}"))?;
        let bundle: Self = serde_json::from_value(value.0)
            .map_err(|error| format!("invalid bootstrap bundle schema: {error}"))?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 0 {
            return Err("bootstrap bundle requires schema version 0".into());
        }
        self.producer.validate()?;
        if self.modules.len() != MODULE_SPECS.len() {
            return Err("bootstrap bundle requires exactly six reviewed modules".into());
        }
        let mut marshal_bytes = 0usize;
        for (module, spec) in self.modules.iter().zip(&MODULE_SPECS) {
            if module.name != spec.name
                || module.source_path != spec.source_path
                || module.source_sha256 != spec.source_sha256
                || module.is_package != spec.is_package
            {
                return Err(format!(
                    "bootstrap module identity/order/package differs from reviewed source {}",
                    spec.name
                ));
            }
            let bytes = module.decode_hex()?;
            marshal_bytes = marshal_bytes
                .checked_add(bytes.len())
                .ok_or("marshal byte count overflow")?;
            if marshal_bytes > MAX_MARSHAL_BYTES {
                return Err("bootstrap module marshal payloads exceed 2 MiB combined".into());
            }
        }
        self.app.decode_hex()?;
        Ok(())
    }

    /// Verify this producer and every pinned upstream source against a complete
    /// stock-artifact inspection before the caller prepares an execution archive.
    pub(super) fn validate_sources(&self, inspection: &Inspection) -> Result<(), String> {
        self.validate()?;
        inspection.pins.validate()?;
        let pins = &inspection.pins;
        if pins.release != "20261009"
            || pins.revision != "ccc07c40c2731bfb459c119f2388f65a5a470de6"
            || pins.python_version != PYTHON_VERSION
            || pins.target_triple != TARGET_TRIPLE
            || pins.full.sha256 != FULL_SHA256
            || pins.full.size != 95_632_430
            || pins.install_only.sha256 != INSTALL_ONLY_SHA256
            || pins.install_only.size != 57_626_877
            || inspection.schema_version != 0
            || inspection.full.pin.filename != pins.full.filename
            || inspection.full.pin.sha256 != pins.full.sha256
            || inspection.full.pin.size != pins.full.size
            || inspection.full.pin.url != pins.full.url
        {
            return Err("bootstrap producer differs from pinned PBS inspection".into());
        }
        require_file(inspection, "python/PYTHON.json", METADATA_SHA256, 127_144)?;
        require_file(
            inspection,
            RUNTIME_LIBRARY_PATH,
            RUNTIME_LIBRARY_SHA256,
            73_563_968,
        )?;
        require_file(inspection, EXECUTABLE_PATH, EXECUTABLE_SHA256, 73_325_136)?;
        let metadata = &inspection.metadata;
        if metadata.path != "python/PYTHON.json"
            || metadata.size != 127_144
            || metadata.sha256 != METADATA_SHA256
            || metadata.python_version != PYTHON_VERSION
            || metadata.target_triple != TARGET_TRIPLE
            || metadata.build_options != "pgo+lto"
            || metadata.libpython_link_mode != "shared"
            || metadata.gil != "conventional"
            || metadata.debug
            || metadata.stdlib != "python/install/lib/python3.13"
            || metadata.runtime_library.path != RUNTIME_LIBRARY_PATH
            || metadata.runtime_library.resolved_path != RUNTIME_LIBRARY_PATH
            || metadata.runtime_library.size != 73_563_968
            || metadata.runtime_library.sha256 != RUNTIME_LIBRARY_SHA256
        {
            return Err(
                "bootstrap producer differs from verified PBS metadata/runtime identity".into(),
            );
        }
        for spec in &MODULE_SPECS {
            require_file(
                inspection,
                &format!("python/{}", spec.source_path),
                spec.source_sha256,
                spec.source_size,
            )?;
        }
        Ok(())
    }
}

impl Producer {
    fn validate(&self) -> Result<(), String> {
        if self.python_version != PYTHON_VERSION
            || self.target_triple != TARGET_TRIPLE
            || self.full_sha256 != FULL_SHA256
            || self.install_only_sha256 != INSTALL_ONLY_SHA256
            || self.metadata_sha256 != METADATA_SHA256
            || self.runtime_library_sha256 != RUNTIME_LIBRARY_SHA256
            || self.executable_sha256 != EXECUTABLE_SHA256
            || self.bytecode_magic != "f30d0d0a"
            || self.cache_tag != "cpython-313"
        {
            return Err(
                "bootstrap bytecode producer identity is not the pinned PBS runtime".into(),
            );
        }
        Ok(())
    }
}

impl Module {
    pub(super) fn decode_hex(&self) -> Result<Vec<u8>, String> {
        let bytes = decode_hex(&self.bytecode_hex, MAX_MARSHAL_BYTES)?;
        if bytes.is_empty() || glue_format::digest(&bytes) != self.bytecode_sha256 {
            return Err(format!(
                "bootstrap module {} marshal payload is empty or differs from its SHA-256",
                self.name
            ));
        }
        Ok(bytes)
    }
}

impl App {
    pub(super) fn decode_hex(&self) -> Result<Vec<u8>, String> {
        if self.source_path != APP_PATH {
            return Err("bootstrap app source path differs from the reviewed fixture path".into());
        }
        let bytes = decode_hex(&self.source_hex, MAX_APP_BYTES)?;
        if bytes.contains(&0)
            || std::str::from_utf8(&bytes).is_err()
            || glue_format::digest(&bytes) != self.source_sha256
        {
            return Err("bootstrap app must be UTF-8 without NUL and match its SHA-256".into());
        }
        Ok(bytes)
    }
}

fn require_file(inspection: &Inspection, path: &str, hash: &str, size: u64) -> Result<(), String> {
    let entry = inspection
        .full
        .entries
        .get(path)
        .ok_or_else(|| format!("verified PBS inspection lacks {path}"))?;
    if entry.kind != EntryKind::RegularFile
        || entry.size != size
        || entry.sha256.as_deref() != Some(hash)
        || entry.link_target.is_some()
        || entry.resolved_target.is_some()
    {
        return Err(format!(
            "verified PBS regular source identity differs at {path}"
        ));
    }
    Ok(())
}

fn decode_hex(hex: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 || hex.len() / 2 > max_bytes {
        return Err(
            "bootstrap hexadecimal payload has odd length or exceeds its byte limit".into(),
        );
    }
    fn nibble(byte: u8) -> Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("bootstrap payload requires lowercase hexadecimal bytes".into()),
        }
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(nibble(pair[0])? * 16 + nibble(pair[1])?))
        .collect()
}

// Preserve serde_json's recursion limit while rejecting duplicate keys before
// constructing the typed contract. Unknown fields are rejected by each struct.
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
                    .map(|number| UniqueValue(Value::Number(number)))
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
mod tests {
    use super::*;
    use glue_pbs::{
        ArtifactReport,
        archive::Entry,
        metadata::{ExtensionCandidate, ExtensionLinkage, FileIdentity, MetadataReport},
        pins::Pins,
    };
    use std::collections::BTreeMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn fixture() -> Value {
        serde_json::json!({
            "schema_version": 0,
            "producer": {
                "python_version": PYTHON_VERSION, "target_triple": TARGET_TRIPLE,
                "full_sha256": FULL_SHA256, "install_only_sha256": INSTALL_ONLY_SHA256,
                "metadata_sha256": METADATA_SHA256, "runtime_library_sha256": RUNTIME_LIBRARY_SHA256,
                "executable_sha256": EXECUTABLE_SHA256, "bytecode_magic": "f30d0d0a", "cache_tag": "cpython-313",
            },
            "modules": MODULE_SPECS.iter().map(|spec| serde_json::json!({
                "name": spec.name, "is_package": spec.is_package,
                "source_path": spec.source_path, "source_sha256": spec.source_sha256,
                "bytecode_sha256": glue_format::digest(b"\xe3fixture"), "bytecode_hex": hex(b"\xe3fixture"),
            })).collect::<Vec<_>>(),
            "app": {"source_path": APP_PATH, "source_sha256": glue_format::digest(b"print('fixture')\n"), "source_hex": hex(b"print('fixture')\n")},
        })
    }

    fn parse(value: &Value) -> Result<Bundle, String> {
        Bundle::parse(&serde_json::to_vec(value).unwrap())
    }

    fn identity(path: &str, digest: &str, size: u64) -> FileIdentity {
        FileIdentity {
            path: path.into(),
            resolved_path: path.into(),
            sha256: digest.into(),
            size,
        }
    }

    fn candidate(name: &str) -> ExtensionCandidate {
        ExtensionCandidate {
            name: name.into(),
            variant: "default".into(),
            init_fn: format!("PyInit_{name}"),
            in_core: false,
            required: false,
            linkage: ExtensionLinkage::StaticObjectsDeclared,
            shared_library: None,
            static_library: None,
            objects: Vec::new(),
            links: Vec::new(),
            registration_observed: false,
        }
    }

    fn inspection() -> Inspection {
        let pins =
            Pins::from_json(include_bytes!("../../../fixtures/python-pbs/pins.json")).unwrap();
        let mut entries = BTreeMap::new();
        for (path, hash, size) in [
            ("python/PYTHON.json".to_owned(), METADATA_SHA256, 127_144),
            (
                RUNTIME_LIBRARY_PATH.to_owned(),
                RUNTIME_LIBRARY_SHA256,
                73_563_968,
            ),
            (EXECUTABLE_PATH.to_owned(), EXECUTABLE_SHA256, 73_325_136),
        ]
        .into_iter()
        .chain(MODULE_SPECS.iter().map(|spec| {
            (
                format!("python/{}", spec.source_path),
                spec.source_sha256,
                spec.source_size,
            )
        })) {
            entries.insert(
                path,
                Entry {
                    kind: EntryKind::RegularFile,
                    size,
                    mode: 0o644,
                    sha256: Some(hash.into()),
                    link_target: None,
                    resolved_target: None,
                },
            );
        }
        Inspection {
            schema_version: 0,
            full: ArtifactReport {
                pin: pins.full.clone(),
                decompressed_tar_bytes: 0,
                entries,
            },
            pins,
            metadata: MetadataReport {
                path: "python/PYTHON.json".into(),
                size: 127_144,
                sha256: METADATA_SHA256.into(),
                metadata_version: "8".into(),
                python_version: PYTHON_VERSION.into(),
                target_triple: TARGET_TRIPLE.into(),
                build_options: "pgo+lto".into(),
                gil: "conventional".into(),
                debug: false,
                libpython_link_mode: "shared".into(),
                runtime_library: identity(RUNTIME_LIBRARY_PATH, RUNTIME_LIBRARY_SHA256, 73_563_968),
                stdlib: "python/install/lib/python3.13".into(),
                encodings_resources: Vec::new(),
                math: candidate("math"),
                ssl: candidate("_ssl"),
                core_links: Vec::new(),
                crt_features: Vec::new(),
                inittab_source: identity("python/build/Modules/config.c", "unused", 0),
                inittab_object: identity("python/build/Modules/config.o", "unused", 0),
            },
            install_only: None,
            bootstrap_observed: false,
            loader_compatibility_validated: false,
        }
    }

    #[test]
    fn accepts_pinned_contract_and_roundtrips_serialization() {
        let bundle = parse(&fixture()).unwrap();
        bundle.validate_sources(&inspection()).unwrap();
        assert_eq!(bundle.modules[0].decode_hex().unwrap(), b"\xe3fixture");
        assert_eq!(bundle.app.decode_hex().unwrap(), b"print('fixture')\n");
        assert_eq!(
            serde_json::to_value(Bundle::parse(&serde_json::to_vec(&bundle).unwrap()).unwrap())
                .unwrap(),
            fixture()
        );
    }

    #[test]
    fn rejects_duplicate_json_keys_at_every_contract_level() {
        let json = serde_json::to_string(&fixture()).unwrap();
        for pattern in [
            "\"schema_version\":0",
            "\"python_version\":\"3.13.16\"",
            "\"name\":\"codecs\"",
            "\"source_path\":\"fixtures/python-bootstrap/app.py\"",
        ] {
            let repeated = json.replacen(pattern, &format!("{pattern},{pattern}"), 1);
            assert!(
                Bundle::parse(repeated.as_bytes())
                    .unwrap_err()
                    .contains("duplicate JSON key")
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_at_every_contract_level() {
        for path in [Vec::<&str>::new(), vec!["producer"], vec!["app"]] {
            let mut value = fixture();
            let mut target = &mut value;
            for key in path {
                target = &mut target[key];
            }
            target
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), Value::Bool(false));
            assert!(parse(&value).unwrap_err().contains("unknown field"));
        }
        let mut value = fixture();
        value["modules"][0]["extra"] = Value::Bool(false);
        assert!(parse(&value).unwrap_err().contains("unknown field"));
    }

    #[test]
    fn rejects_wrong_schema_and_every_producer_identity() {
        let mut value = fixture();
        value["schema_version"] = 1.into();
        assert!(parse(&value).unwrap_err().contains("schema version"));
        for field in [
            "python_version",
            "target_triple",
            "full_sha256",
            "install_only_sha256",
            "metadata_sha256",
            "runtime_library_sha256",
            "executable_sha256",
            "bytecode_magic",
            "cache_tag",
        ] {
            let mut value = fixture();
            value["producer"][field] = "different".into();
            assert!(
                parse(&value).unwrap_err().contains("producer identity"),
                "accepted {field}"
            );
        }
    }

    #[test]
    fn requires_exact_sorted_sources_and_package_flags() {
        let mut value = fixture();
        value["modules"].as_array_mut().unwrap().swap(0, 1);
        assert!(
            parse(&value)
                .unwrap_err()
                .contains("identity/order/package")
        );
        let mut value = fixture();
        value["modules"].as_array_mut().unwrap().pop();
        assert!(parse(&value).unwrap_err().contains("six"));
        for (field, replacement) in [
            ("name", Value::String("encodings".into())),
            ("is_package", Value::Bool(true)),
            (
                "source_path",
                Value::String("install/lib/python3.13/../codecs.py".into()),
            ),
            ("source_sha256", Value::String("0".repeat(64))),
        ] {
            let mut value = fixture();
            value["modules"][0][field] = replacement;
            assert!(
                parse(&value)
                    .unwrap_err()
                    .contains("identity/order/package")
            );
        }
    }

    #[test]
    fn rejects_invalid_hex_and_payload_hashes() {
        for bad in ["e", "E300", "gg", ""] {
            let mut value = fixture();
            value["modules"][0]["bytecode_hex"] = bad.into();
            assert!(parse(&value).is_err());
        }
        for (object, key) in [("modules", "bytecode_sha256"), ("app", "source_sha256")] {
            let mut value = fixture();
            if object == "modules" {
                value[object][0][key] = "0".repeat(64).into();
            } else {
                value[object][key] = "0".repeat(64).into();
            }
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn bounds_json_marshal_and_combined_payloads() {
        assert!(
            Bundle::parse(&vec![b' '; MAX_JSON_BYTES + 1])
                .unwrap_err()
                .contains("4 MiB")
        );
        let mut bundle = parse(&fixture()).unwrap();
        bundle.modules[0].bytecode_hex = "00".repeat(MAX_MARSHAL_BYTES + 1);
        assert!(
            bundle.modules[0]
                .decode_hex()
                .unwrap_err()
                .contains("byte limit")
        );
        let payload = vec![0; MAX_MARSHAL_BYTES / 2 + 1];
        let mut bundle = parse(&fixture()).unwrap();
        for module in &mut bundle.modules[..2] {
            module.bytecode_hex = hex(&payload);
            module.bytecode_sha256 = glue_format::digest(&payload);
        }
        assert!(bundle.validate().unwrap_err().contains("2 MiB combined"));
    }

    #[test]
    fn bounds_and_validates_app_source() {
        for bytes in [vec![0], vec![0xff], vec![b'a'; MAX_APP_BYTES + 1]] {
            let mut value = fixture();
            value["app"]["source_hex"] = hex(&bytes).into();
            value["app"]["source_sha256"] = glue_format::digest(&bytes).into();
            assert!(parse(&value).is_err());
        }
        let mut value = fixture();
        value["app"]["source_path"] = "../app.py".into();
        assert!(parse(&value).unwrap_err().contains("fixture path"));
    }

    #[test]
    fn rejects_json_tail_and_deep_recursion() {
        let mut bytes = serde_json::to_vec(&fixture()).unwrap();
        bytes.extend_from_slice(b" {}");
        assert!(Bundle::parse(&bytes).unwrap_err().contains("tail"));
        let deep = format!("{}0{}", "[".repeat(140), "]".repeat(140));
        assert!(
            Bundle::parse(deep.as_bytes())
                .unwrap_err()
                .contains("recursion")
        );
    }

    #[test]
    fn checks_inspected_source_member_hashes_sizes_and_types() {
        let bundle = parse(&fixture()).unwrap();
        let path = format!("python/{}", MODULE_SPECS[0].source_path);
        let mut report = inspection();
        report.full.entries.get_mut(&path).unwrap().sha256 = Some("0".repeat(64));
        assert!(
            bundle
                .validate_sources(&report)
                .unwrap_err()
                .contains("regular source identity")
        );
        let mut report = inspection();
        report.full.entries.get_mut(&path).unwrap().size += 1;
        assert!(bundle.validate_sources(&report).is_err());
        let mut report = inspection();
        report.full.entries.get_mut(&path).unwrap().kind = EntryKind::Symlink;
        assert!(bundle.validate_sources(&report).is_err());
        let mut report = inspection();
        report.full.entries.remove(&path);
        assert!(
            bundle
                .validate_sources(&report)
                .unwrap_err()
                .contains("lacks")
        );
    }

    #[test]
    fn checks_inspected_pin_metadata_runtime_and_executable_identities() {
        let bundle = parse(&fixture()).unwrap();
        for path in ["python/PYTHON.json", RUNTIME_LIBRARY_PATH, EXECUTABLE_PATH] {
            let mut report = inspection();
            report.full.entries.get_mut(path).unwrap().sha256 = Some("0".repeat(64));
            assert!(
                bundle.validate_sources(&report).is_err(),
                "accepted changed {path}"
            );
        }
        let mut report = inspection();
        report.metadata.runtime_library.resolved_path = "python/other-library".into();
        assert!(
            bundle
                .validate_sources(&report)
                .unwrap_err()
                .contains("metadata/runtime")
        );
        let mut report = inspection();
        report.metadata.sha256 = "0".repeat(64);
        assert!(bundle.validate_sources(&report).is_err());
        let mut report = inspection();
        report.full.pin.sha256 = "0".repeat(64);
        assert!(
            bundle
                .validate_sources(&report)
                .unwrap_err()
                .contains("pinned PBS inspection")
        );
    }
}
