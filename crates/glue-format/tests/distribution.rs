use glue_format::*;
use std::collections::{BTreeMap, BTreeSet};
fn example(implementation: RuntimeImplementation) -> Manifest {
    let (version, abi) = match implementation {
        RuntimeImplementation::Lua => (
            "5.4.9",
            RuntimeAbi::Lua {
                version: RuntimeVersion {
                    major: 5,
                    minor: 4,
                    patch: 9,
                },
                integer_bits: 64,
                number: LuaNumber::Float64,
            },
        ),
        RuntimeImplementation::Cpython => (
            "3.14.5",
            RuntimeAbi::Python {
                version: RuntimeVersion {
                    major: 3,
                    minor: 14,
                    patch: 5,
                },
                gil: GilMode::Conventional,
                debug: false,
            },
        ),
        RuntimeImplementation::Node => (
            "26.10.0",
            RuntimeAbi::Node {
                version: RuntimeVersion {
                    major: 26,
                    minor: 10,
                    patch: 0,
                },
                node_api: 10,
                addon_abi: 147,
                bridge_revision: "1".into(),
            },
        ),
    };
    Manifest {
        schema_version: 1,
        app_id: "example".into(),
        entrypoint: "main".into(),
        targets: BTreeMap::new(),
        runtimes: BTreeMap::new(),
        components: BTreeMap::new(),
        native_modules: BTreeMap::new(),
        host_imports: BTreeMap::new(),
        resources: BTreeMap::from([(
            "main".into(),
            ResourceSpec {
                size: 0,
                sha256: digest(b""),
                compression: Compression::Deflate,
            },
        )]),
        distribution: Some(DistributionSpec {
            delivery: DeliveryMode::Compact,
            runtime: RuntimeDescriptor {
                implementation,
                version: version.into(),
                abi,
                target: "aarch64-apple-darwin".into(),
                provider: RuntimeProvider::Bundled,
                executable: "runtime/helper".into(),
                inputs: BTreeMap::from([("helper".into(), InputIdentity::of(b"exe"))]),
                requirements: BTreeSet::new(),
            },
            payloads: BTreeMap::from([(
                "runtime/helper".into(),
                PayloadRecord {
                    size: 3,
                    sha256: digest(b"exe"),
                    mode: 0o755,
                    kind: PayloadKind::File,
                },
            )]),
            native: NativeInventory::default(),
            launch: RuntimeLaunchSpec {
                executable: "runtime/helper".into(),
                args: vec!["{archive}".into()],
                environment: BTreeMap::new(),
                clear_environment: true,
            },
        }),
    }
}
#[test]
fn all_descriptors_round_trip_without_fixture_admission() {
    for language in [
        RuntimeImplementation::Lua,
        RuntimeImplementation::Cpython,
        RuntimeImplementation::Node,
    ] {
        let m = example(language);
        let bytes = m.to_json().unwrap();
        assert_eq!(Manifest::from_json(&bytes).unwrap(), m);
        assert!(!String::from_utf8(bytes).unwrap().contains("fixture"));
    }
}
#[test]
fn invalid_modes_paths_revisions_and_abi_reject() {
    for path in [
        "/absolute",
        "../escape",
        "runtime/../escape",
        "runtime\\escape",
        "app.glue",
        "runtime/helper/child",
    ] {
        let mut m = example(RuntimeImplementation::Lua);
        let d = m.distribution.as_mut().unwrap();
        let p = d.payloads["runtime/helper"].clone();
        d.payloads.insert(path.into(), p);
        assert!(m.validate().is_err(), "{path}");
    }
    let mut m = example(RuntimeImplementation::Lua);
    m.schema_version = 99;
    assert!(m.validate().is_err());
    m.schema_version = 0;
    assert!(m.validate().is_err());
    m.schema_version = 1;
    m.distribution.as_mut().unwrap().delivery = DeliveryMode::Memory;
    assert!(m.validate().is_err());
    let mut m = example(RuntimeImplementation::Lua);
    m.distribution.as_mut().unwrap().runtime.implementation = RuntimeImplementation::Node;
    assert!(m.validate().is_err());
    let mut m = example(RuntimeImplementation::Lua);
    m.distribution.as_mut().unwrap().runtime.version = "5.4.90".into();
    assert!(m.validate().is_err());
    let m = example(RuntimeImplementation::Lua);
    let s = String::from_utf8(m.to_json().unwrap()).unwrap().replace(
        "\"runtime/helper\":",
        "\"runtime/helper\":{\"size\":0},\"runtime/helper\":",
    );
    assert!(Manifest::from_json(s.as_bytes()).is_err());
}
#[test]
fn safe_links_and_cycles_are_checked() {
    let mut m = example(RuntimeImplementation::Lua);
    let d = m.distribution.as_mut().unwrap();
    d.payloads.insert(
        "runtime/link".into(),
        PayloadRecord {
            size: 6,
            sha256: digest(b"helper"),
            mode: 0o755,
            kind: PayloadKind::Symlink {
                target: "helper".into(),
            },
        },
    );
    m.validate().unwrap();
    assert_eq!(
        resolve_payload_link("a/b/link", "../../target").unwrap(),
        "target"
    );
    assert!(resolve_payload_link("a/link", "../../escape").is_err());
    m.distribution
        .as_mut()
        .unwrap()
        .payloads
        .get_mut("runtime/helper")
        .unwrap()
        .kind = PayloadKind::Symlink {
        target: "link".into(),
    };
    assert!(m.validate().is_err());
}
