use glue_format::{Archive, Compression, Manifest, ResourceSpec, digest, write_archive};
use glue_resources::{DEFAULT_CACHE_BYTES, EntryKind, MAX_CACHE_ENTRIES, ResourceError, Resources};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};

fn payloads(files: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    files
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
        .collect()
}

fn manifest(files: &BTreeMap<String, Vec<u8>>, compression: Compression) -> Manifest {
    let mut value: Manifest = serde_json::from_value(json!({
        "schema_version": 0,
        "app_id": "resources.fixture",
        "entrypoint": "main",
        "targets": {
            "mac-arm64": {
                "os": "macos", "arch": "aarch64", "minimum_os_version": "14.0",
                "abi": { "family": "darwin" }, "page_sizes": [4096], "cpu_features": []
            }
        },
        "resources": {},
        "runtimes": {
            "lua": {
                "target": "mac-arm64", "build_id": "lua-5.4-fixture",
                "abi": {
                    "language": "lua", "version": { "major": 5, "minor": 4, "patch": 7 },
                    "integer_bits": 64, "number": "float64"
                },
                "provisioning": {
                    "mode": "host", "runtime_library": "/fixture/liblua.dylib",
                    "stdlib": "/fixture/lua", "discovery": "explicit_paths"
                },
                "required_features": []
            }
        },
        "components": {
            "main": {
                "runtime": "lua", "entry_point": files.keys().next().unwrap(),
                "native_modules": []
            }
        },
        "native_modules": {}, "host_imports": {}
    }))
    .unwrap();
    value.resources = files
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                ResourceSpec {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                    compression,
                },
            )
        })
        .collect();
    value.validate().unwrap();
    value
}

fn archive_bytes(files: &BTreeMap<String, Vec<u8>>, compression: Compression) -> Vec<u8> {
    write_archive(
        Cursor::new(Vec::new()),
        &manifest(files, compression),
        files,
    )
    .unwrap()
    .into_inner()
}

fn resources(files: &BTreeMap<String, Vec<u8>>, budget: usize) -> Resources<Cursor<Vec<u8>>> {
    Resources::new(
        Archive::open(Cursor::new(archive_bytes(files, Compression::Stored))).unwrap(),
        budget,
    )
}

#[test]
fn stat_and_list_show_only_sorted_immediate_children() {
    let files = payloads(&[
        ("app/main.lua", b"return 1"),
        ("assets/icon.bin", b"icon"),
        ("assets/nested/data.bin", b"nested"),
        ("assets/readme.txt", b"read me"),
        ("root.txt", b"root"),
    ]);
    let reader = resources(&files, 8);
    assert!(reader.stat("").unwrap().is_dir());
    assert_eq!(reader.stat("assets").unwrap().size, 0);
    assert_eq!(reader.stat("assets").unwrap().compression, None);
    let root = reader.list("").unwrap();
    assert_eq!(
        root.iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["app", "assets", "root.txt"]
    );
    let assets = reader.list("assets").unwrap();
    assert_eq!(
        assets
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["icon.bin", "nested", "readme.txt"]
    );
    assert_eq!(assets[1].path, "assets/nested");
    assert_eq!(assets[1].metadata.kind, EntryKind::Directory);
    let metadata = reader.stat("assets/icon.bin").unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.size, 4);
    assert_eq!(metadata.compressed_size, 4);
    assert_eq!(metadata.compression, Some(Compression::Stored));
    assert_eq!(reader.cache_bytes(), 0);
    assert_eq!(reader.cached_resources(), 0);
}

#[test]
fn unknown_paths_directories_and_noncanonical_aliases_have_explicit_errors() {
    let files = payloads(&[("app/main.lua", b"return 1")]);
    let mut reader = resources(&files, 8);
    assert!(matches!(
        reader.stat("missing"),
        Err(ResourceError::NotFound(_))
    ));
    assert!(matches!(
        reader.list("missing"),
        Err(ResourceError::NotFound(_))
    ));
    assert!(matches!(
        reader.read("missing"),
        Err(ResourceError::NotFound(_))
    ));
    assert!(matches!(
        reader.list("app/main.lua"),
        Err(ResourceError::NotDirectory(_))
    ));
    assert!(matches!(
        reader.read("app"),
        Err(ResourceError::IsDirectory(_))
    ));
    assert!(matches!(
        reader.open(""),
        Err(ResourceError::IsDirectory(_))
    ));
    for path in [
        "/app",
        ".",
        "app/",
        "app//main.lua",
        "app/../main.lua",
        "app\\main.lua",
    ] {
        assert!(
            matches!(reader.stat(path), Err(ResourceError::InvalidPath(_))),
            "{path}"
        );
        assert!(
            matches!(reader.list(path), Err(ResourceError::InvalidPath(_))),
            "{path}"
        );
        assert!(
            matches!(reader.read(path), Err(ResourceError::InvalidPath(_))),
            "{path}"
        );
    }
    // Identity is case-sensitive even though archive validation rejects aliases.
    assert!(matches!(
        reader.stat("APP"),
        Err(ResourceError::NotFound(_))
    ));
}

#[test]
fn read_at_obeys_offsets_short_reads_eof_and_empty_buffers() {
    let files = payloads(&[("main.lua", b"abcdef"), ("empty.bin", b"")]);
    let mut reader = resources(&files, 6);
    let mut buffer = [b'!'; 4];
    assert_eq!(reader.read_at("main.lua", 1, &mut buffer).unwrap(), 4);
    assert_eq!(&buffer, b"bcde");
    buffer.fill(b'!');
    assert_eq!(reader.read_at("main.lua", 4, &mut buffer).unwrap(), 2);
    assert_eq!(&buffer, b"ef!!");
    assert_eq!(reader.read_at("main.lua", 6, &mut buffer).unwrap(), 0);
    assert_eq!(
        reader.read_at("main.lua", u64::MAX, &mut buffer).unwrap(),
        0
    );
    assert_eq!(reader.read_at("main.lua", 0, &mut []).unwrap(), 0);
    assert_eq!(reader.read_at("empty.bin", 0, &mut buffer).unwrap(), 0);
    assert_eq!(&buffer, b"ef!!");
}

#[test]
fn streams_seek_safely_and_use_virtual_origins() {
    let files = payloads(&[("main.lua", b"abcdef")]);
    let mut reader = resources(&files, 6);
    let mut stream = reader.open("main.lua").unwrap();
    assert_eq!(stream.origin(), "glue://resources.fixture/main.lua");
    assert!(stream.seek(SeekFrom::Current(-1)).is_err());
    assert_eq!(stream.stream_position().unwrap(), 0);
    assert_eq!(stream.seek(SeekFrom::End(-3)).unwrap(), 3);
    let mut buffer = [0; 4];
    assert_eq!(stream.read(&mut buffer).unwrap(), 3);
    assert_eq!(&buffer[..3], b"def");
    assert_eq!(stream.read(&mut buffer).unwrap(), 0);
    assert!(stream.seek(SeekFrom::End(-7)).is_err());
    assert_eq!(stream.stream_position().unwrap(), 6);
    assert_eq!(stream.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
    assert!(stream.seek(SeekFrom::Current(1)).is_err());
    assert_eq!(stream.stream_position().unwrap(), u64::MAX);
    assert_eq!(stream.read(&mut buffer).unwrap(), 0);
    assert_eq!(
        stream.seek(SeekFrom::Current(i64::MIN)).unwrap(),
        i64::MAX as u64
    );
    assert_eq!(stream.seek(SeekFrom::End(4)).unwrap(), 10);
    assert_eq!(stream.read(&mut buffer).unwrap(), 0);
    stream.rewind().unwrap();
    let mut clone = stream.clone();
    assert_eq!(clone.read(&mut buffer[..2]).unwrap(), 2);
    assert_eq!(stream.stream_position().unwrap(), 0);
    assert_eq!(clone.stream_position().unwrap(), 2);
}

#[test]
fn stream_origins_percent_encode_special_path_characters() {
    let files = payloads(&[("assets/a #%.txt", b"filename with URI characters")]);
    let mut reader = resources(&files, 64);
    let mut stream = reader.open("assets/a #%.txt").unwrap();
    assert_eq!(
        stream.origin(),
        "glue://resources.fixture/assets/a%20%23%25.txt"
    );
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"filename with URI characters");
}

#[test]
fn lru_evicts_the_least_recently_read_resource_within_the_byte_budget() {
    let files = payloads(&[("a", b"aaa"), ("b", b"bbb"), ("c", b"ccc")]);
    let mut reader = resources(&files, 6);
    let a = reader.read("a").unwrap();
    let b = reader.read("b").unwrap();
    assert!(Arc::ptr_eq(&a, &reader.read("a").unwrap()));
    reader.read("c").unwrap();
    assert_eq!(reader.cache_bytes(), 6);
    assert_eq!(reader.cached_resources(), 2);
    assert!(Arc::ptr_eq(&a, &reader.read("a").unwrap()));
    let b_after_eviction = reader.read("b").unwrap();
    assert!(!Arc::ptr_eq(&b, &b_after_eviction));
    assert_eq!(&*b_after_eviction, b"bbb");
    assert!(reader.cache_bytes() <= reader.cache_budget());
}

#[test]
fn zero_budget_disables_caching_and_oversized_reads_preserve_cached_files() {
    let files = payloads(&[("a", b"aaa"), ("b", b"bbbbbb"), ("empty", b"")]);
    let mut disabled = resources(&files, 0);
    let first = disabled.read("a").unwrap();
    assert!(!Arc::ptr_eq(&first, &disabled.read("a").unwrap()));
    disabled.read("empty").unwrap();
    assert_eq!(disabled.cache_bytes(), 0);
    assert_eq!(disabled.cached_resources(), 0);

    let mut reader = resources(&files, 4);
    let a = reader.read("a").unwrap();
    let oversized = reader.read("b").unwrap();
    assert!(!Arc::ptr_eq(&oversized, &reader.read("b").unwrap()));
    assert_eq!(reader.cache_bytes(), 3);
    assert_eq!(reader.cached_resources(), 1);
    assert!(Arc::ptr_eq(&a, &reader.read("a").unwrap()));

    let default = Resources::with_default_cache(
        Archive::open(Cursor::new(archive_bytes(&files, Compression::Stored))).unwrap(),
    );
    assert_eq!(default.cache_budget(), DEFAULT_CACHE_BYTES);
}

#[test]
fn empty_resources_never_enter_a_cache_with_a_positive_budget() {
    let files = payloads(&[("a", b"aaa"), ("empty", b"")]);
    let mut reader = resources(&files, 3);
    let a = reader.read("a").unwrap();
    assert!(reader.read("empty").unwrap().is_empty());
    let mut empty = reader.open("empty").unwrap();
    assert_eq!(empty.read(&mut [0]).unwrap(), 0);
    assert_eq!(reader.cached_resources(), 1);
    assert_eq!(reader.cache_bytes(), 3);
    assert!(Arc::ptr_eq(&a, &reader.read("a").unwrap()));
}

#[test]
fn cache_entry_limit_evicts_tiny_resources_before_the_byte_budget_is_full() {
    let files: BTreeMap<String, Vec<u8>> = (0..=MAX_CACHE_ENTRIES)
        .map(|index| (format!("resource/{index:04}"), vec![b'x']))
        .collect();
    let mut reader = resources(&files, MAX_CACHE_ENTRIES + 1);
    let first = reader.read("resource/0000").unwrap();
    for path in files.keys().skip(1) {
        assert_eq!(&*reader.read(path).unwrap(), b"x");
        assert!(reader.cached_resources() <= MAX_CACHE_ENTRIES);
        assert!(reader.cache_bytes() <= reader.cache_budget());
    }
    assert_eq!(reader.cached_resources(), MAX_CACHE_ENTRIES);
    assert_eq!(reader.cache_bytes(), MAX_CACHE_ENTRIES);
    assert!(reader.cache_bytes() < reader.cache_budget());
    // The first file was least recently used when the entry cap was reached.
    assert!(!Arc::ptr_eq(&first, &reader.read("resource/0000").unwrap()));
    assert_eq!(reader.cached_resources(), MAX_CACHE_ENTRIES);
}

#[test]
fn active_streams_keep_verified_bytes_after_eviction_and_archive_drop() {
    let files = payloads(&[("a", b"aaa"), ("b", b"bbb")]);
    let mut reader = resources(&files, 3);
    let mut a = reader.open("a").unwrap();
    reader.read("b").unwrap();
    assert_eq!(reader.cache_bytes(), 3);
    assert_eq!(reader.cached_resources(), 1);
    drop(reader);
    let mut result = Vec::new();
    a.read_to_end(&mut result).unwrap();
    assert_eq!(result, b"aaa");
    assert_eq!(a.seek(SeekFrom::Start(1)).unwrap(), 1);
    result.clear();
    a.read_to_end(&mut result).unwrap();
    assert_eq!(result, b"aa");
}

#[test]
fn compressed_payloads_are_cached_by_decoded_size() {
    let files = payloads(&[("main.lua", &vec![b'x'; 4096])]);
    let archive = Archive::open(Cursor::new(archive_bytes(&files, Compression::Deflate))).unwrap();
    let mut reader = Resources::new(archive, 4096);
    let metadata = reader.stat("main.lua").unwrap();
    assert!(metadata.compressed_size < metadata.size);
    assert_eq!(metadata.compression, Some(Compression::Deflate));
    assert_eq!(&*reader.read("main.lua").unwrap(), &vec![b'x'; 4096]);
    assert_eq!(reader.cache_bytes(), 4096);
}

#[test]
fn corrupt_resources_never_publish_bytes_or_evict_valid_cache_entries() {
    let corrupt_payload = b"unique-corrupt-resource-payload";
    let files = payloads(&[("a", b"aaa"), ("b", corrupt_payload)]);
    let mut bytes = archive_bytes(&files, Compression::Stored);
    let offset = bytes
        .windows(corrupt_payload.len())
        .position(|window| window == corrupt_payload)
        .unwrap();
    bytes[offset] ^= 1;
    let mut reader = Resources::new(Archive::open(Cursor::new(bytes)).unwrap(), 32);
    let a = reader.read("a").unwrap();
    assert!(matches!(reader.read("b"), Err(ResourceError::Archive(_))));
    assert!(matches!(reader.open("b"), Err(ResourceError::Archive(_))));
    let mut buffer = [b'!'; 4];
    assert!(matches!(
        reader.read_at("b", 0, &mut buffer),
        Err(ResourceError::Archive(_))
    ));
    assert_eq!(&buffer, b"!!!!");
    assert_eq!(reader.cache_bytes(), 3);
    assert_eq!(reader.cached_resources(), 1);
    assert!(Arc::ptr_eq(&a, &reader.read("a").unwrap()));
}
