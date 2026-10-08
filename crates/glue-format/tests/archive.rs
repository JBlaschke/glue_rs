use glue_format::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read, Seek, SeekFrom},
};

fn fixture(compression: Compression, extra: bool) -> (Manifest, BTreeMap<String, Vec<u8>>) {
    let mut resources = BTreeMap::from([("app/main.lua".to_owned(), b"return 42\n".to_vec())]);
    if extra {
        resources.insert("assets/empty".to_owned(), Vec::new());
        resources.insert(
            "assets/message.txt".to_owned(),
            b"bounded resources".to_vec(),
        );
    }
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        app_id: "archive.fixture".to_owned(),
        entrypoint: "main".to_owned(),
        targets: BTreeMap::from([(
            "mac".to_owned(),
            TargetProfile {
                os: OperatingSystem::Macos,
                arch: Architecture::Aarch64,
                minimum_os_version: "14.0".to_owned(),
                abi: TargetAbi::Darwin,
                page_sizes: BTreeSet::from([4096]),
                cpu_features: BTreeSet::new(),
            },
        )]),
        resources: resources
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    ResourceSpec {
                        size: bytes.len() as u64,
                        sha256: digest(bytes),
                        compression,
                    },
                )
            })
            .collect(),
        runtimes: BTreeMap::from([(
            "lua".to_owned(),
            RuntimeSpec {
                target: "mac".to_owned(),
                build_id: "lua-fixture".to_owned(),
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
                    runtime_library: "/fixture/liblua.dylib".to_owned(),
                    stdlib: "/fixture/lua".to_owned(),
                    discovery: HostDiscovery::ExplicitPaths,
                },
                required_features: BTreeSet::new(),
            },
        )]),
        components: BTreeMap::from([(
            "main".to_owned(),
            ComponentSpec {
                runtime: "lua".to_owned(),
                entry_point: "app/main.lua".to_owned(),
                native_modules: BTreeSet::new(),
            },
        )]),
        native_modules: BTreeMap::new(),
        host_imports: BTreeMap::new(),
    };
    (manifest, resources)
}

fn archive_bytes(compression: Compression, extra: bool) -> Vec<u8> {
    let (manifest, resources) = fixture(compression, extra);
    write_archive(Cursor::new(Vec::new()), &manifest, &resources)
        .unwrap()
        .into_inner()
}
fn number16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn number32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn number64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn payload_start(bytes: &[u8]) -> usize {
    64 + number64(bytes, 16) as usize
}
fn central_start(bytes: &[u8]) -> usize {
    payload_start(bytes) + number32(bytes, bytes.len() - 6) as usize
}
fn payload_length(bytes: &mut [u8]) {
    put64(bytes, 24, (bytes.len() - payload_start(bytes)) as u64);
}
fn reject(bytes: Vec<u8>) -> ArchiveError {
    Archive::open(Cursor::new(bytes)).unwrap_err()
}
fn reject_message(bytes: Vec<u8>, message: &str) {
    let error = reject(bytes).to_string();
    assert!(error.contains(message), "expected {message:?}, got {error}");
}
fn central_records(bytes: &[u8]) -> Vec<usize> {
    let mut records = Vec::new();
    let mut position = central_start(bytes);
    for _ in 0..number16(bytes, bytes.len() - 12) {
        records.push(position);
        position += 46
            + number16(bytes, position + 28) as usize
            + number16(bytes, position + 30) as usize
            + number16(bytes, position + 32) as usize;
    }
    records
}
fn local_extra(bytes: &[u8], header: usize) -> usize {
    header + 30 + number16(bytes, header + 26) as usize
}
fn central_extra(bytes: &[u8], central: usize) -> usize {
    central + 46 + number16(bytes, central + 28) as usize
}

#[test]
fn stored_deflate_zip64_roundtrip_is_deterministic_and_lazy() {
    for compression in [Compression::Stored, Compression::Deflate] {
        let (manifest, resources) = fixture(compression, true);
        let first = write_archive(Cursor::new(Vec::new()), &manifest, &resources)
            .unwrap()
            .into_inner();
        assert_eq!(first, archive_bytes(compression, true));
        let mut archive = Archive::open(Cursor::new(&first)).unwrap();
        assert_eq!(archive.manifest(), &manifest);
        assert_eq!(archive.entries().len(), 3);
        for (path, bytes) in resources {
            let entry = &archive.entries()[&path];
            assert_eq!(entry.compression, compression);
            assert_eq!(entry.size, bytes.len() as u64);
            assert_eq!(archive.read_resource(&path).unwrap(), bytes);
        }
        archive.verify_all().unwrap();
        let payload = payload_start(&first);
        // A small member still carries real local ZIP64 sentinel sizes.
        assert_eq!(number32(&first, payload + 18), u32::MAX);
        assert_eq!(number32(&first, payload + 22), u32::MAX);
        assert_eq!(number16(&first, local_extra(&first, payload)), 1);
    }
}

#[test]
fn standard_zip32_member_is_supported() {
    let (manifest, resources) = fixture(Compression::Stored, false);
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "app/main.lua",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    std::io::Write::write_all(&mut writer, &resources["app/main.lua"]).unwrap();
    let payload = writer.finish().unwrap().into_inner();
    let mut bytes = archive_bytes(Compression::Stored, false);
    bytes.truncate(payload_start(&bytes));
    bytes.extend_from_slice(&payload);
    payload_length(&mut bytes);
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    assert_eq!(archive.manifest(), &manifest);
    assert_eq!(
        archive.read_resource("app/main.lua").unwrap(),
        resources["app/main.lua"]
    );
}

#[test]
fn zip64_footer_is_supported_without_giant_allocations() {
    let mut bytes = archive_bytes(Compression::Stored, false);
    let base = payload_start(&bytes);
    let old_eocd = bytes.split_off(bytes.len() - 22);
    let zip64_offset = (bytes.len() - base) as u64;
    let count = number16(&old_eocd, 10) as u64;
    let cd_size = number32(&old_eocd, 12) as u64;
    let cd_offset = number32(&old_eocd, 16) as u64;
    bytes.extend_from_slice(&0x0606_4b50_u32.to_le_bytes());
    bytes.extend_from_slice(&44_u64.to_le_bytes());
    bytes.extend_from_slice(&45_u16.to_le_bytes());
    bytes.extend_from_slice(&45_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for value in [count, count, cd_size, cd_offset] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&0x0706_4b50_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&zip64_offset.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&old_eocd);
    let end = bytes.len();
    put16(&mut bytes, end - 14, u16::MAX);
    put16(&mut bytes, end - 12, u16::MAX);
    put32(&mut bytes, end - 10, u32::MAX);
    put32(&mut bytes, end - 6, u32::MAX);
    payload_length(&mut bytes);
    Archive::open(Cursor::new(&bytes))
        .unwrap()
        .verify_all()
        .unwrap();
    let mut oversized = bytes.clone();
    put64(&mut oversized, base + zip64_offset as usize + 4, u64::MAX);
    reject_message(oversized, "extensible");
    let mut inconsistent = bytes.clone();
    put64(
        &mut inconsistent,
        base + zip64_offset as usize + 24,
        count + 1,
    );
    reject_message(inconsistent, "disagree");
    let mut oversized_count = bytes.clone();
    for field in [24, 32] {
        put64(
            &mut oversized_count,
            base + zip64_offset as usize + field,
            65_536,
        );
    }
    assert!(matches!(
        Archive::open_with_limits(
            Cursor::new(oversized_count),
            ArchiveLimits {
                max_entries: 100,
                ..ArchiveLimits::default()
            }
        ),
        Err(ArchiveError::Limit {
            limit: "entry count",
            actual: 65_536,
            ..
        })
    ));
    let mut disks = bytes;
    let end = disks.len();
    put32(&mut disks, end - 26, 2);
    reject_message(disks, "disk");
}

#[test]
fn locator_rejects_corruption_overflow_truncation_and_trailing_bytes() {
    let original = archive_bytes(Compression::Stored, false);
    for offset in [0, 8, 12, 32, 64] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        reject(bytes);
    }
    for len in [0, 1, 63, 64, original.len() - 1] {
        reject(original[..len].to_vec());
    }
    let mut overflow = original.clone();
    put64(&mut overflow, 24, u64::MAX);
    reject_message(overflow, "overflow");
    let mut trailing = original;
    trailing.push(0);
    reject_message(trailing, "exactly");
}

#[test]
fn configured_limits_reject_before_payload_read_or_allocation() {
    let original = archive_bytes(Compression::Deflate, true);
    for limits in [
        ArchiveLimits {
            max_manifest_bytes: 1,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_archive_bytes: 64,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_entry_bytes: 1,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_total_uncompressed_bytes: 1,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_central_directory_bytes: 1,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            max_entries: 1,
            ..ArchiveLimits::default()
        },
    ] {
        assert!(matches!(
            Archive::open_with_limits(Cursor::new(&original), limits),
            Err(ArchiveError::Limit { .. })
        ));
    }
    let mut bytes = original;
    put64(&mut bytes, 16, u64::MAX);
    assert!(matches!(reject(bytes), ArchiveError::Limit { .. }));
}

#[test]
fn compressed_member_cost_is_bounded_before_decoding() {
    for compression in [Compression::Stored, Compression::Deflate] {
        let bytes = archive_bytes(compression, false);
        assert!(matches!(
            Archive::open_with_limits(
                Cursor::new(bytes),
                ArchiveLimits {
                    max_compressed_entry_bytes: 0,
                    ..ArchiveLimits::default()
                }
            ),
            Err(ArchiveError::Limit {
                limit: "compressed resource bytes",
                ..
            })
        ));
    }
}

#[test]
fn duplicate_raw_entries_reject_even_when_zip_library_would_collapse_them() {
    let mut bytes = archive_bytes(Compression::Stored, false);
    let cd = central_start(&bytes);
    let end = bytes.len() - 22;
    let duplicate = bytes[cd..end].to_vec();
    bytes.splice(end..end, duplicate.iter().copied());
    let end = bytes.len();
    put16(&mut bytes, end - 14, 2);
    put16(&mut bytes, end - 12, 2);
    put32(&mut bytes, end - 10, (duplicate.len() * 2) as u32);
    payload_length(&mut bytes);
    reject_message(bytes, "duplicate");
}

#[test]
fn local_header_disagreement_is_rejected() {
    let original = archive_bytes(Compression::Stored, false);
    let local = payload_start(&original);
    for offset in [4, 6, 14, 30] {
        let mut bytes = original.clone();
        bytes[local + offset] ^= 1;
        reject_message(bytes, "disagree");
    }
    let mut method = original.clone();
    put16(&mut method, local + 8, 8);
    reject_message(method, "disagree");
    let mut bytes = original;
    let extra = local_extra(&bytes, local);
    bytes[extra + 4] ^= 1;
    reject_message(bytes, "sizes disagree");
}

#[test]
fn unsupported_zip_features_are_rejected() {
    let original = archive_bytes(Compression::Stored, false);
    for flags in [1, 8, 0x40, 0x2000, 2] {
        let mut bytes = original.clone();
        let cd = central_start(&bytes);
        put16(&mut bytes, cd + 8, flags);
        reject(bytes);
    }
    for mode in [0o120777, 0o040755, 0o020600] {
        let mut bytes = original.clone();
        let cd = central_start(&bytes);
        put32(&mut bytes, cd + 38, mode << 16);
        reject_message(bytes, "special members");
    }
    let mut method = original.clone();
    let cd = central_start(&method);
    put16(&mut method, cd + 10, 93);
    reject_message(method, "compression");
    let mut extra = original.clone();
    let cd = central_start(&extra);
    let pos = central_extra(&extra, cd);
    put16(&mut extra, pos, 0x7075);
    reject_message(extra, "ZIP64 extra");
    let mut malformed = original.clone();
    let cd = central_start(&malformed);
    let pos = central_extra(&malformed, cd);
    put16(&mut malformed, pos + 2, 0xffff);
    reject_message(malformed, "ZIP64 extra");
    let mut disk = original;
    let cd = central_start(&disk);
    put16(&mut disk, cd + 34, 1);
    reject_message(disk, "disk");
}

#[test]
fn footer_bounds_and_counts_are_strict() {
    let original = archive_bytes(Compression::Stored, false);
    for offset in [4, 6, 8, 10, 12, 16, 20] {
        let mut bytes = original.clone();
        let end = bytes.len() - 22;
        bytes[end + offset] ^= 1;
        reject(bytes);
    }
    let mut sentinel = original;
    let end = sentinel.len();
    put32(&mut sentinel, end - 6, u32::MAX);
    reject_message(sentinel, "ZIP64 footer is missing");
}

#[test]
fn full_member_ranges_reject_overlap_and_offsets_into_metadata() {
    let original = archive_bytes(Compression::Stored, true);
    let mut overlap = original.clone();
    let base = payload_start(&overlap);
    let records = central_records(&overlap);
    let extra = central_extra(&overlap, records[0]);
    let local_extra = local_extra(&overlap, base);
    // Increase the first stored member into the next local header, keeping all
    // claimed lengths consistent so the occupied-range check must catch it.
    let size = number64(&overlap, extra + 4) + 1;
    for pos in [extra + 4, extra + 12, local_extra + 4, local_extra + 12] {
        put64(&mut overlap, pos, size);
    }
    reject_message(overlap, "overlapping");
    let mut metadata = original;
    let cd = central_start(&metadata);
    let offset = (cd - payload_start(&metadata)) as u32;
    put32(&mut metadata, cd + 42, offset);
    reject_message(metadata, "central directory");
}

#[test]
fn corrupted_stored_bytes_fail_crc_before_becoming_visible() {
    let mut bytes = archive_bytes(Compression::Stored, false);
    let archive = Archive::open(Cursor::new(&bytes)).unwrap();
    let offset = payload_start(&bytes) + archive.entries()["app/main.lua"].data_offset as usize;
    bytes[offset] ^= 1;
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        archive.read_resource("app/main.lua"),
        Err(ArchiveError::Integrity { check: "CRC32", .. })
    ));
}

#[test]
fn crc_consistent_tampering_still_fails_manifest_hash() {
    let mut bytes = archive_bytes(Compression::Stored, false);
    let archive = Archive::open(Cursor::new(&bytes)).unwrap();
    let entry = &archive.entries()["app/main.lua"];
    let base = payload_start(&bytes);
    let data = base + entry.data_offset as usize;
    let size = entry.size as usize;
    bytes[data] ^= 1;
    let crc = crc32fast::hash(&bytes[data..data + size]);
    put32(&mut bytes, base + 14, crc);
    let cd = central_start(&bytes);
    put32(&mut bytes, cd + 16, crc);
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        archive.read_resource("app/main.lua"),
        Err(ArchiveError::Integrity {
            check: "SHA-256",
            ..
        })
    ));
}

fn edit_deflate_length(bytes: &mut Vec<u8>, grow: bool) {
    let old_cd = central_start(bytes);
    let base = payload_start(bytes);
    let extra = central_extra(bytes, old_cd);
    let old_compressed = number64(bytes, extra + 12);
    let new_compressed = if grow {
        old_compressed + 1
    } else {
        old_compressed - 1
    };
    if grow {
        bytes.insert(old_cd, 0);
    } else {
        bytes.remove(old_cd - 1);
    }
    let cd = if grow { old_cd + 1 } else { old_cd - 1 };
    let extra = central_extra(bytes, cd);
    let local = local_extra(bytes, base);
    put64(bytes, extra + 12, new_compressed);
    put64(bytes, local + 12, new_compressed);
    let end = bytes.len();
    put32(bytes, end - 6, (cd - base) as u32);
    payload_length(bytes);
}

#[test]
fn deflate_rejects_truncation_and_trailing_compressed_junk() {
    for grow in [false, true] {
        let mut bytes = archive_bytes(Compression::Deflate, false);
        edit_deflate_length(&mut bytes, grow);
        let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
        assert!(matches!(
            archive.read_resource("app/main.lua"),
            Err(ArchiveError::Integrity { .. })
        ));
    }
}

#[test]
fn deflate_output_is_bounded_by_declared_member_size() {
    let (mut manifest, resources) = fixture(Compression::Deflate, false);
    let original = archive_bytes(Compression::Deflate, false);
    let base = payload_start(&original);
    let mut payload = original[base..].to_vec();
    manifest.resources.get_mut("app/main.lua").unwrap().size -= 1;
    let cd = number32(&payload, payload.len() - 6) as usize;
    let local = local_extra(&payload, 0);
    let central = central_extra(&payload, cd);
    put64(
        &mut payload,
        local + 4,
        resources["app/main.lua"].len() as u64 - 1,
    );
    put64(
        &mut payload,
        central + 4,
        resources["app/main.lua"].len() as u64 - 1,
    );
    let mut bytes = Vec::new();
    wrap_payload(&mut bytes, &manifest.to_json().unwrap(), &payload);
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        archive.read_resource("app/main.lua"),
        Err(ArchiveError::Integrity {
            check: "length",
            ..
        })
    ));
}

fn wrap_payload(bytes: &mut Vec<u8>, manifest_bytes: &[u8], payload: &[u8]) {
    use sha2::{Digest, Sha256};
    bytes.extend_from_slice(&ARCHIVE_MAGIC);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(manifest_bytes));
    bytes.extend_from_slice(manifest_bytes);
    bytes.extend_from_slice(payload);
}

#[test]
fn canonical_manifest_and_resource_inventory_are_required() {
    let original = archive_bytes(Compression::Stored, false);
    let base = payload_start(&original);
    let manifest_bytes = &original[64..base];
    let mut padded = b" ".to_vec();
    padded.extend_from_slice(manifest_bytes);
    let mut bytes = Vec::new();
    wrap_payload(&mut bytes, &padded, &original[base..]);
    reject_message(bytes, "canonical");
    let (mut manifest, _) = fixture(Compression::Stored, false);
    manifest
        .resources
        .get_mut("app/main.lua")
        .unwrap()
        .compression = Compression::Deflate;
    let mut bytes = Vec::new();
    wrap_payload(&mut bytes, &manifest.to_json().unwrap(), &original[base..]);
    reject_message(bytes, "size/compression");
}

fn rename_member(bytes: &mut [u8], record: usize, name: &str) {
    let length = number16(bytes, record + 28) as usize;
    assert_eq!(length, name.len());
    let header = payload_start(bytes) + number32(bytes, record + 42) as usize;
    bytes[record + 46..record + 46 + length].copy_from_slice(name.as_bytes());
    bytes[header + 30..header + 30 + length].copy_from_slice(name.as_bytes());
}

#[test]
fn zip_paths_reject_traversal_case_and_file_directory_aliases() {
    let original = archive_bytes(Compression::Stored, true);
    for name in ["app/../x.lua", "/pp/main.lua"] {
        let mut bytes = original.clone();
        let record = central_records(&bytes)[0];
        rename_member(&mut bytes, record, name);
        assert!(matches!(
            reject(bytes),
            ArchiveError::Manifest(FormatError::InvalidResourcePath { .. })
        ));
    }
    let mut case = original.clone();
    let record = central_records(&case)[2];
    rename_member(&mut case, record, "Assets/message.txt");
    reject_message(case, "case collision");
    let mut conflict = original.clone();
    let record = central_records(&conflict)[2];
    rename_member(&mut conflict, record, "assets/empty/a.txt");
    reject_message(conflict, "file/directory conflict");
    let mut nonascii = original;
    let record = central_records(&nonascii)[0];
    nonascii[record + 46] = 0xff;
    reject_message(nonascii, "UTF8");
}

#[test]
fn undeclared_payload_and_empty_member_crc_are_rejected() {
    let mut bytes = archive_bytes(Compression::Stored, true);
    let record = central_records(&bytes)[0];
    rename_member(&mut bytes, record, "app/nope.lua");
    reject_message(bytes, "undeclared");
    let mut bytes = archive_bytes(Compression::Stored, true);
    let record = central_records(&bytes)[1];
    let header = payload_start(&bytes) + number32(&bytes, record + 42) as usize;
    put32(&mut bytes, record + 16, 1);
    put32(&mut bytes, header + 14, 1);
    let mut archive = Archive::open(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        archive.read_resource("assets/empty"),
        Err(ArchiveError::Integrity { check: "CRC32", .. })
    ));
}

#[test]
fn writer_refuses_wrong_resources_and_nonempty_destination() {
    let (manifest, mut resources) = fixture(Compression::Stored, false);
    assert!(write_archive(Cursor::new(vec![0]), &manifest, &resources).is_err());
    resources.get_mut("app/main.lua").unwrap().push(0);
    assert!(write_archive(Cursor::new(Vec::new()), &manifest, &resources).is_err());
    resources.remove("app/main.lua");
    assert!(write_archive(Cursor::new(Vec::new()), &manifest, &resources).is_err());
}

#[test]
fn reads_handle_fragmented_sources_and_do_not_decode_payload_at_open() {
    #[derive(Debug)]
    struct Fragmented {
        inner: Cursor<Vec<u8>>,
        forbidden: std::ops::Range<u64>,
    }
    impl Read for Fragmented {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let position = self.inner.position();
            if self.forbidden.contains(&position) {
                return Err(std::io::Error::other("payload data was read at open"));
            }
            let count = buf.len().min(1);
            self.inner.read(&mut buf[..count])
        }
    }
    impl Seek for Fragmented {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(from)
        }
    }
    let bytes = archive_bytes(Compression::Stored, false);
    let archive = Archive::open(Cursor::new(&bytes)).unwrap();
    let entry = &archive.entries()["app/main.lua"];
    let start = payload_start(&bytes) as u64 + entry.data_offset;
    let end = start + entry.compressed_size;
    let source = Fragmented {
        inner: Cursor::new(bytes),
        forbidden: start..end,
    };
    Archive::open(source).unwrap();
    // Separate fragmented source permits content reads and exercises decoder
    // progress when one compressed byte arrives per read.
    let bytes = archive_bytes(Compression::Deflate, false);
    let mut archive = Archive::open(Fragmented {
        inner: Cursor::new(bytes),
        forbidden: 0..0,
    })
    .unwrap();
    assert_eq!(
        archive.read_resource("app/main.lua").unwrap(),
        b"return 42\n"
    );
}
