use crate::{
    archive::{Inventory, Limits, read_inventory},
    pins::{ArtifactPin, MAX_COMPRESSED_BYTES},
};
use flate2::bufread::GzDecoder;
use ruzstd::decoding::StreamingDecoder;
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, Read, Seek, SeekFrom};

#[derive(Clone, Copy)]
pub(crate) enum Compression {
    Zstd,
    Gzip,
}

/// Check the compressed pin before parsing, then check the bytes actually
/// consumed by the decoder as well. A changed input cannot produce a report.
pub(crate) fn inspect<R: Read + Seek>(
    input: &mut R,
    pin: &ArtifactPin,
    compression: Compression,
    limits: &Limits,
) -> Result<Inventory, String> {
    if pin.size == 0 || pin.size > MAX_COMPRESSED_BYTES {
        return Err("compressed PBS size exceeds the bound".into());
    }
    input
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut first = HashingReader::new(&mut *input, pin.size);
    io::copy(&mut first, &mut io::sink()).map_err(|error| format!("read PBS input: {error}"))?;
    first.verify(pin)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let source = BufReader::with_capacity(64 * 1024, HashingReader::new(input, pin.size));
    let (inventory, mut source) = match compression {
        Compression::Zstd => {
            // Explicitly bounded before the first frame allocates its window.
            // The pinned full artifact advertises a 128 MiB window. Larger
            // windows remain unsupported, even when their compressed pin matches.
            let mut decoder = StreamingDecoder::new_with_max_window_size(source, 128 * 1024 * 1024)
                .map_err(|error| format!("PBS zstd header: {error}"))?;
            let declared_size = decoder.decoder.content_size();
            if declared_size > limits.max_tar_bytes {
                return Err("PBS zstd expanded size exceeds the bound".into());
            }
            let inventory = read_inventory(&mut decoder, limits)?;
            if !decoder.decoder.is_finished()
                || decoder
                    .decoder
                    .get_checksum_from_data()
                    .is_some_and(|expected| {
                        Some(expected) != decoder.decoder.get_calculated_checksum()
                    })
                || (declared_size != 0 && declared_size != inventory.decompressed_bytes)
            {
                return Err("PBS zstd checksum, size or frame completion mismatch".into());
            }
            (inventory, decoder.into_inner())
        }
        Compression::Gzip => {
            let mut decoder = GzDecoder::new(source);
            let inventory = read_inventory(&mut decoder, limits)?;
            (inventory, decoder.into_inner())
        }
    };
    // One frame/member only. Reject extra frames, members and arbitrary tails,
    // including bytes buffered beyond the compression trailer.
    let mut tail = [0u8; 1];
    if source.read(&mut tail).map_err(|error| error.to_string())? != 0 {
        return Err("PBS compressed input has trailing data or another frame/member".into());
    }
    source.into_inner().verify(pin)?;
    Ok(inventory)
}

struct HashingReader<R> {
    inner: R,
    bytes: u64,
    max: u64,
    hash: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R, max: u64) -> Self {
        Self {
            inner,
            bytes: 0,
            max,
            hash: Sha256::new(),
        }
    }

    fn verify(self, pin: &ArtifactPin) -> Result<(), String> {
        if self.bytes != pin.size || crate::hex_digest(&self.hash.finalize()) != pin.sha256 {
            return Err(format!(
                "PBS compressed size/SHA-256 differs from pin {}",
                pin.filename
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("compressed byte count overflow"))?;
        if self.bytes > self.max {
            return Err(io::Error::other("PBS compressed size exceeds its pin"));
        }
        self.hash.update(&buffer[..count]);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression as GzipCompression, write::GzEncoder};
    use std::io::{Cursor, Write};

    fn tar() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..8].copy_from_slice(b"python/a");
        bytes[100..108].copy_from_slice(b"0000644\0");
        bytes[124..136].copy_from_slice(b"00000000001\0");
        bytes[148..156].fill(b' ');
        bytes[156] = b'0';
        bytes[257..265].copy_from_slice(
            b"ustar\0"
                .iter()
                .chain(b"00")
                .copied()
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let checksum: u32 = bytes.iter().map(|byte| u32::from(*byte)).sum();
        bytes[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        bytes.push(b'a');
        bytes.resize(2048, 0);
        bytes
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), GzipCompression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn pin(bytes: &[u8]) -> ArtifactPin {
        ArtifactPin {
            filename: "test".into(),
            sha256: crate::hex_digest(&Sha256::digest(bytes)),
            size: bytes.len() as u64,
            url: String::new(),
        }
    }

    #[test]
    fn reads_single_gzip_and_zstd_frames_with_verified_pin() {
        let original = tar();
        for (bytes, compression) in [
            (gzip(&original), Compression::Gzip),
            (
                ruzstd::encoding::compress_to_vec(
                    original.as_slice(),
                    ruzstd::encoding::CompressionLevel::Fastest,
                ),
                Compression::Zstd,
            ),
        ] {
            let value = inspect(
                &mut Cursor::new(&bytes),
                &pin(&bytes),
                compression,
                &Limits::default(),
            )
            .unwrap();
            assert_eq!(value.entries["python/a"].size, 1);
            assert_eq!(value.decompressed_bytes, 2048);
        }
    }

    #[test]
    fn rejects_hash_mismatch_before_decompression() {
        let mut pinned = pin(b"not compressed");
        pinned.sha256 = "0".repeat(64);
        let error = inspect(
            &mut Cursor::new(b"not compressed"),
            &pinned,
            Compression::Gzip,
            &Limits::default(),
        )
        .unwrap_err();
        assert!(error.contains("SHA-256"));
    }

    #[test]
    fn rejects_corrupt_gzip_crc_and_truncated_streams_even_with_matching_pin() {
        let mut bytes = gzip(&tar());
        let length = bytes.len();
        bytes[length - 8] ^= 1;
        assert!(
            inspect(
                &mut Cursor::new(&bytes),
                &pin(&bytes),
                Compression::Gzip,
                &Limits::default()
            )
            .is_err()
        );
        for compression in [Compression::Gzip, Compression::Zstd] {
            assert!(
                inspect(
                    &mut Cursor::new(b"x"),
                    &pin(b"x"),
                    compression,
                    &Limits::default()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_additional_gzip_members_zstd_frames_and_tails() {
        let original = tar();
        for (frame, compression) in [
            (gzip(&original), Compression::Gzip),
            (
                ruzstd::encoding::compress_to_vec(
                    original.as_slice(),
                    ruzstd::encoding::CompressionLevel::Fastest,
                ),
                Compression::Zstd,
            ),
        ] {
            for tail in [vec![0u8], frame.clone()] {
                let mut bytes = frame.clone();
                bytes.extend(tail);
                assert!(
                    inspect(
                        &mut Cursor::new(&bytes),
                        &pin(&bytes),
                        compression,
                        &Limits::default()
                    )
                    .unwrap_err()
                    .contains("trailing")
                );
            }
        }
    }

    #[test]
    fn rejects_expansion_beyond_tar_byte_limit() {
        let bytes = gzip(&tar());
        let limits = Limits {
            max_tar_bytes: 1024,
            ..Limits::default()
        };
        assert!(
            inspect(
                &mut Cursor::new(&bytes),
                &pin(&bytes),
                Compression::Gzip,
                &limits
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_zstd_window_bomb_before_allocating() {
        let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0, 0xa0, 1, 0, 0];
        let error = inspect(
            &mut Cursor::new(bytes),
            &pin(&bytes),
            Compression::Zstd,
            &Limits::default(),
        )
        .unwrap_err();
        assert!(error.contains("window_size is too big"));
    }

    #[test]
    fn rejects_zstd_content_checksum_mismatch() {
        let mut bytes = ruzstd::encoding::compress_to_vec(
            tar().as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert_ne!(bytes[4] & 4, 0, "test frame must carry a checksum");
        let length = bytes.len();
        bytes[length - 1] ^= 1;
        assert!(
            inspect(
                &mut Cursor::new(&bytes),
                &pin(&bytes),
                Compression::Zstd,
                &Limits::default()
            )
            .unwrap_err()
            .contains("checksum")
        );
    }

    #[test]
    fn rejects_input_changed_between_digest_and_decode() {
        struct ChangingInput {
            first: Cursor<Vec<u8>>,
            second: Cursor<Vec<u8>>,
            seeks: u32,
        }
        impl Read for ChangingInput {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.seeks < 2 {
                    self.first.read(buffer)
                } else {
                    self.second.read(buffer)
                }
            }
        }
        impl Seek for ChangingInput {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.seeks += 1;
                if self.seeks < 2 {
                    self.first.seek(position)
                } else {
                    self.second.seek(position)
                }
            }
        }
        let encode = |value: &[u8]| {
            let mut encoder = GzEncoder::new(Vec::new(), GzipCompression::none());
            encoder.write_all(value).unwrap();
            encoder.finish().unwrap()
        };
        let bytes = encode(&tar());
        let mut different = tar();
        different[512] = b'b';
        let changed = encode(&different);
        assert_eq!(bytes.len(), changed.len());
        let mut input = ChangingInput {
            first: Cursor::new(bytes.clone()),
            second: Cursor::new(changed),
            seeks: 0,
        };
        assert!(
            inspect(
                &mut input,
                &pin(&bytes),
                Compression::Gzip,
                &Limits::default()
            )
            .unwrap_err()
            .contains("SHA-256")
        );
    }
}
