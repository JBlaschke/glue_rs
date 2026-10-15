//! Bounded buffering that retains read-ahead across nearby absolute seeks.
//!
//! Archive validation deliberately checks both central and local headers. A
//! normal `BufReader::seek(Start(..))` discards read-ahead for every small field;
//! this adapter translates known positions to `seek_relative` instead.
use std::io::{self, BufReader, Read, Seek, SeekFrom};

pub const MAX_READ_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct BufferedReader<R: Read> {
    inner: BufReader<R>,
    position: Option<u64>,
}

impl<R: Read> BufferedReader<R> {
    pub fn new(source: R) -> Self {
        Self {
            inner: BufReader::with_capacity(MAX_READ_BUFFER_BYTES, source),
            position: None,
        }
    }

    pub fn with_capacity(capacity: usize, source: R) -> io::Result<Self> {
        if capacity == 0 || capacity > MAX_READ_BUFFER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "archive read buffer must be 1..=65536 bytes",
            ));
        }
        Ok(Self {
            inner: BufReader::with_capacity(capacity, source),
            position: None,
        })
    }

    pub fn get_ref(&self) -> &R {
        self.inner.get_ref()
    }
}

impl<R: Read> Read for BufferedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(bytes) {
            Ok(count) => {
                self.position = self
                    .position
                    .and_then(|position| position.checked_add(count as u64));
                Ok(count)
            }
            Err(error) => {
                self.position = None;
                Err(error)
            }
        }
    }
}

impl<R: Read + Seek> Seek for BufferedReader<R> {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let target = match seek {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(offset) => {
                let current = self.stream_position()?;
                Some(
                    if offset >= 0 {
                        current.checked_add(offset as u64)
                    } else {
                        current.checked_sub(offset.unsigned_abs())
                    }
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek position is outside u64 range",
                        )
                    })?,
                )
            }
            SeekFrom::End(_) => None,
        };
        if let (Some(current), Some(target)) = (self.position, target) {
            let delta = i64::try_from(i128::from(target) - i128::from(current));
            if let Ok(delta) = delta {
                self.position = None;
                self.inner.seek_relative(delta)?;
                self.position = Some(target);
                return Ok(target);
            }
        }
        self.position = None;
        let position = self.inner.seek(seek)?;
        self.position = Some(position);
        Ok(position)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        if let Some(position) = self.position {
            return Ok(position);
        }
        let position = self.inner.stream_position()?;
        self.position = Some(position);
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Archive, Manifest, write_archive};
    use std::{cell::Cell, collections::BTreeMap, io::Cursor, rc::Rc};

    struct Counted {
        source: Cursor<Vec<u8>>,
        reads: Rc<Cell<usize>>,
        seeks: Rc<Cell<usize>>,
        fail_read: bool,
        fail_seek: bool,
    }
    impl Read for Counted {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            if self.fail_read {
                return Err(io::Error::other("injected read failure"));
            }
            self.source.read(bytes)
        }
    }
    impl Seek for Counted {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.seeks.set(self.seeks.get() + 1);
            if self.fail_seek {
                return Err(io::Error::other("injected seek failure"));
            }
            self.source.seek(position)
        }
    }
    fn counted(bytes: Vec<u8>) -> Counted {
        Counted {
            source: Cursor::new(bytes),
            reads: Rc::new(Cell::new(0)),
            seeks: Rc::new(Cell::new(0)),
            fail_read: false,
            fail_seek: false,
        }
    }

    #[test]
    fn ten_thousand_header_field_seeks_use_bounded_page_reads() {
        fn headers(reader: &mut (impl Read + Seek)) {
            for row in 0..10_000 {
                let mut fixed = [0; 46];
                let mut name = [0; 18];
                reader.seek(SeekFrom::Start(row * 64)).unwrap();
                reader.read_exact(&mut fixed).unwrap();
                reader.seek(SeekFrom::Start(row * 64 + 46)).unwrap();
                reader.read_exact(&mut name).unwrap();
                assert!(fixed.iter().chain(name.iter()).all(|byte| *byte == 7));
            }
        }
        let mut plain = counted(vec![7; 640_000]);
        headers(&mut plain);
        assert_eq!(plain.reads.get(), 20_000);
        assert_eq!(plain.seeks.get(), 20_000);
        let source = counted(vec![7; 640_000]);
        let reads = source.reads.clone();
        let seeks = source.seeks.clone();
        let mut buffered = BufferedReader::new(source);
        headers(&mut buffered);
        assert!(reads.get() <= 11, "{} reads", reads.get());
        assert!(seeks.get() <= 2, "{} seeks", seeks.get());
        assert_eq!(buffered.stream_position().unwrap(), 640_000);
    }

    #[test]
    fn arbitrary_backward_forward_end_and_invalid_seeks_preserve_bytes() {
        let bytes: Vec<_> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let mut expected = Cursor::new(bytes.clone());
        let mut actual = BufferedReader::new(Cursor::new(bytes));
        for seek in [
            SeekFrom::Start(100),
            SeekFrom::Current(-50),
            SeekFrom::Start(100_000),
            SeekFrom::Start(30),
            SeekFrom::End(-100),
            SeekFrom::Start(250_000),
            SeekFrom::Start(0),
        ] {
            assert_eq!(actual.seek(seek).unwrap(), expected.seek(seek).unwrap());
            let mut a = [0; 17];
            let mut b = [0; 17];
            assert_eq!(actual.read(&mut a).unwrap(), expected.read(&mut b).unwrap());
            assert_eq!(a, b);
        }
        let before = actual.stream_position().unwrap();
        assert!(actual.seek(SeekFrom::Current(i64::MIN)).is_err());
        assert_eq!(actual.stream_position().unwrap(), before);
        let mut initial = Cursor::new(vec![9; 200]);
        initial.set_position(123);
        let mut buffered = BufferedReader::new(initial);
        let mut bytes = [0; 10];
        buffered.read_exact(&mut bytes).unwrap();
        assert_eq!(buffered.stream_position().unwrap(), 133);
    }

    #[test]
    fn bounds_and_inner_io_failures_are_not_hidden() {
        assert!(BufferedReader::with_capacity(0, Cursor::new(vec![])).is_err());
        assert!(
            BufferedReader::with_capacity(MAX_READ_BUFFER_BYTES + 1, Cursor::new(vec![])).is_err()
        );
        let mut source = counted(vec![0; 200_000]);
        source.fail_read = true;
        assert_eq!(
            BufferedReader::new(source)
                .read(&mut [0; 1])
                .unwrap_err()
                .to_string(),
            "injected read failure"
        );
        let mut source = counted(vec![0; 200_000]);
        source.fail_seek = true;
        assert_eq!(
            BufferedReader::new(source)
                .seek(SeekFrom::End(0))
                .unwrap_err()
                .to_string(),
            "injected seek failure"
        );
    }

    #[test]
    fn invalid_archive_and_corrupt_payload_rejections_stay_identical() {
        let manifest =
            Manifest::from_json(include_bytes!("../../../fixtures/resources/manifest.json"))
                .unwrap();
        let contents = BTreeMap::from([
            (
                "app/main.lua".to_owned(),
                include_bytes!("../../../fixtures/resources/input/app/main.lua").to_vec(),
            ),
            (
                "assets/message.txt".to_owned(),
                include_bytes!("../../../fixtures/resources/input/assets/message.txt").to_vec(),
            ),
        ]);
        let original = write_archive(Cursor::new(Vec::new()), &manifest, &contents)
            .unwrap()
            .into_inner();
        let mut bad = original.clone();
        bad[0] ^= 1;
        let plain = Archive::open(Cursor::new(bad.clone()))
            .err()
            .unwrap()
            .to_string();
        let buffered = Archive::open(BufferedReader::new(Cursor::new(bad)))
            .err()
            .unwrap()
            .to_string();
        assert_eq!(plain, buffered);
        let content = &contents["assets/message.txt"];
        let index = original
            .windows(content.len())
            .position(|bytes| bytes == content)
            .unwrap();
        let mut bad = original;
        bad[index] ^= 1;
        let plain = Archive::open(Cursor::new(bad.clone()))
            .unwrap()
            .read_resource("assets/message.txt")
            .unwrap_err()
            .to_string();
        let buffered = Archive::open(BufferedReader::new(Cursor::new(bad)))
            .unwrap()
            .read_resource("assets/message.txt")
            .unwrap_err()
            .to_string();
        assert_eq!(plain, buffered);
    }
}
