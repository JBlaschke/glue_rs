//! Selected installed-tree reads through owned no-follow directory descriptors.
//!
//! Input backing bytes and directory names must remain stable during preparation.
//! Descriptor-relative opens prevent path substitution from following symlinks;
//! they do not freeze a writable file's contents or certify unselected files.

use crate::{PackError, io_error};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

const MAX_SELECTED_FILES: usize = 1041;
const MAX_SELECTED_BYTES: u64 = 128 * 1024 * 1024;

/// Resolve only the already existing output parent. The input's absolute
/// ancestors are opened without following aliases before any payload read.
pub(super) fn reject_overlap(root: &Path, output: &Path) -> Result<(), PackError> {
    let parent = output
        .parent()
        .ok_or_else(|| PackError::Profile("installed runtime output has no parent".into()))?;
    let parent = fs::canonicalize(parent)
        .map_err(|source| io_error("resolve host output parent", parent, source))?;
    if !parent.is_dir() {
        return Err(PackError::Profile(
            "host prerequisite output parent must be a directory".into(),
        ));
    }
    let output =
        parent.join(output.file_name().ok_or_else(|| {
            PackError::Profile("installed runtime output has no final name".into())
        })?);
    if root.starts_with(&output) || output.starts_with(root) {
        return Err(PackError::Profile(
            "installed runtime input and output trees must not overlap".into(),
        ));
    }
    // An existing leaf can itself be an alias into the input. Never follow it
    // or read payloads for a destination that cannot be exclusively created.
    match fs::symlink_metadata(&output) {
        Ok(_) => Err(io_error(
            "create host prefix",
            &output,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "host prefix already exists",
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("stat host output prefix", &output, error)),
    }
}

/// At most four descriptors are live here: the retained installation root,
/// the current selected ancestor, its replacement, and a selected leaf. No
/// directory inventory, unselected leaf or executable alias is opened.
#[cfg(test)]
pub(super) fn read(
    root: &Path,
    limits: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, Vec<u8>>, PackError> {
    validate_limits(limits)?;
    let directory = open_root(root)?;
    read_selected(&directory, root, limits)
}

/// Retain the same no-follow root through physical containment admission and
/// selected reads. Path spelling alone does not identify directories on a
/// case-insensitive filesystem or through mount aliases.
pub(super) fn read_for_output(
    root: &Path,
    output: &Path,
    limits: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, Vec<u8>>, PackError> {
    reject_overlap(root, output)?;
    validate_limits(limits)?;
    let directory = open_root(root)?;
    reject_identity_overlap(&directory, root, output)?;
    read_selected(&directory, root, limits)
}

fn reject_identity_overlap(directory: &File, root: &Path, output: &Path) -> Result<(), PackError> {
    let source = directory
        .metadata()
        .map_err(|source| io_error("stat installed runtime root", root, source))?;
    let parent = output
        .parent()
        .ok_or_else(|| PackError::Profile("installed runtime output has no parent".into()))?;
    let parent = fs::canonicalize(parent)
        .map_err(|source| io_error("resolve host output parent", parent, source))?;
    for ancestor in parent.ancestors() {
        let destination = fs::metadata(ancestor)
            .map_err(|source| io_error("stat host output ancestor", ancestor, source))?;
        if (source.dev(), source.ino()) == (destination.dev(), destination.ino()) {
            return Err(PackError::Profile(
                "installed runtime input and output trees must not overlap".into(),
            ));
        }
    }
    Ok(())
}

fn validate_limits(limits: &BTreeMap<String, u64>) -> Result<(), PackError> {
    if limits.is_empty() || limits.len() > MAX_SELECTED_FILES {
        return Err(PackError::Profile(
            "installed runtime selected file count exceeds its admitted bound".into(),
        ));
    }
    let total = limits.values().try_fold(0_u64, |total, size| {
        total.checked_add(*size).ok_or(PackError::Allocation)
    })?;
    if total > MAX_SELECTED_BYTES {
        return Err(PackError::Profile(
            "installed runtime selected byte caps exceed 128 MiB".into(),
        ));
    }
    for relative in limits.keys() {
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.contains(['\\', '\0'])
            || relative
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(PackError::Profile(
                "installed runtime selected paths must be canonical relative names".into(),
            ));
        }
    }
    Ok(())
}

fn open_root(root: &Path) -> Result<File, PackError> {
    if !root.is_absolute() {
        return Err(PackError::Profile(
            "installed runtime input root must be absolute".into(),
        ));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|source| {
            io_error(
                "open installed runtime filesystem root",
                Path::new("/"),
                source,
            )
        })?;
    let mut path = PathBuf::from("/");
    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                path.push(name);
                directory = open_relative(
                    &directory,
                    name.as_bytes(),
                    &path,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?;
            }
            _ => {
                return Err(PackError::Profile(
                    "installed runtime input root must be canonical and absolute".into(),
                ));
            }
        }
    }
    Ok(directory)
}

fn open_relative(parent: &File, name: &[u8], path: &Path, flags: i32) -> Result<File, PackError> {
    let name = CString::new(name)
        .map_err(|_| PackError::Profile("installed runtime path contains a NUL byte".into()))?;
    // SAFETY: parent owns a live descriptor, name is a terminated single path
    // component, and flags never request creation or a variadic mode argument.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io_error(
            "open installed runtime input",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: openat returned a fresh descriptor whose sole owner is this File.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn read_selected(
    directory: &File,
    root: &Path,
    limits: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, Vec<u8>>, PackError> {
    let mut files = BTreeMap::new();
    for (relative, maximum) in limits {
        let mut names = relative.split('/').peekable();
        let mut ancestor = None;
        let mut path = root.to_path_buf();
        while let Some(name) = names.next() {
            path.push(name);
            let parent = ancestor.as_ref().unwrap_or(directory);
            if names.peek().is_some() {
                ancestor = Some(open_relative(
                    parent,
                    name.as_bytes(),
                    &path,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?);
            } else {
                let mut file = open_relative(
                    parent,
                    name.as_bytes(),
                    &path,
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )?;
                let before = file
                    .metadata()
                    .map_err(|source| io_error("stat installed runtime input", &path, source))?;
                if !before.is_file() || before.len() > *maximum {
                    return Err(PackError::Profile(format!(
                        "installed runtime selected input must be a bounded regular file: {relative}"
                    )));
                }
                let length = usize::try_from(before.len()).map_err(|_| PackError::Allocation)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length)
                    .map_err(|_| PackError::Allocation)?;
                bytes.resize(length, 0);
                file.read_exact(&mut bytes)
                    .map_err(|source| io_error("read installed runtime input", &path, source))?;
                let mut extra = [0];
                if file
                    .read(&mut extra)
                    .map_err(|source| io_error("finish installed runtime input", &path, source))?
                    != 0
                    || file
                        .metadata()
                        .map_err(|source| {
                            io_error("restat installed runtime input", &path, source)
                        })?
                        .len()
                        != before.len()
                {
                    return Err(PackError::Profile(format!(
                        "installed runtime selected input changed while reading: {relative}"
                    )));
                }
                files.insert(relative.clone(), bytes);
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "glue-installed-runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(fs::canonicalize(root).unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn fifo(path: &Path) {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: terminated fixture-owned new path and an ordinary Unix mode.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn owns_only_declared_bytes_without_enumerating_or_opening_other_inputs() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join("lib")).unwrap();
        fs::write(fixture.0.join("lib/source"), b"source\0\xff").unwrap();
        fs::write(fixture.0.join("empty"), b"").unwrap();
        fifo(&fixture.0.join("unselected FIFO"));
        symlink("/unavailable/interpreter", fixture.0.join("python")).unwrap();
        let limits = BTreeMap::from([("empty".into(), 0), ("lib/source".into(), 8)]);
        assert_eq!(
            read(&fixture.0, &limits).unwrap(),
            BTreeMap::from([
                ("empty".into(), Vec::new()),
                ("lib/source".into(), b"source\0\xff".to_vec())
            ])
        );
    }

    #[test]
    fn rejects_links_in_absolute_ancestors_selected_directories_and_leaves() {
        let fixture = Fixture::new();
        let root = fixture.0.join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("lib")).unwrap();
        fs::write(root.join("lib/source"), b"source").unwrap();
        let limits = BTreeMap::from([("lib/source".into(), 6)]);
        let alias = fixture.0.join("alias");
        symlink(&root, &alias).unwrap();
        assert!(read(&alias, &limits).is_err());
        let outer_alias = fixture.0.join("outer-alias");
        symlink(&fixture.0, &outer_alias).unwrap();
        assert!(read(&outer_alias.join("root"), &limits).is_err());
        fs::rename(root.join("lib"), root.join("real-lib")).unwrap();
        symlink("real-lib", root.join("lib")).unwrap();
        assert!(read(&root, &limits).is_err());
        fs::remove_file(root.join("lib")).unwrap();
        fs::rename(root.join("real-lib"), root.join("lib")).unwrap();
        fs::rename(root.join("lib/source"), root.join("lib/real-source")).unwrap();
        symlink("real-source", root.join("lib/source")).unwrap();
        assert!(read(&root, &limits).is_err());
    }

    #[test]
    fn rejects_missing_nonregular_and_oversized_selected_leaves() {
        let fixture = Fixture::new();
        let path = fixture.0.join("selected");
        let limits = BTreeMap::from([("selected".into(), 3)]);
        assert!(read(&fixture.0, &limits).is_err());
        fs::create_dir(&path).unwrap();
        assert!(read(&fixture.0, &limits).is_err());
        fs::remove_dir(&path).unwrap();
        fifo(&path);
        assert!(read(&fixture.0, &limits).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"four").unwrap();
        assert!(read(&fixture.0, &limits).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"four");
    }

    #[test]
    fn retained_root_descriptor_does_not_follow_a_replaced_root_path() {
        let fixture = Fixture::new();
        let root = fixture.0.join("input");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("selected"), b"original").unwrap();
        let directory = open_root(&root).unwrap();
        fs::rename(&root, fixture.0.join("retained-input")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("selected"), b"replacement").unwrap();
        let limits = BTreeMap::from([("selected".into(), 11)]);
        assert_eq!(
            read_selected(&directory, &root, &limits).unwrap()["selected"],
            b"original"
        );
    }

    #[test]
    fn declaration_budgets_and_unsafe_names_reject_before_input_access() {
        let missing = Path::new("/unavailable/installed-runtime");
        for name in [
            "",
            "/absolute",
            "../escape",
            "a/../escape",
            "a//b",
            "a\\b",
            "a\0b",
        ] {
            assert!(matches!(
                read(missing, &BTreeMap::from([(name.into(), 0)])),
                Err(PackError::Profile(_))
            ));
        }
        assert!(matches!(
            read(
                missing,
                &BTreeMap::from([("a".into(), MAX_SELECTED_BYTES + 1)])
            ),
            Err(PackError::Profile(_))
        ));
        let many = (0..=MAX_SELECTED_FILES)
            .map(|index| (format!("file-{index}"), 0))
            .collect();
        assert!(matches!(read(missing, &many), Err(PackError::Profile(_))));
    }

    #[test]
    fn overlap_in_either_direction_and_output_parent_aliases_reject() {
        let fixture = Fixture::new();
        let root = fixture.0.join("input");
        fs::create_dir(&root).unwrap();
        assert!(reject_overlap(&root, &root.join("output")).is_err());
        assert!(reject_overlap(&root, &root).is_err());
        assert!(reject_overlap(&root, &fixture.0).is_err());
        let alias = fixture.0.join("alias");
        symlink(&root, &alias).unwrap();
        assert!(reject_overlap(&root, &alias.join("output")).is_err());
        assert!(reject_overlap(&root, &fixture.0.join("sibling")).is_ok());
        assert!(!root.join("output").exists());
    }

    #[test]
    fn physical_containment_is_checked_before_missing_payloads() {
        let fixture = Fixture::new();
        let root = fixture.0.join("CaseInput");
        fs::create_dir(&root).unwrap();
        let directory = open_root(&root).unwrap();
        assert!(reject_identity_overlap(&directory, &root, &root.join("output")).is_err());
        assert!(reject_identity_overlap(&directory, &root, &fixture.0.join("sibling")).is_ok());
        // Default Mac filesystems accept this spelling as the same directory.
        // On case-sensitive builders the direct identity assertions still run.
        let alias = fixture.0.join("caseinput");
        if alias.is_dir() {
            let error = read_for_output(
                &alias,
                &root.join("output"),
                &BTreeMap::from([("missing-payload".into(), 1)]),
            )
            .unwrap_err();
            assert!(error.to_string().contains("must not overlap"), "{error}");
            assert!(!root.join("output").exists());
        }
    }

    #[test]
    fn existing_output_leaves_and_aliases_reject_without_following_them() {
        let fixture = Fixture::new();
        let root = fixture.0.join("input");
        fs::create_dir(&root).unwrap();
        let existing = fixture.0.join("existing");
        fs::write(&existing, b"preserve output").unwrap();
        let alias = fixture.0.join("alias");
        symlink(&root, &alias).unwrap();
        let dangling = fixture.0.join("dangling");
        symlink(fixture.0.join("missing"), &dangling).unwrap();
        for output in [&existing, &alias, &dangling] {
            assert!(matches!(
                reject_overlap(&root, output),
                Err(PackError::Io { .. })
            ));
        }
        assert_eq!(fs::read(existing).unwrap(), b"preserve output");
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::symlink_metadata(dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!fixture.0.join("missing").exists());
    }
}
