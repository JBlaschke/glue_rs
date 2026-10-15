//! Build-time fixture packer; deliberately does not run package scripts.
use glue_format::{Compression, Manifest, ResourceSpec, digest, write_archive};
use std::{collections::BTreeMap, fs, path::Path};
fn walk(
    root: &Path,
    path: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            return Err("symlink fixture input denied".into());
        }
        if ty.is_dir() {
            walk(root, &entry.path(), files)?;
        } else if ty.is_file() {
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or("non-UTF8 path")?
                    .replace('\\', "/"),
                fs::read(entry.path())?,
            );
        }
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: pack SOURCE ARCHIVE".into());
    }
    let mut files = BTreeMap::new();
    walk(Path::new(&args[1]), Path::new(&args[1]), &mut files)?;
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/resources/manifest.json"))?;
    value["components"]["main"]["entry_point"] = "module-index.json".into();
    // The spike uses the legacy fixture envelope only as a bounded resource store.
    let mut manifest: Manifest = serde_json::from_value(value)?;
    manifest.resources = files
        .iter()
        .map(|(p, b)| {
            (
                p.clone(),
                ResourceSpec {
                    size: b.len() as u64,
                    sha256: digest(b),
                    compression: Compression::Deflate,
                },
            )
        })
        .collect();
    write_archive(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[2])?,
        &manifest,
        &files,
    )?;
    Ok(())
}
