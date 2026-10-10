//! Source-only archive resolution and length-delimited immutable resource replies.
//! This module has no Python API or filesystem lookup during request handling.

use glue_format::{ResourcePath, validate_resource_paths};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_REPLY: usize = 4 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_TOTAL: usize = 48 * 1024 * 1024;
const ROOTS: [&str; 2] = ["app/python", "stdlib"];

pub(super) struct Index {
    app_id: String,
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeSet<String>,
    owners: BTreeMap<String, &'static str>,
}

impl Index {
    pub(super) fn new(app_id: &str, files: BTreeMap<String, Vec<u8>>) -> Result<Self, String> {
        if app_id.is_empty()
            || app_id.len() > 128
            || !app_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("invalid archive importer app identity".into());
        }
        if files.len() > MAX_FILES {
            return Err("archive importer file count exceeds 4096".into());
        }
        validate_resource_paths(files.keys()).map_err(|e| e.to_string())?;
        let mut total = 0usize;
        let mut directories = BTreeSet::new();
        for (key, bytes) in &files {
            if !ROOTS
                .iter()
                .any(|root| key.starts_with(&format!("{root}/")))
            {
                return Err(format!("resource outside archive import roots: {key}"));
            }
            total = total
                .checked_add(bytes.len())
                .ok_or("archive importer size overflow")?;
            if bytes.len() > MAX_REPLY || total > MAX_TOTAL {
                return Err("archive importer verified bytes exceed bounded profile".into());
            }
            let mut parent = key.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                directories.insert(prefix.into());
                parent = prefix;
            }
        }
        let mut owners = BTreeMap::new();
        for root in ROOTS {
            let prefix = format!("{root}/");
            for key in files.keys().filter_map(|key| key.strip_prefix(&prefix)) {
                let first = key.split('/').next().unwrap();
                let name = first.strip_suffix(".py").unwrap_or(first);
                if module_name(name)
                    && name != "__init__"
                    && owners
                        .insert(name.into(), root)
                        .is_some_and(|prior| prior != root)
                {
                    return Err(format!("archive import roots overlap: {name}"));
                }
            }
        }
        for directory in &directories {
            if files.contains_key(&format!("{directory}.py"))
                && files.contains_key(&format!("{directory}/__init__.py"))
            {
                return Err(format!("ambiguous archive module/directory: {directory}"));
            }
        }
        Ok(Self {
            app_id: app_id.into(),
            files,
            directories,
            owners,
        })
    }

    fn origin(&self, key: &str) -> String {
        let mut encoded = String::new();
        for byte in key.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
                encoded.push(byte as char);
            } else {
                use std::fmt::Write;
                write!(&mut encoded, "%{byte:02X}").unwrap();
            }
        }
        format!("glue://{}/{encoded}", self.app_id)
    }

    fn resolve(&self, name: &str) -> Result<Vec<u8>, String> {
        if !module_name(name) || name.len() > 255 {
            return Err("invalid archive Python module name".into());
        }
        let top = name.split('.').next().unwrap();
        let Some(root) = self.owners.get(top) else {
            return Ok(b"missing\n\n\n".to_vec());
        };
        let directory = format!("{root}/{}", name.replace('.', "/"));
        // A module cannot gain descendants merely because similarly named files
        // are present; each parent must itself resolve as a package/namespace.
        let mut parent = directory.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if prefix == *root {
                break;
            }
            if !self.directories.contains(prefix)
                || (self.files.contains_key(&format!("{prefix}.py"))
                    && !self.files.contains_key(&format!("{prefix}/__init__.py")))
            {
                return Ok(b"blocked\n\n\n".to_vec());
            }
            parent = prefix;
        }
        let package = format!("{directory}/__init__.py");
        let module = format!("{directory}.py");
        let reply = if self.files.contains_key(&package) {
            format!("package\n{package}\n{}\n{directory}", self.origin(&package))
        } else if self.files.contains_key(&module) {
            format!("module\n{module}\n{}\n", self.origin(&module))
        } else if self.directories.contains(&directory) {
            format!("namespace\n{directory}\n\n{directory}")
        } else {
            "blocked\n\n\n".into()
        };
        Ok(reply.into_bytes())
    }

    pub(super) fn request(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        if request.len() > 4096 {
            return Err("archive resource request exceeds 4096 bytes".into());
        }
        let text =
            std::str::from_utf8(request).map_err(|_| "archive resource request is not UTF-8")?;
        let (operation, key) = text
            .split_once('\t')
            .ok_or("malformed archive resource request")?;
        if operation == "resolve" {
            return self.resolve(key);
        }
        ResourcePath::new(key).map_err(|e| e.to_string())?;
        if !ROOTS
            .iter()
            .any(|root| key == *root || key.starts_with(&format!("{root}/")))
        {
            return Err("archive resource request is outside import roots".into());
        }
        match operation {
            "read" => self
                .files
                .get(key)
                .cloned()
                .ok_or_else(|| format!("archive resource is not a file: {key}")),
            "stat" => Ok(if let Some(bytes) = self.files.get(key) {
                format!("file\n{}", bytes.len()).into_bytes()
            } else if self.directories.contains(key) {
                b"directory\n0".to_vec()
            } else {
                b"missing\n0".to_vec()
            }),
            "list" => {
                if !self.directories.contains(key) {
                    return Err(format!("archive resource is not a directory: {key}"));
                }
                let prefix = format!("{key}/");
                let children: BTreeSet<_> = self
                    .files
                    .keys()
                    .chain(self.directories.iter())
                    .filter_map(|path| path.strip_prefix(&prefix))
                    .filter(|name| !name.is_empty() && !name.contains('/'))
                    .collect();
                let reply = children
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("\n")
                    .into_bytes();
                if reply.len() > MAX_REPLY {
                    return Err("archive directory reply exceeds bound".into());
                }
                Ok(reply)
            }
            "origin" => Ok(self.origin(key).into_bytes()),
            _ => Err("unknown archive resource request".into()),
        }
    }
}

fn module_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|part| {
            let mut chars = part.bytes();
            chars
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn files() -> BTreeMap<String, Vec<u8>> {
        [
            ("app/python/pkg/__init__.py", b"pkg".as_slice()),
            ("app/python/pkg/member.py", b"member".as_slice()),
            ("app/python/pkg/data with space.bin", b"\0\xff".as_slice()),
            ("app/python/ns/child.py", b"child".as_slice()),
            ("app/python/plain.py", b"plain".as_slice()),
            ("stdlib/json/__init__.py", b"json".as_slice()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.to_vec()))
        .collect()
    }
    #[test]
    fn resolves_source_packages_namespaces_and_reserved_missing_descendants() {
        let i = Index::new("fixture", files()).unwrap();
        assert_eq!(i.request(b"resolve\tpkg").unwrap(), b"package\napp/python/pkg/__init__.py\nglue://fixture/app/python/pkg/__init__.py\napp/python/pkg");
        assert_eq!(
            i.request(b"resolve\tpkg.member").unwrap(),
            b"module\napp/python/pkg/member.py\nglue://fixture/app/python/pkg/member.py\n"
        );
        assert_eq!(
            i.request(b"resolve\tns").unwrap(),
            b"namespace\napp/python/ns\n\napp/python/ns"
        );
        for name in ["pkg.absent", "plain.child"] {
            assert_eq!(
                i.request(format!("resolve\t{name}").as_bytes()).unwrap(),
                b"blocked\n\n\n"
            );
        }
        assert_eq!(i.request(b"resolve\tabsent").unwrap(), b"missing\n\n\n");
    }
    #[test]
    fn immutable_resource_protocol_returns_bytes_metadata_and_sorted_children() {
        let i = Index::new("fixture", files()).unwrap();
        assert_eq!(
            i.request(b"read\tapp/python/pkg/data with space.bin")
                .unwrap(),
            b"\0\xff"
        );
        assert_eq!(i.request(b"stat\tapp/python/pkg").unwrap(), b"directory\n0");
        assert_eq!(
            i.request(b"stat\tapp/python/absent").unwrap(),
            b"missing\n0"
        );
        assert_eq!(
            i.request(b"list\tapp/python/pkg").unwrap(),
            b"__init__.py\ndata with space.bin\nmember.py"
        );
        assert_eq!(
            i.request(b"origin\tapp/python/pkg/data with space.bin")
                .unwrap(),
            b"glue://fixture/app/python/pkg/data%20with%20space.bin"
        );
    }
    #[test]
    fn rejects_malformed_aliases_escaping_paths_and_unknown_operations() {
        let i = Index::new("fixture", files()).unwrap();
        for request in [
            "resolve\ta..b",
            "resolve\t1name",
            "resolve\tpkg/child",
            "read\t/app/python/pkg",
            "read\tapp/python/../pkg",
            "read\tapp/python/pkg\\member.py",
            "read\tpython/libpython.so",
            "write\tapp/python/pkg",
            "list\tapp/python/plain.py",
            "missingseparator",
        ] {
            assert!(i.request(request.as_bytes()).is_err(), "{request}");
        }
        assert!(i.request(&vec![b'x'; 4097]).is_err());
        assert!(i.request(b"read\t\xff").is_err());
    }
    #[test]
    fn rejects_ambiguous_and_overlapping_import_roots() {
        let mut f = files();
        f.insert("app/python/pkg.py".into(), vec![]);
        assert!(Index::new("fixture", f).is_err());
        let mut f = files();
        f.insert("stdlib/pkg.py".into(), vec![]);
        assert!(Index::new("fixture", f).is_err());
        let mut f = files();
        f.insert("app/python/Pkg/asset".into(), vec![]);
        assert!(Index::new("fixture", f).is_err());
    }
    #[test]
    fn enforces_per_file_and_collection_bounds_before_callbacks() {
        let mut f = files();
        f.insert("app/python/large.bin".into(), vec![0; MAX_REPLY + 1]);
        assert!(Index::new("fixture", f).is_err());
        let f = (0..MAX_FILES + 1)
            .map(|n| (format!("app/python/a{n}.py"), vec![]))
            .collect();
        assert!(Index::new("fixture", f).is_err());
        assert!(Index::new("../fixture", files()).is_err());
    }
}
