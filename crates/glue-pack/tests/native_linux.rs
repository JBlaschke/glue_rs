use glue_format::{DependencyProvider, DiagnosticCode};
use glue_pack::native::{NativeRequest, NativeSearchRoot, collect, linux::inspect_bytes};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
fn fixture(name: &str, needed: Option<&str>, rpath: &str) -> Vec<u8> {
    let mut b = vec![0u8; 2048];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    fn u16(b: &mut [u8], p: usize, n: u16) {
        b[p..p + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn u32(b: &mut [u8], p: usize, n: u32) {
        b[p..p + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn u64(b: &mut [u8], p: usize, n: u64) {
        b[p..p + 8].copy_from_slice(&n.to_le_bytes());
    }
    u16(&mut b, 16, 3);
    u16(&mut b, 18, 62);
    u64(&mut b, 32, 64);
    u16(&mut b, 54, 56);
    u16(&mut b, 56, 4);
    for (i, tag) in [1u32, 2, 7, 0x6474e550].iter().enumerate() {
        let p = 64 + i * 56;
        u32(&mut b, p, *tag);
        let (o, n) = if i == 0 {
            (0, 2048)
        } else if i == 1 {
            (512, 128)
        } else {
            (0, 0)
        };
        u64(&mut b, p + 8, o);
        u64(&mut b, p + 16, 0x1000 + o);
        u64(&mut b, p + 32, n);
        u64(&mut b, p + 40, n);
    }
    let strings = format!("\0{name}\0{}\0{rpath}\0", needed.unwrap_or(""));
    b[768..768 + strings.len()].copy_from_slice(strings.as_bytes());
    let mut tags = vec![
        (5, 0x1000 + 768),
        (10, strings.len() as u64),
        (14, 1),
        (0x6ffffef5, 1),
        (29, (name.len() + needed.unwrap_or("").len() + 3) as u64),
    ];
    if needed.is_some() {
        tags.push((1, (name.len() + 2) as u64));
    }
    tags.push((0, 0));
    for (i, (t, v)) in tags.iter().enumerate() {
        u64(&mut b, 512 + i * 16, *t);
        u64(&mut b, 520 + i * 16, *v);
    }
    b
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "glue-elf-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn elf_accepts_os_loader_features_and_validates_ranges() {
    let b = fixture("libmain.so", Some("libdep.so"), "$ORIGIN");
    let f = inspect_bytes(&b).unwrap();
    assert_eq!(f.architecture, "x86_64");
    assert_eq!(f.dependencies, vec!["libdep.so"]);
    assert_eq!(f.search_paths, vec!["$ORIGIN"]);
    for feature in ["tls", "unwind", "gnu_hash"] {
        assert!(f.features.contains(feature));
    }
    for n in [0, 16, 63, 128, 550, 800] {
        assert!(inspect_bytes(&b[..n]).is_err());
    }
    let mut bad = b;
    bad[18] = 3;
    assert!(inspect_bytes(&bad).is_err());
}
#[test]
fn closure_retains_layout_and_diagnoses_missing_escape_wrong_target() {
    let t = Temp::new();
    fs::create_dir(t.0.join("pkg")).unwrap();
    let main = t.0.join("pkg/main.so");
    let dep = t.0.join("pkg/libdep.so");
    fs::write(&main, fixture("main.so", Some("libdep.so"), "$ORIGIN")).unwrap();
    fs::write(&dep, fixture("libdep.so", None, "$ORIGIN")).unwrap();
    let mut request = NativeRequest {
        images: vec![main.clone()],
        search_roots: vec![NativeSearchRoot {
            source: t.0.clone(),
            deployed: "native/env".into(),
            provider: DependencyProvider::Bundled,
        }],
        target: "x86_64-unknown-linux-gnu".into(),
        normalize: false,
        host_libraries: BTreeSet::new(),
    };
    let result = collect(&request).unwrap();
    assert!(result.payloads.contains_key("native/env/pkg/main.so"));
    assert!(result.payloads.contains_key("native/env/pkg/libdep.so"));
    assert_eq!(result.inventory.edges.len(), 1);
    request.target = "aarch64-unknown-linux-gnu".into();
    assert_eq!(
        collect(&request).unwrap_err().code,
        DiagnosticCode::TargetMismatch
    );
    request.target = "x86_64-unknown-linux-gnu".into();
    fs::remove_file(&dep).unwrap();
    assert_eq!(
        collect(&request).unwrap_err().code,
        DiagnosticCode::MissingDependency
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/bin/sh", &dep).unwrap();
        assert_eq!(
            collect(&request).unwrap_err().code,
            DiagnosticCode::PathEscape
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn real_prebuilt_extension_secondary_library_loads_after_relocation() {
    use std::process::Command;
    let t = Temp::new();
    let source = t.0.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("dep.c"), "int dependency(void){return 42;}\n").unwrap();
    fs::write(source.join("module.c"),"extern int dependency(void); _Thread_local int tls; int answer(void){return dependency()+(tls++);}\n").unwrap();
    for args in [
        vec![
            "-shared",
            "-fPIC",
            "dep.c",
            "-Wl,-soname,libdep.so",
            "-o",
            "libdep.so",
        ],
        vec![
            "-shared",
            "-fPIC",
            "module.c",
            "-L.",
            "-ldep",
            "-Wl,-rpath,$ORIGIN",
            "-o",
            "module.so",
        ],
    ] {
        assert!(
            Command::new("cc")
                .current_dir(&source)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let request = NativeRequest {
        images: vec![source.join("module.so")],
        search_roots: vec![NativeSearchRoot {
            source: source.clone(),
            deployed: "native".into(),
            provider: DependencyProvider::Bundled,
        }],
        target: format!("{arch}-unknown-linux-gnu"),
        normalize: false,
        host_libraries: BTreeSet::new(),
    };
    let collection = collect(&request).unwrap();
    assert!(collection.inventory.features.contains("tls"));
    let readelf = Command::new("readelf")
        .args(["-d", "-V"])
        .arg(source.join("module.so"))
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let text = String::from_utf8(readelf.stdout).unwrap();
    for edge in &collection.inventory.edges {
        assert!(text.contains(&edge.name));
    }
    let deployed = t.0.join("relocated tree ü");
    for (path, src) in collection.payloads {
        if let glue_pack::distribution::PayloadSource::File(src) = src {
            let target = deployed.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(src, target).unwrap();
        }
    }
    fs::write(t.0.join("load.c"),"#include <dlfcn.h>\nint main(int argc,char**argv){(void)argc;void*h=dlopen(argv[1],RTLD_NOW);if(!h)return 1;int(*f)(void)=dlsym(h,\"answer\");return f&&f()==42&&f()==43?0:2;}\n").unwrap();
    assert!(
        Command::new("cc")
            .arg(t.0.join("load.c"))
            .args(["-ldl", "-o"])
            .arg(t.0.join("loader"))
            .status()
            .unwrap()
            .success()
    );
    fs::rename(&source, t.0.join("inaccessible-input")).unwrap();
    assert!(
        Command::new(t.0.join("loader"))
            .arg(deployed.join("native/module.so"))
            .env_clear()
            .current_dir("/")
            .status()
            .unwrap()
            .success()
    );
}
