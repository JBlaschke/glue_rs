use glue_pack::native::macos::inspect_bytes;
#[test]
fn malformed_macho_load_tables_and_missing_slice_reject() {
    assert!(inspect_bytes(b"", None).is_err());
    let mut b = vec![0; 64];
    b[..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    b[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes());
    b[12..16].copy_from_slice(&8u32.to_le_bytes());
    assert_eq!(inspect_bytes(&b, None).unwrap().kind, "bundle");
    assert!(inspect_bytes(&b, Some("x86_64")).is_err());
    b[16..20].copy_from_slice(&1u32.to_le_bytes());
    b[20..24].copy_from_slice(&8u32.to_le_bytes());
    assert!(inspect_bytes(&b, None).is_err());
}
#[cfg(target_os = "macos")]
mod native {
    use glue_format::*;
    use glue_pack::{
        distribution::PayloadSource,
        native::{NativeRequest, NativeSearchRoot, collect},
    };
    use std::{
        collections::BTreeSet,
        fs,
        path::PathBuf,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "glue-dyld-{}-{}",
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
    fn prepare(root: &std::path::Path, absolute: bool) -> NativeRequest {
        fs::create_dir(root).unwrap();
        fs::write(root.join("dep.c"), "int dependency(void){return 42;}\n").unwrap();
        fs::write(
            root.join("module.c"),
            "extern int dependency(void);int answer(void){return dependency();}\n",
        )
        .unwrap();
        let identity = if absolute {
            root.join("libdep.dylib").to_string_lossy().into_owned()
        } else {
            "@loader_path/libdep.dylib".into()
        };
        assert!(
            Command::new("/usr/bin/cc")
                .current_dir(root)
                .args([
                    "-dynamiclib",
                    "dep.c",
                    "-Wl,-headerpad_max_install_names",
                    "-install_name",
                    &identity,
                    "-o",
                    "libdep.dylib"
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/cc")
                .current_dir(root)
                .args([
                    "-bundle",
                    "module.c",
                    "-L.",
                    "-ldep",
                    "-Wl,-headerpad_max_install_names",
                    "-o",
                    "module.so"
                ])
                .status()
                .unwrap()
                .success()
        );
        NativeRequest {
            images: vec![root.join("module.so")],
            search_roots: vec![NativeSearchRoot {
                source: root.to_owned(),
                deployed: "native/example".into(),
                provider: DependencyProvider::Bundled,
            }],
            target: if cfg!(target_arch = "aarch64") {
                "aarch64-apple-darwin"
            } else {
                "x86_64-apple-darwin"
            }
            .into(),
            normalize: false,
            host_libraries: BTreeSet::new(),
        }
    }
    #[test]
    fn prebuilt_images_load_unchanged_and_normalize_only_on_request() {
        for absolute in [false, true] {
            let t = Temp::new();
            let source = t.0.join("build input");
            let mut request = prepare(&source, absolute);
            let input_hash = digest(&fs::read(source.join("module.so")).unwrap());
            if absolute {
                assert_eq!(
                    collect(&request).unwrap_err().code,
                    DiagnosticCode::TransformationRequired
                );
                request.normalize = true;
            }
            let closure = collect(&request).unwrap();
            assert_eq!(
                digest(&fs::read(source.join("module.so")).unwrap()),
                input_hash
            );
            if absolute {
                assert_eq!(closure.inventory.transformations.len(), 2);
            } else {
                assert!(closure.inventory.transformations.is_empty());
            }
            let otool = Command::new("/usr/bin/otool")
                .arg("-L")
                .arg(source.join("module.so"))
                .output()
                .unwrap();
            assert!(otool.status.success());
            let output = String::from_utf8(otool.stdout).unwrap();
            assert!(output.contains("libdep.dylib"));
            let deployed = t.0.join("relocated ü tree");
            for (p, s) in closure.payloads {
                let out = deployed.join(p);
                fs::create_dir_all(out.parent().unwrap()).unwrap();
                match s {
                    PayloadSource::File(p) => {
                        fs::copy(p, &out).unwrap();
                    }
                    PayloadSource::Bytes { bytes, .. } => fs::write(&out, bytes).unwrap(),
                    _ => panic!("unexpected link"),
                };
                assert!(
                    Command::new("/usr/bin/codesign")
                        .args(["--verify", "--strict"])
                        .arg(&out)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            fs::write(t.0.join("loader.c"),"#include <dlfcn.h>\n#include <stdio.h>\nint main(int argc,char**argv){(void)argc;void*h=dlopen(argv[1],RTLD_NOW);if(!h){fputs(dlerror(),stderr);return 1;}int(*f)(void)=dlsym(h,\"answer\");return f&&f()==42?0:2;}\n").unwrap();
            assert!(
                Command::new("/usr/bin/cc")
                    .arg(t.0.join("loader.c"))
                    .arg("-o")
                    .arg(t.0.join("loader"))
                    .status()
                    .unwrap()
                    .success()
            );
            fs::remove_dir_all(&source).unwrap();
            assert!(
                Command::new(t.0.join("loader"))
                    .arg(deployed.join("native/example/module.so"))
                    .env_clear()
                    .current_dir("/")
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
    #[test]
    fn missing_dependency_wrong_slice_and_os_floor_reject() {
        let t = Temp::new();
        let source = t.0.join("input");
        let mut request = prepare(&source, false);
        request.target = if cfg!(target_arch = "aarch64") {
            "x86_64-apple-darwin"
        } else {
            "aarch64-apple-darwin"
        }
        .into();
        assert_eq!(
            collect(&request).unwrap_err().code,
            DiagnosticCode::TargetMismatch
        );
        request.target = if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
        .into();
        let module = source.join("module.so");
        let mut bytes = fs::read(&module).unwrap();
        let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let mut offset = 32usize;
        let mut changed = false;
        for _ in 0..count {
            let command =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fffffff;
            let size =
                u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
            if command == 0x32 {
                bytes[offset + 12..offset + 16].copy_from_slice(&0x7fff0000u32.to_le_bytes());
                changed = true;
                break;
            }
            offset += size;
        }
        assert!(changed, "compiler did not emit macOS build version");
        fs::write(&module, &bytes).unwrap();
        assert_eq!(
            collect(&request).unwrap_err().code,
            DiagnosticCode::TargetMismatch
        );
        // Restore the independently compiled input before checking missing edges.
        let source2 = t.0.join("input2");
        request = prepare(&source2, false);
        fs::remove_file(source2.join("libdep.dylib")).unwrap();
        assert_eq!(
            collect(&request).unwrap_err().code,
            DiagnosticCode::MissingDependency
        );
    }
}
