//! A trusted, bounded entry launcher over the existing byte-only archive bridge.

use glue_format::ResourcePath;

// The temporary function keeps launcher variables out of application globals.
// Delete its only global name before compilation/execution, including failures.
// _compile_source preserves encoding cookies and the measured virtual-filename
// diagnostic handling; user source never becomes a NUL-terminated C string.
const LAUNCHER_TEMPLATE: &str = r#"def _glue_run_source_entry():
    import sys as _sys
    import _glue_archive_bootstrap as _bootstrap
    _globals = _sys.modules["__main__"].__dict__
    del _globals["_glue_run_source_entry"]
    _origin = _bootstrap._origin({entry})
    _globals["__file__"] = _origin
    _globals["__package__"] = None
    _globals["__spec__"] = None
    _globals["__cached__"] = None
    _globals["__loader__"] = None
    _sys.argv = [_origin]
    exec(_bootstrap._compile_source(_bootstrap._ask("read", {entry}), _origin), _globals, _globals)
_glue_run_source_entry()
"#;

pub(super) fn launcher(entry: &str) -> Result<Vec<u8>, String> {
    ResourcePath::new(entry).map_err(|e| e.to_string())?;
    if !entry.starts_with("app/") || !entry.ends_with(".py") {
        return Err("Python source entry must be a .py resource below app/".into());
    }
    if entry.len() > 4096 - "origin\t".len() {
        return Err("Python source entry exceeds the archive callback request bound".into());
    }
    let literal = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    let source = LAUNCHER_TEMPLATE.replace("{entry}", &literal);
    if !source.is_ascii() || source.len() > 256 * 1024 || source.contains('\0') {
        return Err("Python source launcher exceeds the C boundary source contract".into());
    }
    Ok(source.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_entries_are_canonical_resources_and_safe_string_literals() {
        for entry in [
            "app/tasks/report.py",
            "app/python/report.py",
            "app/task's [draft].py",
            "app/task';print('injected')#.py",
        ] {
            let source = String::from_utf8(launcher(entry).unwrap()).unwrap();
            let literal = serde_json::to_string(entry).unwrap();
            assert!(source.contains(&format!("_bootstrap._origin({literal})")));
            assert!(source.contains(&format!("_bootstrap._ask(\"read\", {literal})")));
            assert!(source.is_ascii());
            assert!(!source.contains('\0'));
        }
        for entry in [
            "stdlib/report.py",
            "app/report.pyc",
            "app/../report.py",
            "/app/report.py",
            "app/report\n.py",
            "app/é.py",
            "app/report\0.py",
        ] {
            assert!(launcher(entry).is_err(), "{entry:?}");
        }
        let long = format!(
            "app/{}/{}.py",
            vec!["a".repeat(255); 15].join("/"),
            "b".repeat(244)
        );
        ResourcePath::new(&long).unwrap();
        assert!(launcher(&long).is_err());
    }
}
