use serde::{Deserialize, Serialize};

pub const MAX_COMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Build-time inputs only. This is not a runtime manifest or execution profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub schema_version: u32,
    pub release: String,
    pub revision: String,
    pub python_version: String,
    pub target_triple: String,
    pub build_options: String,
    pub full: ArtifactPin,
    pub install_only: ArtifactPin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPin {
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    pub url: String,
}

impl Pins {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 16 * 1024 {
            return Err("PBS pins exceed 16 KiB".into());
        }
        let pins: Self = serde_json::from_value(crate::strict_json(bytes)?)
            .map_err(|error| format!("invalid PBS pins: {error}"))?;
        pins.validate()?;
        Ok(pins)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 0
            || self.target_triple != "aarch64-unknown-linux-gnu"
            || self.build_options != "pgo+lto"
        {
            return Err("PBS inspector requires schema 0, GNU Linux arm64, pgo+lto".into());
        }
        let parts: Vec<_> = self.python_version.split('.').collect();
        if parts.len() != 3
            || parts[0] != "3"
            || parts[1] != "13"
            || parts[2].is_empty()
            || !parts[2].bytes().all(|byte| byte.is_ascii_digit())
            || parts[2].parse::<u16>().is_err()
            || (parts[2].len() > 1 && parts[2].starts_with('0'))
        {
            return Err("PBS inspector requires an exact CPython 3.13 patch version".into());
        }
        if self.release.len() != 8
            || !self.release.bytes().all(|byte| byte.is_ascii_digit())
            || !hex(&self.revision, 40)
        {
            return Err(
                "PBS release/revision must be a date tag and exact lowercase Git SHA".into(),
            );
        }
        let prefix = format!(
            "cpython-{}+{}-{}-",
            self.python_version, self.release, self.target_triple
        );
        for (pin, suffix) in [
            (&self.full, "pgo+lto-full.tar.zst"),
            (&self.install_only, "install_only.tar.gz"),
        ] {
            if pin.filename != format!("{prefix}{suffix}")
                || !hex(&pin.sha256, 64)
                || pin.size == 0
                || pin.size > MAX_COMPRESSED_BYTES
            {
                return Err("PBS artifact identity, size or SHA-256 is invalid".into());
            }
            let expected_url = format!(
                "https://github.com/astral-sh/python-build-standalone/releases/download/{}/{}",
                self.release,
                pin.filename.replace('+', "%2B")
            );
            if pin.url != expected_url {
                return Err(
                    "PBS artifact URL must identify its exact pinned upstream release".into(),
                );
            }
        }
        Ok(())
    }
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> Pins {
        Pins::from_json(include_bytes!("../../../fixtures/python-pbs/pins.json")).unwrap()
    }

    #[test]
    fn exact_checked_in_artifact_pins_are_valid() {
        pins().validate().unwrap();
    }

    #[test]
    fn rejects_unsupported_variant_and_targets() {
        for field in [
            "target", "build", "version", "stripped", "url", "digest", "revision", "size",
        ] {
            let mut pins = pins();
            match field {
                "target" => pins.target_triple = "x86_64-unknown-linux-gnu".into(),
                "build" => pins.build_options = "freethreaded+pgo+lto".into(),
                "version" => pins.python_version = "3.13".into(),
                "stripped" => {
                    pins.install_only.filename = pins
                        .install_only
                        .filename
                        .replace("install_only", "install_only_stripped")
                }
                "url" => pins.full.url = "https://example.com/runtime".into(),
                "digest" => pins.full.sha256 = "0".repeat(63),
                "revision" => pins.revision = "main".into(),
                "size" => pins.full.size = MAX_COMPRESSED_BYTES + 1,
                _ => unreachable!(),
            }
            assert!(pins.validate().is_err(), "{field}");
        }
    }

    #[test]
    fn rejects_duplicate_fields_unknown_fields_and_oversized_json() {
        assert!(
            Pins::from_json(br#"{"schema_version":0,"schema_version":0}"#)
                .unwrap_err()
                .contains("duplicate")
        );
        let mut value = serde_json::to_value(pins()).unwrap();
        value["download_at_execution"] = true.into();
        assert!(Pins::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Pins::from_json(&vec![b' '; 16 * 1024 + 1]).is_err());
    }
}
