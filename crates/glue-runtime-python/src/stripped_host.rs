//! Independently pinned stock stripped host image. This is not a new producer,
//! a bundled bootstrap identity, or permission to accept arbitrary stripped ELF.

pub(crate) const LIBRARY_SIZE: u64 = 22_177_832;
pub(crate) const LIBRARY_SHA256: &str =
    "327af7e7114d339222b4fa8af954207c78a3b382f1edda667f16a48c89dfaf75";
pub(crate) const ARTIFACT_SHA256: &str =
    "52c6993abd6ac687cceb787ecee83b166271bc06ad80ac9cac82c5d28d3c00bc";

pub(crate) fn artifact_pin() -> glue_pbs::pins::ArtifactPin {
    glue_pbs::pins::ArtifactPin {
        filename: "cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz".into(),
        size: 29_327_967,
        sha256: ARTIFACT_SHA256.into(),
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz".into(),
    }
}
