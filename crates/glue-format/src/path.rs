use crate::FormatError;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};

/// Maximum number of slash-separated components in a schema-zero resource path.
pub const MAX_RESOURCE_DEPTH: usize = 64;
/// Maximum combined number of files and implicit directory identities.
pub const MAX_RESOURCE_NODES: usize = 200_000;
/// Maximum bytes retained in case-folded keys plus preserved prefix spellings.
/// Tree-node overhead is bounded separately by [`MAX_RESOURCE_NODES`].
pub const MAX_RESOURCE_METADATA_BYTES: usize = 32 * 1024 * 1024;

/// A canonical archive identity, never a host filesystem path.
///
/// Schema zero deliberately restricts resource names to portable ASCII until a
/// Unicode normalization and case-folding contract is chosen. Separators are `/`;
/// empty components, traversal, Windows devices and case collisions are rejected.
/// Paths may have at most [`MAX_RESOURCE_DEPTH`] components.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourcePath(String);

impl ResourcePath {
    pub fn new(value: impl Into<String>) -> Result<Self, FormatError> {
        let value = value.into();
        let invalid = |reason: &str| FormatError::InvalidResourcePath {
            path: value.clone(),
            reason: reason.to_owned(),
        };
        if value.is_empty() || value.len() > 4096 {
            return Err(invalid("must contain between 1 and 4096 bytes"));
        }
        if !value.is_ascii() {
            return Err(invalid("schema zero requires ASCII resource paths"));
        }
        if value.split('/').count() > MAX_RESOURCE_DEPTH {
            return Err(invalid("resource depth limit exceeded (64 components)"));
        }
        if value
            .bytes()
            .any(|b| b.is_ascii_control() || b"\\<>:\"|?*".contains(&b))
        {
            return Err(invalid(
                "contains a control character or nonportable filename character",
            ));
        }
        for component in value.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(invalid(
                    "empty, absolute or traversal components are forbidden",
                ));
            }
            if component.len() > 255 || component.ends_with([' ', '.']) {
                return Err(invalid(
                    "components must fit 255 bytes and cannot end in a space or dot",
                ));
            }
            let stem = component.split('.').next().unwrap().to_ascii_uppercase();
            let device = matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
            if device {
                return Err(invalid(
                    "Windows device names are forbidden, including names with extensions",
                ));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ResourcePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ResourcePath {
    type Err = FormatError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ResourcePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validate file identities, including implicit directory aliases and file/directory conflicts.
///
/// Persistent prefix identities are bounded by [`MAX_RESOURCE_NODES`] and
/// [`MAX_RESOURCE_METADATA_BYTES`], including both strings held for each node.
/// Repeated implicit directories consume this budget only once.
pub fn validate_resource_paths<I, S>(paths: I) -> Result<(), FormatError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut nodes: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut metadata_bytes = 0usize;
    for path in paths {
        let path = ResourcePath::new(path.as_ref())?;
        let components: Vec<_> = path.as_str().split('/').collect();
        let mut prefix = String::new();
        for (index, component) in components.iter().enumerate() {
            if index != 0 {
                prefix.push('/');
            }
            prefix.push_str(component);
            let is_file = index + 1 == components.len();
            let key = prefix.to_ascii_lowercase();
            if let Some((existing, existing_is_file)) = nodes.get(&key) {
                let reason = if existing != &prefix {
                    Some(format!("case collision with {existing:?}"))
                } else if *existing_is_file && is_file {
                    Some("duplicate resource path".to_owned())
                } else if *existing_is_file || is_file {
                    Some(format!("file/directory conflict at {existing:?}"))
                } else {
                    None
                };
                if let Some(reason) = reason {
                    return Err(FormatError::InvalidResourcePath {
                        path: path.to_string(),
                        reason,
                    });
                }
            } else {
                // Cap persistent state before inserting. A path and the current
                // lowercase key are individually bounded by ResourcePath::new.
                if nodes.len() >= MAX_RESOURCE_NODES {
                    return Err(FormatError::InvalidResourcePath {
                        path: path.to_string(),
                        reason: format!(
                            "resource node limit exceeded ({MAX_RESOURCE_NODES} nodes)"
                        ),
                    });
                }
                let next_bytes = prefix
                    .len()
                    .checked_mul(2)
                    .and_then(|bytes| metadata_bytes.checked_add(bytes))
                    .filter(|bytes| *bytes <= MAX_RESOURCE_METADATA_BYTES)
                    .ok_or_else(|| FormatError::InvalidResourcePath {
                        path: path.to_string(),
                        reason: format!(
                            "resource metadata byte limit exceeded ({MAX_RESOURCE_METADATA_BYTES} bytes)"
                        ),
                    })?;
                nodes.insert(key, (prefix.clone(), is_file));
                metadata_bytes = next_bytes;
            }
        }
    }
    Ok(())
}
