//! Bounded release-only Requires-Python comparisons for the admitted profiles.

use glue_format::RuntimeVersion;

const MAX_VALUE_BYTES: usize = 256;
const MAX_CONJUNCTS: usize = 16;

#[derive(Clone, Copy)]
struct Release {
    components: [u64; 3],
    count: usize,
    prefix: bool,
}

fn release(value: &str) -> Result<Release, String> {
    let (value, prefix) = value
        .strip_suffix(".*")
        .map_or((value, false), |value| (value, true));
    let mut components = [0; 3];
    let mut count = 0;
    for component in value.split('.') {
        if count == components.len()
            || component.is_empty()
            || !component.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("Requires-Python supports only one to three decimal release components; prerelease, dev, post, local, epoch and arbitrary-equality syntax are unsupported".into());
        }
        components[count] = component
            .parse()
            .map_err(|_| "Requires-Python release component exceeds u64".to_owned())?;
        count += 1;
    }
    Ok(Release {
        components,
        count,
        prefix,
    })
}

/// Check the admitted release-only subset without interpreting unsupported PEP
/// 440 syntax. The caller handles missing/duplicate/folded METADATA headers.
pub(super) fn validate(value: &str, target: &RuntimeVersion) -> Result<(), String> {
    if value.len() > MAX_VALUE_BYTES {
        return Err("Requires-Python value exceeds 256 bytes".into());
    }
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 127)
    {
        return Err("Requires-Python requires ASCII specifiers with ordinary spaces".into());
    }
    let original = value;
    let mut value = value.trim_matches(' ');
    if value.starts_with('(') {
        value = value
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
            .ok_or("Requires-Python has unmatched enclosing parentheses")?
            .trim_matches(' ');
    }
    if value.contains(['(', ')']) {
        return Err("Requires-Python permits only one enclosing pair of parentheses".into());
    }
    if value.is_empty() {
        return Err("Requires-Python must contain a nonempty release specifier".into());
    }
    if value.split(',').count() > MAX_CONJUNCTS {
        return Err("Requires-Python exceeds 16 conjuncts".into());
    }
    let actual = [
        u64::from(target.major),
        u64::from(target.minor),
        u64::from(target.patch),
    ];
    let mut satisfied = true;
    // Parse every conjunct even when an earlier one already excludes the
    // runtime, so unsupported syntax never receives a compatibility result.
    for clause in value.split(',') {
        let clause = clause.trim_matches(' ');
        let (operator, version) = ["<=", ">=", "==", "!=", "~=", "<", ">"]
            .into_iter()
            .find_map(|operator| clause.strip_prefix(operator).map(|tail| (operator, tail)))
            .ok_or("Requires-Python requires <, <=, >, >=, ==, != or ~= comparisons")?;
        let release = release(version.trim_matches(' '))?;
        if release.prefix && !matches!(operator, "==" | "!=") {
            return Err("Requires-Python terminal .* prefixes require == or !=".into());
        }
        let equal = if release.prefix {
            actual[..release.count] == release.components[..release.count]
        } else {
            actual == release.components
        };
        let matches = match operator {
            "<" => actual < release.components,
            "<=" => actual <= release.components,
            ">" => actual > release.components,
            ">=" => actual >= release.components,
            "==" => equal,
            "!=" => !equal,
            "~=" => {
                if release.count < 2 {
                    return Err(
                        "Requires-Python ~= comparisons require at least two release components"
                            .into(),
                    );
                }
                actual >= release.components
                    && actual[..release.count - 1] == release.components[..release.count - 1]
            }
            _ => unreachable!("the operator came from a fixed comparison list"),
        };
        satisfied &= matches;
    }
    if !satisfied {
        return Err(format!(
            "Requires-Python {original:?} excludes selected CPython {}.{}.{}",
            target.major, target.minor, target.patch
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: RuntimeVersion = RuntimeVersion {
        major: 3,
        minor: 13,
        patch: 16,
    };

    #[test]
    fn release_comparisons_zero_pad_and_conjoin() {
        for value in [
            ">=3.10",
            ">3.13",
            "<4",
            "<=3.13.16",
            "==3.13.16",
            "!=3.13.15",
            " ( >= 3.9, < 4, != 3.13.15 ) ",
            "==0003.0013.0016",
            ">=0,<=65535",
        ] {
            validate(value, &TARGET).unwrap_or_else(|error| panic!("{value}: {error}"));
        }
        for value in [
            ">=3.14",
            ">3.13.16",
            "<3.13",
            "<=3.13.15",
            "==3.13",
            "!=3.13.16",
            ">=3.9,<3.13",
        ] {
            let error = validate(value, &TARGET).unwrap_err();
            assert!(
                error.contains("excludes selected CPython 3.13.16"),
                "{value}: {error}"
            );
        }
    }

    #[test]
    fn wildcard_and_compatible_ranges_keep_numeric_prefix_boundaries() {
        for value in [
            "==3.*",
            "==3.13.*",
            "==3.13.16.*",
            "!=3.1.*",
            "~=3.13",
            "~=3.13.16",
            "~=3.12",
        ] {
            validate(value, &TARGET).unwrap();
        }
        for value in [
            "==3.1.*",
            "!=3.*",
            "!=3.13.*",
            "~=3.13.17",
            "~=3.12.9",
            "~=3.14",
        ] {
            assert!(
                validate(value, &TARGET).unwrap_err().contains("excludes"),
                "{value}"
            );
        }
        for value in ["~=3", ">=3.*", "~=3.13.*", "==3.13.*.*", "==3..*", "==*"] {
            assert!(validate(value, &TARGET).is_err(), "{value}");
        }
    }

    #[test]
    fn unsupported_or_malformed_syntax_is_not_interpreted_as_compatible() {
        for value in [
            "",
            " ",
            "()",
            "==3.13.16,",
            ",>=3",
            "==3.13.16,,!=4",
            "3.13",
            "=3.13",
            "===3.13.16",
            ">=3.13rc1",
            ">=3.13.dev1",
            "==3.13.post1",
            "==3.13+local",
            "==1!3.13",
            "==3.13.16.0",
            ">=3.13; python_version == '3.13'",
            "==3. 13.16",
            ">=3.9 || <4",
            "(>=3.9",
            ">=3.9)",
            "((>=3.9))",
            "(>=3.9),<4",
            ">=3.9\t",
            ">=3.9\n",
            ">=3.9\0",
            "==３.13.16",
            ">=4,===3.13.16",
        ] {
            assert!(validate(value, &TARGET).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn value_conjunct_and_integer_bounds_apply_before_evaluation() {
        let maximum = format!(">=3{}", " ".repeat(MAX_VALUE_BYTES - 3));
        validate(&maximum, &TARGET).unwrap();
        assert!(
            validate(&(maximum + " "), &TARGET)
                .unwrap_err()
                .contains("256")
        );
        validate(&[">=3"; MAX_CONJUNCTS].join(","), &TARGET).unwrap();
        assert!(
            validate(&[">=3"; MAX_CONJUNCTS + 1].join(","), &TARGET)
                .unwrap_err()
                .contains("16 conjuncts")
        );
        assert!(
            validate(">=18446744073709551616", &TARGET)
                .unwrap_err()
                .contains("u64")
        );
        assert!(
            validate("==18446744073709551615", &TARGET)
                .unwrap_err()
                .contains("excludes")
        );
    }
}
