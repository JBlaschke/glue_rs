use glue_format::{
    MAX_RESOURCE_DEPTH, MAX_RESOURCE_METADATA_BYTES, MAX_RESOURCE_NODES, ResourcePath,
    validate_resource_paths,
};

#[test]
fn depth_64_is_accepted_and_65_rejects_without_prefix_expansion() {
    let deepest = std::iter::repeat_n("a", MAX_RESOURCE_DEPTH)
        .collect::<Vec<_>>()
        .join("/");
    ResourcePath::new(&deepest).unwrap();
    validate_resource_paths([&deepest]).unwrap();
    let too_deep = format!("{deepest}/a");
    let error = ResourcePath::new(&too_deep).unwrap_err().to_string();
    assert!(error.contains("depth limit"), "{error}");
    assert!(validate_resource_paths([too_deep]).is_err());
}

#[test]
fn implicit_directories_count_toward_the_node_budget() {
    // Lazy generation keeps input storage constant. Each resource shares one
    // directory, so repeated prefixes must not be charged more than once.
    let paths = |files| (0..files).map(|index| format!("shared/file{index:06}"));
    validate_resource_paths(paths(MAX_RESOURCE_NODES - 1)).unwrap();
    let error = validate_resource_paths(paths(MAX_RESOURCE_NODES))
        .unwrap_err()
        .to_string();
    assert!(error.contains("node limit"), "{error}");
}

fn deep_path(index: usize, shared_prefix: bool) -> String {
    // 4031-byte paths with 64 components. Prefix expansion remains below 34 MiB
    // because the validator must reject before exceeding its persistent budget.
    let unique = format!("n{index:06}{}", "x".repeat(55));
    let common = "x".repeat(62);
    let mut components = vec![common; MAX_RESOURCE_DEPTH];
    if shared_prefix {
        components[MAX_RESOURCE_DEPTH - 1] = unique;
    } else {
        components[0] = unique;
    }
    components.join("/")
}

#[test]
fn both_stored_prefix_strings_count_toward_the_metadata_byte_budget() {
    let first = deep_path(0, false);
    let mut prefix_bytes = 0usize;
    let per_path_bytes: usize = first
        .split('/')
        .enumerate()
        .map(|(index, component)| {
            prefix_bytes += component.len() + usize::from(index != 0);
            2 * prefix_bytes
        })
        .sum();
    let accepted = MAX_RESOURCE_METADATA_BYTES / per_path_bytes;
    validate_resource_paths((0..accepted).map(|index| deep_path(index, false))).unwrap();
    let error = validate_resource_paths((0..=accepted).map(|index| deep_path(index, false)))
        .unwrap_err()
        .to_string();
    assert!(error.contains("metadata byte limit"), "{error}");
}

#[test]
fn shared_prefixes_do_not_consume_the_metadata_budget_repeatedly() {
    // Charging 63 shared directories for every path would breach the budget;
    // charging each once leaves less than 3 MiB of prefix identity strings.
    validate_resource_paths((0..256).map(|index| deep_path(index, true))).unwrap();
    let duplicate = deep_path(0, true);
    let error = validate_resource_paths([&duplicate, &duplicate])
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate resource path"), "{error}");
    let differently_cased = duplicate.replacen('x', "X", 1);
    let error = validate_resource_paths([duplicate, differently_cased])
        .unwrap_err()
        .to_string();
    assert!(error.contains("case collision"), "{error}");
}
