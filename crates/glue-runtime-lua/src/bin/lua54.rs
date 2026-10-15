fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(glue_runtime_lua::helper::main_with_args(
        std::env::args_os().skip(1),
    ))
}
