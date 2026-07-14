use std::process::ExitCode;

fn main() -> ExitCode {
    calcifer::run(std::env::args_os())
}
