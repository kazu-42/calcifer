use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(unix)]
    rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);

    calcifer::run_internal_supervisor_fixture()
}
