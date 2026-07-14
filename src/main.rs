use std::process::ExitCode;

fn main() -> ExitCode {
    // Harden this process before it creates state or spawns any coordinator,
    // guardian, App Server, login, or interactive provider child.
    #[cfg(unix)]
    rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);

    calcifer::run(std::env::args_os())
}
