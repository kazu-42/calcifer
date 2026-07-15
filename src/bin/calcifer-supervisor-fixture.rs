use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        calcifer::run_internal_supervisor_fixture()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ExitCode::FAILURE
    }
}
