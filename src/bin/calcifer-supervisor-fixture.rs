use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::process::umask(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO);
        if calcifer::internal_production_supervisor_role_requested() {
            return calcifer::run_internal_production_supervisor_role();
        }
        if calcifer::internal_tui_launcher_requested() {
            return calcifer::run_internal_tui_launcher();
        }
        calcifer::run_internal_supervisor_fixture()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ExitCode::FAILURE
    }
}
