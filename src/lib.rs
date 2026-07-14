mod cli;
mod commands;
mod output;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, error::ErrorKind};

use crate::cli::{Cli, Commands};
use crate::output::ErrorReport;

const HUMAN_USAGE_ERROR: &str =
    "error: invalid command-line arguments\n\nRun 'calcifer --help' for usage.";
const HUMAN_INTERNAL_ERROR: &str = "error: Calcifer could not render or write diagnostic output.";
const JSON_INTERNAL_ERROR: &str = r#"{"schema_version":1,"command":null,"ok":false,"error":{"code":"internal_error","message":"Calcifer could not render or write output"}}"#;

/// Runs Calcifer with an explicit argument iterator.
///
/// This boundary keeps process-global argument handling out of command logic and
/// makes the CLI contract testable without touching credentials or provider state.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let json_requested = args.iter().any(|arg| arg == "--json");

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let exit_code = error.exit_code();
            if error.print().is_err() {
                return ExitCode::FAILURE;
            }
            return exit_code_from_i32(exit_code);
        }
        Err(error) if json_requested => {
            let report = ErrorReport::usage();
            let rendered = report
                .to_json()
                .unwrap_or_else(|_| JSON_INTERNAL_ERROR.to_owned());
            if write_stderr(&rendered).is_err() {
                return ExitCode::FAILURE;
            }
            return exit_code_from_i32(error.exit_code());
        }
        Err(error) => {
            let exit_code = error.exit_code();
            if write_stderr(HUMAN_USAGE_ERROR).is_err() {
                return ExitCode::FAILURE;
            }
            return exit_code_from_i32(exit_code);
        }
    };

    match cli.command {
        Commands::Doctor => {
            let report = commands::doctor::inspect();
            let rendered = if cli.json {
                report.to_json()
            } else {
                Ok(report.to_human())
            };
            let rendered = match rendered {
                Ok(rendered) => rendered,
                Err(_) => {
                    let message = if cli.json {
                        JSON_INTERNAL_ERROR
                    } else {
                        HUMAN_INTERNAL_ERROR
                    };
                    let _ = write_stderr(message);
                    return ExitCode::FAILURE;
                }
            };
            if write_stdout(&rendered).is_err() {
                let message = if cli.json {
                    JSON_INTERNAL_ERROR
                } else {
                    HUMAN_INTERNAL_ERROR
                };
                let _ = write_stderr(message);
                return ExitCode::FAILURE;
            }
            ExitCode::from(report.exit_code())
        }
    }
}

/// Verifies clap's command definition during unit tests and CI.
pub fn verify_cli_definition() {
    Cli::command().debug_assert();
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
}

fn write_stdout(message: &str) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{message}")
}

fn write_stderr(message: &str) -> io::Result<()> {
    writeln!(io::stderr().lock(), "{message}")
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn clap_definition_is_valid() {
        verify_cli_definition();
    }

    #[test]
    fn json_flag_is_global() {
        let before = Cli::try_parse_from(["calcifer", "--json", "doctor"]);
        let after = Cli::try_parse_from(["calcifer", "doctor", "--json"]);

        assert!(before.is_ok());
        assert!(after.is_ok());
    }

    #[test]
    fn unimplemented_commands_fail_closed() {
        for command in ["auth", "run", "switch", "use"] {
            let result = Cli::try_parse_from(["calcifer", command]);
            assert!(result.is_err(), "{command} must remain unavailable");
        }
    }
}
