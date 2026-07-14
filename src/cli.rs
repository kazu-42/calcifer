use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "calcifer",
    version,
    about = "Manage isolated profiles for official coding-agent CLIs",
    long_about = "Calcifer is a pre-alpha local profile manager for official coding-agent CLIs.\n\
                  Account switching, usage monitoring, and automatic failover are not implemented yet.",
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// Emit command results and usage errors as JSON; help and version remain text.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Inspect the local environment without reading or changing credentials.
    Doctor,
}
