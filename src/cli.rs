use std::ffi::OsString;
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "calcifer",
    version,
    about = "Manage isolated profiles for official coding-agent CLIs",
    long_about = "Calcifer is a pre-alpha local profile manager for official coding-agent CLIs.\n\
                  The current functional slice supports isolated Codex profiles, explicit resume,\n\
                  and structured per-profile usage reads. Automatic failover is not implemented yet.",
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

    /// Register or list isolated provider profiles.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Read structured usage and reset information for one or all profiles.
    Status {
        /// Profile to inspect; omit to inspect every registered profile.
        profile: Option<ProfileReference>,
    },

    /// Launch an official provider CLI with one immutable profile.
    Run {
        /// Provider and local profile alias, for example codex@work.
        profile: ProfileReference,

        /// Arguments passed to the official provider CLI after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },

    /// Resume a Codex session in the profile that owns it.
    Resume {
        /// Provider and local profile alias, for example codex@work.
        profile: ProfileReference,

        /// Exact Codex session ID or name; omit to use official `codex resume --last` behavior.
        session_id: Option<String>,

        /// Additional arguments passed to `codex resume` after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },

    /// Internal single-profile process supervisor.
    #[command(name = "__internal-codex", hide = true)]
    InternalCodex {
        profile: ProfileReference,
        mode: InternalProcessMode,
        session_id: Option<String>,

        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },

    /// Internal provider guardian; requires a coordinator-owned socket.
    #[command(name = "__internal-codex-provider", hide = true)]
    InternalCodexProvider {
        profile: ProfileReference,
        run_id: String,
        mode: InternalProcessMode,
        session_id: Option<String>,

        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum InternalProcessMode {
    Run,
    ResumeLast,
    ResumeExact,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthCommand {
    /// Authenticate a new managed profile through the provider's official CLI.
    Add {
        /// Provider to register.
        provider: ProviderArgument,

        /// Local alias used in Calcifer commands and output.
        alias: String,
    },

    /// List registered profiles without reading credentials.
    List,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ProviderArgument {
    Codex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfileReference {
    pub(crate) provider: ProviderArgument,
    pub(crate) alias: String,
}

impl FromStr for ProfileReference {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (provider, alias) = value
            .split_once('@')
            .ok_or("profile must use provider@alias syntax")?;
        if provider != "codex"
            || alias.contains('@')
            || crate::profiles::validate_alias(alias).is_err()
        {
            return Err("profile must use codex@alias syntax");
        }
        Ok(Self {
            provider: ProviderArgument::Codex,
            alias: alias.to_owned(),
        })
    }
}
