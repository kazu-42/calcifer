use std::ffi::OsString;
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use uuid::Uuid;

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

    /// Register, verify, rename, remove, or list isolated provider profiles.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Read structured usage and reset information for one or all profiles.
    Status {
        /// Profile to inspect; omit to inspect every registered profile.
        profile: Option<ProfileReference>,
    },

    /// Check an immutable Calcifer release without reading credentials.
    Update {
        #[command(subcommand)]
        command: UpdateCommand,
    },

    /// Launch an official provider CLI with one immutable profile.
    Run {
        /// Skip conversation capture and require explicit exact recovery later.
        #[arg(long)]
        untracked: bool,

        /// Provider and local profile alias, for example codex@work.
        profile: ProfileReference,

        /// Arguments passed to the official provider CLI after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },

    /// Resume a tracked workspace head or a session in an explicit profile.
    Resume {
        /// Use official --last without capture; requires a profile and no exact ID.
        #[arg(long, requires = "profile", conflicts_with = "session_id")]
        untracked: bool,

        /// Provider and local profile alias; omit to resume this workspace's tracked head.
        profile: Option<ProfileReference>,

        /// Exact Codex session UUID; with a profile omitted, Calcifer uses the tracked head.
        session_id: Option<String>,

        /// Additional arguments passed to `codex resume` after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },

    /// Internal single-profile process supervisor.
    #[command(name = "__internal-codex", hide = true)]
    InternalCodex {
        profile_id: ProfileId,
        expected_profile: ProfileReference,
        mode: InternalProcessMode,
        session_id: Option<String>,

        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },

    /// Internal provider guardian; requires a coordinator-owned socket.
    #[command(name = "__internal-codex-provider", hide = true)]
    InternalCodexProvider {
        profile_id: ProfileId,
        run_id: String,
        mode: InternalProcessMode,
        session_id: Option<String>,

        #[arg(last = true, allow_hyphen_values = true)]
        provider_args: Vec<OsString>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfileId(String);

impl ProfileId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProfileId {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Uuid::parse_str(value).map_err(|_| "profile id must be a canonical UUID")?;
        if parsed.to_string() != value {
            return Err("profile id must be a canonical UUID");
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum UpdateCommand {
    /// Check one strict release channel for this exact compile target.
    Check {
        /// Release channel; defaults to the current binary's channel.
        #[arg(long, value_enum)]
        channel: Option<ReleaseChannelArgument>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ReleaseChannelArgument {
    Stable,
    Preview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum InternalProcessMode {
    Run,
    RunUntracked,
    ResumeLast,
    ResumeLastUntracked,
    ResumeExact,
    ResumeHead,
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

    /// Verify a legacy profile's private provider identity without logging in.
    Verify {
        /// Existing profile to verify, for example codex@work.
        profile: ProfileReference,
    },

    /// Rename a local profile alias without re-authenticating.
    Rename {
        /// Existing profile to rename, for example codex@work.
        profile: ProfileReference,

        /// New local alias for the same immutable profile.
        new_alias: String,
    },

    /// Remove one Calcifer-managed local profile without provider logout.
    Remove {
        /// Existing profile to remove, for example codex@work.
        profile: ProfileReference,

        /// Confirm deletion without an interactive TTY prompt.
        #[arg(long)]
        yes: bool,
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
