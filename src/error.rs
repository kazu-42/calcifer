use std::fmt;
use std::io;

use crate::commands::update::UpdateError;
use crate::conversations::ConversationError;
use crate::executable::ExecutableError;
use crate::profiles::ProfileError;
use crate::project_config::ProjectConfigError;

#[derive(Debug)]
pub(crate) enum AppError {
    ConfirmationRequired,
    Conversation(ConversationError),
    Executable(ExecutableError),
    InteractiveJsonUnsupported,
    Io(io::Error),
    Profile(ProfileError),
    ProjectConfig(ProjectConfigError),
    ProviderArgumentRejected,
    ProviderLoginFailed,
    Update(UpdateError),
}

impl AppError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::ConfirmationRequired => "confirmation_required",
            Self::Conversation(error) => error.code(),
            Self::Executable(error) => error.code(),
            Self::InteractiveJsonUnsupported => "interactive_json_unsupported",
            Self::Io(_) => "process_io_error",
            Self::Profile(error) => error.code(),
            Self::ProjectConfig(error) => error.code(),
            Self::ProviderArgumentRejected => "provider_argument_rejected",
            Self::ProviderLoginFailed => "provider_login_failed",
            Self::Update(error) => error.code(),
        }
    }

    pub(crate) fn safe_message(&self) -> String {
        match self {
            Self::ConfirmationRequired => "Profile removal requires an explicit TTY confirmation or `--yes`. No local profile state was changed.".to_owned(),
            Self::Conversation(error) => error.safe_message().to_owned(),
            Self::Executable(error) => error.safe_message().to_owned(),
            Self::InteractiveJsonUnsupported => "--json is not available for interactive auth, run, or resume commands because provider output owns the terminal.".to_owned(),
            Self::Io(error) => {
                let _ = error.kind();
                "Calcifer could not start or wait for the official provider CLI.".to_owned()
            }
            Self::Profile(error) => error.safe_message(),
            Self::ProjectConfig(error) => error.safe_message().to_owned(),
            Self::ProviderArgumentRejected => "Calcifer rejected a provider argument that could bypass the selected managed account or provider.".to_owned(),
            Self::ProviderLoginFailed => "The official Codex login command did not complete successfully. No profile was registered.".to_owned(),
            Self::Update(error) => error.safe_message().to_owned(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_message())
    }
}

impl std::error::Error for AppError {}

impl From<ExecutableError> for AppError {
    fn from(error: ExecutableError) -> Self {
        Self::Executable(error)
    }
}

impl From<ConversationError> for AppError {
    fn from(error: ConversationError) -> Self {
        Self::Conversation(error)
    }
}

impl From<ProfileError> for AppError {
    fn from(error: ProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<ProjectConfigError> for AppError {
    fn from(error: ProjectConfigError) -> Self {
        Self::ProjectConfig(error)
    }
}

impl From<UpdateError> for AppError {
    fn from(error: UpdateError) -> Self {
        Self::Update(error)
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
