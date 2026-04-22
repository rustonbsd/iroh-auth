use iroh::EndpointId;

// Errors
#[derive(Debug)]
pub enum AuthenticatorError {
    AddFailed,
    AcceptFailed(String),
    OpenFailed(String),
    AcceptFailedAndBlock(String, EndpointId),
    OpenFailedAndBlock(String, EndpointId),
    EndpointNotSet,
}

#[derive(Debug)]
pub enum InFlightError {
    PromotionNotAllowed(String),
}

impl std::fmt::Display for AuthenticatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticatorError::AddFailed => write!(f, "Failed to add authenticated ID"),
            AuthenticatorError::AcceptFailed(msg) => write!(f, "Accept failed: {}", msg),
            AuthenticatorError::OpenFailed(msg) => write!(f, "Open failed: {}", msg),
            AuthenticatorError::EndpointNotSet => write!(
                f,
                "Authenticator endpoint not set: missing authenticator.start(endpoint).await"
            ),
            AuthenticatorError::AcceptFailedAndBlock(msg, id) => {
                write!(f, "Blocked endpoint ID: {}: {}", msg, id)
            }
            AuthenticatorError::OpenFailedAndBlock(msg, id) => {
                write!(f, "Blocked endpoint ID: {}: {}", msg, id)
            }
        }
    }
}

impl std::fmt::Display for InFlightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InFlightError::PromotionNotAllowed(msg) => write!(f, "Promotion not allowed: {}", msg),
        }
    }
}

impl std::error::Error for InFlightError {}
impl std::error::Error for AuthenticatorError {}
