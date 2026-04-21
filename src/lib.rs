mod auth;
mod error;
mod protocol;
mod secret;

use std::time::Duration;

pub use secret::IntoSecret;
pub use error::AuthenticatorError;
pub use auth::Authenticator;

pub const ALPN: &[u8] = b"/iroh/auth/0.1";
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSMISSION_TIMEOUT: Duration = Duration::from_millis(5000);

#[cfg(test)]
mod tests;