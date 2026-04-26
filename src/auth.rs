use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use hkdf::Hkdf;
use iroh::{endpoint::Connection, Endpoint, EndpointId, PublicKey};
use lru::LruCache;
use n0_watcher::Watchable;
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha512;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use tokio::{
    sync::Mutex,
    time::{timeout, Instant},
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    protocol::release_in_flight, AuthenticatorError, IntoSecret, ALPN, AUTH_TIMEOUT,
    TRANSMISSION_TIMEOUT,
};

#[derive(Debug, Clone)]
pub struct Authenticator {
    secret: SecretSlice<u8>,
    endpoint: Arc<Mutex<Option<iroh::Endpoint>>>,
    pub(crate) auth_state: Arc<Mutex<LruCache<EndpointId, WatchableRemote>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
    InFlight,
    Authenticated,
    Blocked,
}

impl std::fmt::Display for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthState::Unauthenticated => write!(f, "Unauthenticated"),
            AuthState::InFlight => write!(f, "InFlight"),
            AuthState::Authenticated => write!(f, "Authenticated"),
            AuthState::Blocked => write!(f, "Blocked"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegisterResponse {
    InFlightRegistered,   // auth after this
    AlreadyInFlight, // another auth was running while we called this, only check is_authenticated, don't auth again
    AlreadyAuthenticated, // we are already authenticated, same as AlreadyInFlight => only check is_authenticated, don't auth again
    AlreadyBlocked,       // we are blocked, DO NOT AUTH AGAIN, just reject
}

#[derive(Debug, Clone)]
pub(crate) struct WatchableRemote {
    id: PublicKey,
    inner: Watchable<AuthState>,
}

impl WatchableRemote {
    /// inner is AuthState::Unauthenticated by default
    pub fn new(id: PublicKey) -> Self {
        Self {
            id,
            inner: Watchable::new(AuthState::Unauthenticated),
        }
    }

    pub fn watcher(&self) -> Watchable<AuthState> {
        self.inner.clone()
    }

    pub fn id(&self) -> &PublicKey {
        &self.id
    }

    pub fn state(&self) -> AuthState {
        self.inner.get()
    }

    pub fn set_state(&self, state: AuthState) {
        self.inner.set(state).ok();
    }
}

impl PartialEq for WatchableRemote {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for WatchableRemote {}

impl PartialEq<PublicKey> for WatchableRemote {
    fn eq(&self, other: &PublicKey) -> bool {
        self.id() == other
    }
}

impl std::hash::Hash for WatchableRemote {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl Authenticator {
    pub const ALPN: &'static [u8] = crate::ALPN;
    const ACCEPT_CONTEXT: &'static [u8] = b"iroh-auth-accept";
    const OPEN_CONTEXT: &'static [u8] = b"iroh-auth-open";

    pub fn new<S: IntoSecret>(secret: S) -> Self {
        Self {
            secret: secret.into_secret(),
            endpoint: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(crate::LRU_CACHE_SIZE).expect("LRU_CACHE_SIZE must be > 0"),
            ))),
        }
    }

    pub async fn set_endpoint(&self, endpoint: &Endpoint) {
        let mut guard = self.endpoint.lock().await;
        if guard.is_none() {
            *guard = Some(endpoint.clone());
            trace!("Authenticator endpoint set to {}", endpoint.id());
        }
    }

    async fn id(&self) -> Result<PublicKey, AuthenticatorError> {
        self.endpoint
            .lock()
            .await
            .as_ref()
            .map(|ep| ep.id())
            .ok_or(AuthenticatorError::EndpointNotSet)
    }

    pub(crate) async fn endpoint(&self) -> Result<iroh::Endpoint, AuthenticatorError> {
        self.endpoint
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or(AuthenticatorError::EndpointNotSet)
    }

    pub async fn is_authenticated(&self, id: &PublicKey) -> bool {
        self.auth_state
            .lock()
            .await
            .get(id)
            .map(|watchable| {
                if watchable.state() == AuthState::Authenticated {
                    return true;
                }
                false
            })
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub async fn list_authenticated(&self) -> Vec<PublicKey> {
        self.auth_state
            .lock()
            .await
            .iter()
            .filter_map(|(id, watchable)| {
                if watchable.state() == AuthState::Authenticated {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    #[cfg(test)]
    pub async fn list_blocked(&self) -> Vec<PublicKey> {
        self.auth_state
            .lock()
            .await
            .iter()
            .filter_map(|(id, watchable)| {
                if watchable.state() == AuthState::Blocked {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }
}

impl Authenticator {
    async fn end_of_auth(
        &self,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
        open: bool,
    ) -> Result<(), AuthenticatorError> {
        send.finish().map_err(|err| {
            error!("[end_of_auth] failed to finish stream: {}", err);
            if open {
                AuthenticatorError::OpenFailed(format!("Failed to finish stream: {}", err))
            } else {
                AuthenticatorError::AcceptFailed(format!("Failed to finish stream: {}", err))
            }
        })?;

        const MAX_READ_SIZE: usize = 1024;
        if let Err(err) = tokio::time::timeout(AUTH_TIMEOUT, recv.read_to_end(MAX_READ_SIZE))
            .await
            .map_err(|_| {
                if open {
                    AuthenticatorError::OpenFailed(
                        "Failed to wait for stream stopped: timeout".to_string(),
                    )
                } else {
                    AuthenticatorError::AcceptFailed(
                        "Failed to wait for stream stopped: timeout".to_string(),
                    )
                }
            })
            .and_then(|res| {
                res.map_err(|err| {
                    if open {
                        AuthenticatorError::OpenFailed(format!(
                            "Failed to read remaining data from stream: {}",
                            err
                        ))
                    } else {
                        AuthenticatorError::AcceptFailed(format!(
                            "Failed to read remaining data from stream: {}",
                            err
                        ))
                    }
                })
            })
        {
            warn!("[end_of_auth] {}", err);
        }
        Ok(())
    }

    /// Accept an incoming connection and perform SPAKE2 authentication.
    /// On success, adds the remote ID to the authenticated set.
    /// Returns Ok(()) on success, or an AuthenticatorError on failure.
    pub(crate) async fn auth_accept(&self, conn: Connection) -> Result<(), AuthenticatorError> {
        let remote_id = conn.remote_id();
        debug!("[auth_accept] accepting auth connection from {}", remote_id);
        let (mut send, mut recv) = timeout(TRANSMISSION_TIMEOUT, conn.accept_bi())
            .await
            .map_err(|_| {
                error!("[auth_accept] accept bidirectional stream timed out");
                AuthenticatorError::AcceptFailed(
                    "Accept bidirectional stream timed out".to_string(),
                )
            })?
            .map_err(|err| {
                error!("[auth_accept] accept bidirectional stream failed: {}", err);
                AuthenticatorError::AcceptFailed(format!(
                    "Accept bidirectional stream failed: {}",
                    err
                ))
            })?;

        let (spake, token_b) = Spake2::<Ed25519Group>::start_b(
            &Password::new(self.secret.expose_secret()),
            &Identity::new(conn.remote_id().as_bytes()),
            &Identity::new(self.id().await?.as_bytes()),
        );

        let mut token_a = [0u8; 33];
        recv.read_exact(&mut token_a).await.map_err(|err| {
            error!("[auth_accept] failed to read token_a: {}", err);
            AuthenticatorError::AcceptFailed(format!("Failed to read token_a: {}", err))
        })?;

        send.write_all(&token_b).await.map_err(|err| {
            error!("[auth_accept] failed to write token_b: {}", err);
            AuthenticatorError::AcceptFailed(format!("Failed to write token_b: {}", err))
        })?;

        let shared_secret = spake.finish(&token_a).map_err(|err| {
            error!("[auth_accept] SPAKE2 invalid: {}", err);
            AuthenticatorError::AcceptFailedAndBlock(format!("SPAKE2 invalid: {}", err), remote_id)
        })?;

        let hk = Hkdf::<Sha512>::new(None, shared_secret.as_slice());
        let mut accept_key = [0u8; 64];
        let mut open_key = [0u8; 64];
        hk.expand(Self::ACCEPT_CONTEXT, &mut accept_key)
            .map_err(|err| {
                error!("[auth_accept] failed to expand accept_key: {}", err);
                AuthenticatorError::AcceptFailed(format!("Failed to expand accept_key: {}", err))
            })?;
        hk.expand(Self::OPEN_CONTEXT, &mut open_key)
            .map_err(|err| {
                error!("[auth_accept] failed to expand open_key: {}", err);
                AuthenticatorError::AcceptFailed(format!("Failed to expand open_key: {}", err))
            })?;

        send.write_all(&accept_key).await.map_err(|err| {
            error!("[auth_accept] failed to write accept_key: {}", err);
            AuthenticatorError::AcceptFailed(format!("Failed to write accept_key: {}", err))
        })?;
        let mut remote_open_key = [0u8; 64];
        recv.read_exact(&mut remote_open_key).await.map_err(|err| {
            error!("[auth_accept] failed to read remote_open_key: {}", err);
            AuthenticatorError::AcceptFailed(format!("Failed to read remote_open_key: {}", err))
        })?;

        let _ = self.end_of_auth(&mut send, &mut recv, false).await;

        if !bool::from(remote_open_key.ct_eq(&open_key)) {
            error!("[auth_accept] remote open_key mismatch");
            return Err(AuthenticatorError::AcceptFailedAndBlock(
                "Remote open_key mismatch".to_string(),
                remote_id,
            ));
        }

        info!("[auth_accept] authenticated connection from {}", remote_id);

        Ok(())
    }

    /// Open an outgoing connection and perform SPAKE2 authentication.
    /// On success, adds the remote ID to the authenticated set.
    /// Returns Ok(()) on success, or an AuthenticatorError on failure.
    pub(crate) async fn auth_open(&self, conn: Connection) -> Result<(), AuthenticatorError> {
        let remote_id = conn.remote_id();
        debug!("[auth_open] opening auth connection to {}", remote_id);
        let (mut send, mut recv) = timeout(TRANSMISSION_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| {
                error!("[auth_open] open bidirectional stream timed out");
                AuthenticatorError::OpenFailed("Open bidirectional stream timed out".to_string())
            })?
            .map_err(|err| {
                error!("[auth_open] open bidirectional stream failed: {}", err);
                AuthenticatorError::OpenFailed(format!("Open bidirectional stream failed: {}", err))
            })?;

        let (spake, token_a) = Spake2::<Ed25519Group>::start_a(
            &Password::new(self.secret.expose_secret()),
            &Identity::new(self.id().await?.as_bytes()),
            &Identity::new(conn.remote_id().as_bytes()),
        );

        send.write_all(&token_a).await.map_err(|err| {
            error!("[auth_open] failed to write token_a: {}", err);
            AuthenticatorError::OpenFailed(format!("Failed to write token_a: {}", err))
        })?;

        let mut token_b = [0u8; 33];
        recv.read_exact(&mut token_b).await.map_err(|err| {
            error!("[auth_open] failed to read token_b: {}", err);
            AuthenticatorError::OpenFailed(format!("Failed to read token_b: {}", err))
        })?;

        let shared_secret = spake.finish(&token_b).map_err(|err| {
            error!("[auth_open] SPAKE2 invalid: {}", err);
            AuthenticatorError::OpenFailedAndBlock(format!("SPAKE2 invalid: {}", err), remote_id)
        })?;

        let hk = Hkdf::<Sha512>::new(None, shared_secret.as_slice());
        let mut accept_key = [0u8; 64];
        let mut open_key = [0u8; 64];
        hk.expand(Self::ACCEPT_CONTEXT, &mut accept_key)
            .map_err(|err| {
                error!("[auth_open] failed to expand accept_key: {}", err);
                AuthenticatorError::OpenFailed(format!("Failed to expand accept_key: {}", err))
            })?;
        hk.expand(Self::OPEN_CONTEXT, &mut open_key)
            .map_err(|err| {
                error!("[auth_open] failed to expand open_key: {}", err);
                AuthenticatorError::OpenFailed(format!("Failed to expand open_key: {}", err))
            })?;

        let mut remote_accept_key = [0u8; 64];
        recv.read_exact(&mut remote_accept_key)
            .await
            .map_err(|err| {
                error!("[auth_open] failed to read remote_accept_key: {}", err);
                AuthenticatorError::OpenFailed(format!("Failed to read remote_accept_key: {}", err))
            })?;

        if !bool::from(remote_accept_key.ct_eq(&accept_key)) {
            error!("[auth_open] remote accept_key mismatch");

            // Writing a random dummy open_key back to finishing the stream but not give away
            // that the accept_key was correct to avoid leaking information to an attacker about valid accept_keys
            // (probably not needed but better safe than sorry ^^)
            send.write_all(&rand::random::<[u8; 64]>()).await.ok();
            let _ = self.end_of_auth(&mut send, &mut recv, true).await;

            return Err(AuthenticatorError::OpenFailedAndBlock(
                "Remote accept_key mismatch".to_string(),
                remote_id,
            ));
        }

        send.write_all(&open_key).await.map_err(|err| {
            error!("[auth_open] failed to write open_key: {}", err);
            AuthenticatorError::OpenFailed(format!("Failed to write open_key: {}", err))
        })?;
        let _ = self.end_of_auth(&mut send, &mut recv, true).await;

        info!("[auth_open] authenticated connection to {}", remote_id);

        Ok(())
    }
}

impl Authenticator {
    pub(crate) async fn perform_auth(
        &self,
        remote_id: EndpointId,
        endpoint: Endpoint,
    ) -> Result<(), AuthenticatorError> {
        let start_time = Instant::now();
        if let Err(err) = timeout(AUTH_TIMEOUT, endpoint.online()).await.map_err(|_| {
            AuthenticatorError::OpenFailed(
                "[before_connect] awaiting endpoint.online() timed out".to_string(),
            )
        }) {
            error!(
                "[before_connect] awaiting endpoint.online() failed: {}",
                err
            );
            release_in_flight(
                self.auth_state.clone(),
                remote_id,
                AuthState::Unauthenticated,
            )
            .await
            .map_err(|err| {
                AuthenticatorError::OpenFailed(format!(
                    "[before_connect] failed to release in-flight state for {}: {}",
                    remote_id, err
                ))
            })?;
            return Err(err);
        }

        while start_time.elapsed() < AUTH_TIMEOUT {
            debug!(
                "[before_connect] background: connecting to {} for auth",
                remote_id
            );
            match timeout(
                remaining_timeout(start_time, AUTH_TIMEOUT),
                endpoint.connect(remote_id, ALPN),
            )
            .await
            {
                Ok(Ok(conn)) => {
                    debug!(
                        "[before_connect] connected to {}, performing auth",
                        remote_id
                    );
                    match timeout(
                        remaining_timeout(start_time, AUTH_TIMEOUT),
                        self.auth_open(conn),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            debug!(
                                "[before_connect] authentication successful for {}",
                                remote_id
                            );

                            release_in_flight(
                                self.auth_state.clone(),
                                remote_id,
                                AuthState::Authenticated,
                            )
                            .await
                            .map_err(|err| {
                                error!(
                                    "[before_connect] failed to release in-flight state for {}: {}",
                                    remote_id, err
                                );
                                AuthenticatorError::OpenFailed(format!(
                                    "[before_connect] failed to release in-flight state for {}: {}",
                                    remote_id, err
                                ))
                            })?;
                            return Ok(());
                        }
                        Ok(Err(err)) => match &err {
                            AuthenticatorError::OpenFailedAndBlock(msg, public_key) => {
                                warn!(
                                    "[before_connect] authentication failed and blocking {}: {}",
                                    public_key, msg
                                );
                                release_in_flight(
                                    self.auth_state.clone(),
                                    remote_id,
                                    AuthState::Blocked,
                                )
                                .await
                                .map_err(|err| {
                                    AuthenticatorError::OpenFailedAndBlock(format!(
                                        "[before_connect] failed to release in-flight state for {}: {}",
                                        public_key, err
                                    ), *public_key)
                                })?;
                                return Err(AuthenticatorError::OpenFailedAndBlock(
                                    msg.clone(),
                                    *public_key,
                                ));
                            }
                            _ => {
                                warn!(
                                    "[before_connect] authentication failed for {}: {}",
                                    remote_id, err
                                );
                            }
                        },
                        Err(_) => {
                            warn!(
                                "[before_connect] authentication timed out for {}, retrying...",
                                remote_id
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!(
                            "[before_connect] failed to open connection for authentication to {}: {}, retrying...",
                            remote_id, e
                        );
                }
                Err(e) => {
                    warn!(
                        "[before_connect] connection attempt timed out for {}: {}, retrying...",
                        remote_id, e
                    );
                }
            };
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        warn!(
            "[before_connect] background: authentication timed out for {}",
            remote_id
        );

        // Timeout no more retries, clean up in-flight state
        release_in_flight(
            self.auth_state.clone(),
            remote_id,
            AuthState::Unauthenticated,
        )
        .await
        .map_err(|err| {
            AuthenticatorError::OpenFailed(format!(
                "[before_connect] failed to release in-flight state for {}: {}",
                remote_id, err
            ))
        })?;
        Err(AuthenticatorError::OpenFailed(format!(
            "Authentication timed out for {}",
            remote_id
        )))
    }
}

fn remaining_timeout(start: Instant, timeout_duration: Duration) -> Duration {
    timeout_duration.saturating_sub(Instant::now().saturating_duration_since(start))
}
