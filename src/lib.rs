use n0_watcher::Watchable;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

use hkdf::Hkdf;
use iroh::{
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, VarInt},
    protocol::ProtocolHandler,
    Endpoint, EndpointId, PublicKey, Watcher,
};
use n0_future::{time::timeout, StreamExt};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha512;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;

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
pub enum TransmissionError {
    SendFailed(String),
    ReadFailed(String),
    SendTimeout,
    ReadTimeout,
}

#[derive(Debug)]
pub enum InFlightError {
    LockPoisoned(String),
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
                "Authenticator endpoint not set: missing authenticator.start(endpoint)"
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

impl std::fmt::Display for TransmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransmissionError::SendFailed(msg) => write!(f, "Send failed: {}", msg),
            TransmissionError::ReadFailed(msg) => write!(f, "Read failed: {}", msg),
            TransmissionError::SendTimeout => write!(f, "Send timed out"),
            TransmissionError::ReadTimeout => write!(f, "Read timed out"),
        }
    }
}

impl std::fmt::Display for InFlightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InFlightError::LockPoisoned(msg) => write!(f, "In-flight lock poisoned: {}", msg),
            InFlightError::PromotionNotAllowed(msg) => write!(f, "Promotion not allowed: {}", msg),
        }
    }
}

impl std::error::Error for InFlightError {}
impl std::error::Error for TransmissionError {}
impl std::error::Error for AuthenticatorError {}

pub trait IntoSecret {
    fn into_secret(self) -> SecretSlice<u8>;
}

impl IntoSecret for SecretSlice<u8> {
    fn into_secret(self) -> SecretSlice<u8> {
        self
    }
}

impl IntoSecret for String {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.into_bytes().into_boxed_slice())
    }
}

impl IntoSecret for &str {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.as_bytes().to_vec().into_boxed_slice())
    }
}

impl IntoSecret for Vec<u8> {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.into_boxed_slice())
    }
}

impl IntoSecret for &[u8] {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.to_vec().into_boxed_slice())
    }
}

impl<const N: usize> IntoSecret for &[u8; N] {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.as_slice().to_vec().into_boxed_slice())
    }
}

impl IntoSecret for Box<[u8]> {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self)
    }
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    secret: SecretSlice<u8>,
    endpoint: Arc<Mutex<Option<iroh::Endpoint>>>,
    auth_state: Arc<Mutex<HashMap<EndpointId, WatchableRemote>>>,
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
pub enum RegisterResponse {
    InFlightRegistered,   // auth after this
    AlreadyInFlight, // another auth was running while we called this, only check is_authenticaded, don't auth again
    AlreadyAuthenticated, // we are already authenticaded, same as AlreadyInFlight => only check is_authenticaded, don't auth again
    AlreadyBlocked,       // we are blocked, DO NOT AUTH AGAIN, just reject
}

#[derive(Debug, Clone)]
struct WatchableRemote {
    id: PublicKey,
    inner: Watchable<AuthState>,
}

impl WatchableRemote {
    /// inner is AuthState::Unauthenticated by default
    fn new(id: PublicKey) -> Self {
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
        self.state() == other.state()
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

pub const ALPN: &[u8] = b"/iroh/auth/0.1";
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSMISSION_TIMEOUT: Duration = Duration::from_millis(5000);

impl Authenticator {
    pub const ALPN: &'static [u8] = ALPN;
    const ACCEPT_CONTEXT: &'static [u8] = b"iroh-auth-accept";
    const OPEN_CONTEXT: &'static [u8] = b"iroh-auth-open";

    pub fn new<S: IntoSecret>(secret: S) -> Self {
        Self {
            secret: secret.into_secret(),
            endpoint: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_endpoint(&self, endpoint: &Endpoint) {
        if let Ok(mut guard) = self.endpoint.lock() {
            if guard.is_none() {
                *guard = Some(endpoint.clone());
                trace!("Authenticator endpoint set to {}", endpoint.id());
            }
        }
    }

    fn id(&self) -> Result<PublicKey, AuthenticatorError> {
        self.endpoint
            .lock()
            .map_err(|_| AuthenticatorError::EndpointNotSet)?
            .as_ref()
            .map(|ep| ep.id())
            .ok_or(AuthenticatorError::EndpointNotSet)
    }

    fn endpoint(&self) -> Result<iroh::Endpoint, AuthenticatorError> {
        self.endpoint
            .lock()
            .map_err(|_| AuthenticatorError::EndpointNotSet)?
            .as_ref()
            .cloned()
            .ok_or(AuthenticatorError::EndpointNotSet)
    }

    fn is_authenticated(&self, id: &PublicKey) -> bool {
        self.auth_state
            .lock()
            .map(|in_flight| {
                if let Some(watchable) = in_flight.get(id) {
                    if watchable.state() == AuthState::Authenticated {
                        return true;
                    }
                }
                false
            })
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn list_authenticated(&self) -> Vec<PublicKey> {
        self.auth_state
            .lock()
            .map(|in_flight| {
                in_flight
                    .iter()
                    .filter_map(|(id, watchable)| {
                        if watchable.state() == AuthState::Authenticated {
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn list_blocked(&self) -> Vec<PublicKey> {
        self.auth_state
            .lock()
            .map(|in_flight| {
                in_flight
                    .iter()
                    .filter_map(|(id, watchable)| {
                        if watchable.state() == AuthState::Blocked {
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
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
            .map_err(|err| {
                if open {
                    AuthenticatorError::OpenFailed(format!(
                        "Failed to wait for stream stopped: {}",
                        err
                    ))
                } else {
                    AuthenticatorError::AcceptFailed(format!(
                        "Failed to wait for stream stopped: {}",
                        err
                    ))
                }
            })
        {
            warn!("[end_of_auth] {}", err);
        }
        Ok(())
    }

    /// Accept an incoming connection and perform SPAKE2 authentication.
    /// On success, adds the remote ID to the authenticated set.
    /// Returns Ok(()) on success, or an AuthenticatorError on failure.
    async fn auth_accept(&self, conn: Connection) -> Result<(), AuthenticatorError> {
        let remote_id = conn.remote_id();
        debug!("[auth_accept] accepting auth connection from {}", remote_id);
        let (mut send, mut recv) = timeout(TRANSMISSION_TIMEOUT, conn.accept_bi())
            .await
            .map_err(|_| {
                error!("[auth_accept] accept bidirectional stream timed out");
                AuthenticatorError::AcceptFailed(format!("Accept bidirectional stream timed out"))
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
            &Identity::new(self.id()?.as_bytes()),
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

        self.end_of_auth(&mut send, &mut recv, false).await?;

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
    async fn auth_open(&self, conn: Connection) -> Result<(), AuthenticatorError> {
        let remote_id = conn.remote_id();
        debug!("[auth_open] opening auth connection to {}", remote_id);
        let (mut send, mut recv) = timeout(TRANSMISSION_TIMEOUT, conn.open_bi())
            .await
            .map_err(|_| {
                error!("[auth_open] open bidirectional stream timed out");
                AuthenticatorError::OpenFailed(format!("Open bidirectional stream timed out"))
            })?
            .map_err(|err| {
                error!("[auth_open] open bidirectional stream failed: {}", err);
                AuthenticatorError::OpenFailed(format!("Open bidirectional stream failed: {}", err))
            })?;

        let (spake, token_a) = Spake2::<Ed25519Group>::start_a(
            &Password::new(self.secret.expose_secret()),
            &Identity::new(self.id()?.as_bytes()),
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
            self.end_of_auth(&mut send, &mut recv, true).await?;

            return Err(AuthenticatorError::OpenFailedAndBlock(
                "Remote accept_key mismatch".to_string(),
                remote_id,
            ));
        }

        send.write_all(&open_key).await.map_err(|err| {
            error!("[auth_open] failed to write open_key: {}", err);
            AuthenticatorError::OpenFailed(format!("Failed to write open_key: {}", err))
        })?;
        self.end_of_auth(&mut send, &mut recv, true).await?;

        info!("[auth_open] authenticated connection to {}", remote_id);

        Ok(())
    }
}

impl ProtocolHandler for Authenticator {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote_id = connection.remote_id();
        let res = match timeout(AUTH_TIMEOUT, self.auth_accept(connection)).await {
            Ok(Ok(())) => {
                release_in_flight(self.auth_state.clone(), remote_id, AuthState::Authenticated)
                    .ok();
                Ok(())
            }
            Ok(Err(err)) => match &err {
                AuthenticatorError::AcceptFailedAndBlock(msg, public_key) => {
                    warn!(
                        "[accept] authentication failed and blocking {}: {}",
                        public_key, msg
                    );
                    release_in_flight(self.auth_state.clone(), remote_id, AuthState::Blocked).ok();
                    Err(iroh::protocol::AcceptError::from_err(err))
                }
                _ => {
                    warn!("[accept] authentication failed: {}", err);
                    release_in_flight(
                        self.auth_state.clone(),
                        remote_id,
                        AuthState::Unauthenticated,
                    )
                    .ok();
                    Err(iroh::protocol::AcceptError::from_err(err))
                }
            },
            Err(_) => {
                warn!("[accept] authentication failed: timed out");
                release_in_flight(
                    self.auth_state.clone(),
                    remote_id,
                    AuthState::Unauthenticated,
                )
                .ok();
                Err(iroh::protocol::AcceptError::from_err(
                    AuthenticatorError::AcceptFailed("Authentication timed out".into()),
                ))
            }
        };

        res
    }
}

impl EndpointHooks for Authenticator {
    async fn after_handshake<'a>(
        &'a self,
        conn_info: &'a iroh::endpoint::ConnectionInfo,
    ) -> iroh::endpoint::AfterHandshakeOutcome {
        if self.is_authenticated(&conn_info.remote_id()) {
            debug!(
                "[after_handshake] already authenticated: {}",
                conn_info.remote_id()
            );
            return AfterHandshakeOutcome::accept();
        }

        let endpoint_id = conn_info.remote_id();
        if conn_info.alpn() == Self::ALPN {
            debug!(
                "[after_handshake] accepting auth connection: {}",
                String::from_utf8_lossy(conn_info.alpn())
            );
            return AfterHandshakeOutcome::accept();
        }

        // wait for authentication to complete
        let in_flight_watcher =
            if let Some(watchable) = get_auth_state(self.auth_state.clone(), endpoint_id) {
                match watchable.state() {
                    AuthState::Unauthenticated => {
                        debug!(
                            "[after_handshake] no in-flight auth for {}, rejecting connection",
                            endpoint_id
                        );
                        return AfterHandshakeOutcome::Reject {
                            error_code: VarInt::from_u32(401),
                            reason: b"No authentication in progress".to_vec(),
                        };
                    }
                    AuthState::InFlight => {
                        debug!(
                            "[after_handshake] waiting for in-flight auth for {}",
                            endpoint_id
                        );
                        watchable.watcher()
                    }
                    AuthState::Authenticated => {
                        // we try is_authenticated, if not we clear to None and reject
                        if self.is_authenticated(&conn_info.remote_id()) {
                            debug!(
                                "[after_handshake] already authenticated: {}",
                                conn_info.remote_id()
                            );
                            return AfterHandshakeOutcome::accept();
                        }

                        warn!("expected {endpoint_id} to be authenticated, resetting");
                        return AfterHandshakeOutcome::Reject {
                            error_code: VarInt::from_u32(500),
                            reason: b"in_flight status indicates already authenticated".to_vec(),
                        };
                    }
                    AuthState::Blocked => {
                        debug!(
                            "[after_handshake] endpoint {} is blocked, rejecting connection",
                            endpoint_id
                        );
                        return AfterHandshakeOutcome::Reject {
                            error_code: VarInt::from_u32(403),
                            reason: b"Endpoint is blocked".to_vec(),
                        };
                    }
                }
            } else {
                debug!(
                    "[after_handshake] no in-flight auth for {}, rejecting connection",
                    endpoint_id
                );
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(401),
                    reason: b"No authentication in progress".to_vec(),
                };
            };

        let wait_for_auth = async {
            let mut stream = in_flight_watcher.watch().stream();
            while let Some(in_flight) = stream.next().await {
                if matches!(
                    in_flight,
                    AuthState::Unauthenticated | AuthState::Authenticated | AuthState::Blocked
                ) {
                    return;
                }
            }
        };

        match timeout(AUTH_TIMEOUT, wait_for_auth).await {
            Ok(_) => {
                if self.is_authenticated(&endpoint_id) {
                    AfterHandshakeOutcome::accept()
                } else {
                    AfterHandshakeOutcome::Reject {
                        error_code: VarInt::from_u32(401),
                        reason: b"Authentication failed".to_vec(),
                    }
                }
            }
            Err(_) => {
                warn!(
                    "[after_handshake] authentication timed out for {}",
                    endpoint_id
                );
                AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(401),
                    reason: b"Authentication timed out".to_vec(),
                }
            }
        }
    }

    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a iroh::EndpointAddr,
        alpn: &'a [u8],
    ) -> iroh::endpoint::BeforeConnectOutcome {
        let remote_id = remote_addr.id;
        if self.is_authenticated(&remote_id) {
            debug!("[before_connect] already authenticated: {}", remote_id);
            return iroh::endpoint::BeforeConnectOutcome::Accept;
        }

        if alpn == Self::ALPN {
            debug!(
                "[before_connect] initiating auth for client connection with alpn {} to {}",
                String::from_utf8_lossy(alpn),
                remote_id
            );
            return iroh::endpoint::BeforeConnectOutcome::Accept;
        }

        match register_in_flight(self.auth_state.clone(), remote_id) {
            Ok(RegisterResponse::InFlightRegistered) => {
                debug!(
                    "[before_connect] registered in-flight auth for {}, performing auth",
                    remote_id
                );

                // We spawn the authentication worker in a new task
                // before_connect returns directly with BeforeConnectOutcome::Accept
                let endpoint = match self.endpoint() {
                    Ok(ep) => ep,
                    Err(_) => {
                        warn!("[before_connect] authenticator endpoint not set");
                        return iroh::endpoint::BeforeConnectOutcome::Reject;
                    }
                };
                self.spawn_auth_worker(remote_id, endpoint);
            }
            Ok(RegisterResponse::AlreadyInFlight) | Ok(RegisterResponse::AlreadyAuthenticated) => {
                if self.is_authenticated(&remote_id) {
                    debug!(
                    "[before_connect] already authenticated (in flight), accepting connection to {}",
                    remote_id
                );
                    return iroh::endpoint::BeforeConnectOutcome::Accept;
                }
            }
            Ok(RegisterResponse::AlreadyBlocked) => {
                debug!(
                    "[before_connect] endpoint {} is blocked, rejecting connection",
                    remote_id
                );
                return iroh::endpoint::BeforeConnectOutcome::Reject;
            }
            Err(err) => {
                warn!(
                    "[before_connect] failed to register in-flight auth for {}: {}",
                    remote_id, err
                );
                return iroh::endpoint::BeforeConnectOutcome::Reject;
            }
        }
        iroh::endpoint::BeforeConnectOutcome::Accept
    }
}

impl Authenticator {
    fn spawn_auth_worker(&self, remote_id: EndpointId, endpoint: Endpoint) {
        tokio::spawn({
            let auth = self.clone();
            let remote_id = remote_id.clone();
            let in_flight_ref = self.auth_state.clone();
            let start_time = Instant::now();
            async move {
                while start_time.elapsed() < AUTH_TIMEOUT {
                    debug!(
                        "[before_connect] background: connecting to {} for auth",
                        remote_id
                    );
                    match endpoint.connect(remote_id, Self::ALPN).await {
                        Ok(conn) => {
                            debug!(
                                "[before_connect] background: connected to {}, performing auth",
                                remote_id
                            );
                            match timeout(AUTH_TIMEOUT, auth.auth_open(conn)).await {
                                Ok(Ok(())) => {
                                    debug!(
                                        "[before_connect] background: authentication successful for {}",
                                        remote_id
                                    );

                                    release_in_flight(
                                        in_flight_ref.clone(),
                                        remote_id,
                                        AuthState::Authenticated,
                                    )
                                    .ok();
                                    return;
                                }
                                Ok(Err(err)) => match &err {
                                    AuthenticatorError::OpenFailedAndBlock(msg, public_key) => {
                                        warn!(
                                            "[before_connect] authentication failed and blocking {}: {}",
                                            public_key, msg
                                        );
                                        release_in_flight(
                                            in_flight_ref.clone(),
                                            remote_id,
                                            AuthState::Blocked,
                                        )
                                        .ok();
                                        return;
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
                                        "[before_connect] background: authentication timed out for {}, retrying...",
                                        remote_id
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[before_connect] background: failed to open connection for authentication to {}: {}, retrying...",
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
                release_in_flight(in_flight_ref.clone(), remote_id, AuthState::Unauthenticated)
                    .ok();
            }
        });
    }
}

fn register_in_flight(
    in_flight: Arc<Mutex<HashMap<EndpointId, WatchableRemote>>>,
    endpoint_id: PublicKey,
) -> Result<RegisterResponse, InFlightError> {
    if let Ok(mut in_flight) = in_flight.lock() {
        match in_flight.entry(endpoint_id) {
            Entry::Occupied(entry) => match entry.get().state() {
                AuthState::Unauthenticated => {
                    entry.get().set_state(AuthState::InFlight);
                    Ok(RegisterResponse::InFlightRegistered)
                }
                AuthState::Authenticated => Ok(RegisterResponse::AlreadyAuthenticated),
                AuthState::InFlight => Ok(RegisterResponse::AlreadyInFlight),
                AuthState::Blocked => Ok(RegisterResponse::AlreadyBlocked),
            },
            Entry::Vacant(entry) => {
                let watchable = WatchableRemote::new(endpoint_id);
                watchable.set_state(AuthState::InFlight);
                entry.insert(watchable);
                Ok(RegisterResponse::InFlightRegistered)
            }
        }
    } else {
        warn!("failed to acquire in_flight lock");
        Err(InFlightError::LockPoisoned(
            "register_in_flight".to_string(),
        ))
    }
}

fn release_in_flight(
    in_flight: Arc<Mutex<HashMap<EndpointId, WatchableRemote>>>,
    endpoint_id: PublicKey,
    target_state: AuthState,
) -> Result<(), InFlightError> {
    if target_state == AuthState::InFlight {
        return Err(InFlightError::PromotionNotAllowed(
            "cannot release by promoting to InFlight".to_string(),
        ));
    }
    if let Ok(mut in_flight) = in_flight.lock() {
        match in_flight.entry(endpoint_id) {
            Entry::Occupied(entry) => {
                let c_state = entry.get().state();
                match c_state {
                    AuthState::InFlight => {
                        entry.get().set_state(target_state);
                        Ok(())
                    }
                    _ => Err(InFlightError::PromotionNotAllowed(format!(
                        "only promote to {} from {} not from {}",
                        target_state,
                        AuthState::InFlight,
                        c_state
                    ))),
                }
            }
            Entry::Vacant(entry) => {
                debug!("no entry detected, this means we are the accepting side of a auth request, accept target_state unconditionally");
                let watchable = WatchableRemote::new(endpoint_id);
                watchable.set_state(target_state);
                entry.insert(watchable);
                Ok(())
            }
        }
    } else {
        Err(InFlightError::LockPoisoned("release_in_flight".to_string()))
    }
}

fn get_auth_state(
    auth_state: Arc<Mutex<HashMap<EndpointId, WatchableRemote>>>,
    endpoint_id: PublicKey,
) -> Option<WatchableRemote> {
    if let Ok(in_flight) = auth_state.lock() {
        return in_flight.get(&endpoint_id).cloned();
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use iroh::RelayMap;
    use tokio::time;

    #[test]
    fn test_token_different() {
        let password = b"testpassword";
        let id_a = b"identityA";
        let id_b = b"identityB";

        let (spake_a, token_a) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(id_a),
            &Identity::new(id_b),
        );

        let (spake_b, token_b) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(id_a),
            &Identity::new(id_b),
        );

        assert_ne!(token_a, token_b);

        let key_a = spake_a.finish(&token_b).unwrap();
        let key_b = spake_b.finish(&token_a).unwrap();

        assert_eq!(key_a, key_b);
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct DummyProtocol;
    impl ProtocolHandler for DummyProtocol {
        async fn accept(&self, _conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_auth_success() {
        let secret = b"supersecrettoken1234567890123456";
        assert!(run_auth_test(secret, secret).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_auth_parallel() {
        // enable logs for this test debug (only iroh_auth::debug)
        //tracing_subscriber::fmt()
        //    .with_env_filter(tracing_subscriber::EnvFilter::new("iroh_auth=debug"))
        //    .init();

        let secret = b"supersecrettoken1234567890123456";
        let worked = Arc::new(AtomicUsize::new(0));
        let count = 10;
        for _ in 0..count {
            let worked = worked.clone();
            tokio::spawn(async move {
                assert!(run_auth_parallel_test(secret, secret, count).await.unwrap());
                worked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }

        while worked.load(std::sync::atomic::Ordering::SeqCst) < count {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_auth_failure() {
        let secret_a = b"supersecrettoken1234567890123456";
        let secret_b = b"differentsecrettoken123456789012";
        assert!(!run_auth_test(secret_a, secret_b).await.unwrap());
    }

    async fn run_auth_test(
        secret_a: &'static [u8],
        secret_b: &'static [u8],
    ) -> Result<bool, String> {
        let auth_a = Authenticator::new(secret_a);
        let endpoint_a = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![b"/dummy/1".to_vec()])
            .hooks(auth_a.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_a.set_endpoint(&endpoint_a);

        let auth_b = Authenticator::new(secret_b);
        let endpoint_b = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![b"/dummy/1".to_vec()])
            .hooks(auth_b.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_b.set_endpoint(&endpoint_b);

        let router_a = iroh::protocol::Router::builder(endpoint_a.clone())
            .accept(Authenticator::ALPN, auth_a.clone())
            .spawn();

        let router_b = iroh::protocol::Router::builder(endpoint_b.clone())
            .accept(Authenticator::ALPN, auth_b.clone())
            .spawn();

        tokio::spawn({
            let endpoint_a = endpoint_a.clone();
            let endpoint_b = endpoint_b.clone();
            async move {
                endpoint_a
                    .connect(endpoint_b.addr(), b"/dummy/1")
                    .await
                    .ok();
            }
        });

        let wait_loop = async {
            let wait_a = async {
                while auth_a.list_authenticated().is_empty() && auth_a.list_blocked().is_empty() {
                    time::sleep(Duration::from_millis(100)).await;
                }
            };
            let wait_b = async {
                while auth_b.list_authenticated().is_empty() && auth_b.list_blocked().is_empty() {
                    time::sleep(Duration::from_millis(100)).await;
                }
            };
            tokio::join!(wait_a, wait_b);
        };

        if timeout(AUTH_TIMEOUT * 2, wait_loop).await.is_err() {
            router_a.shutdown().await.ok();
            router_b.shutdown().await.ok();
            return Err("Authentication did not complete in time".to_string());
        }

        router_a.shutdown().await.ok();
        router_b.shutdown().await.ok();

        Ok(auth_a.is_authenticated(&endpoint_b.id()) && auth_b.is_authenticated(&endpoint_a.id()))
    }

    async fn run_auth_parallel_test(
        secret_a: &'static [u8],
        secret_b: &'static [u8],
        parallel_count: usize,
    ) -> Result<bool, String> {
        let auth_a = Authenticator::new(secret_a);
        let mut endpoint_a_builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0);
        for i in 0..parallel_count {
            endpoint_a_builder =
                endpoint_a_builder.alpns(vec![format!("/dummy/{}", i).into_bytes()]);
        }
        let endpoint_a = endpoint_a_builder
            .clear_relay_transports()
            .relay_mode(iroh::RelayMode::Custom(
                RelayMap::try_from_iter(["https://iroh-relay.rustonbsd.com"]).unwrap(),
            ))
            .hooks(auth_a.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_a.set_endpoint(&endpoint_a);

        let auth_b = Authenticator::new(secret_b);
        let mut endpoint_b_builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0);
        for i in 0..parallel_count {
            endpoint_b_builder =
                endpoint_b_builder.alpns(vec![format!("/dummy/{}", i).into_bytes()]);
        }
        let endpoint_b = endpoint_b_builder
            .clear_relay_transports()
            .relay_mode(iroh::RelayMode::Custom(
                RelayMap::try_from_iter(["https://iroh-relay.rustonbsd.com"]).unwrap(),
            ))
            .hooks(auth_b.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_b.set_endpoint(&endpoint_b);

        let mut router_a_builder = iroh::protocol::Router::builder(endpoint_a.clone());
        for i in 0..parallel_count {
            router_a_builder =
                router_a_builder.accept(format!("/dummy/{}", i).into_bytes(), DummyProtocol);
        }
        let router_a = router_a_builder
            .accept(Authenticator::ALPN, auth_a.clone())
            .spawn();

        let mut router_b_builder = iroh::protocol::Router::builder(endpoint_b.clone());
        for i in 0..parallel_count {
            router_b_builder =
                router_b_builder.accept(format!("/dummy/{}", i).into_bytes(), DummyProtocol);
        }
        let router_b = router_b_builder
            .accept(Authenticator::ALPN, auth_b.clone())
            .spawn();

        for i in 0..parallel_count {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tokio::spawn({
                let endpoint_a = endpoint_a.clone();
                let endpoint_b = endpoint_b.clone();
                async move {
                    endpoint_a
                        .connect(
                            endpoint_b.addr(),
                            format!("/dummy/{}", i).into_bytes().as_slice(),
                        )
                        .await
                        .ok();
                }
            });
        }

        let wait_loop = async {
            let wait_a = async {
                while auth_a.list_authenticated().is_empty() && auth_a.list_blocked().is_empty() {
                    time::sleep(Duration::from_millis(100)).await;
                }
            };
            let wait_b = async {
                while auth_b.list_authenticated().is_empty() && auth_b.list_blocked().is_empty() {
                    time::sleep(Duration::from_millis(100)).await;
                }
            };
            tokio::join!(wait_a, wait_b);
        };

        if timeout(AUTH_TIMEOUT * 2, wait_loop).await.is_err() {
            router_a.shutdown().await.ok();
            router_b.shutdown().await.ok();
            return Err("Authentication did not complete in time".to_string());
        }

        router_a.shutdown().await.ok();
        router_b.shutdown().await.ok();

        Ok(auth_a.is_authenticated(&endpoint_b.id()) && auth_b.is_authenticated(&endpoint_a.id()))
    }

    #[test]
    fn test_into_secret_impls() {
        use secrecy::ExposeSecret;

        let expected_bytes = b"my-secret-key";

        // &str
        let secret = "my-secret-key".into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);

        // String
        let secret = String::from("my-secret-key").into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);
        // Vec<u8>
        let secret = b"my-secret-key".to_vec().into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);

        // &[u8]
        let bytes: &[u8] = b"my-secret-key";
        let secret = bytes.into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);

        // &[u8; N]
        let bytes: &[u8; 13] = b"my-secret-key";
        let secret = bytes.into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);

        // Box<[u8]>
        let bytes: Box<[u8]> = Box::new(*b"my-secret-key");
        let secret = bytes.into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);

        // SecretSlice<u8>
        let ps = SecretSlice::new(Box::new(*b"my-secret-key"));
        let secret = ps.into_secret();
        assert_eq!(secret.expose_secret(), expected_bytes);
    }
}
