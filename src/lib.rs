use n0_watcher::Watchable;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{debug, error, info, trace, warn};

use hkdf::Hkdf;
use iroh::{
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, VarInt},
    protocol::ProtocolHandler,
    Endpoint, EndpointId, PublicKey, Watcher,
};
use n0_future::{task::spawn, time::timeout, StreamExt};
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WatchableCounter {
    authenticated: usize,
    blocked: usize,
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    secret: SecretSlice<u8>,
    authenticated: Arc<Mutex<BTreeSet<PublicKey>>>,
    watcher: Watchable<WatchableCounter>,
    endpoint: Arc<Mutex<Option<iroh::Endpoint>>>,
}

pub const ALPN: &[u8] = b"/iroh/auth/0.1";
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(60);

impl Authenticator {
    pub const ALPN: &'static [u8] = ALPN;
    const ACCEPT_CONTEXT: &'static [u8] = b"iroh-auth-accept";
    const OPEN_CONTEXT: &'static [u8] = b"iroh-auth-open";

    pub fn new<S: IntoSecret>(secret: S) -> Self {
        Self {
            secret: secret.into_secret(),
            authenticated: Arc::new(Mutex::new(BTreeSet::new())),
            watcher: Watchable::new(WatchableCounter::default()),
            endpoint: Arc::new(Mutex::new(None)),
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
        self.authenticated
            .lock()
            .map(|set| set.contains(id))
            .unwrap_or(false)
    }

    fn add_authenticated(&self, id: PublicKey) -> Result<(), AuthenticatorError> {
        self.authenticated
            .lock()
            .map_err(|_| AuthenticatorError::AddFailed)?
            .insert(id);
        let mut counter = self.watcher.get();
        counter.authenticated += 1;
        self.watcher
            .set(counter)
            .map_err(|_| AuthenticatorError::AddFailed)?;
        Ok(())
    }

    fn add_blocked(&self) -> Result<(), AuthenticatorError> {
        let mut counter = self.watcher.get();
        counter.blocked += 1;
        self.watcher
            .set(counter)
            .map_err(|_| AuthenticatorError::AddFailed)?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn list_authenticated(&self) -> Vec<PublicKey> {
        self.authenticated
            .lock()
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Accept an incoming connection and perform SPAKE2 authentication.
    /// On success, adds the remote ID to the authenticated set.
    /// Returns Ok(()) on success, or an AuthenticatorError on failure.
    async fn auth_accept(&self, conn: Connection) -> Result<(), AuthenticatorError> {
        let remote_id = conn.remote_id();
        debug!("[auth_accept] accepting auth connection from {}", remote_id);
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|err| {
            error!("[auth_accept] accept bidirectional stream failed: {}", err);
            AuthenticatorError::AcceptFailed(format!("Accept bidirectional stream failed: {}", err))
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

        if !bool::from(remote_open_key.ct_eq(&open_key)) {
            error!("[auth_accept] remote open_key mismatch");
            return Err(AuthenticatorError::AcceptFailedAndBlock(
                "Remote open_key mismatch".to_string(),
                remote_id,
            ));
        }

        self.add_authenticated(conn.remote_id())?;
        info!("[auth_accept] authenticated connection from {}", remote_id);

        Ok(())
    }

    /// Open an outgoing connection and perform SPAKE2 authentication.
    /// On success, adds the remote ID to the authenticated set.
    /// Returns Ok(()) on success, or an AuthenticatorError on failure.
    async fn auth_open(&self, conn: Connection) -> Result<(), AuthenticatorError> {
        let remote_id = conn.remote_id();
        debug!("[auth_open] opening auth connection to {}", remote_id);
        let (mut send, mut recv) = conn.open_bi().await.map_err(|err| {
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
            send.finish().ok();
            conn.closed().await;

            return Err(AuthenticatorError::OpenFailedAndBlock(
                "Remote accept_key mismatch".to_string(),
                remote_id,
            ));
        }

        send.write_all(&open_key).await.map_err(|err| {
            error!("[auth_open] failed to write open_key: {}", err);
            AuthenticatorError::OpenFailed(format!("Failed to write open_key: {}", err))
        })?;
        send.finish().map_err(|err| {
            error!("[auth_open] failed to finish stream: {}", err);
            AuthenticatorError::OpenFailed(format!("Failed to finish stream: {}", err))
        })?;

        conn.closed().await;

        self.add_authenticated(conn.remote_id())?;
        info!("[auth_open] authenticated connection to {}", remote_id);

        Ok(())
    }
}

impl ProtocolHandler for Authenticator {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        match timeout(AUTH_TIMEOUT, self.auth_accept(connection)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => match &err {
                AuthenticatorError::AcceptFailedAndBlock(msg, public_key) => {
                    warn!("[accept] authentication failed and blocking {}: {}", public_key, msg);
                    self.add_blocked().ok();
                    Err(iroh::protocol::AcceptError::from_err(err))
                }
                _ => {
                    warn!("[accept] authentication failed: {}", err);
                    Err(iroh::protocol::AcceptError::from_err(err))
                }
            },
            Err(_) => {
                warn!("[accept] authentication failed: timed out");
                Err(iroh::protocol::AcceptError::from_err(
                    AuthenticatorError::AcceptFailed("Authentication timed out".into()),
                ))
            }
        }
    }
}

impl EndpointHooks for Authenticator {
    async fn after_handshake<'a>(
        &'a self,
        conn_info: &'a iroh::endpoint::ConnectionInfo,
    ) -> iroh::endpoint::AfterHandshakeOutcome {
        if self.is_authenticated(&conn_info.remote_id()) {
            debug!("[after_handshake] already authenticated: {}", conn_info.remote_id());
            return AfterHandshakeOutcome::accept();
        }

        if conn_info.alpn() == Self::ALPN {
            debug!(
                "[after_handshake] skipping auth for connection with alpn {}",
                String::from_utf8_lossy(conn_info.alpn())
            );
            return AfterHandshakeOutcome::accept();
        }

        let remote_id = conn_info.remote_id();
        let counter = self.watcher.get();

        let wait_for_auth = async {
            let mut stream = self.watcher.watch().stream();
            while let Some(next_counter) = stream.next().await {
                if next_counter != counter && self.is_authenticated(&remote_id) {
                    return Ok(()) as Result<(), AuthenticatorError>;
                }
            }
            Err(AuthenticatorError::AcceptFailed(
                "Watcher stream ended unexpectedly".to_string(),
            ))
        };

        match timeout(AUTH_TIMEOUT, wait_for_auth).await {
            Ok(_) => AfterHandshakeOutcome::accept(),
            Err(_) => {
                warn!("[after_handshake] authentication timed out for {}", remote_id);
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
        if self.is_authenticated(&remote_addr.id) {
            debug!("[before_connect] already authenticated: {}", remote_addr.id);
            return iroh::endpoint::BeforeConnectOutcome::Accept;
        }

        if alpn == Self::ALPN {
            debug!(
                "[before_connect] skipping auth for connection to {} with alpn {:?}",
                remote_addr.id, alpn
            );
            return iroh::endpoint::BeforeConnectOutcome::Accept;
        }

        debug!(
            "[before_connect] initiating auth for client connection with alpn {} to {}",
            String::from_utf8_lossy(alpn),
            remote_addr.id
        );
        let endpoint = match self.endpoint() {
            Ok(ep) => ep,
            Err(_) => {
                warn!("[before_connect] authenticator endpoint not set");
                return iroh::endpoint::BeforeConnectOutcome::Reject;
            }
        };
        spawn({
            let auth = self.clone();
            let remote_id = remote_addr.id;

            async move {
                debug!("[before_connect] background: connecting to {} for auth", remote_id);
                let start = std::time::Instant::now();
                while start.elapsed() < AUTH_TIMEOUT {
                    match endpoint.connect(remote_id, Self::ALPN).await {
                        Ok(conn) => {
                            debug!("[before_connect] background: connected to {}, performing auth", remote_id);
                            match timeout(AUTH_TIMEOUT, auth.auth_open(conn)).await {
                                Ok(Ok(())) => {
                                    debug!(
                                        "[before_connect] background: authentication successful for {}",
                                        remote_id
                                    );
                                    return;
                                }
                                Ok(Err(err)) => match &err {
                                    AuthenticatorError::OpenFailedAndBlock(msg, public_key) => {
                                        warn!(
                                            "[before_connect] authentication failed and blocking {}: {}",
                                            public_key, msg
                                        );
                                        auth.add_blocked().ok();
                                        return;
                                    }
                                    _ => {
                                        warn!("[before_connect] authentication failed for {}: {}", remote_id, err);
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
                    
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                warn!("[before_connect] background: authentication timed out for {}", remote_id);
            }
        });
        iroh::endpoint::BeforeConnectOutcome::Accept
    }
}

#[cfg(test)]
mod tests {
    use iroh::Watcher;

    use super::*;
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
        let endpoint_a = iroh::Endpoint::builder()
            .hooks(auth_a.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_a.set_endpoint(&endpoint_a);
        let dummy_a = DummyProtocol;

        let auth_b = Authenticator::new(secret_b);
        let endpoint_b = iroh::Endpoint::builder()
            .hooks(auth_b.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_b.set_endpoint(&endpoint_b);
        let dummy_b = DummyProtocol;

        let router_a = iroh::protocol::Router::builder(endpoint_a.clone())
            .accept(Authenticator::ALPN, auth_a.clone())
            .accept(b"/dummy/1", dummy_a)
            .spawn();

        let router_b = iroh::protocol::Router::builder(endpoint_b.clone())
            .accept(Authenticator::ALPN, auth_b.clone())
            .accept(b"/dummy/1", dummy_b)
            .spawn();

        spawn({
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
            use n0_future::StreamExt;

            let wait_a = async {
                let mut stream = auth_a.watcher.watch().stream();
                while let Some(counter) = stream.next().await {
                    debug!(
                        "auth_a watcher: authenticated={}, blocked={}",
                        counter.authenticated, counter.blocked
                    );
                    if counter.authenticated >= 1 || counter.blocked >= 1 {
                        break;
                    }
                }
            };
            let wait_b = async {
                let mut stream = auth_b.watcher.watch().stream();
                while let Some(counter) = stream.next().await {
                    debug!(
                        "auth_b watcher: authenticated={}, blocked={}",
                        counter.authenticated, counter.blocked
                    );
                    if counter.authenticated >= 1 || counter.blocked >= 1 {
                        break;
                    }
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
