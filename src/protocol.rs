use std::sync::Arc;

use iroh::{
    endpoint::{AfterHandshakeOutcome, EndpointHooks, VarInt},
    protocol::ProtocolHandler,
    EndpointId, PublicKey, Watcher,
};
use lru::LruCache;
use n0_future::StreamExt;
use tokio::{sync::Mutex, time::timeout};
use tracing::{debug, error, info, warn};

use crate::{
    auth::{AuthState, RegisterResponse, WatchableRemote},
    error::InFlightError,
    Authenticator, AuthenticatorError, ALPN, AUTH_TIMEOUT,
};

impl ProtocolHandler for Authenticator {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote_id = connection.remote_id();
        let res = match timeout(AUTH_TIMEOUT, self.auth_accept(connection)).await {
            Ok(Ok(())) => {
                release_in_flight(self.auth_state.clone(), remote_id, AuthState::Authenticated)
                    .await
                    .ok();
                Ok(())
            }
            Ok(Err(err)) => match &err {
                AuthenticatorError::AcceptFailedAndBlock(msg, public_key) => {
                    warn!(
                        "[accept] authentication failed and blocking {}: {}",
                        public_key, msg
                    );
                    release_in_flight(self.auth_state.clone(), remote_id, AuthState::Blocked)
                        .await
                        .ok();
                    Err(iroh::protocol::AcceptError::from_err(err))
                }
                _ => {
                    warn!("[accept] authentication failed: {}", err);
                    release_in_flight(
                        self.auth_state.clone(),
                        remote_id,
                        AuthState::Unauthenticated,
                    )
                    .await
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
                .await
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
        let endpoint_id = conn_info.remote_id();
        if self.is_authenticated(&endpoint_id).await {
            debug!("[after_handshake] already authenticated: {}", endpoint_id);
            return AfterHandshakeOutcome::accept();
        }

        if conn_info.alpn() == ALPN {
            debug!(
                "[after_handshake] accepting auth connection: {}",
                String::from_utf8_lossy(conn_info.alpn())
            );
            return AfterHandshakeOutcome::accept();
        }

        // wait for authentication to complete
        let in_flight_watcher = if let Some(watchable) =
            get_auth_state(self.auth_state.clone(), endpoint_id).await
        {
            match watchable.state() {
                AuthState::Unauthenticated => {
                    debug!("[after_handshake] no in-flight auth for {}, we are asymetric (the other node successfully authed but we didn't), initiating auth ourself",endpoint_id);
                    match register_in_flight(self.auth_state.clone(), endpoint_id).await {
                        Ok(RegisterResponse::AlreadyInFlight) => {
                            debug!(
                                    "[after_handshake] already in-flight auth for {}, waiting for it to complete",
                                    endpoint_id
                                );
                            watchable.watcher()
                        }
                        Ok(RegisterResponse::InFlightRegistered) => {
                            debug!(
                                    "[after_handshake] registered in-flight auth for {}, performing auth",
                                    endpoint_id
                                );
                            let endpoint = match self.endpoint().await {
                                Ok(ep) => ep,
                                Err(_) => {
                                    error!("[after_handshake] authenticator endpoint not set");
                                    return AfterHandshakeOutcome::Reject {
                                        error_code: VarInt::from_u32(500),
                                        reason: b"Internal server error".to_vec(),
                                    };
                                }
                            };
                            if let Err(err) = self.perform_auth(endpoint_id, endpoint).await {
                                error!(
                                        "[after_handshake] authentication failed for {}, rejecting connection with error: {}",
                                        endpoint_id, err
                                    );
                                return AfterHandshakeOutcome::Reject {
                                    error_code: VarInt::from_u32(401),
                                    reason: b"Authentication failed".to_vec(),
                                };
                            } else {
                                info!(
                                    "[after_handshake] authentication succeeded for {}",
                                    endpoint_id
                                );
                                debug!(
                                    "[after_handshake] authentication succeeded for {}, waiting for state update",
                                    endpoint_id
                                );
                                return iroh::endpoint::AfterHandshakeOutcome::accept();
                            }
                        }
                        _ => {
                            debug!(
                                    "[after_handshake] failed to register in-flight auth for {}, rejecting connection",
                                    endpoint_id
                                );
                            return AfterHandshakeOutcome::Reject {
                                error_code: VarInt::from_u32(401),
                                reason: b"Authentication failed".to_vec(),
                            };
                        }
                    }
                }
                AuthState::InFlight => {
                    debug!(
                        "[after_handshake] waiting for in-flight auth for {}",
                        endpoint_id
                    );
                    watchable.watcher()
                }
                AuthState::Authenticated => {
                    debug!(
                        "[after_handshake] already authenticated: {}",
                        conn_info.remote_id()
                    );
                    return AfterHandshakeOutcome::accept();
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
                if self.is_authenticated(&endpoint_id).await {
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
        if self.is_authenticated(&remote_id).await {
            debug!("[before_connect] already authenticated: {}", remote_id);
            return iroh::endpoint::BeforeConnectOutcome::Accept;
        }

        if alpn == ALPN {
            debug!(
                "[before_connect] initiating auth for client connection with alpn {} to {}",
                String::from_utf8_lossy(alpn),
                remote_id
            );
            return iroh::endpoint::BeforeConnectOutcome::Accept;
        }

        match register_in_flight(self.auth_state.clone(), remote_id).await {
            Ok(RegisterResponse::InFlightRegistered) => {
                debug!(
                    "[before_connect] registered in-flight auth for {}, performing auth",
                    remote_id
                );

                let endpoint = match self.endpoint().await {
                    Ok(ep) => ep,
                    Err(_) => {
                        error!("[before_connect] authenticator endpoint not set");
                        return iroh::endpoint::BeforeConnectOutcome::Reject;
                    }
                };
                if let Err(err) = self.perform_auth(remote_id, endpoint).await {
                    error!(
                        "[before_connect] authentication failed for {}, rejecting connection with error: {}",
                        remote_id, err
                    );
                    iroh::endpoint::BeforeConnectOutcome::Reject
                } else {
                    info!(
                        "[before_connect] authentication succeeded for {}",
                        remote_id
                    );
                    iroh::endpoint::BeforeConnectOutcome::Accept
                }
            }
            Ok(RegisterResponse::AlreadyInFlight) | Ok(RegisterResponse::AlreadyAuthenticated) => {
                if self.is_authenticated(&remote_id).await {
                    debug!(
                    "[before_connect] already authenticated (in flight), accepting connection to {}",
                    remote_id
                );
                }
                iroh::endpoint::BeforeConnectOutcome::Accept
            }
            Ok(RegisterResponse::AlreadyBlocked) => {
                debug!(
                    "[before_connect] endpoint {} is blocked, rejecting connection",
                    remote_id
                );
                iroh::endpoint::BeforeConnectOutcome::Reject
            }
            Err(err) => {
                warn!(
                    "[before_connect] failed to register in-flight auth for {}: {}",
                    remote_id, err
                );
                iroh::endpoint::BeforeConnectOutcome::Reject
            }
        }
    }
}

pub(crate) async fn register_in_flight(
    in_flight: Arc<Mutex<LruCache<EndpointId, WatchableRemote>>>,
    endpoint_id: PublicKey,
) -> Result<RegisterResponse, InFlightError> {
    let mut guard = in_flight.lock().await;
    if let Some(entry) = guard.get(&endpoint_id) {
        return match entry.state() {
            AuthState::Unauthenticated => {
                entry.set_state(AuthState::InFlight);
                Ok(RegisterResponse::InFlightRegistered)
            }
            AuthState::Authenticated => Ok(RegisterResponse::AlreadyAuthenticated),
            AuthState::InFlight => Ok(RegisterResponse::AlreadyInFlight),
            AuthState::Blocked => Ok(RegisterResponse::AlreadyBlocked),
        };
    }

    let watchable = WatchableRemote::new(endpoint_id);
    watchable.set_state(AuthState::InFlight);

    if let Some(evicted) = guard.put(endpoint_id, watchable) {
        debug!(
            "evicting endpoint {} from auth cache due to capacity limit",
            evicted.id()
        );
    }

    Ok(RegisterResponse::InFlightRegistered)
}

pub(crate) async fn release_in_flight(
    in_flight: Arc<Mutex<LruCache<EndpointId, WatchableRemote>>>,
    endpoint_id: PublicKey,
    target_state: AuthState,
) -> Result<(), InFlightError> {
    if target_state == AuthState::InFlight {
        return Err(InFlightError::PromotionNotAllowed(
            "cannot release by promoting to InFlight".to_string(),
        ));
    }
    let mut guard = in_flight.lock().await;

    // occupied
    if let Some(entry) = guard.get(&endpoint_id) {
        return match entry.state() {
            AuthState::InFlight => {
                entry.set_state(target_state);
                Ok(())
            }
            AuthState::Authenticated => {
                if target_state == AuthState::Blocked {
                    entry.set_state(AuthState::Blocked);
                    debug!(
                        "endpoint {} was authenticated but is now blocked, updating state to Blocked",
                        endpoint_id
                    );
                    Ok(())
                } else {
                    debug!(
                        "endpoint {} is already authenticated, no-op",
                        endpoint_id
                    );
                    Ok(())
                }
            }
            current_state => {
                if current_state == target_state {
                    debug!(
                        "endpoint {} is already in target state {}, no state change needed",
                        endpoint_id, target_state
                    );
                    Ok(())
                } else {
                    Err(InFlightError::PromotionNotAllowed(format!(
                        "only promote to {} from {} not from {}",
                        target_state,
                        AuthState::InFlight,
                        entry.state()
                    )))
                }
            }
        };
    }

    // vacant
    let watchable = WatchableRemote::new(endpoint_id);
    watchable.set_state(target_state);

    if let Some(evicted) = guard.put(endpoint_id, watchable) {
        debug!(
            "evicting endpoint {} from auth cache due to capacity limit",
            evicted.id()
        );
    }

    Ok(())
}

pub(crate) async fn get_auth_state(
    auth_state: Arc<Mutex<LruCache<EndpointId, WatchableRemote>>>,
    endpoint_id: PublicKey,
) -> Option<WatchableRemote> {
    auth_state.lock().await.get(&endpoint_id).cloned()
}
