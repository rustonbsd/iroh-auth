#[cfg(test)]
mod tests {
    use std::{
        sync::{atomic::AtomicUsize, Arc},
        time::Duration,
    };

    use crate::{Authenticator, IntoSecret, AUTH_TIMEOUT};
    use iroh::{endpoint::Connection, protocol::ProtocolHandler};
    use secrecy::SecretSlice;
    use spake2::{Ed25519Group, Identity, Password, Spake2};
    use tokio::time::{self, timeout};

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

        let key_a = spake_a.finish(&token_b).expect("SPAKE2 A failed to finish");
        let key_b = spake_b.finish(&token_a).expect("SPAKE2 B failed to finish");

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
        assert!(run_auth_test(secret, secret)
            .await
            .expect("Auth test failed"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_auth_parallel() {
        let secret = b"supersecrettoken1234567890123456";
        let worked = Arc::new(AtomicUsize::new(0));
        let count = 10;
        for _ in 0..count {
            let worked = worked.clone();
            tokio::spawn(async move {
                assert!(run_auth_parallel_test(secret, secret, count)
                    .await
                    .expect("auth_parallel test failed"));
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
        assert!(!run_auth_test(secret_a, secret_b)
            .await
            .expect("Auth failure test failed"));
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
        auth_a.set_endpoint(&endpoint_a).await;

        let auth_b = Authenticator::new(secret_b);
        let endpoint_b = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![b"/dummy/1".to_vec()])
            .hooks(auth_b.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_b.set_endpoint(&endpoint_b).await;

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
                while auth_a.list_authenticated().await.is_empty()
                    && auth_a.list_blocked().await.is_empty()
                {
                    time::sleep(Duration::from_millis(100)).await;
                }
            };
            let wait_b = async {
                while auth_b.list_authenticated().await.is_empty()
                    && auth_b.list_blocked().await.is_empty()
                {
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

        Ok(auth_a.is_authenticated(&endpoint_b.id()).await
            && auth_b.is_authenticated(&endpoint_a.id()).await)
    }

    async fn run_auth_parallel_test(
        secret_a: &'static [u8],
        secret_b: &'static [u8],
        parallel_count: usize,
    ) -> Result<bool, String> {
        let auth_a = Authenticator::new(secret_a);
        let mut endpoint_a_builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0);
        let alpns = (0..parallel_count)
            .map(|i| format!("/dummy/{}", i).into_bytes())
            .collect();
        endpoint_a_builder = endpoint_a_builder.alpns(alpns);

        let endpoint_a = endpoint_a_builder
            .hooks(auth_a.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_a.set_endpoint(&endpoint_a).await;

        let auth_b = Authenticator::new(secret_b);
        let mut endpoint_b_builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0);
        let alpns = (0..parallel_count)
            .map(|i| format!("/dummy/{}", i).into_bytes())
            .collect();
        endpoint_b_builder = endpoint_b_builder.alpns(alpns);
        let endpoint_b = endpoint_b_builder
            .hooks(auth_b.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        auth_b.set_endpoint(&endpoint_b).await;

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

        let success = Arc::new(AtomicUsize::new(0));
        for i in 0..parallel_count {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tokio::spawn({
                let endpoint_a = endpoint_a.clone();
                let endpoint_b = endpoint_b.clone();
                let success = success.clone();
                async move {
                    if endpoint_a
                        .connect(
                            endpoint_b.addr(),
                            format!("/dummy/{}", i).into_bytes().as_slice(),
                        )
                        .await
                        .is_ok()
                    {
                        success.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
        }

        let wait_loop = async {
            let wait_a = async {
                while auth_a.list_authenticated().await.len() + auth_a.list_blocked().await.len()
                    < 1
                    || success.load(std::sync::atomic::Ordering::SeqCst) < parallel_count
                {
                    time::sleep(Duration::from_millis(1000)).await;
                }
            };
            let wait_b = async {
                while auth_b.list_authenticated().await.len() + auth_b.list_blocked().await.len()
                    < 1
                    || success.load(std::sync::atomic::Ordering::SeqCst) < parallel_count
                {
                    time::sleep(Duration::from_millis(1000)).await;
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

        Ok(auth_a.is_authenticated(&endpoint_b.id()).await
            && auth_b.is_authenticated(&endpoint_a.id()).await)
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
