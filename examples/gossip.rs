#[tokio::main]
async fn main() -> Result<(), String> {
    #[cfg(feature = "gossip-example")]
    {
        use iroh::PublicKey;
        use iroh::{protocol::Router, Endpoint};
        use iroh_auth::{self, Authenticator};

        use iroh_gossip::{net::Gossip, TopicId};

        use sha2::Digest;

        tracing_subscriber::fmt()
            .with_env_filter("iroh_auth=debug")
            .init();

        let peers: Vec<PublicKey> = if let Some(s) = std::env::args().nth(1) {
            println!("Connecting to peer: {}", s);
            vec![s.parse::<PublicKey>().map_err(|e| e.to_string())?]
        } else {
            vec![]
        };

        // #1 Create Authenticator
        let auth = Authenticator::new("my-secure-network-secret-12345");
        let endpoint = Endpoint::builder()
            // #2 Add auth hooks
            .hooks(auth.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;

        // #3 Pass endpoint to the Authenticator for establishing auth connections
        auth.set_endpoint(&endpoint);

        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = Router::builder(endpoint)
            // #4 Add Authenticator to the router
            .accept(iroh_auth::ALPN, auth.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        println!(
            "cargo run --example gossip --features=gossip-example -- {}",
            router.endpoint().id()
        );

        let mut topic_hash = sha2::Sha256::new();
        topic_hash.update("my-gossip-topic");
        let topic = TopicId::from_bytes(topic_hash.finalize().into());

        let (sender, recv) = gossip
            .subscribe_and_join(topic, peers)
            .await
            .map_err(|e| e.to_string())?
            .split();

        tokio::spawn(async move {
            use n0_future::StreamExt;

            let mut recv = recv;
            loop {
                tokio::select! {
                    msg = recv.next() => {
                        match msg {
                            Some(Ok(msg)) => {
                                match msg {
                                    iroh_gossip::api::Event::Received(msg) => {
                                        println!(
                                            "Received msg from {}: {:?}",
                                            msg.delivered_from, msg.content
                                        );
                                    }
                                    iroh_gossip::api::Event::NeighborUp(remote_id) => {
                                        println!("Neighbor up: {}", remote_id);
                                    }
                                    iroh_gossip::api::Event::NeighborDown(remote_id) => {
                                        println!("Neighbor down: {}", remote_id);
                                    }
                                    _ => {}
                                }
                            }
                            None => break,
                            _ => {}
                        }
                    },
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                }
            }

            println!("ended receiving messages");
        });

        println!("You can now type messages to send to the gossip topic. Press Ctrl-C to exit.");
        let stdin = tokio::io::stdin();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut line = String::new();
        loop {
            use tokio::io::AsyncBufReadExt;

            line.clear();
            tokio::select! {
                _ = reader.read_line(&mut line) => {
                    let msg = line.trim().as_bytes().to_vec();
                    if msg.is_empty() {
                        continue;
                    }
                    sender.broadcast(msg.into()).await.unwrap();
                }
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        }

        gossip.shutdown().await.map_err(|e| e.to_string())?;
        router.shutdown().await.map_err(|e| e.to_string())?;
        println!("Shutting down...");
        std::process::exit(0);
    }
    #[cfg(not(feature = "gossip-example"))]
    Err("gossip-example feature not enabled".to_string())
}
