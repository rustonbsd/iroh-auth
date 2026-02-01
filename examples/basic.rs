use iroh::{Endpoint, protocol::Router};
use iroh_auth::Authenticator;

#[derive(Debug)]
struct MyProtocolHandler;

impl iroh::protocol::ProtocolHandler for MyProtocolHandler {
    async fn accept(
        &self,
        _connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        // Handle the protocol-specific logic here
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    // 1. Create the authenticator with a shared secret
    let auth = Authenticator::new("my-super-secret-password");

    // 2. Build the endpoint with the auth hooks
    let endpoint = Endpoint::builder()
        .hooks(auth.clone())
        .bind()
        .await.map_err(|e| e.to_string())?;

    // 3. The authenticator needs a reference to the bound endpoint 
    // to initiate authentication handshakes.
    auth.set_endpoint(&endpoint);

    // 4. Register the auth protocol handler
    let router = Router::builder(endpoint)
        .accept(iroh_auth::ALPN, auth.clone())

        // Register your actual application protocols here
        .accept(b"/my-app/1.0", MyProtocolHandler)
        .spawn();
    
    // ... run your application
    router.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}