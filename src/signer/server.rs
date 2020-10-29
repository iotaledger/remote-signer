use tonic::{transport::Server, Request, Response, Status};

use signer::signer_server::{Signer, SignerServer};
use signer::{SignWithKeyRequest, SignWithKeyResponse};

use remote_signer::common::config;

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug, Default)]
pub struct Ed25519Signer { }

#[tonic::async_trait]
impl Signer for Ed25519Signer {
    async fn sign_with_key(
        &self,
        request: Request<SignWithKeyRequest>,
    ) -> Result<Response<SignWithKeyResponse>, Status> {
        println!("Got a request: {:?}", request);

        let reply = SignWithKeyResponse {
            signature: String::from("ciao")
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::parse_signer("signer_config.json")?;
    let addr = "[::1]:50051".parse()?;
    let signer = Ed25519Signer::default();

    println!("Serving on {}...", addr);

    Server::builder()
        .add_service(SignerServer::new(signer))
        .serve(addr)
        .await?;

    Ok(())
}