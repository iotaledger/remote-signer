use tonic::{transport::Server, Request, Response, Status};

use dispatcher::signature_dispatcher_server::{SignatureDispatcher, SignatureDispatcherServer};
use dispatcher::{SignMilestoneRequest, SignMilestoneResponse};

use remote_signer::common::config;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

#[derive(Debug, Default)]
pub struct Dispatcher {
    signers: Vec<config::KeySigner>
}

#[tonic::async_trait]
impl SignatureDispatcher for Dispatcher {
    async fn sign_milestone(
        &self,
        request: Request<SignMilestoneRequest>,
    ) -> Result<Response<SignMilestoneResponse>, Status> {
        println!("Got a request: {:?}", request);
        println!("Signers: {:?}", self.signers);

        let reply = dispatcher::SignMilestoneResponse {
            signatures: vec![String::from("ciao"), String::from("culo")]
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::parse("dispatcher_config.json");
    let addr = "[::1]:50051".parse()?;
    let dispatcher = Dispatcher { signers: config.signers };

    println!("Serving on {}...", addr);

    Server::builder()
        .add_service(SignatureDispatcherServer::new(dispatcher))
        .serve(addr)
        .await?;

    Ok(())
}