use tonic::{transport::Server, Request, Response, Status};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use dispatcher::signature_dispatcher_server::{SignatureDispatcher, SignatureDispatcherServer};
use dispatcher::{SignMilestoneRequest, SignMilestoneResponse};

use signer::signer_client::SignerClient;
use signer::SignWithKeyRequest;

use remote_signer::common::config;

use clap::{App, Arg};
use futures::future;
use itertools::Itertools;
use std::error::Error;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug)]
pub struct Ed25519SignatureDispatcher {
    config: config::DispatcherConfig,
    tls_auth: ClientTlsConfig,
    keysigners: Vec<config::BytesKeySigner>
}

impl Ed25519SignatureDispatcher {
    async fn connect_signer_tls(&self, endpoint: String) -> Result<Channel, Box<dyn Error>>
    {
        Ok(
            Channel::from_shared(endpoint)?
                .tls_config(self.tls_auth.clone())?
                .connect()
                .await?
        )
    }
}

#[tonic::async_trait]
impl SignatureDispatcher for Ed25519SignatureDispatcher {
    async fn sign_milestone(
        &self,
        request: Request<SignMilestoneRequest>,
    ) -> Result<Response<SignMilestoneResponse>, Status> {

        let r = request.get_ref();
        // Check that the pubkeys do not repeat
        let pub_keys_unique = r.pub_keys.iter().unique();
        // We do not need to check for the lexicographical sorting of the keys, it is not our job

        let matched_signers = pub_keys_unique.map(|pubkey| {
            self.keysigners.iter().find(
                |keysigner| keysigner.pubkey == pubkey.to_owned()
            )
        });

        // Clone the iterator to avoid consuming it for the next map
        if matched_signers.clone().any(|signer| signer.is_none()) {
            return Err(Status::invalid_argument("I don't know the signer for one or more of the provided public keys."))
        }

        let confirmed_signers = matched_signers.map(|signer| signer.unwrap());

        let signatures = future::join_all(
            // map of Futures<Output=Result<SignWithKeyResponse, Error>>
            confirmed_signers.map(|signer|
                async move {
                    let channel = match self.connect_signer_tls(signer.endpoint.clone()).await {
                        Ok(channel) => channel,
                        Err(e) => return Err(Status::internal(format!("Could not connect to the signer `{}`, {}", signer.endpoint, e)))
                    };

                    let mut client = SignerClient::new(channel);

                    let request = tonic::Request::new(SignWithKeyRequest {
                        pub_key: signer.pubkey.to_owned(),
                        ms_essence: r.ms_essence.to_owned()
                    });

                    client.sign_with_key(request).await
                }
            )
        );

        let signatures = signatures.await;
        if let Some(e) = signatures.iter().find(|signature| signature.is_err()) {
            return Err(e.as_ref().unwrap_err().to_owned());
        }

        let reply = SignMilestoneResponse {
            signatures: signatures.iter().map(|signature| signature.as_ref().unwrap().get_ref().to_owned().signature).collect()
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_arg = App::new("Remote Signer Dispatcher")
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .takes_value(true)
             .value_name("FILE")
             .default_value("dispatcher_config.json")
             .help("Dispatcher .json configuration file")
        ).get_matches();

    let (config, keysigners) = config::parse_dispatcher(config_arg.value_of("config").unwrap())?;
    let addr = config.bind_addr.parse()?;
    let server_root_ca_cert = tokio::fs::read(&config.tlsauth.ca).await?;
    let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);
    let client_cert = tokio::fs::read(&config.tlsauth.client_cert).await?;
    let client_key = tokio::fs::read(&config.tlsauth.client_key).await?;
    let client_identity = Identity::from_pem(client_cert, client_key);
    let tls_auth = ClientTlsConfig::new()
        .ca_certificate(server_root_ca_cert)
        .identity(client_identity);
    let dispatcher = Ed25519SignatureDispatcher { config, tls_auth, keysigners };

    println!("Serving on {}...", addr);

    Server::builder()
        .add_service(SignatureDispatcherServer::new(dispatcher))
        .serve(addr)
        .await?;

    Ok(())
}