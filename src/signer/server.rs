use std::convert::TryFrom;

use tonic::{Request, Response, Status};
use tonic::transport::{Server, ServerTlsConfig, Certificate, Identity};

use signer::signer_server::{Signer, SignerServer};
use signer::{SignWithKeyRequest, SignWithKeyResponse};

use remote_signer::common::config;

use clap::{App, Arg};

use simple_logger::SimpleLogger;
#[macro_use] extern crate log;

use ed25519_zebra::SigningKey;

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug)]
pub struct Ed25519Signer {
    config: config::SignerConfig,
    keypairs: Vec<config::BytesPubPriv>
}

#[tonic::async_trait]
impl Signer for Ed25519Signer {
    async fn sign_with_key(
        &self,
        request: Request<SignWithKeyRequest>,
    ) -> Result<Response<SignWithKeyResponse>, Status> {

        debug!("Got Request: {:?}", request);

        let r = request.get_ref();
        let matched_key = match self.keypairs.iter().find(
            |pair| pair.pubkey == r.pub_key
        ) {
            Some(key) => key,
            None => {
                warn!("Requested public key is not known!");
                warn!("Request: {:?}", request);
                warn!("Available Pubkeys: {:?}", self.keypairs.iter().map(|pair| pair.pubkey.clone()).collect::<Vec<Vec<u8>>>());
                return Err(Status::invalid_argument("This signer does not sign with the provided key."))
            }
        };

        let sk = SigningKey::try_from(matched_key.privkey.as_ref()).unwrap();
        let signature = sk.sign(r.ms_essence.as_ref());

        let reply = SignWithKeyResponse {
            signature: <[u8; 64]>::from(signature).to_vec()
        };

        info!("Successfully signed.");
        info!("MS Essence: {:?}", r.ms_essence);
        info!("Used Key: {:?}", matched_key.pubkey);

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    SimpleLogger::from_env().init().unwrap();
    let config_arg = App::new("Remote Signer")
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .takes_value(true)
             .value_name("FILE")
             .default_value("signer_config.json")
             .help("Dispatcher .json configuration file")
        ).get_matches();

    let conf_path = config_arg.value_of("config").unwrap();
    info!("Parsing configuration file `{}`.", conf_path);
    let (config, keypairs) = config::parse_signer(conf_path)?;
    debug!("Parsed configuration file: {:?}", config);
    let addr = config.bind_addr.parse()?;
    let server_cert = tokio::fs::read(&config.tls.cert).await?;
    let server_key = tokio::fs::read(&config.tls.key).await?;
    let server_identity = Identity::from_pem(server_cert, server_key);
    let client_ca_cert = tokio::fs::read(&config.tls.ca).await?;
    let client_ca_cert = Certificate::from_pem(client_ca_cert);
    let tls = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);

    let signer = Ed25519Signer { config, keypairs };
    debug!("Initialized Signer server: {:?}", signer);

    info!("Serving on {}...", addr);

    Server::builder()
        .tls_config(tls)?
        .add_service(SignerServer::new(signer))
        .serve(addr)
        .await?;

    Ok(())
}