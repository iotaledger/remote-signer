use std::convert::TryFrom;

use tonic::{Request, Response, Status};
use tonic::transport::Server;

use signer::signer_server::{Signer, SignerServer};
use signer::{SignWithKeyRequest, SignWithKeyResponse};

use remote_signer::common::config;

use clap::{App, Arg};

use simple_logger::SimpleLogger;
#[macro_use] extern crate log;

use ed25519_zebra::SigningKey;
use async_std::sync::{Arc, Mutex};
use tokio::signal::unix::{SignalKind, signal};
use remote_signer::common::config::{SignerConfig, BytesPubPriv};
use async_std::net::SocketAddr;
use log::LevelFilter;

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug)]
pub struct Ed25519Signer {
    keypairs: Arc<Mutex<Vec<config::BytesPubPriv>>>
}

#[tonic::async_trait]
impl Signer for Ed25519Signer {
    async fn sign_with_key(
        &self,
        request: Request<SignWithKeyRequest>,
    ) -> Result<Response<SignWithKeyResponse>, Status> {

        debug!("Got Request: {:?}", request);

        let r = request.get_ref();
        let keys_guard = self.keypairs.lock().await;
        let matched_key = match keys_guard.iter().find(
            |pair| pair.pubkey == r.pub_key
        ) {
            Some(key) => key,
            None => {
                warn!("Requested public key is not known!");
                warn!("Request: {:?}", request);
                warn!("Available Pubkeys: {:?}", keys_guard.iter().map(|pair| pair.pubkey.clone()).collect::<Vec<Vec<u8>>>());
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
    SimpleLogger::from_env().with_level(LevelFilter::Info).init().unwrap();
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

    let signer = Ed25519Signer {
        keypairs: Arc::new(Mutex::new(keypairs))
    };
    debug!("Initialized Signer server: {:?}", signer);

    info!("Serving on {}...", addr);
    let signal = reload_configs_upon_signal(conf_path, Arc::clone(&signer.keypairs));

    let serve = Server::builder()
        .add_service(SignerServer::new(signer))
        .serve(addr);

    info!("listening for sighup");

    (serve.await?, signal.await?);

    Ok(())
}

async fn reload_configs_upon_signal(conf_path : &str, key_pairs: Arc<Mutex<Vec<BytesPubPriv>>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = signal(SignalKind::hangup())?;

    // Print whenever a HUP signal is received
    loop {
        stream.recv().await;
        info!("got signal HUP");
        let (_, keysigners, _) = parse_confs(conf_path).await?;
        let mut signers = key_pairs.lock().await;
        signers.clear();
        for bk in keysigners {
            signers.push(bk)
        }
    }
}

async fn parse_confs(conf_path: &str) -> Result<(SignerConfig, Vec<BytesPubPriv>, SocketAddr), Box<dyn std::error::Error>> {
    info!("Parsing configuration file `{}`.", conf_path);
    let (config, keysigners) = config::parse_signer(conf_path)?;
    debug!("Parsed configuration file: {:?}", config);
    let addr = config.bind_addr.parse()?;
    Ok((config, keysigners, addr))
}