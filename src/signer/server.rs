use std::convert::TryFrom;

use tonic::transport::Server;
use tonic::{Request, Response, Status};

use signer::signer_server::{Signer, SignerServer};
use signer::{SignWithKeyRequest, SignWithKeyResponse};

use futures::future;
use remote_signer::common::config;

use clap::{App, Arg};

use simple_logger::SimpleLogger;
#[macro_use]
extern crate log;

use async_std::net::SocketAddr;
use async_std::sync::{Arc, Mutex};
use ed25519_zebra::SigningKey;
use futures::TryFutureExt;
use remote_signer::common::config::{BytesPubPriv, SignerConfig};
use remote_signer::RemoteSignerError;
use tokio::signal::unix::{signal, SignalKind};

pub mod signer {
    tonic::include_proto!("signer");
}

#[derive(Debug)]
pub struct Ed25519Signer {
    keypairs: Arc<Mutex<Vec<config::BytesPubPriv>>>,
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
        let matched_key = match keys_guard.iter().find(|pair| pair.pubkey == r.pub_key) {
            Some(key) => key,
            None => {
                warn!("Requested public key is not known!");
                warn!("Request: {:?}", request);
                warn!(
                    "Available Pubkeys: {:?}",
                    keys_guard
                        .iter()
                        .map(|pair| pair.pubkey.clone())
                        .collect::<Vec<Vec<u8>>>()
                );
                return Err(Status::invalid_argument(
                    "This signer does not sign with the provided key.",
                ));
            }
        };

        let sk = SigningKey::try_from(matched_key.privkey.as_ref()).unwrap();
        let signature = sk.sign(r.ms_essence.as_ref());

        let reply = SignWithKeyResponse {
            signature: <[u8; 64]>::from(signature).to_vec(),
        };

        info!("Successfully signed.");
        info!("MS Essence: {:?}", r.ms_essence);
        info!("Used Key: {:?}", matched_key.pubkey);

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> remote_signer::Result<()> {
    SimpleLogger::from_env().init().unwrap();
    let config_arg = App::new("Remote Signer")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .takes_value(true)
                .value_name("FILE")
                .default_value("signer_config.json")
                .help("Signer .json configuration file"),
        )
        .get_matches();

    let conf_path = config_arg.value_of("config").unwrap();
    info!("Parsing configuration file `{}`.", conf_path);
    let (config, keypairs) = config::parse_signer(conf_path)?;
    debug!("Parsed configuration file: {:?}", config);
    let addr = config.bind_addr.parse()?;

    let signer = Ed25519Signer {
        keypairs: Arc::new(Mutex::new(keypairs)),
    };
    debug!("Initialized Signer server: {:?}", signer);

    let signal = reload_configs_upon_signal(conf_path, Arc::clone(&signer.keypairs));

    let serv = Server::builder()
        .add_service(SignerServer::new(signer))
        .serve(addr)
        .map_err(|error| RemoteSignerError::from(error));

    info!("Serving on {}...", addr);

    let result = future::try_join(signal, serv).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

async fn reload_configs_upon_signal(
    conf_path: &str,
    key_pairs: Arc<Mutex<Vec<BytesPubPriv>>>,
) -> remote_signer::Result<()> {
    info!("listening for sighup");
    let mut stream = signal(SignalKind::hangup()).expect("Problems receiving signal");

    // Print whenever a HUP signal is received
    loop {
        stream.recv().await;
        let conf = parse_confs(conf_path);
        if conf.is_err() {
            error!("Can't parse configs. {:?}", conf.err().unwrap());
            continue;
        }
        let (_, keysigners, _) = conf.unwrap();
        let mut signers = key_pairs.lock().await;
        signers.clear();
        signers.extend_from_slice(&keysigners);
    }
}

fn parse_confs(
    conf_path: &str,
) -> remote_signer::Result<(SignerConfig, Vec<BytesPubPriv>, SocketAddr)> {
    info!("Parsing configuration file `{}`.", conf_path);
    let (config, keysigners) = config::parse_signer(conf_path)?;
    debug!("Parsed configuration file: {:?}", config);
    let addr = config
        .bind_addr
        .parse()
        .map_err(|err| RemoteSignerError::from(err))?;
    Ok((config, keysigners, addr))
}
