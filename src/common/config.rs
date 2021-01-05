use serde::Deserialize;
use hex::FromHex;
use std::convert::{TryFrom, TryInto};
use ed25519_zebra::{VerificationKey, VerificationKeyBytes, SigningKey};

#[derive(Deserialize, Clone, Debug)]
pub struct DispatcherConfig {
    pub bind_addr: String,
    pub signers: Vec<HexKeySigner>,
    pub tlsauth: ClientTlsAuth,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ClientTlsAuth {
    pub ca: String,
    pub client_cert: String,
    pub client_key: String
}

#[derive(Deserialize, Clone, Debug)]
pub struct SignerConfig {
    pub bind_addr: String,
    pub keys: Vec<HexPubPriv>,
    pub tls: ServerTlsAuth
}

#[derive(Deserialize, Clone, Debug)]
pub struct ServerTlsAuth {
    pub ca: String,
    pub cert: String,
    pub key: String
}

#[derive(Deserialize, Clone, Debug)]
pub struct HexKeySigner {
    pub pubkey: HexEd25519Key,
    pub endpoint: String
}

#[derive(Deserialize, Clone, Debug)]
pub struct HexPubPriv {
    pub pubkey: HexEd25519Key,
    pub privkey: HexEd25519Key
}

#[derive(Deserialize, Clone, Debug)]
pub struct HexEd25519Key(String);

impl TryInto<Vec<u8>> for HexEd25519Key {
    type Error = hex::FromHexError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        Vec::from_hex(self.0)
    }
}
#[derive(Debug, Clone)]
pub struct BytesKeySigner {
    pub pubkey: Vec<u8>,
    pub endpoint: String
}

#[derive(Debug)]
pub struct BytesPubPriv {
    pub pubkey: Vec<u8>,
    pub privkey: Vec<u8>
}

fn validate_ed25519_pubkey(pubkey: &HexEd25519Key) -> bool {
    let pubkey_bytes: Vec<u8> = match pubkey.to_owned().try_into() {
        Ok(bytes) => bytes,
        _ => return false
    };
    match VerificationKey::try_from(pubkey_bytes.as_slice()) {
        Ok(_) => true,
        _ => false
    }
}

fn validate_ed25519_pubkeys(pubkeys: Vec<&HexEd25519Key>) -> bool {
    pubkeys.iter().all(|pubkey| validate_ed25519_pubkey(pubkey))
}

fn validate_ed25519_privkey(keypair: &HexPubPriv) -> bool {
        let privkey_provided_bytes: Vec<u8> = match keypair.privkey.to_owned().try_into() {
            Ok(bytes) => bytes,
            _ => return false
        };
        match SigningKey::try_from(privkey_provided_bytes.as_slice()) {
            Ok(privkey_provided) => {
                let pubkey_provided_bytes: Vec<u8> = match keypair.pubkey.to_owned().try_into() {
                    Ok(bytes) => bytes,
                    _ => return false
                };
                let pubkey_computed = VerificationKeyBytes::from(&privkey_provided);
                pubkey_provided_bytes == pubkey_computed.as_ref()
            },
            _ => false
        }
}

fn validate_ed25519_privkeys(keypairs: &Vec<HexPubPriv>) -> bool {
    keypairs.iter().all(|keypair| validate_ed25519_privkey(keypair))
}

pub fn parse_dispatcher(path: &str) -> Result<(DispatcherConfig, Vec<BytesKeySigner>), Box<dyn std::error::Error>> {
    let conf_file = config::File::new(path, config::FileFormat::Json);
    let mut conf = config::Config::default();
    conf.merge(conf_file)?;
    let conf = conf.try_into::<DispatcherConfig>()?;
    let pubkeys = conf.signers.iter().map(|signer| &signer.pubkey ).collect();
    if !validate_ed25519_pubkeys(pubkeys) {
        return Err(Box::new(config::ConfigError::Message(String::from("At least one of the configured HexEd25519 public keys is invalid."))));
    }
    let keysigners: Vec<BytesKeySigner> = conf.signers.iter().map(|signer|
        BytesKeySigner {
            pubkey: signer.pubkey.to_owned().try_into().unwrap(),
            endpoint: signer.endpoint.to_owned()
        }
    ).collect();
    Ok((conf, keysigners))
}

pub fn parse_signer(path: &str) -> Result<(SignerConfig, Vec<BytesPubPriv>), Box<dyn std::error::Error>> {
    let conf_file = config::File::new(path, config::FileFormat::Json);
    let mut conf = config::Config::default();
    conf.merge(conf_file)?;
    let conf = conf.try_into::<SignerConfig>()?;
    let pubkeys = conf.keys.iter().map(|keypair| &keypair.pubkey ).collect();
    if !validate_ed25519_pubkeys(pubkeys) {
        return Err(Box::new(config::ConfigError::Message(String::from("At least one of the configured HexEd25519 public keys is invalid."))));
    }
    if !validate_ed25519_privkeys(&conf.keys) {
        return Err(Box::new(config::ConfigError::Message(String::from("At least one of the configured HexEd25519 private keys is invalid or does not match the corresponding public key."))));
    }
    let keypairs: Vec<BytesPubPriv> = conf.keys.iter().map(|keypair|
        BytesPubPriv {
            pubkey: keypair.pubkey.to_owned().try_into().unwrap(),
            privkey: keypair.privkey.to_owned().try_into().unwrap()
        }
    ).collect();
    Ok((conf, keypairs))
}
