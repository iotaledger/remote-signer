use config;
use serde::Deserialize;
use base64;
use std::convert::{TryFrom, TryInto};
use ed25519_zebra::{VerificationKey, VerificationKeyBytes, SigningKey};

#[derive(Deserialize, Clone, Debug)]
pub struct DispatcherConfig {
    pub signers: Vec<KeySigner>
}

#[derive(Deserialize, Clone, Debug)]
pub struct SignerConfig {
    pub keys: Vec<PubPriv>
}

#[derive(Deserialize, Clone, Debug)]
pub struct KeySigner {
    pub pubkey: B64Key,
    pub signer: String
}

#[derive(Deserialize, Clone, Debug)]
pub struct PubPriv {
    pub pubkey: B64Key,
    pub privkey: B64Key
}

#[derive(Deserialize, Clone, Debug)]
pub struct B64Key(String);

impl TryInto<Vec<u8>> for B64Key {
    type Error = base64::DecodeError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        base64::decode(self.0)
    }
}

fn validate_ed25519_pubkey(pubkey: &B64Key) -> bool {
    let pubkey_bytes: Vec<u8> = match pubkey.to_owned().try_into() {
        Ok(bytes) => bytes,
        _ => return false
    };
    match VerificationKey::try_from(pubkey_bytes.as_slice()) {
        Ok(_) => true,
        _ => false
    }
}

fn validate_ed25519_pubkeys(pubkeys: Vec<&B64Key>) -> bool {
    pubkeys.iter().fold(true,
        |acc, pubkey| acc && validate_ed25519_pubkey(pubkey)
    )
}

fn validate_ed25519_privkey(keypair: &PubPriv) -> bool {
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
                if pubkey_provided_bytes == pubkey_computed.as_ref() {
                    true
                } else {
                    false
                }
            },
            _ => false
        }
}

fn validate_ed25519_privkeys(keypairs: &Vec<PubPriv>) -> bool {
    keypairs.iter().fold(true,
        |acc, keypair| acc && validate_ed25519_privkey(keypair)
    )
}

pub fn parse_dispatcher(path: &str) -> Result<DispatcherConfig, Box<dyn std::error::Error>> {
    let conf_file = config::File::new(path, config::FileFormat::Json);
    let mut conf = config::Config::default();
    conf.merge(conf_file)?;
    let conf = conf.try_into::<DispatcherConfig>()?;
    let pubkeys = conf.signers.iter().map(|signer| &signer.pubkey ).collect();
    if !validate_ed25519_pubkeys(pubkeys) {
        return Err(Box::new(config::ConfigError::Message(String::from("At least one of the configured Ed25519 public keys is invalid."))));
    }
    println!("Parsed Config:\n{:?}\n", conf);
    Ok(conf)
}

pub fn parse_signer(path: &str) -> Result<SignerConfig, Box<dyn std::error::Error>> {
    let conf_file = config::File::new(path, config::FileFormat::Json);
    let mut conf = config::Config::default();
    conf.merge(conf_file)?;
    let conf = conf.try_into::<SignerConfig>()?;
    let pubkeys = conf.keys.iter().map(|signer| &signer.pubkey ).collect();
    if !validate_ed25519_pubkeys(pubkeys) {
        return Err(Box::new(config::ConfigError::Message(String::from("At least one of the configured Ed25519 public keys is invalid."))));
    }
    if !validate_ed25519_privkeys(&conf.keys) {
        return Err(Box::new(config::ConfigError::Message(String::from("At least one of the configured Ed25519 private keys is invalid or does not match the corresponding public key."))));
    }
    println!("Parsed Config:\n{:?}\n", conf);
    Ok(conf)
}
