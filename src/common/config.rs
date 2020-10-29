use config;
use serde::Deserialize;
use std::convert::TryFrom;
use ed25519_zebra::VerificationKey;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub signers: Vec<KeySigner>
}
#[derive(Deserialize, Clone, Debug)]
pub struct KeySigner {
    pub pubkey: String,
    pub signer: String
}

fn validate_ed25519_pubkey(pubkey: &String) -> bool {
    let pubkey_bytes = pubkey.as_bytes();
    match VerificationKey::try_from(pubkey_bytes) {
        Ok(_) => true,
        _ => false
    }
}

fn validate_ed25519_pubkeys(pubkeys: Vec<&String>) -> bool {
    pubkeys.iter().fold(true,
        |acc, pubkey| acc && validate_ed25519_pubkey(pubkey)
    )
}

pub fn parse(path: &str) -> Result<Config, String> {
    let conf_file = config::File::new(path, config::FileFormat::Json);
    let mut conf = config::Config::default();
    conf.merge(conf_file).expect(&format!("Cannot read config file '{}':", path));
    let conf = conf.try_into::<Config>().expect("Config file not well formatted:");
    let pubkeys: Vec<&String> = conf.signers.iter().map(|signer| &signer.pubkey ).collect();
    if !validate_ed25519_pubkeys(pubkeys) {
        panic!("At least one of the configured Ed25519 public keys is invalid.");
    }
    println!("Parsed Config:\n{:?}\n", conf);
    Ok(conf)
//    Err(String::from("Cazzo!"))
}
