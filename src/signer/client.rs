use signer::signer_client::SignerClient;
use signer::SignWithKeyRequest;

pub mod signer {
    tonic::include_proto!("signer");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignerClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(SignWithKeyRequest {
        pubKey: String::from("pubkey1"),
        ms_essence: "cazzo!".as_bytes()
    });
    
    let response = client.sign_with_key(request).await?;
    
    println!("RESPONSE={:?}", response);

    Ok(())
}