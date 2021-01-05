use dispatcher::signature_dispatcher_client::SignatureDispatcherClient;
use dispatcher::SignMilestoneRequest;

use hex::FromHex;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignatureDispatcherClient::connect("http://localhost:50051").await?;

    let request = tonic::Request::new(SignMilestoneRequest {
        pub_keys: vec![
            Vec::from_hex("3a0f0d32ed6e427c581da7ac52d22e727bee48c4af74a1850a57a2047c1e387e").unwrap()
        ],
        ms_essence: "Sign this!".as_bytes().to_vec()
    });
    
    let response = client.sign_milestone(request).await?;
    
    println!("RESPONSE={:?}", response);

    Ok(())
}
