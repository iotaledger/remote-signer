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
            Vec::from_hex("839d0a84fc988ebadfb641e7b434ccb719cbaf584b6f60451ac3b4b362975ea9").unwrap()
        ],
        ms_essence: "Sign this!".as_bytes().to_vec()
    });
    
    let response = client.sign_milestone(request).await?;
    
    println!("RESPONSE={:?}", response);

    Ok(())
}
