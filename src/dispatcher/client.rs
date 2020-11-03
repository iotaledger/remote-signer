use dispatcher::signature_dispatcher_client::SignatureDispatcherClient;
use dispatcher::SignMilestoneRequest;

use hex::FromHex;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignatureDispatcherClient::connect("http://dispatcher.remote-signer:50051").await?;

    let request = tonic::Request::new(SignMilestoneRequest {
        pub_keys: vec![
            Vec::from_hex("d578d0a8e5392040cf5c3ba0153c28c300d8eaed3d8d7ef43729cadfe1e2467b").unwrap()
        ],
        ms_essence: "Sign this!".as_bytes().to_vec()
    });
    
    let response = client.sign_milestone(request).await?;
    
    println!("RESPONSE={:?}", response);

    Ok(())
}
