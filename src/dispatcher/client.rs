use dispatcher::signature_dispatcher_client::SignatureDispatcherClient;
use dispatcher::SignMilestoneRequest;

use hex::FromHex;

pub mod dispatcher {
    tonic::include_proto!("dispatcherv3");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignatureDispatcherClient::connect("http://localhost:50051").await?;

    let request = tonic::Request::new(SignMilestoneRequest {
        pub_keys: vec![
            Vec::from_hex("YOURPUBLICKEYHERE").unwrap(),
        ],
        ms_essence: "Sign this!".as_bytes().to_vec()
    });

    let response = client.sign_milestone(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
