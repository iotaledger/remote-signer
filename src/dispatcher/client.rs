use dispatcher::signature_dispatcher_client::SignatureDispatcherClient;
use dispatcher::SignMilestoneRequest;

pub mod dispatcher {
    tonic::include_proto!("dispatcher");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SignatureDispatcherClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(SignMilestoneRequest {
        pub_keys: vec![
            String::from("pubkey1"),
            String::from("another pubkey")
        ],
        ms_essence: "Sign this!".as_bytes().to_vec()
    });
    
    let response = client.sign_milestone(request).await?;
    
    println!("RESPONSE={:?}", response);

    Ok(())
}
