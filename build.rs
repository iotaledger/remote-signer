fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/dispatcher/dispatcher.proto")?;
    tonic_build::compile_protos("proto/signer/signer.proto")?;
    Ok(())
}
