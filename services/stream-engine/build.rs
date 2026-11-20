fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../packages/proto";
    let proto_file = "../../packages/proto/sanitizedb/v1/stream_engine.proto";
    println!("cargo:rerun-if-changed={proto_file}");

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&[proto_file], &[proto_root])?;
    Ok(())
}
