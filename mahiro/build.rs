use prost_build::Config;

fn main() {
    Config::new()
        .bytes(["."])
        .compile_protos(&["../proto/protocol.proto"], &["../proto"])
        .unwrap();
}
