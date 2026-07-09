use aya_build::BpfBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    BpfBuilder::new()
        .debug(false)
        .build("src/main.rs", &out_dir)
        .unwrap();
}
