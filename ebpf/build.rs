use std::env;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use aya_build::BpfBuilder;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    
    if target_os != "linux" {
        println!("cargo:warning=eBPF build skipped on non-Linux target");
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let stub_path = out_dir.join("edepot-ebpf.stub");
        std::fs::write(&stub_path, []).unwrap();
        return;
    }

    #[cfg(target_os = "linux")]
    {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        BpfBuilder::new()
            .debug(false)
            .build("src/main.rs", &out_dir)
            .unwrap();
    }
}
