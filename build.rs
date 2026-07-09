use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest_dir.join("ebpf");

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("build.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let has_ebpf_feature = env::var("CARGO_FEATURE_EBPF").is_ok();

    let bpf_path = if target_os == "linux" && has_ebpf_feature {
        build_ebpf_linux(&ebpf_dir, &out_dir)
    } else {
        build_stub(&out_dir)
    };

    println!("cargo:rustc-env=BPF_OBJECT={}", bpf_path.display());
}

fn build_stub(out_dir: &PathBuf) -> PathBuf {
    let stub_path = out_dir.join("edepot-ebpf.stub");
    std::fs::write(&stub_path, []).unwrap();
    stub_path
}

fn build_ebpf_linux(ebpf_dir: &PathBuf, out_dir: &PathBuf) -> PathBuf {
    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg("bpfel-unknown-none")
        .current_dir(ebpf_dir)
        .env("CARGO_MANIFEST_DIR", ebpf_dir)
        .status()
        .expect("Failed to build eBPF program");

    if !status.success() {
        panic!("eBPF build failed");
    }

    let bpf_file = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("edepot-ebpf");

    if !bpf_file.exists() {
        panic!("eBPF object not found at {:?}", bpf_file);
    }

    let output_path = out_dir.join("edepot-ebpf.o");
    std::fs::copy(&bpf_file, &output_path).expect("Failed to copy eBPF object");

    output_path
}
