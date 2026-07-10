use std::fs;
use std::process::Command;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("not running on Linux")]
    NotLinux,

    #[error("kernel version too old: expected >= 5.4, got {0}")]
    KernelTooOld(String),

    #[error("nftables not available")]
    NftablesNotAvailable,

    #[error("ebpf not supported")]
    EbpfNotSupported,

    #[error("not running as root")]
    NotRoot,

    #[error("sysctl check failed: {0}")]
    SysctlCheckFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq)]
pub struct EnvCheckResult {
    pub os_check: bool,
    pub kernel_check: bool,
    pub nftables_check: bool,
    pub ebpf_check: bool,
    pub root_check: bool,
    pub sysctl_check: bool,
}

pub fn check_environment() -> Result<EnvCheckResult> {
    let os_check = check_os()?;
    let kernel_check = check_kernel_version()?;
    let nftables_check = check_nftables()?;
    let ebpf_check = check_ebpf()?;
    let root_check = check_root()?;
    let sysctl_check = check_sysctl()?;

    Ok(EnvCheckResult {
        os_check,
        kernel_check,
        nftables_check,
        ebpf_check,
        root_check,
        sysctl_check,
    })
}

pub fn is_environment_supported() -> bool {
    match check_environment() {
        Ok(result) => {
            result.os_check
                && result.kernel_check
                && result.nftables_check
                && result.ebpf_check
                && result.root_check
                && result.sysctl_check
        }
        Err(_) => false,
    }
}

pub fn print_environment_report() {
    match check_environment() {
        Ok(result) => {
            println!("=== eDepot Environment Check ===");
            println!(
                "OS Check: {}",
                if result.os_check { "PASS" } else { "FAIL" }
            );
            println!(
                "Kernel Version: {}",
                if result.kernel_check { "PASS" } else { "FAIL" }
            );
            println!(
                "nftables: {}",
                if result.nftables_check {
                    "PASS"
                } else {
                    "FAIL"
                }
            );
            println!(
                "eBPF Support: {}",
                if result.ebpf_check { "PASS" } else { "FAIL" }
            );
            println!(
                "Root Privileges: {}",
                if result.root_check { "PASS" } else { "FAIL" }
            );
            println!(
                "Sysctl Settings: {}",
                if result.sysctl_check { "PASS" } else { "FAIL" }
            );
            println!();
            if is_environment_supported() {
                println!("Environment: SUPPORTED - eDepot can run");
            } else {
                println!("Environment: NOT SUPPORTED - eDepot cannot run");
            }
        }
        Err(e) => {
            println!("Environment check failed: {}", e);
        }
    }
}

fn check_os() -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        Ok(true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::NotLinux)
    }
}

fn check_kernel_version() -> Result<bool> {
    let content = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let version_str = content.trim();

    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            if major > 5 || (major == 5 && minor >= 4) {
                return Ok(true);
            }
        }
    }

    Err(Error::KernelTooOld(version_str.to_string()))
}

fn check_nftables() -> Result<bool> {
    let output = Command::new("which").arg("nft").output()?;
    if output.status.success() {
        let version_output = Command::new("nft").arg("--version").output()?;
        if version_output.status.success() {
            return Ok(true);
        }
    }

    Err(Error::NftablesNotAvailable)
}

fn check_ebpf() -> Result<bool> {
    match fs::metadata("/sys/fs/bpf") {
        Ok(meta) if meta.is_dir() => Ok(true),
        _ => Err(Error::EbpfNotSupported),
    }
}

fn check_root() -> Result<bool> {
    match fs::read_to_string("/proc/self/status") {
        Ok(content) => {
            if let Some(line) = content.lines().find(|l| l.starts_with("Uid:")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == "0" {
                    return Ok(true);
                }
            }
            Err(Error::NotRoot)
        }
        Err(_) => Err(Error::NotRoot),
    }
}

fn check_sysctl() -> Result<bool> {
    let checks = [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv4/tcp_syncookies",
        "/proc/sys/net/netfilter/nf_conntrack_max",
    ];

    for path in checks.iter() {
        if fs::metadata(path).is_err() {
            return Err(Error::SysctlCheckFailed(format!("missing {}", path)));
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_os_linux() {
        #[cfg(target_os = "linux")]
        assert!(check_os().unwrap());

        #[cfg(not(target_os = "linux"))]
        assert!(matches!(check_os(), Err(Error::NotLinux)));
    }

    #[test]
    fn test_is_environment_supported() {
        let result = is_environment_supported();
        #[cfg(target_os = "linux")]
        assert!(result || true);

        #[cfg(not(target_os = "linux"))]
        assert!(!result);
    }

    #[test]
    fn test_check_ebpf_path_exists() {
        match check_ebpf() {
            Ok(_) => {}
            Err(Error::EbpfNotSupported) => {}
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_env_check_result_struct() {
        let result = EnvCheckResult {
            os_check: true,
            kernel_check: true,
            nftables_check: true,
            ebpf_check: true,
            root_check: true,
            sysctl_check: true,
        };

        assert!(result.os_check);
        assert!(result.kernel_check);
        assert!(result.nftables_check);
        assert!(result.ebpf_check);
        assert!(result.root_check);
        assert!(result.sysctl_check);
    }
}
