use std::mem;

use aya::maps::perf::AsyncPerfEventArray;
use aya::Bpf;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::event::NetworkEvent;
use crate::error::Result;

use super::NetworkEventRaw;

pub struct EbpfEventSource {
    bpf: Option<Bpf>,
    interface: Option<String>,
}

impl EbpfEventSource {
    pub async fn new(interface: Option<&str>) -> Result<Self> {
        debug!("Loading eBPF bytes from BPF_OBJECT");
        let bpf_bytes = include_bytes!(env!("BPF_OBJECT"));
        debug!("eBPF bytes size: {} bytes", bpf_bytes.len());

        let bpf = if bpf_bytes.is_empty() {
            debug!("eBPF bytes are empty, running without eBPF");
            None
        } else {
            debug!("Loading eBPF program from bytes");
            let loaded_bpf = aya::Bpf::load(bpf_bytes)?;
            debug!("eBPF program loaded successfully");

            if let Some(interface) = interface {
                Self::attach_xdp(&loaded_bpf, interface)?;
            }

            Self::attach_tracepoint(&loaded_bpf)?;

            Some(loaded_bpf)
        };

        info!("eBPF event source created");
        Ok(Self {
            bpf,
            interface: interface.map(|s| s.to_string()),
        })
    }

    fn attach_xdp(bpf: &Bpf, interface: &str) -> Result<()> {
        debug!("Loading XDP program on interface: {}", interface);
        let xdp = bpf
            .program_mut("xdp_syn_filter")
            .ok_or(super::error::Error::ProgramNotFound("xdp_syn_filter"))?;
        debug!("Found XDP program, loading...");
        xdp.load()?;
        debug!("XDP program loaded, attaching to interface...");
        xdp.attach(interface, aya::programs::XdpFlags::default())?;
        info!("Attached XDP program to interface: {}", interface);
        debug!("XDP program attached successfully to {}", interface);
        Ok(())
    }

    fn attach_tracepoint(bpf: &Bpf) -> Result<()> {
        debug!("Loading tracepoint program: inet_sock_set_state");
        let tracepoint = bpf
            .program_mut("inet_sock_set_state")
            .ok_or(super::error::Error::ProgramNotFound("inet_sock_set_state"))?;
        debug!("Found tracepoint program, loading...");
        tracepoint.load()?;
        debug!("Tracepoint program loaded, attaching...");
        tracepoint.attach()?;
        info!("Loaded tracepoint: inet_sock_set_state");
        debug!("Tracepoint attached successfully");
        Ok(())
    }
}

#[async_trait::async_trait]
impl super::event_source::EventSource for EbpfEventSource {
    async fn start(&self, tx: mpsc::Sender<NetworkEvent>) -> Result<()> {
        if let Some(bpf) = &self.bpf {
            debug!("Setting up eBPF event loop");
            let events_map = bpf.map("EVENTS").ok_or(super::error::Error::MapNotFound("EVENTS"))?;
            debug!("Found EVENTS map, creating AsyncPerfEventArray");

            let mut events = AsyncPerfEventArray::try_from(events_map)?;
            debug!("AsyncPerfEventArray created");

            let tx_clone = tx.clone();
            let cpu_count = aya::util::online_cpus().unwrap().len();
            debug!("Spawning event readers for {} CPUs", cpu_count);

            for cpu in 0..cpu_count {
                let mut buf = events.open(cpu, None, None)?;
                let tx = tx_clone.clone();

                tokio::task::spawn(async move {
                    debug!("Event reader for CPU {} started", cpu);
                    let mut buffers = vec![0u8; 4096];

                    loop {
                        let events = buf.read_events(&mut buffers).await;
                        match events {
                            Ok(read) => {
                                debug!("CPU {}: read {} events", cpu, read.read);
                                for i in 0..read.read {
                                    let offset = i * mem::size_of::<NetworkEventRaw>();
                                    if offset + mem::size_of::<NetworkEventRaw>() <= read.read {
                                        let raw: &NetworkEventRaw = unsafe {
                                            &*(buffers.as_ptr().add(offset)
                                                as *const NetworkEventRaw)
                                        };
                                        let event = raw.to_network_event();
                                        debug!(
                                            "CPU {}: event from {} port {} protocol {}",
                                            cpu, event.src_ip, event.dst_port, event.protocol
                                        );
                                        if tx.send(event).await.is_err() {
                                            debug!("Event channel closed, exiting event loop for CPU {}", cpu);
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Perf event read error on CPU {}: {}", cpu, e);
                                break;
                            }
                        }
                    }
                    debug!("Event reader for CPU {} exited", cpu);
                });
            }

            info!("eBPF event loop started");
            debug!("eBPF event loop fully initialized");
        } else {
            info!("eBPF not available, event source running in stub mode");
            debug!("No eBPF object, event source in stub mode");
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "ebpf"
    }
}