use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::event::NetworkEvent;
use crate::error::Result;

use super::event_source::EventSource;
use super::EbpfEventSource;
use super::ProcNetEventSource;

pub struct HybridEventSource {
    ebpf_source: EbpfEventSource,
    proc_net_source: ProcNetEventSource,
}

impl HybridEventSource {
    pub async fn new(interface: Option<&str>, poll_interval_ms: u64) -> Result<Self> {
        let ebpf_source = EbpfEventSource::new(interface).await?;
        let proc_net_source = ProcNetEventSource::new(poll_interval_ms);

        Ok(Self {
            ebpf_source,
            proc_net_source,
        })
    }
}

#[async_trait::async_trait]
impl EventSource for HybridEventSource {
    async fn start(&self, tx: mpsc::Sender<NetworkEvent>) -> Result<()> {
        info!("Starting hybrid event source (eBPF + /proc/net)");
        debug!("eBPF source: {}, /proc/net source: {}", self.ebpf_source.name(), self.proc_net_source.name());

        self.ebpf_source.start(tx.clone()).await?;

        tokio::spawn(async move {
            if let Err(e) = self.proc_net_source.start(tx).await {
                error!("Error in /proc/net event source: {}", e);
            }
        });

        Ok(())
    }

    fn name(&self) -> &str {
        "hybrid"
    }
}