use tokio::sync::mpsc;
use tracing::info;

use crate::event::NetworkEvent;
use crate::error::Result;

#[async_trait::async_trait]
pub trait EventSource: Send + Sync + 'static {
    async fn start(&self, tx: mpsc::Sender<NetworkEvent>) -> Result<()>;
    fn name(&self) -> &str;
}

#[derive(Debug, PartialEq)]
pub enum EventSourceType {
    Ebpf,
    ProcNet,
    Hybrid,
}

impl std::str::FromStr for EventSourceType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ebpf" => Ok(Self::Ebpf),
            "procnet" => Ok(Self::ProcNet),
            "hybrid" => Ok(Self::Hybrid),
            _ => Err(format!("Invalid event source type: {}", s)),
        }
    }
}

impl std::fmt::Display for EventSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSourceType::Ebpf => write!(f, "ebpf"),
            EventSourceType::ProcNet => write!(f, "procnet"),
            EventSourceType::Hybrid => write!(f, "hybrid"),
        }
    }
}

pub struct EventSourceBuilder {
    source_type: EventSourceType,
    interface: Option<String>,
    poll_interval_ms: u64,
}

impl EventSourceBuilder {
    pub fn new(source_type: EventSourceType) -> Self {
        Self {
            source_type,
            interface: None,
            poll_interval_ms: 1000,
        }
    }

    pub fn interface(mut self, interface: &str) -> Self {
        self.interface = Some(interface.to_string());
        self
    }

    pub fn poll_interval_ms(mut self, interval: u64) -> Self {
        self.poll_interval_ms = interval;
        self
    }

    pub async fn build(self) -> Result<Box<dyn EventSource>> {
        match self.source_type {
            EventSourceType::Ebpf => {
                #[cfg(feature = "ebpf")]
                {
                    let source = EbpfEventSource::new(self.interface.as_deref()).await?;
                    info!("Created eBPF event source");
                    Ok(Box::new(source))
                }
                #[cfg(not(feature = "ebpf"))]
                {
                    Err(crate::error::Error::EbpfFeatureDisabled)
                }
            }
            EventSourceType::ProcNet => {
                let source = ProcNetEventSource::new(self.poll_interval_ms);
                info!("Created /proc/net event source (poll interval: {}ms)", self.poll_interval_ms);
                Ok(Box::new(source))
            }
            EventSourceType::Hybrid => {
                #[cfg(feature = "ebpf")]
                {
                    let source = HybridEventSource::new(
                        self.interface.as_deref(),
                        self.poll_interval_ms,
                    )
                    .await?;
                    info!("Created hybrid event source");
                    Ok(Box::new(source))
                }
                #[cfg(not(feature = "ebpf"))]
                {
                    let source = ProcNetEventSource::new(self.poll_interval_ms);
                    info!("eBPF feature disabled, falling back to /proc/net event source");
                    Ok(Box::new(source))
                }
            }
        }
    }
}

#[cfg(feature = "ebpf")]
mod ebpf_source;
#[cfg(feature = "ebpf")]
use ebpf_source::EbpfEventSource;

use crate::collector::proc_net_source::ProcNetEventSource;

#[cfg(feature = "ebpf")]
use crate::collector::hybrid_source::HybridEventSource;