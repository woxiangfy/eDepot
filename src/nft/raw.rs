use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use ipnet::IpNet;
use nftables::helper::{apply_ruleset, get_current_ruleset, NftablesError};
use nftables::schema::{
    Chain, Element, NfCmd, NfListObject, Nftables, Set, SetFlag, SetType, SetTypeValue, Table,
};
use nftables::types::{NfChainPolicy, NfFamily, NfHook};
use thiserror::Error;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BanEntry {
    Ip(IpAddr),
    Cidr(IpNet),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("nftables client error: {0}")]
    Client(String),

    #[error("invalid IP address")]
    InvalidIp,

    #[error("IP address already exists in set")]
    IpAlreadyExists,

    #[error("IP address conflicts with existing CIDR")]
    IpCidrConflict,

    #[error("failed to create table")]
    TableCreationFailed,

    #[error("failed to create set")]
    SetCreationFailed,

    #[error("failed to create chain")]
    ChainCreationFailed,

    #[error("failed to add element: {0}")]
    AddElementFailed(String),

    #[error("failed to remove element: {0}")]
    RemoveElementFailed(String),
}

impl From<NftablesError> for Error {
    fn from(e: NftablesError) -> Self {
        Error::Client(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct NftRawController {
    table: String,
    ipv4_set: String,
    ipv6_set: String,
    banned_entries: Arc<Mutex<HashMap<BanEntry, u32>>>,
}

impl NftRawController {
    pub fn new(table: &str) -> Result<Self> {
        Ok(Self {
            table: table.to_string(),
            ipv4_set: format!("{}_ipv4", table),
            ipv6_set: format!("{}_ipv6", table),
            banned_entries: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn sync_from_nftables(&self) -> Result<()> {
        let elements = self.get_all_set_elements()?;
        let mut banned = self.banned_entries.lock().unwrap();
        banned.clear();

        for elem in elements {
            banned.insert(BanEntry::Ip(elem), 0);
        }

        debug!(
            "Synced {} elements from nftables to local banned_entries",
            banned.len()
        );
        Ok(())
    }

    fn get_all_set_elements(&self) -> Result<Vec<IpAddr>> {
        let mut result = Vec::new();

        match get_current_ruleset() {
            Ok(nftables) => {
                for obj in nftables.objects.into_owned() {
                    if let NfObject::ListObject(NfListObject::Set(set)) = obj {
                        if set.table.as_ref() == self.table
                            && (set.name.as_ref() == self.ipv4_set
                                || set.name.as_ref() == self.ipv6_set)
                        {
                            if let Some(elems) = set.elem {
                                for elem in elems.into_owned() {
                                    if let nftables::expr::Expression::String(s) = elem {
                                        if let Ok(ip) = s.parse::<Ipv4Addr>() {
                                            result.push(IpAddr::V4(ip));
                                        } else if let Ok(ip) = s.parse::<Ipv6Addr>() {
                                            result.push(IpAddr::V6(ip));
                                        } else if let Ok(cidr) = s.parse::<IpNet>() {
                                            result.push(cidr.network().into());
                                        } else {
                                            warn!("Failed to parse element: {}", s);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to get current ruleset: {}", e);
                return Err(Error::Client(e.to_string()));
            }
        }

        Ok(result)
    }

    pub fn create_table(&self) -> Result<()> {
        let table = Table {
            family: NfFamily::INet,
            name: self.table.clone().into(),
            ..Default::default()
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table)))].into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                debug!("Created nftables table: {}", self.table);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    debug!("Table {} already exists, skipping creation", self.table);
                    Ok(())
                } else {
                    Err(Error::TableCreationFailed)
                }
            }
        }
    }

    pub fn create_sets(&self) -> Result<()> {
        self.create_ipv4_set()?;
        self.create_ipv6_set()?;
        Ok(())
    }

    fn create_ipv4_set(&self) -> Result<()> {
        let set = Set {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: self.ipv4_set.clone().into(),
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            flags: Some(HashSet::from([SetFlag::Interval, SetFlag::Timeout])),
            ..Default::default()
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Set(
                Box::new(set),
            )))]
            .into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                debug!("Created IPv4 set: {}", self.ipv4_set);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    debug!(
                        "IPv4 set {} already exists, skipping creation",
                        self.ipv4_set
                    );
                    Ok(())
                } else {
                    Err(Error::SetCreationFailed)
                }
            }
        }
    }

    fn create_ipv6_set(&self) -> Result<()> {
        let set = Set {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: self.ipv6_set.clone().into(),
            set_type: SetTypeValue::Single(SetType::Ipv6Addr),
            flags: Some(HashSet::from([SetFlag::Interval, SetFlag::Timeout])),
            ..Default::default()
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Set(
                Box::new(set),
            )))]
            .into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                debug!("Created IPv6 set: {}", self.ipv6_set);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    debug!(
                        "IPv6 set {} already exists, skipping creation",
                        self.ipv6_set
                    );
                    Ok(())
                } else {
                    Err(Error::SetCreationFailed)
                }
            }
        }
    }

    pub fn create_chains(&self) -> Result<()> {
        self.create_ingress_chain()?;
        self.create_egress_chain()?;
        Ok(())
    }

    fn create_ingress_chain(&self) -> Result<()> {
        let chain = Chain {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: "ingress".into(),
            hook: Some(NfHook::Input),
            prio: Some(-100),
            policy: Some(NfChainPolicy::Drop),
            ..Default::default()
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(chain)))].into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                debug!("Created ingress chain for table: {}", self.table);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    debug!("Ingress chain already exists for table: {}", self.table);
                    Ok(())
                } else {
                    Err(Error::ChainCreationFailed)
                }
            }
        }
    }

    fn create_egress_chain(&self) -> Result<()> {
        let chain = Chain {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: "egress".into(),
            hook: Some(NfHook::Output),
            prio: Some(-100),
            policy: Some(NfChainPolicy::Drop),
            ..Default::default()
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(chain)))].into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                debug!("Created egress chain for table: {}", self.table);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    debug!("Egress chain already exists for table: {}", self.table);
                    Ok(())
                } else {
                    Err(Error::ChainCreationFailed)
                }
            }
        }
    }

    pub fn add_ip_to_set(&self, ip: IpAddr, duration: u32) -> Result<()> {
        let (set_name, ip_str) = match ip {
            IpAddr::V4(_) => (self.ipv4_set.clone(), ip.to_string()),
            IpAddr::V6(_) => (self.ipv6_set.clone(), ip.to_string()),
        };

        {
            let banned = self.banned_entries.lock().unwrap();
            if self.is_ip_conflict_with_cidr_cached(ip, &banned) {
                warn!("IP {} conflicts with existing CIDR, skipping ban", ip);
                return Err(Error::IpCidrConflict);
            }

            if banned.contains_key(&BanEntry::Ip(ip)) {
                drop(banned);
                debug!("IP {} already banned, updating duration", ip);
                self.remove_ip_from_set(ip)?;
            }
        }

        let elem = Element {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: set_name.clone().into(),
            elem: vec![nftables::expr::Expression::String(ip_str.into())].into(),
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Element(elem)))].into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                self.banned_entries
                    .lock()
                    .unwrap()
                    .insert(BanEntry::Ip(ip), duration);
                debug!(
                    "Added IP {} to set {} with {}s duration",
                    ip, set_name, duration
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    Err(Error::IpAlreadyExists)
                } else {
                    Err(Error::AddElementFailed(err_str))
                }
            }
        }
    }

    pub fn add_cidr_to_set(&self, cidr: IpNet, duration: u32) -> Result<()> {
        let (set_name, cidr_str) = match cidr {
            IpNet::V4(_) => (self.ipv4_set.clone(), cidr.to_string()),
            IpNet::V6(_) => (self.ipv6_set.clone(), cidr.to_string()),
        };

        self.remove_ips_in_cidr(&cidr)?;

        let elem = Element {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: set_name.clone().into(),
            elem: vec![nftables::expr::Expression::String(cidr_str.into())].into(),
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Add(NfListObject::Element(elem)))].into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                let mut banned = self.banned_entries.lock().unwrap();
                banned.insert(BanEntry::Cidr(cidr), duration);
                debug!(
                    "Added CIDR {} to set {} with {}s duration",
                    cidr, set_name, duration
                );
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("file exists") {
                    Err(Error::IpAlreadyExists)
                } else {
                    Err(Error::AddElementFailed(err_str))
                }
            }
        }
    }

    fn remove_ips_in_cidr(&self, cidr: &IpNet) -> Result<()> {
        let mut ips_to_remove: Vec<IpAddr> = Vec::new();
        let mut cidrs_to_remove: Vec<IpNet> = Vec::new();

        let banned = self.banned_entries.lock().unwrap();
        for (entry, _) in banned.iter() {
            match entry {
                BanEntry::Ip(ip) => {
                    if cidr.contains(ip) {
                        ips_to_remove.push(*ip);
                    }
                }
                BanEntry::Cidr(entry_cidr) => {
                    if cidr.contains(&entry_cidr.network())
                        && entry_cidr.prefix_len() >= cidr.prefix_len()
                    {
                        cidrs_to_remove.push(*entry_cidr);
                    }
                }
            }
        }
        drop(banned);

        for ip in ips_to_remove {
            if let Err(e) = self.remove_ip_from_set(ip) {
                warn!("Failed to remove IP {} before adding CIDR: {}", ip, e);
            }
        }

        for cidr_to_remove in cidrs_to_remove {
            if let Err(e) = self.remove_cidr_from_set(cidr_to_remove) {
                warn!(
                    "Failed to remove CIDR {} before adding CIDR: {}",
                    cidr_to_remove, e
                );
            }
        }

        Ok(())
    }

    fn is_ip_conflict_with_cidr_cached(&self, ip: IpAddr, banned: &HashMap<BanEntry, u32>) -> bool {
        for (entry, _) in banned.iter() {
            if let BanEntry::Cidr(cidr) = entry {
                if cidr.contains(&ip) {
                    return true;
                }
            }
        }
        false
    }

    pub fn remove_ip_from_set(&self, ip: IpAddr) -> Result<()> {
        let (set_name, ip_str) = match ip {
            IpAddr::V4(_) => (self.ipv4_set.clone(), ip.to_string()),
            IpAddr::V6(_) => (self.ipv6_set.clone(), ip.to_string()),
        };

        let elem = Element {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: set_name.clone().into(),
            elem: vec![nftables::expr::Expression::String(ip_str.into())].into(),
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Delete(NfListObject::Element(
                elem,
            )))]
            .into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                self.banned_entries
                    .lock()
                    .unwrap()
                    .remove(&BanEntry::Ip(ip));
                debug!("Removed IP {} from set {}", ip, set_name);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("no such file or directory") {
                    debug!("IP {} not found in set, ignoring", ip);
                    Ok(())
                } else {
                    Err(Error::RemoveElementFailed(err_str))
                }
            }
        }
    }

    pub fn remove_cidr_from_set(&self, cidr: IpNet) -> Result<()> {
        let (set_name, cidr_str) = match cidr {
            IpNet::V4(_) => (self.ipv4_set.clone(), cidr.to_string()),
            IpNet::V6(_) => (self.ipv6_set.clone(), cidr.to_string()),
        };

        let elem = Element {
            family: NfFamily::INet,
            table: self.table.clone().into(),
            name: set_name.clone().into(),
            elem: vec![nftables::expr::Expression::String(cidr_str.into())].into(),
        };

        let nftables = Nftables {
            objects: vec![NfObject::CmdObject(NfCmd::Delete(NfListObject::Element(
                elem,
            )))]
            .into(),
        };

        match apply_ruleset(&nftables) {
            Ok(_) => {
                self.banned_entries
                    .lock()
                    .unwrap()
                    .remove(&BanEntry::Cidr(cidr));
                debug!("Removed CIDR {} from set {}", cidr, set_name);
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("no such file or directory") {
                    debug!("CIDR {} not found in set, ignoring", cidr);
                    Ok(())
                } else {
                    Err(Error::RemoveElementFailed(err_str))
                }
            }
        }
    }

    pub fn get_banned_ips(&self) -> Result<Vec<(IpAddr, u32)>> {
        let banned = self.banned_entries.lock().unwrap();
        let mut result = Vec::with_capacity(banned.len());

        for (entry, duration) in banned.iter() {
            match entry {
                BanEntry::Ip(ip) => {
                    result.push((*ip, *duration));
                }
                BanEntry::Cidr(cidr) => {
                    result.push((cidr.network(), *duration));
                }
            }
        }

        Ok(result)
    }
}

use nftables::schema::NfObject;
