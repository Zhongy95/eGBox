use crate::bpf::{BpfESXMapsMut, BpfESXSkel as Skel};
use anyhow::{Context, Result};
use enum_dispatch::enum_dispatch;
use glob::glob;
use libbpf_rs::{Map, MapFlags};
use serde::Deserialize;
use std::convert::{From, Into, TryFrom, TryInto};
use toml::value::Array;

use crate::policy::config::Conf;
use crate::policy::{bitflags, keys, values};
use crate::utils::{calculate_profile_key, path_to_dev_ino, SingleOrVec};
use plain::as_bytes;
use std::path::PathBuf;
use nix::unistd::Gid;

//Load Rule interface

#[enum_dispatch]
pub trait LoadRule {
    fn key(&self, config: &Conf, uid: u32,gid_use:bool) -> Result<Vec<u8>>;

    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>>;

    fn map<'a: 'a>(&self, maps: &'a mut BpfESXMapsMut) -> &'a mut Map;

    /// Lookup existing value and return it as POD if it exists.
    fn lookup_existing_value<'a: 'a>(
        &self,
        key: &[u8],
        maps: &'a mut BpfESXMapsMut,
    ) -> Result<Option<Vec<u8>>> {
        let map = self.map(maps);
        Ok(map.lookup(key, MapFlags::ANY)?)
    }

    fn load<'a: 'a>(
        &self,
        config: &Conf,
        uid: u32,
        skel: &'a mut Skel,
        decision: &PolicyDecision,
        gid_use:bool
    ) -> Result<()> {
        println!("load aa uid:{}",uid);
        let mut key;
        match self.key(&config, uid,gid_use){
            Ok(key_s) => {key = key_s;},
            Err(e)=>{return Err(e)}
        }
        let key = &mut self.key(&config, uid,gid_use).unwrap();
        println!("load key uid:{:?}",key);
        let value = &mut self
            .value(&decision)
            .context("Failed to create map value")?;

        let mut maps = skel.maps_mut();
        if let Some(existing) = self.lookup_existing_value(key, &mut maps)? {
            for (old, new) in existing.iter().zip(value.iter_mut()) {
                *new |= *old;
            }
        }

        //update the actual map value
        let map = self.map(&mut maps);
        map.update(key, value, MapFlags::ANY)
            .context("Failed to update map value")?;

        Ok(())
    }
}
#[enum_dispatch(LoadRule)]
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum Rule {
    //File policies
    #[serde(alias = "fs")]
    Filesystem(FilesystemRule),
    #[serde(alias = "net")]
    Net(NetRule),
}

// ============================================================================
// File/Filesystem/Device Rules
// ============================================================================

/// Represents a set of filesystem access flags.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct FileAccess(String);

/// Represents a filesystem rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemRule {
    #[serde(alias = "profile")]
    pub(crate) pathname: String,
    pub(crate) uid: SingleOrVec<i32>,
    access: FileAccess,
    pub(crate) action: SingleOrVec<String>,
    pub(crate) gid: SingleOrVec<i32>,
}



impl LoadRule for FilesystemRule {
    fn key(&self, config: &Conf, uid: u32,gid_use:bool) -> Result<Vec<u8>> {
        //Look up the device ID of the filesystem
        let (mut st_dev,mut st_ino) =(0,0);
        if &self.pathname == "/*"{
             (st_dev, st_ino) =(0,0);
        }else if self.pathname.ends_with("/*"){
            let path_without_suffix = &self.pathname.replace("/*","");
            match path_to_dev_ino(&PathBuf::from(path_without_suffix)){
                Ok((dev,ino)) => {(st_dev, st_ino) = (dev,ino);},
                Err(e)=>{
                    return Err(e);
                }
            }
        } else if self.pathname.ends_with("/"){
            let path_without_suffix = &self.pathname.replace("/","");
            match path_to_dev_ino(&PathBuf::from(path_without_suffix)){
                Ok((dev,ino)) => {(st_dev, st_ino) = (dev,ino);},
                Err(e)=>{
                    return Err(e);
                }
            }
        } else if self.pathname.ends_with("/**") {
            let path_without_suffix = &self.pathname.replace("/**","");
            match path_to_dev_ino(&PathBuf::from(path_without_suffix)){
                Ok((dev,ino)) => {(st_dev, st_ino) = (dev,ino);},
                Err(e)=>{
                    return Err(e);
                }
            }
        }else{
            match path_to_dev_ino(&PathBuf::from(&self.pathname)){
                Ok((dev,ino)) => {(st_dev, st_ino) = (dev,ino);},
                Err(e)=>{
                    return Err(e);
                }
            }

        }
        // let uidvec: Vec<_> = self.uid.clone().into();

        if gid_use{
            let key_group = keys::FsPolicyKeyGroup {
                config_id: config.config_id() as u32,
                device_id: st_dev as u64,
                profile_key: calculate_profile_key(st_ino, st_dev) as u64,
                gid: uid as u32,
            };
            return Ok(unsafe { as_bytes(&key_group).into() });
        }

        let key = keys::FsPolicyKey {
                config_id: config.config_id() as u32,
                device_id: st_dev as u64,
                profile_key: calculate_profile_key(st_ino, st_dev) as u64,
                uid: uid as u32,
            };

        // println!(
        //     "config_id:{},dev_id:{},profile_key:{},uid:{}",
        //     config.config_id(),
        //     key.device_id,
        //     key.profile_key,uid
        // );
        Ok(unsafe { as_bytes(&key).into() })
    }
    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let access = bitflags::FileAccess::try_from(self.access.0.as_str())?;

        let mut value = values::PolicyT::default();
        match decision {
            PolicyDecision::Allow => {
                println!("value.allow = {}", access.bits());
                value.allow = access.bits()
            }
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Audit => {
                println!("value.audit = {}", access.bits());
                value.audit = access.bits()
            }
            PolicyDecision::Deny => {
                value.deny = access.bits()
            }
        }

        Ok(unsafe { as_bytes(&value).into() })
    }

    fn map<'a: 'a>(&self, maps: &'a mut BpfESXMapsMut) -> &'a mut Map {
        maps.fs_policies()
    }

    fn load<'a: 'a>(
        &self,
        config: &Conf,
        uid: u32,
        skel: &'a mut Skel,
        decision: &PolicyDecision,
        gid_use:bool
    ) -> Result<()> {
        let mut key;
        match self.key(&config, uid,gid_use){
            Ok(key_s) => {key = key_s;},
            Err(e)=>{return Err(e)}
        }
        let key = &mut self.key(&config, uid,gid_use).unwrap();
        println!("load key :{:?}",key);
        let value = &mut self
            .value(&decision)
            .context("Failed to create map value")?;

        let mut maps = skel.maps_mut();
        if let Some(existing) = self.lookup_existing_value(key, &mut maps)? {
            for (old, new) in existing.iter().zip(value.iter_mut()) {
                *new |= *old;
            }
        }

        //update the actual map value

        let mut map = self.map(&mut maps);
        if gid_use {
            map =maps.fs_group_policies();
        }
        // if self.pathname.ends_with("/*") || self.pathname.ends_with("/**") || self.pathname.ends_with("/"){
        //     map = maps.fs_dir_policies();
        //     // maps.fs_dir_policies();
        // }
        map.update(key, value, MapFlags::ANY)
            .context("Failed to update map value")?;

        Ok(())
    }
}

// ============================================================================
// Net Rules
// ============================================================================

/// Represents network access categories.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum NetAccess {
    Client,
    Server,
    Send,
    Recv,
    Any,
}

impl From<String> for NetAccess {
    fn from(value: String) -> Self {
        match value {
            value if value == "Client" => Self::Client,
            value if value == "Server" => Self::Server,
            value if value == "Send" => Self::Send,
            value if value == "Recv" => Self::Recv,
            value if value == "Any" => Self::Any,
            _=>{Self::Recv}
        }
    }
}

impl From<NetAccess> for bitflags::NetOperation {
    fn from(value: NetAccess) -> Self {
        match value {
            NetAccess::Client => Self::MASK_CLIENT,
            NetAccess::Server => Self::MASK_SERVER,
            NetAccess::Send => Self::MASK_SEND,
            NetAccess::Recv => Self::MASK_RECV,
            NetAccess::Any => Self::all(),
        }
    }
}

/// Represents a network access rule.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetRule {
    #[serde(alias = "net")]
    access: SingleOrVec<String>,
    pub(crate) action: SingleOrVec<String>,
    pub(crate) uid: SingleOrVec<i32>,
    pub(crate) gid: SingleOrVec<i32>,
}

impl LoadRule for NetRule {
    fn key(&self, config: &Conf, uid: u32,gid_use:bool) -> Result<Vec<u8>> {
        //group privileged
        if gid_use {
            let key_group = keys::NetPolicyKeyGroup {
                config_id: config.config_id() as u32,
                gid:uid
            };
            return Ok(unsafe { as_bytes(&key_group).into() });
        }

        let key = keys::NetPolicyKey {
            config_id: config.config_id() as u32,
            uid: uid
        };
        println!("Net rule loaded , config_id:{}", config.config_id());
        Ok(unsafe { as_bytes(&key).into() })
    }
    fn value(&self, decision: &PolicyDecision) -> Result<Vec<u8>> {
        let netvec_str: Vec<_> = self.access.clone().into();
        let mut netvec = Vec::new();
        for netstr in netvec_str{
            let netacess:NetAccess = netstr.into(); 
            netvec.push(netacess);
        }
        let access: bitflags::NetOperation = netvec
            .iter()
            .fold(bitflags::NetOperation::default(), |v1, v2| {
                v1 | bitflags::NetOperation::from(v2.clone())
            });

        let mut value = values::PolicyT::default();
        match decision {
            PolicyDecision::Allow => {
                println!("value.allow = {}", access.bits());
                value.allow = access.bits()
            }
            PolicyDecision::Taint => value.taint = access.bits(),
            PolicyDecision::Audit => {
                println!("value.audit = {}", access.bits());
                value.audit = access.bits()
            }
            PolicyDecision::Deny => {
                value.deny = access.bits()
            }
        }

        Ok(unsafe { as_bytes(&value).into() })
    }

    fn map<'a: 'a>(&self, maps: &'a mut BpfESXMapsMut) -> &'a mut Map {
        maps.net_policies()
    }

    fn load<'a: 'a>(
        &self,
        config: &Conf,
        uid: u32,
        skel: &'a mut Skel,
        decision: &PolicyDecision,
        gid_use:bool
    ) -> Result<()> {
        println!("load aa uid:{}",uid);
        let mut key;
        match self.key(&config, uid,gid_use){
            Ok(key_s) => {key = key_s;},
            Err(e)=>{return Err(e)}
        }
        let key = &mut self.key(&config, uid,gid_use).unwrap();
        println!("load key uid:{:?}",key);
        let value = &mut self
            .value(&decision)
            .context("Failed to create map value")?;

        let mut maps = skel.maps_mut();
        if let Some(existing) = self.lookup_existing_value(key, &mut maps)? {
            for (old, new) in existing.iter().zip(value.iter_mut()) {
                *new |= *old;
            }
        }

        //update the actual map value
        let mut map = self.map(&mut maps);
        if gid_use{
            map = maps.net_group_policies();
        }
        map.update(key, value, MapFlags::ANY)
            .context("Failed to update map value")?;

        Ok(())
    }
}

/// Represents a policy decision.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PolicyDecision {
    Audit,
    Allow,
    Taint,
    Deny,
}

impl From<PolicyDecision> for bitflags::PolicyDecision {
    fn from(value: PolicyDecision) -> Self {
        match value {
            PolicyDecision::Audit => Self::AUDIT,
            PolicyDecision::Allow => Self::ALLOW,
            PolicyDecision::Taint => Self::TAINT,
            PolicyDecision::Deny => Self::DENY,
        }
    }
}
