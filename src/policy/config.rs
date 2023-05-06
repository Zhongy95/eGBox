use crate::bpf::{BpfESXMapsMut, BpfESXSkel as Skel};
use anyhow::{bail, Context, Result};
use enum_dispatch::enum_dispatch;
use glob::glob;
use libbpf_rs::{Map, MapFlags};
use serde::Deserialize;
use std::borrow::Borrow;
use toml::value::Array;

use plain::as_bytes;

use crate::policy::rule::{FilesystemRule, LoadRule, NetRule, PolicyDecision, Rule};
use crate::utils::{calculate_profile_key, path_to_dev_ino};
use std::ffi::OsStr;
use std::io::Read;
use std::marker::Copy;
use std::path::{Path, PathBuf};
use libc::getpid;



const MAX_POLICY_SIZE: u32 = 1024;
const AUDIT_RINGBUF_PAGES: u64 = 1 << 12;

type AccessT = u32;

struct AccessStateT {
    access: u32,
    state: u64,
}

struct PolicyT {
    allow: AccessStateT,
    taint: AccessStateT,
    audit: AccessStateT,
}

pub struct ConfigT {
    pub profile: String,
    pub fs_policies: Option<FsConfigT>,
}

pub struct FsConfigT {
    path: Option<String>,
    policy: PolicyT,
}

#[derive(Deserialize, Debug)]
pub struct fs {
    action: Option<Array>,
    access: Option<String>,
    file: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct net {
    action: Option<Array>,
    access: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Conf {
    pub profile: String,
    pub fs: Option<Vec<FilesystemRule>>,
    pub net: Option<Vec<NetRule>>,
}

impl Conf {
    //使用toml文件进行配置
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        use std::fs::File;

        let mut reader = File::open(&path).context("Failed to open policy file for reading")?;

        match path.as_ref().extension().and_then(OsStr::to_str) {
            Some("toml") => {
                let mut s = String::new();
                reader.read_to_string(&mut s)?;
                toml::from_str(&s).context("Failed to parse policy file as TOML")
            }
            _ => bail!("No such file"),
        }
    }

    //生成configId
    pub fn config_id(&self) -> u32 {
        Self::config_id_for_name(&self.profile) as u32
    }

    pub fn config_id_for_name(name: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);

        hasher.finish()
    }

    pub fn load(&self, skel: &mut Skel) -> Result<()> {
        //load fs rules
        // if let FileRules = &self.fs.unwrap(){
        println!("fs rule exist");

        skel.bss().config_id = self.config_id() as u64;
        skel.bss().esx_pid = unsafe{getpid() as u32};

        println!("config_id = {}", skel.bss().config_id);
        println!("pid = {}",skel.bss().esx_pid);

        match &self.fs {
            Some(x) => {
                self.load_fsprofiles(x, skel);
                self.load_fsrules(x, skel);
            }
            None => println!("None"),
        }

        match &self.net {
            Some(x) => {
                self.load_netrules(x, skel);
            }
            None => println!("No net rule"),
        }

        Ok(())
    }

    pub fn load_fsprofiles<'a>(&self, rules: &[FilesystemRule], skel: &mut Skel) -> Result<()> {
        for rule in rules.iter() {
            let (st_dev, st_ino) = path_to_dev_ino(&PathBuf::from(&rule.pathname))
                .context(format!("Failed to get information for {}", &rule.pathname))?;
            let profile_key: u64 = calculate_profile_key(st_ino, st_dev);

            let taint_on_exec: bool = false;
            let mut maps = skel.maps_mut();
            let map = maps.profiles();

            map.update(
                unsafe { as_bytes(&profile_key).into() },
                unsafe { as_bytes(&taint_on_exec).into() },
                MapFlags::ANY,
            )
            .context("Failed to update map value")?;

            let mut maps = skel.maps_mut();
            let mapc = maps.profile_config();
            let config_id: u64 = self.config_id() as u64;

            println!(
                "profiles {} added successfullfy,config_id = {}",
                &profile_key, &config_id
            );

            mapc.update(
                unsafe { as_bytes(&profile_key).into() },
                unsafe { as_bytes(&config_id).into() },
                MapFlags::ANY,
            )
            .context("Failed to update map value")?;

            println!(
                "successfully add {},st_dev: {},st_ino: {},profile key: {},config_id:{}",
                &rule.pathname,
                st_dev << 16,
                st_ino,
                profile_key,
                &config_id
            );
        }
        Ok(())
    }

    pub fn load_fsrules(&self, rules: &[FilesystemRule], skel: &mut Skel) {
        for rule in rules.iter() {
            // if let Err(e) = rule.load(self,skel,decision.clone()){
            //     log::warn!("Failed to load {:?} rule",decision);
            // }
            let mut actionvec: Vec<_> = rule.action.clone().into();
            let mut uidvec: Vec<_> = rule.uid.clone().into();
            for uid  in &uidvec {
                let uid = *uid as u32;
                println!("uid : {}",uid,);
                for decision in &actionvec {
                    println!("decision:{}",decision);
                    match decision.as_ref() {
                        "audit" => {
                            rule.load(self, uid, skel, &PolicyDecision::Audit);
                        }
                        "allow" => {
                            println!("allow loading,uid={}",uid);
                            rule.load(self, uid, skel, &PolicyDecision::Allow);
                            println!("allow load,uid={}",uid);
                        }
                        "taint" => {
                            rule.load(self, uid, skel, &PolicyDecision::Taint);
                        }
                        _ => {}
                    }
                }
            }

            //rule.load(self, skel, &decision.clone());
        }
    }

    pub fn load_netrules(&self, rules: &[NetRule], skel: &mut Skel) {
        for rule in rules.iter() {
            // if let Err(e) = rule.load(self,skel,decision.clone()){
            //     log::warn!("Failed to load {:?} rule",decision);
            // }
            let netvec: Vec<_> = rule.action.clone().into();
            let uidvec: Vec<_> = rule.uid.clone().into();
            for uid in uidvec {
                let uid = uid as u32;

                for decision in &netvec {
                    match decision.as_ref() {
                        "audit" => {
                            rule.load(self, uid, skel, &PolicyDecision::Audit);
                        }
                        "allow" => {
                            rule.load(self, uid, skel, &PolicyDecision::Allow);
                        }
                        "taint" => {
                            rule.load(self, uid, skel, &PolicyDecision::Taint);
                        }
                        _ => {}
                    }
                }
            }

            //rule.load(self, skel, &decision.clone());
        }
    }


}
