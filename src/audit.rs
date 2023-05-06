use libc::{pid_t, uid_t};
use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;

use plain::Plain;

use super::bindings::raw;
use crate::policy::bitflags::{FileAccess, NetOperation};
use crate::utils::{covert_full_path, get_name_from_uid};
use serde::{Deserialize, Serialize};
use serde_json::Result;

pub type AuditData = raw::fs_audit_event_t;
pub type AuditDataC = raw::comline_audit_event;
pub type AuditDataCommon = raw::audit_event_t;

impl Display for AuditData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let comm = std::str::from_utf8(&self.comm).unwrap_or("Unkown");
        let mut access = String::new();
        access = match self.access {
            0x01 => "READ",
            0x02 => "WRITE",
            0x04 => "APPEND",
            0x08 => "EXEC",
            0x10 => "CHMOD",
            0x20 => "GETATTR",
            0x80 => "DELETE",
            _ => "NONE",
        }
        .parse()
        .unwrap();
        write!(
            f,
            "pid = {},uid = {},comm ={},config_id ={},access:{}",
            self.pid, self.uid, comm, self.profile_key, access
        )
    }
}







impl Display for AuditDataC {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let comm = std::str::from_utf8(&self.comm).unwrap_or("Unkown").replace("\u{0000}","").add(" ");
        let args = std::str::from_utf8(&self.args).unwrap_or("Unkown").replace("\u{0000}\u{0000}","");

        write!(
            f,
            "\"commandline\" , \"pid\" : \"{}\",\"ppid\":\"{}\",\"uid\" : \"{}\",\"comm\" :\"{}\",\"args\" :\"{}\"",
            self.pid, self.ppid, self.uid, comm, args
        )
    }
}


impl Display for AuditDataCommon {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let comm = std::str::from_utf8(&self.comm).unwrap_or("Unkown").replace("\u{0000}","");


        let username = get_name_from_uid(self.uid as uid_t).unwrap();
        let info = unsafe {
            match self.type_ {
                AuditType::AUDIT_TYPE_FILE => self.__bindgen_anon_1.file.to_string(),
                AuditType::AUDIT_TYPE_NET => self.__bindgen_anon_1.net.to_string(),
                _ => "UNKNOWN".to_string(),
            }
        };


        write!(
            f,
            r#" "{}","uid":{},"username":"{}","gid":{},"pid" :{},"comm":"{}","configId":"{}",{}"#,
            self.level, self.uid, username,self.gid, self.pid, comm, self.config_id, info
        )
    }
}

pub type AuditType = raw::audit_type_t;

unsafe impl Plain for AuditData {}
unsafe impl Plain for AuditDataC {}
unsafe impl Plain for AuditDataCommon {}

pub fn audit_callback(data: &[u8]) -> i32 {
    let data = AuditData::from_bytes(data).expect("Failed to convert audit data from raw bytes");
    // println!("{}", data);
    // log::info!("{}", data);

    0
}
pub fn audit_callbackc(data: &[u8]) -> i32 {
    let data = AuditDataC::from_bytes(data).expect("Failed to convert audit data from raw bytes");
    // println!("{}", data);
    // log::info!("{}", data);

    0
}

pub fn audit_callbackA(data: &[u8]) -> i32 {
    let data =
        AuditDataCommon::from_bytes(data).expect("Failed to convert audit data from raw bytes");
    // println!("{}", data);
    log::info!("{}", data);

    0
}

pub type AuditFile = raw::audit_file_t;
impl Display for AuditFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let path = std::str::from_utf8(&self.path.fullpath).unwrap_or("Unkown");
        let fullpath = covert_full_path(path, self.path.pathsize, self.path.count).unwrap();
        let access = FileAccess::from_bits(self.access).expect("Failed to convert file");

        write!(
            f,
            r#""type":"FILE","access":"{:?}","count":{},"fullpath":"{}""#,
            access,
            self.path.count,
            fullpath
        )
    }
}



unsafe impl Plain for AuditFile {}

pub type AuditNet = raw::audit_net_t;
impl Display for AuditNet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let op =
            NetOperation::from_bits(self.operation).expect("Failed to convert network operation");
        write!(f, r#""type":"NET","operation":"{:?}""#, op)
    }
}


unsafe impl Plain for AuditNet {}

pub type AuditLevel = raw::audit_level_t;

impl Display for AuditLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let level = match self {
            AuditLevel::AUDIT_DENY => "DENY".to_string(),
            AuditLevel::AUDIT_INFO => "INFO".to_string(),
            AuditLevel::AUDIT_ALLOW => "ALLOW".to_string(),
            AuditLevel::AUDIT__NONE => "NONE".to_string(),
            AuditLevel::AUDIT_WARN => "WARN".to_string(),
            _ => "UNKNoWN".to_string(),
        };
        write!(f, "{}", level)
    }
}
