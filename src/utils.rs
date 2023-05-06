use anyhow::{anyhow, bail, Context, Result};
use glob::glob;
use goblin::mach::constants::SECT_TEXT;
use libc::uid_t;
use serde::Deserialize;
use std::convert::From;
use std::ffi::CStr;
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use object::{Object, ObjectSymbol};

pub fn path_to_dev_ino(path: &Path) -> Result<(u64, u64)> {
    let stat = fs::metadata(path).context(format!("Failed to load metadata for {:?}", path))?;

    Ok((stat.st_dev() as u64, stat.st_ino()))
}

pub fn calculate_profile_key(st_ino: u64, st_dev: u64) -> u64 {
    st_ino | (st_dev << 16)
}

pub fn covert_full_path(str: &str, pos: u32, count: u32) -> Result<String> {
    let mut path = str.to_string();

    path.trim();
    // let target = "\u{0}".to_string();
    path.truncate(pos as usize);
    let mut pathtmp = path.clone();
    let mut name: Vec<String> = Vec::new();
    let end = String::from("//");
    for i in 0..count {
        let position = pathtmp.find("/");
        let mut pathnext = pathtmp.split_off(position.unwrap());
        if pathnext.eq(&end) {
            break;
        }
        let mut namenow = pathtmp.clone();
        pathnext.remove(0);
        name.push(namenow);
        pathtmp = pathnext.clone();
    }
    // let mut fullpath = String::new();
    let mut fullpath = String::from("/");
    for i in 0..name.len() {
        if i == 0 {
            fullpath = [fullpath, name.get(name.len() - i - 1).unwrap().to_string()].join("");
        } else {
            fullpath = [fullpath, name.get(name.len() - i - 1).unwrap().to_string()].join("/");
        }
    }
    Ok(fullpath)
}

pub fn get_name_from_uid(uid: uid_t) -> Result<String> {
    let user = unsafe { libc::getpwuid(uid as uid_t) };
    let username = unsafe { CStr::from_ptr((unsafe { *user }).pw_name) };
    let str_buf = username.to_str().unwrap();


    Ok(String::from(str_buf))
}



/// Allow a single or vector value
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum SingleOrVec<T> {
    Single(T),
    Vec(Vec<T>),
}

/// Provide an into() conversion to convert into a vector over T
impl<T> From<SingleOrVec<T>> for Vec<T> {
    fn from(value: SingleOrVec<T>) -> Self {
        match value {
            SingleOrVec::Single(v) => vec![v],
            SingleOrVec::Vec(v) => v,
        }
    }
}

impl<T> IntoIterator for SingleOrVec<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Single(item) => vec![item].into_iter(),
            Self::Vec(items) => items.into_iter(),
        }
    }
}
// Taken from libbpf-bootstrap rust example tracecon
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/rust/tracecon/src/main.rs#L47
// Authored by Magnus Kulke
// You can achieve a similar result for testing using objdump -tT so_path | grep fn_name
// Note get_symbol_address will return the deciaml number and objdump uses hex
pub fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(so_path);
    let buffer = fs::read(path).expect("fail to read");
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    // for sym in symbols{
    //     println!("{}",sym.name().unwrap());
    // }
    // let mut symbols = file.symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or_else(|| anyhow!("symbol not found"))?;

    // let relate = file.relative_address_base();
    // let me = Process::new(17385).expect("no process");
    // let maps = me.maps().context("Failed to get maps")?;
    // let mut relate_addr:usize =15421;
    // for entry in maps {
    //     if entry.perms.contains("r-xp") {
    //         relate_addr = (entry.address.0- entry.offset) as usize;
    //         break;
    //     }
    // }
    // println!("relate：{:x}",relate_addr);
    Ok(symbol.address() as usize)
}