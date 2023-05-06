use std::fmt;
use std::fmt::Formatter;
use anyhow::{Context, Result};
use bson::{doc, Document};
use serde::{Deserialize,Serialize};


/// Represents a filesystem rule.
#[derive(Deserialize,Serialize)]
pub struct FilesystemRule {
    pub(crate) pathname: String,
    pub(crate) uid: i32,
    pub(crate) gid:i32,
    pub(crate) access: String,
    pub(crate) action: Vec<String>,
}

impl fmt::Display for FilesystemRule{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f,
               "uid:{}, gid:{},operation:{},pathname:{}",
               self.uid,self.gid,self.access,self.pathname)
    }
}

impl FilesystemRule {
    pub fn create_influence_vec(&self) -> Vec<String>{
        vec![
            self.get_uid_string(),
            self.get_gid_string(),
            "logtype:FILE".to_string(),
            self.get_op_string(),
            self.get_res_string()
        ]
    }
    pub fn get_uid_string(&self) ->String{
        ("UID:".to_string()+self.uid.to_string().as_str()).to_string()
    }
    pub fn get_gid_string(&self) ->String{
        ("GID:".to_string()+self.gid.to_string().as_str()).to_string()
    }
    pub fn get_op_string(&self) ->String{
        ("op:".to_string()+self.access.to_string().as_str()).to_string()
    }
    pub fn get_res_string(&self) ->String{
        ("res:".to_string()+self.pathname.to_string().as_str()).to_string()
    }
    pub fn to_toml_string(&self) ->String{
        let title = "[[fs]]\n";
        let toml_str = title.to_owned() + &toml::to_string(&self).expect("Failed to turn to toml");
        toml_str
    }
    pub fn to_mongodb_doc(&self) ->Document{
        let mut fs_rule_doc = doc! {};
        fs_rule_doc.insert("logtype","logtype:FILE".to_string());
        if self.get_gid_string() != "GID:-1".to_string() {
            fs_rule_doc.insert("gid", self.get_gid_string());
        }
        if self.get_uid_string() != "UID:-1".to_string() {
            fs_rule_doc.insert("uid", self.get_uid_string());
        }
        if self.get_op_string() != "op:any".to_string() {
            fs_rule_doc.insert("op", self.get_op_string());
        }
        if self.get_res_string() != "res:/*".to_string() {
            fs_rule_doc.insert("res", self.get_res_string());
        }
        fs_rule_doc
    }
    pub fn from_pattern(pattern:&Vec<&str>)->FilesystemRule{
        let mut fs_rule = FilesystemRule{
            pathname: "/*".to_string(),
            uid: -1,
            gid: -1,
            access: "any".to_string(),
            action: vec!["allow".to_string()],
        };
        for component in pattern {
            if component.contains("UID:"){
                fs_rule.uid = component.replace("UID:", "").parse::<i32>().unwrap();
            }else if component.contains("GID:"){
                let gid = component.replace("GID:", "").parse::<i32>().unwrap();
                fs_rule.gid = gid;
            }else if component.contains("op:"){
                let op = component.replace("op:", "");
                fs_rule.access = op;
            }else if component.contains("res:"){
                let res = component[4..].to_string();
                fs_rule.pathname = res;
            }
        }
        fs_rule
    }
    pub fn from_pattern_String(pattern:&Vec<String>)->FilesystemRule{
        let mut fs_rule = FilesystemRule{
            pathname: "/*".to_string(),
            uid: -1,
            gid: -1,
            access: "any".to_string(),
            action: vec!["allow".to_string()],
        };

        for component in pattern {
            if component.contains("UID:"){
                fs_rule.uid = component.replace("UID:", "").parse::<i32>().unwrap();
            }else if component.contains("GID:"){
                let gid = component.replace("GID:", "").parse::<i32>().unwrap();
                fs_rule.gid = gid;
            }else if component.contains("op:"){
                let op = component.replace("op:", "");
                fs_rule.access = op;
            }else if component.contains("res:"){
                let res = component[4..].to_string();
                fs_rule.pathname = res;
            }
        }
        fs_rule
    }
}



pub fn generate_fsrule_from_item(pattern:&Vec<&str>)->Result<FilesystemRule>{
    let mut fs_rule = FilesystemRule{
        pathname: "/*".to_string(),
        uid: -1,
        gid: -1,
        access: "any".to_string(),
        action: vec!["allow".to_string()],
    };

    for component in pattern {
        if component.contains("UID:"){
            fs_rule.uid = component.replace("UID:", "").parse::<i32>().unwrap();
        }else if component.contains("GID:"){
            let gid = component.replace("GID:", "").parse::<i32>().unwrap();
            fs_rule.gid = gid;
        }else if component.contains("op:"){
            let op = component.replace("op:", "");
            fs_rule.access = op;
        }else if component.contains("res:"){
            let res = component[4..].to_string();
            fs_rule.pathname = res;
        }
    }
    Ok(fs_rule)
}

/// Represents a net rule.
#[derive(Deserialize,Serialize)]
pub struct NetRule {
    pub(crate) access: String,
    pub(crate) action: Vec<String>,
    pub(crate) uid: i32,
    pub(crate) gid: i32
}
impl fmt::Display for NetRule{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f,
               "uid:{}, gid:{},operation:{}",
               self.uid,self.gid,self.access)
    }
}
pub fn generate_netrule_from_item(pattern:&Vec<&str>)->Result<NetRule>{
    let mut net_rule = NetRule{
        access: "any".to_string(),
        action: vec!["allow".to_string()],
        uid: -1,
        gid: -1,
    };

    for component in pattern {
        if component.contains("UID:"){
            net_rule.uid = component.replace("UID:", "").parse::<i32>().unwrap();
        }else if component.contains("GID:"){
            let gid = component.replace("GID:", "").parse::<i32>().unwrap();
            net_rule.gid = gid;
        }else if component.contains("op:"){
            let op = component.replace("op:", "");
            net_rule.access = op;
        }
    }
    Ok(net_rule)
}

impl NetRule {
    pub fn create_influence_vec(&self) -> Vec<String>{
        vec![
            ("UID:".to_string()+self.uid.to_string().as_str()).to_string(),
            ("GID:".to_string()+self.gid.to_string().as_str()).to_string(),
            "logtype:NET".to_string(),
            ("op:".to_string()+self.access.to_string().as_str()).to_string()
        ]
    }
    pub fn get_uid_string(&self) ->String{
        ("UID:".to_string()+self.uid.to_string().as_str()).to_string()
    }
    pub fn get_gid_string(&self) ->String{
        ("GID:".to_string()+self.gid.to_string().as_str()).to_string()
    }
    pub fn get_op_string(&self) ->String{
        ("op:".to_string()+self.access.to_string().as_str()).to_string()
    }
    pub fn to_toml_string(&self) ->String{
        let title = "[[fs]]\n";
        let toml_str = title.to_owned() + &toml::to_string(&self).expect("Failed to turn to toml");
        toml_str
    }
    pub fn to_mongodb_doc(&self) ->Document{
        let mut net_rule_doc = doc! {};
        net_rule_doc.insert("logtype","logtype:FILE".to_string());
        if self.get_gid_string() != "GID:-1".to_string() {
            net_rule_doc.insert("gid", self.get_gid_string());
        }
        if self.get_uid_string() != "UID:-1".to_string() {
            net_rule_doc.insert("uid", self.get_uid_string());
        }
        if self.get_op_string() != "op:any".to_string() {
            net_rule_doc.insert("op", self.get_op_string());
        }
        net_rule_doc
    }
    pub fn from_pattern(pattern:&Vec<&str>)->NetRule{
        let mut net_rule = NetRule{
            access: "any".to_string(),
            action: vec!["allow".to_string()],
            uid: -1,
            gid: -1,
        };

        for component in pattern {
            if component.contains("UID:"){
                net_rule.uid = component.replace("UID:", "").parse::<i32>().unwrap();
            }else if component.contains("GID:"){
                let gid = component.replace("GID:", "").parse::<i32>().unwrap();
                net_rule.gid = gid;
            }else if component.contains("op:"){
                let op = component.replace("op:", "");
                net_rule.access = op;
            }
        }
        net_rule
    }
    pub fn from_pattern_String(pattern:&Vec<String>)->NetRule{
        let mut net_rule = NetRule{
            access: "any".to_string(),
            action: vec!["allow".to_string()],
            uid: -1,
            gid: -1,
        };

        for component in pattern {
            if component.contains("UID:"){
                net_rule.uid = component.replace("UID:", "").parse::<i32>().unwrap();
            }else if component.contains("GID:"){
                let gid = component.replace("GID:", "").parse::<i32>().unwrap();
                net_rule.gid = gid;
            }else if component.contains("op:"){
                let op = component.replace("op:", "");
                net_rule.access = op;
            }
        }
        net_rule
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EsxLog {
    uid: String,
    gid: String,
    logtype:String,
    op:String,
    res:String
}

impl EsxLog{
    pub fn to_logs_vec(&self)->Vec<String>{
        vec![self.uid.clone(),self.gid.clone(),self.logtype.clone(),self.op.clone(),self.res.clone()]
    }

}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EsxLogItem {
    logtype:String,
    pub item:String
}

impl EsxLogItem{
    pub fn to_logs_vec(&self)->Vec<String>{
        vec![self.logtype.clone(),self.item.clone()]
    }

}


pub fn generate_distinct_logs(target_mongodb_collection:&str)->Vec<Document>{
    let deduplicate_pipe_line = vec![
        doc! {
            "$group": {
                "_id":{
                    "uid":"$uid","gid":"$gid","logtype":"$logtype","op":"$op","res":"$res"
                },
                "onlyOne":{"$first":"$$ROOT"}
             }
        },
        doc!{
         "$replaceRoot":{
            "newRoot":"$onlyOne"
         }
        },
        doc!{
         "$out":target_mongodb_collection
        }
    ];
    return deduplicate_pipe_line;
}

pub fn generate_union_logs_unique(to_mongodb_collection:&str,target_mongodb_collection:&str)->Vec<Document>{
    let union_pipe_line = vec![
        doc! {
            "$project":{
                "_id": 0, "gid": 1,  "uid":1, "logtype":1,"op":1,"res":1
            }
        },
        doc!{
            "$unionWith":{
                "coll":to_mongodb_collection,
                "pipeline":vec![doc! {
                    "$project":{
                        "_id": 0, "gid": 1,  "uid":1, "logtype":1,"op":1,"res":1
                    }
                }]
        }
        },
        doc! {
            "$group": {
                "_id":{
                    "uid":"$uid","gid":"$gid","logtype":"$logtype","op":"$op","res":"$res"
                },
                "onlyOne":{"$first":"$$ROOT"}
             }
        },
        doc!{
         "$replaceRoot":{
            "newRoot":"$onlyOne"
         }
        },
        doc!{
         "$out":target_mongodb_collection
        }
    ];
    return union_pipe_line;
}
pub fn generate_union_logs(to_mongodb_collection:&str,target_mongodb_collection:&str)->Vec<Document>{
    let union_pipe_line = vec![
        doc! {
            "$project":{
                "_id": 0, "gid": 1,  "uid":1, "logtype":1,"op":1,"res":1
            }
        },
        doc!{
            "$unionWith":{
                "coll":to_mongodb_collection,
                "pipeline":vec![doc! {
                    "$project":{
                        "_id": 0, "gid": 1,  "uid":1, "logtype":1,"op":1,"res":1
                    }
                }]
            }
        },
        doc!{
         "$out":target_mongodb_collection
        }
    ];
    return union_pipe_line;
}