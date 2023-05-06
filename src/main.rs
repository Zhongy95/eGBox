// SPDX-License-Identifier: GPL-2
//
// Copyright (C) 2021  William Findlay
//
// Jan. 19, 2021  William Findlay  Created this.

use core::time::Duration;
use chrono::prelude::*;

extern crate chrono;

use anyhow::{bail, Context, Result};
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use plain::Plain;

use bpfESX::audit;
use bpfESX::audit::audit_callback;
use bpfESX::bpf::*;

use bpfESX::policy::config::{net, Conf};
use bpfESX::policy::rule::*;
use bpfESX::uprobe_ext::FindSymbolUprobeExt;
use libbpf_rs::libbpf_sys::bpf_program__attach_lsm;
use std::fs::File;
use std::io::Read;
use std::ops::Add;
use std::path::Path;
use std::thread::sleep;
use clap::{App, AppSettings, Arg, crate_authors, crate_name, crate_version, SubCommand};
use log::LevelFilter::Info;
use bpfESX::log::*;
use bpfESX::subcommands::*;
use bpfESX::utils::get_symbol_address;


fn main() -> Result<()> {
    println!("Hello, world!");
    let app = App::new(crate_name!())
        .version(crate_version!())
        .about("Automated access control with eBPF")
        .author(crate_authors!())
        // If the user supplies no arguments, print help
        .setting(AppSettings::ArgRequiredElseHelp)
        // Make all commands print colored help if available
        .global_setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name("cfg").long("config")
                .takes_value(true)
                .validator(path_validator)
                .help("Use a different config file"),
        )
        .subcommand(
            SubCommand::with_name("daemon")
                .about("Control Esx daemon")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("start")
                        .about("Start the daemon")
                        .display_order(1),
                )
        )
        .subcommand(
        SubCommand::with_name("minner")
            .about("minning policy from logs")
            .setting(AppSettings::ArgRequiredElseHelp)
            .subcommand(
                SubCommand::with_name("mine")
                    .about("mine with deafault log"),
            )
    );
    //
    //Parse arguments
    let args = app.get_matches();
    // //Initialize config
    //
    // //Dispatch to sub command
    match args.subcommand() {
        ("daemon", Some(args)) => daemon::main(args),
        ("minner", Some(args)) => minner::main(args),
        (unknown, _) => bail!("Unkown subcommand {}",unknown),
    }.expect("TODO: panic message");

    // Initialize the logger
    let now = Local::now().format("%Y-%m-%d").to_string();
    let logpath = "log/esxlog".to_string().add(&*now).add(".log");
    bpfESX::log::configure(
        Info,
        Some(&*logpath),
    )?;
    // log::info!("Starting .. ");
    let file_path = "policy/rule_testing.toml";
    let config = parse_config(file_path);

    let skel_builder = BpfESXSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load().context("failed to open")?;

    skel.attach().context("failed to attach")?;

    config.load(&mut skel);
    // Place this process into a BPFContain container

    attach_uprobes(&mut skel).context("Failed to attach uprobes")?;
    // match config.containerize() {
    //     Ok(_) => {}
    //     Err(err) => panic!("Failed to containerize: {:?}", err),
    // }
    println!("successfully attached!");

    let mut ringbuf_builder_c = RingBufferBuilder::default();
    ringbuf_builder_c
        .add(skel.maps().comline_audit_events(), audit::audit_callbackc)
        .context("failed to add callback");
    let ringbuf_c = ringbuf_builder_c.build()?;

    let mut ringbuf_builder_a = RingBufferBuilder::default();
    ringbuf_builder_a
        .add(skel.maps().audit_events(), audit::audit_callbackA)
        .context("failed to add callback");
    let ringbuf_a = ringbuf_builder_a.build()?;

    loop {

        if let Err(e) = ringbuf_c.poll(Duration::new(1, 0)) {
            println!("failed to print ringbuf,")
        }
        if let Err(e) = ringbuf_a.poll(Duration::new(1, 0)) {
            println!("failed to print ringbuf,")
        }

        sleep(Duration::from_millis(50));
    }

}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn parse_config(file_path: &str) -> Conf {
    let mut file = File::open(&file_path).expect("no such file");

    let mut str_val = String::new();

    file.read_to_string(&mut str_val)
        .expect("no such config file");

    let config: Conf = toml::from_str(&str_val).unwrap();

    let config2: Conf = Conf::from_path(file_path).unwrap();

    let profile = &config2.profile;

    println!("profile:{}", profile);
    let fs = &config2.fs;
    let net = &config2.net;

    if let Some(ref fs) = fs {
        for x in fs {
            println!("{:?}", x);
        }
    } else {
        println!("no fs rule");
    }

    if let Some(ref net) = net {
        for x in net {
            println!("{:?}", x);
        }
    }

    // let netPolicy = &config.net;
    // if let Some(ref netPolicy) = netPolicy{
    //     println!("has value");
    // }else {
    //     println!("no value");
    // }

    config2
}

fn load(skel: &mut BpfESXSkel) -> Result<()> {
    Ok(())
}
/// Attach uprobes to events
fn attach_uprobes(skel: &mut BpfESXSkel) -> Result<()> {
    // do_containerize
    // println!("do_c addr :{}", /bin/sh  as *const () as usize);

    let ssh_binary = "/usr/sbin/sshd";
    let ssh_symbol = "setlogin";
    let path_ssh = Path::new("/usr/sbin/sshd");
    let addr = get_symbol_address(ssh_binary,ssh_symbol).expect("failed to find ssh symbol");
    println!("setlogin symbol addr: {}",addr);
    skel.links.uprobe_setlogin = skel
        .progs_mut().
        uprobe_setlogin()
        .attach_uprobe(false,-1,ssh_binary,addr)
        .expect("fail to attach uprobe").into();
    // skel.links.uprobe_setlogin = skel
    //     .progs_mut()
    //     .uprobe_setlogin()
    //     .attach_uprobe_symbol(false, -1, path_ssh, "setlogin").expect("failed to attach uprobe")
    //     .into();

    Ok(())
}

/// Argument validator that ensures a path `arg` exists.
fn path_validator(arg: String) -> Result<(), String> {
    let path = std::path::PathBuf::from(&arg);

    if !path.exists() {
        return Err(format!("Path `{}` does not exist", &arg));
    }

    Ok(())
}