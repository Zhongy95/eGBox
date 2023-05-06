use std::env;
use std::env::args;
use std::fs::{create_dir_all, metadata, OpenOptions, set_permissions};
use std::path::PathBuf;
use daemonize::Daemonize;
use anyhow::{bail, Context, Result};
use clap::ArgMatches;
use fs2::FileExt;
use log::__log_module_path;

/// Main entrypoint into the daemon.
pub fn main(args:&ArgMatches) -> Result<()> {
    // Run the correct subcommand
    let result = match args.subcommand() {
        ("start",_) =>start_daemon(),
        (unkown,_)=>bail!("Unknown subcommand {}",unkown)
    };



    Ok(())
}

fn test(){

}

fn start_daemon() -> Result<()> {
    let base_dir = env::current_dir().expect("not found path");
    let workdir = base_dir.as_path();

    let pidfilebuf = base_dir.join("logs/pidfile");
    let pidfile = pidfilebuf.as_path();

    // Create workdir and set permissions to rwxr-xr-t
    create_dir_all(workdir).context("Failed creating policy directory")?;
    let mut perms = metadata(workdir)
        .context("Failed getting policy directory permissions")?
        .permissions();
    perms.set_readonly(false);
    // perms.set_mode(0o1755);
    set_permissions(workdir, perms).context("Failed setting policy directory permissions")?;

    // Make sure the file is unlocked
    log::info!("Waiting for lock on {:?}...", pidfile);
    let f = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .open(pidfile)
        .context("Failed to open pid file")?;
    f.lock_exclusive().context("Failed to acquire file lock")?;
    f.unlock().context("Failed to release lock")?;

    // Set up the daemon
    let daemonize = Daemonize::new()
        .pid_file(pidfile)
        .working_directory(workdir)
        .exit_action(|| log::info!("Started the daemon!"));

    // Try to start the daemon
    log::info!("Starting daemon...");
    daemonize.start().context("Failed to start the daemon")?;

    // Load BPF and policy, then start work loop
    // let mut context = BpfcontainContext::new(config)?;
    // context.load_policy_from_dir(PathBuf::from(&config.policy.dir))?;
    // context.work_loop();

    Ok(())
}