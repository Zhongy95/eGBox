use std::process::Command;
use clap::ArgMatches;
use anyhow::{bail, Context, Result};

/// Main entrypoint into the daemon.
pub fn main(args:&ArgMatches) -> Result<()> {
    // Run the correct subcommand
    let result = match args.subcommand() {
        ("mine",_) =>mining_from_tab(),
        (unkown,_)=>bail!("Unknown subcommand {}",unkown)
    };



    Ok(())
}

fn mining_from_tab() -> Result<()> {
    Command::new("python3").arg("esxminer/src/OrangeMinert.py");

    Ok(())
}