use std::ops::Add;
use anyhow::{Context as _, Error, Result};
use chrono::Local;
use log::{Level, LevelFilter};
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::file::FileAppender;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::Config;
use log4rs::config::{Appender, Root};
use log4rs::encode::json::JsonEncoder;
use log4rs::encode::pattern::PatternEncoder;


pub fn log_error(err:Error,level: Option<Level>){
    let chain = err.chain();

    for (i,err) in chain.enumerate(){
        // Treat first element in chain differently.
        if i ==0 {
            if let Some(level) = level{
                log::log!(level,"{}",err)
            } else {
                log::error!("{}",err)
            }
            continue;
        }
        if let Some(level) = level {
            log::log!(level, "\t| {}", err)
        } else {
            log::error!("\t| {}", err)
        }
    }
}

/// Configure logging
pub fn configure(log_level: LevelFilter, log_file:Option<&str>) ->Result<()>{
    let config_builder = Config::builder();


    // Log to stderr
    // let stderr = ConsoleAppender::builder()
    //     .encoder(Box::new(PatternEncoder::new("{h([{l}])}: {m}\n")))
    //     .target(Target::Stderr)
    //     .build();
    // let config_builder =
    //     config_builder.appender(Appender::builder().build("stderr", Box::new(stderr)));

    // Log to file
    let config_builder = match log_file {
        Some(log_file) => {
            let file = FileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "{{\"time\":\"{d(%Y-%m-%dT%H:%M:%S)}\",\"{l}\":{m}}}\n",
                )))
                .build(log_file)
                .context("Failed to configure logging to file")?;
            config_builder.appender(Appender::builder().build("file", Box::new(file)))
        }
        None => config_builder,
    };
    // Log to file
    // let config_builder = match log_file {
    //     Some(log_file) => {
    //         let file = FileAppender::builder()
    //             .encoder(Box::new(JsonEncoder::new()
    //             ))
    //             .build(log_file)
    //             .context("Failed to configure logging to file")?;
    //         config_builder.appender(Appender::builder().build("file", Box::new(file)))
    //     }
    //     None => config_builder,
    // };




    // Configure root logger
    // let root_builder = Root::builder().appender("stderr");
    let root_builder = Root::builder();
    let root_builder = match log_file {
        Some(_) => root_builder.appender("file"),
        None => root_builder,
    };

    // Build final config
    let config = config_builder
        .build(root_builder.build(log_level))
        .context("Failed to create logging configuration object")?;

    // Configure the logger
    log4rs::init_config(config).context("Failed to configure logging")?;

    Ok(())

}
