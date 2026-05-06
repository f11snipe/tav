use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;

pub fn command() -> Command {
    Command::new("run")
        .about("Run all monitors in the foreground (Ctrl-C to stop)")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .help("Path to config file (yaml)")
                .value_name("FILE")
                .default_value("conf/config.yaml")
        )
}

pub fn run(
    _matches: &ArgMatches,
    subcommand_matches: &ArgMatches,
) -> Result<CmdExit> {
    let config_file = subcommand_matches.get_one::<String>("config").unwrap();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(crate::run_async(std::path::Path::new(config_file)))?;

    Ok(CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
