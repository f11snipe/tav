use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;

pub fn command() -> Command {
    Command::new("config")
        .about("Config test")
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
    _subcommand_matches: &ArgMatches,
) -> Result<CmdExit> {
    let config_file = _subcommand_matches.get_one::<String>("config").unwrap();
    println!("Running with config: {}", config_file);
    crate::config(config_file)?;
    Ok(CmdExit {
        code: exitcode::OK,
        message: Some("Goodbye".to_string()),
    })
}
