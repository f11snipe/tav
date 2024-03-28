use anyhow::Result;
use clap::{ArgMatches, Command};
use crate::CmdExit;

pub fn command() -> Command {
    Command::new("ping")
        .about("Ping Pong")
}

pub fn run(
    _matches: &ArgMatches,
    _subcommand_matches: &ArgMatches,
) -> Result<CmdExit> {
    Ok(CmdExit {
        code: exitcode::OK,
        message: Some("Pong".to_string()),
    })
}
