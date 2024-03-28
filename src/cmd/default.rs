use anyhow::Result;
use clap::{crate_version, ArgAction};
use clap::{Arg, ArgMatches, Command};
use tracing::info;

pub fn command() -> Command {
    Command::new("tav")
        .version(crate_version!())
        .about("A basic terminal anti-virus")
        .arg(
            Arg::new("no_banner")
                .short('B')
                .long("no-banner")
                .help("Don't show the banner")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Show additional info logs")
                .action(ArgAction::SetTrue),
        )
}

pub fn run(matches: &ArgMatches) -> Result<crate::CmdExit> {
    info!("Default command (examples) with matches: {:?}", matches);
    println!("Examples:");
    println!("\t# Run with default config: conf/config.yaml");
    println!("\ttav run\n");
    println!("\t# Override config location (path to yaml file)");
    println!("\ttav run --config ./config.yaml\n");
    println!("\t# Load and test/debug config file");
    println!("\ttav config --config ./config.yaml\n");
    Ok(crate::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
