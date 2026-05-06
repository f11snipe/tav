use anyhow::Result;
use clap::{crate_version, ArgAction};
use clap::{Arg, ArgMatches, Command};
use tracing::info;

pub fn command() -> Command {
    Command::new("tav")
        .version(crate_version!())
        .about("Minimal, portable terminal antivirus for Unix systems")
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
    println!("Usage: tav [OPTIONS] <COMMAND>\n");
    println!("Commands:");
    println!("  run         Run all monitors in the foreground");
    println!("  config      Parse and display the config file");
    println!("  audit       Query the audit log");
    println!("  quarantine  List or restore quarantined files");
    println!("  intel       Manage the threat intelligence database");
    println!("  daemon      Start / stop / reload the background daemon");
    println!("  watch       Live TUI dashboard (requires --features tui)\n");
    println!("Options:");
    println!("  -v, --verbose    Enable info-level log output");
    println!("  -B, --no-banner  Suppress the startup banner\n");
    println!("Examples:");
    println!("  tav run -c ~/.tav/config.yaml");
    println!("  tav daemon start -c ~/.tav/config.yaml");
    println!("  tav audit --severity high --monitor filesystem");
    println!("  tav intel update -c ~/.tav/config.yaml");
    println!("  tav quarantine list\n");
    println!("Run `tav <COMMAND> --help` for subcommand-specific options.");
    Ok(crate::CmdExit {
        code: exitcode::OK,
        message: None,
    })
}
