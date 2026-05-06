use std::path::PathBuf;
use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;
use crate::actions::quarantine::QuarantineMeta;
use crate::config::Config;

pub fn command() -> Command {
    Command::new("quarantine")
        .about("Manage quarantined files")
        .subcommand(Command::new("list").about("List quarantined files"))
        .subcommand(
            Command::new("restore")
                .about("Restore a quarantined file to its original location")
                .arg(
                    Arg::new("id")
                        .help("Quarantine ID (UUID)")
                        .required(true)
                        .index(1),
                ),
        )
}

pub fn run(
    _matches: &ArgMatches,
    subcommand_matches: &ArgMatches,
) -> Result<CmdExit> {
    let qdir = Config::expand_path("~/.tav/quarantine");

    match subcommand_matches.subcommand() {
        Some(("list", _)) => list_quarantine(&qdir),
        Some(("restore", m)) => {
            let id = m.get_one::<String>("id").unwrap();
            restore_quarantine(&qdir, id)
        }
        _ => {
            println!("Usage: tav quarantine <list|restore>");
            Ok(CmdExit { code: exitcode::OK, message: None })
        }
    }
}

fn list_quarantine(qdir: &PathBuf) -> Result<CmdExit> {
    if !qdir.exists() {
        println!("Quarantine directory is empty ({})", qdir.display());
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    let mut entries: Vec<QuarantineMeta> = Vec::new();
    for entry in std::fs::read_dir(qdir)? {
        let entry = entry?;
        let path  = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<QuarantineMeta>(&text) {
                    entries.push(meta);
                }
            }
        }
    }

    if entries.is_empty() {
        println!("No quarantined files.");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    entries.sort_by(|a, b| a.quarantined_at.cmp(&b.quarantined_at));

    println!("{:<38}  {:<25}  {:<60}  {}", "ID", "DATE", "ORIGINAL PATH", "RULE");
    println!("{}", "─".repeat(140));
    for m in &entries {
        println!(
            "{:<38}  {:<25}  {:<60}  {}",
            m.id,
            m.quarantined_at.format("%Y-%m-%d %H:%M:%S UTC"),
            m.original_path.display(),
            m.matched_rule,
        );
    }

    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn restore_quarantine(qdir: &PathBuf, id: &str) -> Result<CmdExit> {
    let meta_path = qdir.join(format!("{}.meta.json", id));
    let file_path = qdir.join(id);

    if !meta_path.exists() {
        return Ok(CmdExit {
            code: exitcode::NOINPUT,
            message: Some(format!("No quarantine entry found for ID: {}", id)),
        });
    }

    let meta: QuarantineMeta = serde_json::from_str(&std::fs::read_to_string(&meta_path)?)?;

    if let Some(parent) = meta.original_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Try rename first; fall back to copy+remove on cross-device
    match std::fs::rename(&file_path, &meta.original_path) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(18) => {
            std::fs::copy(&file_path, &meta.original_path)?;
            std::fs::remove_file(&file_path)?;
        }
        Err(e) => return Err(e.into()),
    }

    std::fs::remove_file(&meta_path)?;
    println!("Restored: {} -> {}", id, meta.original_path.display());

    Ok(CmdExit { code: exitcode::OK, message: None })
}
