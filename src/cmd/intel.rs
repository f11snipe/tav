use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;
use crate::config::Config;
use crate::intel::IntelDb;

pub fn command() -> Command {
    Command::new("intel")
        .about("Manage threat intelligence (hashes, domains)")
        .subcommand(
            Command::new("add")
                .about("Add a single indicator")
                .subcommand(
                    Command::new("hash")
                        .about("Add a SHA-256 hash to the blocklist or allowlist")
                        .arg(Arg::new("hash").required(true).index(1).help("SHA-256 hex string (64 chars)"))
                        .arg(Arg::new("list").long("list").short('l')
                            .value_parser(["blocklist", "allowlist"]).default_value("blocklist"))
                        .arg(Arg::new("note").long("note").short('n').help("Optional note"))
                )
                .subcommand(
                    Command::new("domain")
                        .about("Add a domain to the blocklist or allowlist")
                        .arg(Arg::new("domain").required(true).index(1))
                        .arg(Arg::new("list").long("list").short('l')
                            .value_parser(["blocklist", "allowlist"]).default_value("blocklist"))
                        .arg(Arg::new("note").long("note").short('n').help("Optional note"))
                )
        )
        .subcommand(
            Command::new("list")
                .about("List intel entries")
                .arg(Arg::new("type").long("type").short('t')
                    .value_parser(["hash", "domain"]).default_value("hash"))
                .arg(Arg::new("list").long("list").short('l')
                    .value_parser(["blocklist", "allowlist"]))
                .arg(Arg::new("limit").long("limit").short('n').default_value("50"))
        )
        .subcommand(
            Command::new("import")
                .about("Bulk-import a flat file of hashes or domains (one per line, # comments ok)")
                .arg(Arg::new("file").required(true).index(1).help("Path to flat file"))
                .arg(Arg::new("type").long("type").short('t')
                    .value_parser(["hash", "domain"]).default_value("hash"))
                .arg(Arg::new("list").long("list").short('l')
                    .value_parser(["blocklist", "allowlist"]).default_value("blocklist"))
        )
        .subcommand(
            Command::new("status")
                .about("Show intel database statistics")
        )
}

pub fn run(
    _matches: &ArgMatches,
    subcommand_matches: &ArgMatches,
) -> Result<CmdExit> {
    let db_path = Config::intel_db_path();

    match subcommand_matches.subcommand() {
        Some(("add", add_m)) => cmd_add(add_m, &db_path),
        Some(("list", list_m)) => cmd_list(list_m, &db_path),
        Some(("import", imp_m)) => cmd_import(imp_m, &db_path),
        Some(("status", _)) => cmd_status(&db_path),
        _ => {
            println!("Usage: tav intel <add|list|import|status>");
            Ok(CmdExit { code: exitcode::OK, message: None })
        }
    }
}

fn cmd_add(m: &ArgMatches, db_path: &std::path::Path) -> Result<CmdExit> {
    let db = IntelDb::open(db_path)?;

    match m.subcommand() {
        Some(("hash", hm)) => {
            let hash      = hm.get_one::<String>("hash").unwrap();
            let list_type = hm.get_one::<String>("list").map(|s| s.as_str()).unwrap_or("blocklist");
            let note      = hm.get_one::<String>("note").map(|s| s.as_str());
            db.add_hash(hash, list_type, note)?;
            println!("Added {} to {}", hash, list_type);
        }
        Some(("domain", dm)) => {
            let domain    = dm.get_one::<String>("domain").unwrap();
            let list_type = dm.get_one::<String>("list").map(|s| s.as_str()).unwrap_or("blocklist");
            let note      = dm.get_one::<String>("note").map(|s| s.as_str());
            db.add_domain(domain, list_type, note)?;
            println!("Added {} to {}", domain, list_type);
        }
        _ => println!("Usage: tav intel add <hash|domain>"),
    }
    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_list(m: &ArgMatches, db_path: &std::path::Path) -> Result<CmdExit> {
    let db       = IntelDb::open(db_path)?;
    let kind     = m.get_one::<String>("type").map(|s| s.as_str()).unwrap_or("hash");
    let list     = m.get_one::<String>("list").map(|s| s.as_str());
    let limit: usize = m.get_one::<String>("limit").and_then(|s| s.parse().ok()).unwrap_or(50);

    let entries = if kind == "hash" {
        db.list_hashes(list, limit)?
    } else {
        db.list_domains(list, limit)?
    };

    if entries.is_empty() {
        println!("No entries.");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    println!("{:<68}  {:<12}  {:<30}  {}", "VALUE", "LIST", "ADDED", "NOTE");
    println!("{}", "─".repeat(120));
    for e in &entries {
        println!("{:<68}  {:<12}  {:<30}  {}",
            e.value, e.list_type, e.added_at, e.note.as_deref().unwrap_or(""));
    }
    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_import(m: &ArgMatches, db_path: &std::path::Path) -> Result<CmdExit> {
    let file      = m.get_one::<String>("file").unwrap();
    let kind      = m.get_one::<String>("type").map(|s| s.as_str()).unwrap_or("hash");
    let list_type = m.get_one::<String>("list").map(|s| s.as_str()).unwrap_or("blocklist");

    let content = std::fs::read_to_string(file)?;
    let db      = IntelDb::open(db_path)?;

    let count = if kind == "hash" {
        db.import_hashes_from_str(&content, list_type)?
    } else {
        db.import_domains_from_str(&content, list_type)?
    };

    println!("Imported {} {} entries into {}", count, kind, list_type);
    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_status(db_path: &std::path::Path) -> Result<CmdExit> {
    if !db_path.exists() {
        println!("Intel DB does not exist yet: {}", db_path.display());
        println!("Run `tav intel add hash <sha256>` or `tav intel import` to create it.");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }
    let db = IntelDb::open(db_path)?;
    let (bl, al) = db.count_hashes()?;
    let domains  = db.load_blocked_domains()?.len();
    println!("Intel DB: {}", db_path.display());
    println!("  Hashes: {} blocklist, {} allowlist", bl, al);
    println!("  Domains: {} blocked", domains);
    Ok(CmdExit { code: exitcode::OK, message: None })
}
