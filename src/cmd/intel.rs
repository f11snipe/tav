use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;
use crate::config::Config;
use crate::intel::IntelDb;

pub fn command() -> Command {
    Command::new("intel")
        .about("Manage threat intelligence (hashes, domains, IPs)")
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
                .subcommand(
                    Command::new("ip")
                        .about("Add an IP address or CIDR range to the blocklist or allowlist")
                        .arg(Arg::new("cidr").required(true).index(1).help("IP address or CIDR (e.g. 10.0.0.1 or 10.0.0.0/8)"))
                        .arg(Arg::new("list").long("list").short('l')
                            .value_parser(["blocklist", "allowlist"]).default_value("blocklist"))
                        .arg(Arg::new("note").long("note").short('n').help("Optional note"))
                )
        )
        .subcommand(
            Command::new("list")
                .about("List intel entries")
                .arg(Arg::new("type").long("type").short('t')
                    .value_parser(["hash", "domain", "ip"]).default_value("hash"))
                .arg(Arg::new("list").long("list").short('l')
                    .value_parser(["blocklist", "allowlist"]))
                .arg(Arg::new("limit").long("limit").short('n').default_value("50"))
        )
        .subcommand(
            Command::new("import")
                .about("Bulk-import a flat file of hashes, domains, or IPs (one per line, # comments ok)")
                .arg(Arg::new("file").required(true).index(1).help("Path to flat file"))
                .arg(Arg::new("type").long("type").short('t')
                    .value_parser(["hash", "domain", "ip"]).default_value("hash"))
                .arg(Arg::new("list").long("list").short('l')
                    .value_parser(["blocklist", "allowlist"]).default_value("blocklist"))
        )
        .subcommand(
            Command::new("update")
                .about("Fetch and import all enabled feeds from config")
                .arg(Arg::new("config").short('c').long("config")
                    .help("Path to config file").default_value("conf/config.yaml"))
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
        Some(("add",    add_m))    => cmd_add(add_m, &db_path),
        Some(("list",   list_m))   => cmd_list(list_m, &db_path),
        Some(("import", imp_m))    => cmd_import(imp_m, &db_path),
        Some(("update", upd_m))    => cmd_update(upd_m, &db_path),
        Some(("status", _))        => cmd_status(&db_path),
        _ => {
            println!("Usage: tav intel <add|list|import|update|status>");
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
        Some(("ip", im)) => {
            let cidr      = im.get_one::<String>("cidr").unwrap();
            let list_type = im.get_one::<String>("list").map(|s| s.as_str()).unwrap_or("blocklist");
            let note      = im.get_one::<String>("note").map(|s| s.as_str());
            // Normalize bare IP
            let normalized = if cidr.contains('/') {
                cidr.clone()
            } else if cidr.contains(':') {
                format!("{}/128", cidr)
            } else {
                format!("{}/32", cidr)
            };
            db.add_ip(&normalized, list_type, None, note)?;
            println!("Added {} to {}", normalized, list_type);
        }
        _ => println!("Usage: tav intel add <hash|domain|ip>"),
    }
    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_list(m: &ArgMatches, db_path: &std::path::Path) -> Result<CmdExit> {
    let db       = IntelDb::open(db_path)?;
    let kind     = m.get_one::<String>("type").map(|s| s.as_str()).unwrap_or("hash");
    let list     = m.get_one::<String>("list").map(|s| s.as_str());
    let limit: usize = m.get_one::<String>("limit").and_then(|s| s.parse().ok()).unwrap_or(50);

    let entries = match kind {
        "hash"   => db.list_hashes(list, limit)?,
        "domain" => db.list_domains(list, limit)?,
        "ip"     => db.list_ips(list, limit)?,
        _        => db.list_hashes(list, limit)?,
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

    let count = match kind {
        "hash"   => db.import_hashes_from_str(&content, list_type)?,
        "domain" => db.import_domains_from_str(&content, list_type)?,
        "ip"     => db.import_ips_from_str(&content, list_type, None)?,
        _        => db.import_hashes_from_str(&content, list_type)?,
    };

    println!("Imported {} {} entries into {}", count, kind, list_type);
    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_update(m: &ArgMatches, db_path: &std::path::Path) -> Result<CmdExit> {
    use std::fs::File;
    use std::io::BufReader;
    use crate::intel::feeds::fetch_and_import;

    let config_file = m.get_one::<String>("config").unwrap();
    let file = File::open(config_file)
        .map_err(|e| anyhow::anyhow!("Cannot open config {}: {}", config_file, e))?;
    let cfg: crate::config::Config = serde_yaml::from_reader(BufReader::new(file))?;

    let enabled_feeds: Vec<_> = cfg.intel.feeds.iter().filter(|f| f.enabled).collect();
    if enabled_feeds.is_empty() {
        println!("No enabled feeds in config. Add feeds under `intel.feeds:` in your config file.");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut total = 0usize;
    for feed in enabled_feeds {
        print!("  Fetching '{}' ({}) ... ", feed.name, feed.feed_type);
        match rt.block_on(fetch_and_import(db_path, feed)) {
            Ok(n)  => { println!("{} records", n); total += n; }
            Err(e) => println!("ERROR: {:#}", e),
        }
    }
    println!("Done. Total records imported: {}", total);
    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_status(db_path: &std::path::Path) -> Result<CmdExit> {
    if !db_path.exists() {
        println!("Intel DB does not exist yet: {}", db_path.display());
        println!("Run `tav intel add hash <sha256>` or `tav intel import` to create it.");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }
    let db = IntelDb::open(db_path)?;
    let (hbl, hal)  = db.count_hashes()?;
    let (dbl, dal)  = db.count_domains()?;
    let (ibl, ial)  = db.count_ips()?;
    let feeds       = db.list_feeds()?;

    println!("Intel DB: {}", db_path.display());
    println!("  Hashes:  {} blocklist, {} allowlist", hbl, hal);
    println!("  Domains: {} blocklist, {} allowlist", dbl, dal);
    println!("  IPs:     {} blocklist, {} allowlist", ibl, ial);

    if !feeds.is_empty() {
        println!("\nFeeds:");
        println!("  {:<30}  {:<8}  {:<10}  {}", "NAME", "TYPE", "RECORDS", "LAST UPDATED");
        println!("  {}", "─".repeat(70));
        for f in &feeds {
            println!("  {:<30}  {:<8}  {:<10}  {}",
                f.name, f.feed_type, f.record_count,
                f.last_updated.as_deref().unwrap_or("never"));
        }
    }
    Ok(CmdExit { code: exitcode::OK, message: None })
}
