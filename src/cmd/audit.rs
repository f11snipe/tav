use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;
use crate::config::Config;
use crate::engine::event::ThreatEvent;

pub fn command() -> Command {
    Command::new("audit")
        .about("Query the audit log")
        .arg(
            Arg::new("monitor")
                .long("monitor")
                .short('m')
                .help("Filter by monitor name (e.g. filesystem, processes)")
                .value_name("NAME"),
        )
        .arg(
            Arg::new("severity")
                .long("severity")
                .short('s')
                .help("Filter by minimum severity (info, low, medium, high, critical)")
                .value_name("LEVEL"),
        )
        .arg(
            Arg::new("since")
                .long("since")
                .help("Show events after this ISO 8601 date (e.g. 2026-05-01)")
                .value_name("DATE"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .short('n')
                .help("Maximum number of events to show")
                .value_name("N")
                .default_value("50"),
        )
}

pub fn run(
    _matches: &ArgMatches,
    subcommand_matches: &ArgMatches,
) -> Result<CmdExit> {
    let log_path = Config::expand_path("~/.tav/audit.jsonl");

    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    let monitor_filter  = subcommand_matches.get_one::<String>("monitor");
    let severity_filter = subcommand_matches.get_one::<String>("severity");
    let since_filter    = subcommand_matches.get_one::<String>("since");
    let limit: usize    = subcommand_matches
        .get_one::<String>("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let since_dt: Option<DateTime<Utc>> = since_filter
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(
            &format!("{}T00:00:00Z", s)
        ).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let severity_rank = |s: &str| match s.to_lowercase().as_str() {
        "info"     => 0,
        "low"      => 1,
        "medium"   => 2,
        "high"     => 3,
        "critical" => 4,
        _          => 0,
    };

    let min_severity = severity_filter
        .map(|s| severity_rank(s))
        .unwrap_or(0);

    let content = std::fs::read_to_string(&log_path)?;
    let mut count = 0;

    println!("{:<38}  {:<12}  {:<12}  {:<12}  {:<30}  {}",
        "ID", "TIME", "MONITOR", "SEVERITY", "ACTION", "RULE");
    println!("{}", "─".repeat(130));

    for line in content.lines().rev() {
        if count >= limit { break; }
        let Ok(event) = serde_json::from_str::<ThreatEvent>(line) else { continue };

        // Apply filters
        if let Some(m) = monitor_filter {
            if event.monitor != *m { continue; }
        }
        if let Some(ref dt) = since_dt {
            if &event.timestamp < dt { continue; }
        }
        let ev_severity = format!("{:?}", event.severity).to_lowercase();
        if severity_rank(&ev_severity) < min_severity { continue; }

        let action = event.action_taken
            .as_ref()
            .map(|a| format!("{:?}", a))
            .unwrap_or_else(|| "—".to_string());

        println!(
            "{:<38}  {:<12}  {:<12}  {:<12}  {:<30}  {}",
            event.id,
            event.timestamp.format("%H:%M:%S"),
            event.monitor,
            ev_severity,
            action,
            event.matched_rule,
        );
        count += 1;
    }

    if count == 0 {
        println!("No matching events.");
    }

    Ok(CmdExit { code: exitcode::OK, message: None })
}
