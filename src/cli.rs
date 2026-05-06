use crate::cmd;

pub fn run() {
    let app = cmd::default::command()
        .subcommand(cmd::run::command())
        .subcommand(cmd::config::command())
        .subcommand(cmd::ping::command())
        .subcommand(cmd::quarantine::command())
        .subcommand(cmd::audit::command())
        .subcommand(cmd::intel::command())
        .subcommand(cmd::daemon::command());

    #[cfg(feature = "tui")]
    let app = app.subcommand(cmd::watch::tui::command());

    let v = app.render_version();
    let matches = app.get_matches();

    cmd::tracing(&matches);
    cmd::banner(&v, &matches);

    let res = matches.subcommand().map_or_else(
        || cmd::default::run(&matches),
        |tup| match tup {
            ("run",        m) => cmd::run::run(&matches, m),
            ("config",     m) => cmd::config::run(&matches, m),
            ("ping",       m) => cmd::ping::run(&matches, m),
            ("quarantine", m) => cmd::quarantine::run(&matches, m),
            ("audit",      m) => cmd::audit::run(&matches, m),
            ("intel",      m) => cmd::intel::run(&matches, m),
            ("daemon",     m) => cmd::daemon::run(&matches, m),
            #[cfg(feature = "tui")]
            ("watch",      m) => cmd::watch::tui::run(&matches, m),
            _ => unreachable!(),
        },
    );

    cmd::result_exit(res);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_run() {
        assert_eq!(5, 5);
    }
}
