use crate::cmd;

pub fn run() {
    let app = cmd::default::command()
        .subcommand(cmd::run::command())
        .subcommand(cmd::config::command())
        .subcommand(cmd::ping::command());

    let v = app.render_version();
    let matches = app.get_matches();

    // use info! or trace! etc. to log
    // to instrument use `#[tracing::instrument(level = "trace", skip(session), err)]`
    cmd::tracing(&matches);
    cmd::banner(&v, &matches);

    let res = matches.subcommand().map_or_else(
        || cmd::default::run(&matches),
        |tup| match tup {
            ("run", subcommand_matches) => cmd::run::run(&matches, subcommand_matches),
            ("config", subcommand_matches) => cmd::config::run(&matches, subcommand_matches),
            ("ping", subcommand_matches) => cmd::ping::run(&matches, subcommand_matches),
            _ => unreachable!(),
        },
    );

    cmd::result_exit(res);
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_run() {
        // run();
        assert_eq!(5, 5);
    }
}
