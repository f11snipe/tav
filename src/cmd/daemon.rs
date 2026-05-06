use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use crate::CmdExit;
use crate::config::Config;

pub fn command() -> Command {
    Command::new("daemon")
        .about("Manage the tav daemon process")
        .subcommand(
            Command::new("start")
                .about("Start tav daemon in the background")
                .arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .default_value("conf/config.yaml"),
                ),
        )
        .subcommand(Command::new("stop").about("Stop the running daemon"))
        .subcommand(Command::new("status").about("Show daemon status"))
        .subcommand(Command::new("reload").about("Reload daemon configuration"))
}

pub fn run(_matches: &ArgMatches, sub: &ArgMatches) -> Result<CmdExit> {
    match sub.subcommand() {
        Some(("start",  m)) => cmd_start(m),
        Some(("stop",   _)) => cmd_stop(),
        Some(("status", _)) => cmd_status(),
        Some(("reload", _)) => cmd_reload(),
        _ => {
            println!("Usage: tav daemon <start|stop|status|reload>");
            Ok(CmdExit { code: exitcode::OK, message: None })
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn pid_path()  -> std::path::PathBuf { Config::expand_path("~/.tav/tav.pid") }
fn sock_path() -> std::path::PathBuf { Config::expand_path("~/.tav/tav.sock") }
fn log_path()  -> std::path::PathBuf { Config::expand_path("~/.tav/tav-daemon.log") }

fn read_pid() -> Option<u32> {
    std::fs::read_to_string(pid_path()).ok()?.trim().parse().ok()
}

fn is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::kill;
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
    #[cfg(not(unix))]
    { let _ = pid; false }
}

// ── Subcommand handlers ───────────────────────────────────────────────────────

fn cmd_start(m: &ArgMatches) -> Result<CmdExit> {
    #[cfg(not(unix))]
    {
        let _ = m;
        println!("Daemon mode is only supported on Unix systems.");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::IntoRawFd;
        use nix::unistd::{dup2, fork, setsid, ForkResult};

        let config_file = m.get_one::<String>("config").unwrap().clone();
        let pid_path    = pid_path();
        let sock_path   = sock_path();
        let log_path    = log_path();

        // Check for existing daemon
        if let Some(pid) = read_pid() {
            if is_alive(pid) {
                println!("Daemon already running (PID {}).", pid);
                return Ok(CmdExit { code: exitcode::OK, message: None });
            }
            let _ = std::fs::remove_file(&pid_path);  // stale
        }

        // Create log dir + file before fork so the parent can report errors.
        if let Some(p) = log_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let log_file = std::fs::OpenOptions::new()
            .create(true).append(true).open(&log_path)?;

        match unsafe { fork()? } {
            ForkResult::Parent { child } => {
                println!("Daemon started (PID {}). Log: {}", child, log_path.display());
            }
            ForkResult::Child => {
                let _ = setsid();

                // Redirect stdin → /dev/null, stdout/stderr → log file
                let null_fd = std::fs::File::open("/dev/null")
                    .map(|f| f.into_raw_fd())
                    .unwrap_or(-1);
                let log_fd = log_file.into_raw_fd();

                if null_fd >= 0 { let _ = dup2(null_fd, 0); }
                let _ = dup2(log_fd, 1);
                let _ = dup2(log_fd, 2);
                if null_fd > 2 { let _ = nix::unistd::close(null_fd); }
                if log_fd  > 2 { let _ = nix::unistd::close(log_fd); }

                // Write PID file
                if let Some(p) = pid_path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let _ = std::fs::write(&pid_path, format!("{}\n", std::process::id()));

                // Start async runtime and run daemon
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");

                let result = rt.block_on(crate::run_daemon_async(
                    std::path::Path::new(&config_file),
                    &sock_path,
                ));

                // Cleanup
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(&sock_path);

                if let Err(e) = result {
                    eprintln!("tav daemon error: {:#}", e);
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }

        Ok(CmdExit { code: exitcode::OK, message: None })
    }
}

fn cmd_stop() -> Result<CmdExit> {
    let Some(pid) = read_pid() else {
        println!("Daemon not running (no PID file).");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    };

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
            Ok(()) => println!("Sent SIGTERM to PID {}.", pid),
            Err(e) => println!("Failed: {}", e),
        }
        let _ = std::fs::remove_file(pid_path());
    }

    #[cfg(not(unix))]
    { let _ = pid; println!("Not supported on this platform."); }

    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_status() -> Result<CmdExit> {
    let Some(pid) = read_pid() else {
        println!("Daemon: not running (no PID file)");
        return Ok(CmdExit { code: exitcode::OK, message: None });
    };

    if !is_alive(pid) {
        println!("Daemon: not running (stale PID {})", pid);
        let _ = std::fs::remove_file(pid_path());
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    let sock = sock_path();
    if sock.exists() {
        match ipc_request(&sock, "status") {
            Ok(resp) => println!("Daemon: running\n{}", resp),
            Err(_)   => println!("Daemon: running (PID {})", pid),
        }
    } else {
        println!("Daemon: running (PID {})", pid);
    }

    Ok(CmdExit { code: exitcode::OK, message: None })
}

fn cmd_reload() -> Result<CmdExit> {
    let sock = sock_path();
    if sock.exists() {
        match ipc_request(&sock, "reload") {
            Ok(resp) => println!("{}", resp),
            Err(e)   => println!("Reload failed: {}", e),
        }
        return Ok(CmdExit { code: exitcode::OK, message: None });
    }

    // Fall back to SIGHUP
    if let Some(pid) = read_pid() {
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            match kill(Pid::from_raw(pid as i32), Signal::SIGHUP) {
                Ok(()) => println!("Sent SIGHUP to PID {}.", pid),
                Err(e) => println!("Failed: {}", e),
            }
        }
    } else {
        println!("Daemon not running.");
    }

    Ok(CmdExit { code: exitcode::OK, message: None })
}

// ── Unix socket IPC helper ────────────────────────────────────────────────────

fn ipc_request(sock: &std::path::Path, cmd: &str) -> Result<String> {
    use std::io::{BufRead, BufReader, Write};
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    #[cfg(not(unix))]
    return Err(anyhow::anyhow!("Unix sockets not available on this platform"));

    #[cfg(unix)]
    {
        let mut stream = UnixStream::connect(sock)?;
        stream.write_all(format!("{}\n", cmd).as_bytes())?;
        let mut lines = BufReader::new(stream).lines();
        let response = lines.next().transpose()?.unwrap_or_default();
        Ok(response)
    }
}
