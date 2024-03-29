use std::{collections::HashMap, thread};
use std::path::Path;
use std::time::Duration;
use sysinfo::{
    Process, Signal, System, Users
};

const INTERVAL: u64 = 250;

pub fn handle(watchlist: &Vec<String>, blacklist: &Vec<String>, prohibited: &HashMap<String, Vec<String>>, handles: &mut Vec<thread::JoinHandle<()>>) {
    let l1 = watchlist.clone();
    let p1 = thread::spawn(move || {
        let mut sys = System::new_all();

        loop {
            sys.refresh_all();
            for (_pid, process) in sys.processes() {
                for p in &l1 {
                    if ps_match(&process, p) {
                        ps_log(process, "FOUND");
                    }
                }
            }
            thread::sleep(Duration::from_millis(INTERVAL));
        }
    });

    handles.push(p1);

    let l2 = blacklist.clone();
    let p2 = thread::spawn(move || {
        let mut sys = System::new_all();

        loop {
            sys.refresh_all();
            for (_pid, process) in sys.processes() {
                for p in &l2 {
                    if ps_match(&process, p) {
                        process.kill_with(Signal::Kill);
                        ps_log(process, "KILLED");
                    }
                }
            }
            thread::sleep(Duration::from_millis(INTERVAL));
        }
    });

    handles.push(p2);

    let l3 = prohibited.clone();
    let p3 = thread::spawn(move || {
        let mut sys = System::new_all();
        let users = Users::new_with_refreshed_list();

        loop {
            sys.refresh_all();
            for (_pid, process) in sys.processes() {
                if let Some(uid) = process.effective_user_id() {
                    let user = users.get_user_by_id(uid).unwrap();
                    for (key, value) in l3.clone().into_iter() {
                        if key == user.name() {
                            for p in &value {
                                if ps_match(&process, p) {
                                    process.kill_with(Signal::Kill);
                                    ps_log(process, "KILLED");
                                }
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(INTERVAL));
        }
    });

    handles.push(p3);
}

pub fn ps_log(process: &Process, prefix: &str) {
    let pid = process.pid();
    let users = Users::new_with_refreshed_list();

    if let Some(uid) = process.effective_user_id() {
        let user = users.get_user_by_id(uid).unwrap();
        println!("{prefix}: [{pid}] {} ({}) {}", process.name(), process.cmd().join(" "), user.name());
    } else {
        println!("{prefix}: [{pid}] {} ({})", process.name(), process.cmd().join(" "));
    }
}

pub fn ps_match(process: &Process, blacklisted: &String) -> bool {
    let cmd = process.cmd().join(" ").to_lowercase();
    let exe = process.exe().unwrap_or_else(|| Path::new("")).to_str().unwrap_or_else(|| "").to_lowercase();
    let name = process.name().to_lowercase();
    let search = blacklisted.to_lowercase();

    return cmd.contains(&search) || exe.contains(&search) || name.contains(&search);
}
