use std::{collections::HashMap, thread};
use std::time::Duration;
use std::fs::File;
use std::io::BufReader;
use tav::ConfigData;
use sysinfo::{
    Process, Signal, System, Users
};

const INTERVAL: u64 = 500;

fn main() -> Result<(), serde_yaml::Error> {
    let file = File::open("conf/config.yaml").expect("Missing config.yaml file");
    let buf_reader = BufReader::new(file);
    let testing: ConfigData = serde_yaml::from_reader(buf_reader)?;

    let fs_watch = &testing.fs.watch.unwrap_or_else(|| Vec::new());
    let fs_blacklist = &testing.fs.blacklist.unwrap_or_else(|| Vec::new());
    let ps_watch = &testing.ps.watch.unwrap_or_else(|| Vec::new());
    let ps_blacklist = &testing.ps.blacklist.unwrap_or_else(|| Vec::new());
    let ps_prohibit = &testing.ps.prohibit.unwrap_or_else(|| HashMap::new());
    let mut handles = Vec::new();

    let l1 = ps_watch.clone();
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

    let l2 = ps_blacklist.clone();
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

    let l3 = ps_prohibit.clone();
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

    for d in fs_watch {
        let d1 = d.clone();
        let l1 = fs_blacklist.clone();
        let h1 = thread::spawn(move || {
            println!("walking: {}", &d1);
            if let Err(e) = tav::files::walk(&d1, &l1) {
                println!("error: {:?}", e);
            } else {
                println!("done walking: {}", &d1);
            }
        });

        handles.push(h1);

        let d2 = d.clone();
        let l2 = fs_blacklist.clone();
        let h2 = thread::spawn(move || {
            println!("watching: {}", &d2);
            if let Err(e) = tav::files::watch(&d2, &l2) {
                println!("error: {:?}", e);
            }
        });

        handles.push(h2);
    }

    for h in handles {
        h.join().unwrap();
    }

    Ok(())
}

fn ps_log(process: &Process, prefix: &str) {
    let pid = process.pid();
    let users = Users::new_with_refreshed_list();

    if let Some(uid) = process.effective_user_id() {
        let user = users.get_user_by_id(uid).unwrap();
        println!("{prefix}: [{pid}] {} ({}) {}", process.name(), process.cmd().join(" "), user.name());
    } else {
        println!("{prefix}: [{pid}] {} ({})", process.name(), process.cmd().join(" "));
    }
}

fn ps_match(process: &Process, subject: &String) -> bool {
    let cmd = process.cmd().join(" ");
    let exe = process.exe().unwrap().to_str().unwrap();
    let name = process.name();

    return cmd.contains(subject) || exe.contains(subject) || name.contains(subject);
}
