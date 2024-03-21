use std::fs;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config};
use std::path::Path;
use walkdir::WalkDir;
use regex::Regex;

fn compare_fs(subject: &str, blacklisted: &String) -> bool {
    // let re = format!("(?m){}", blacklisted).as_str();
    let re = Regex::new(format!("(?m){}", blacklisted).as_str()).unwrap();
    // println!("{:?}", re);
    let Some(_) = re.captures(subject) else {
        // println!("no match! '{}' ({})", blacklisted, subject);
        return false;
    };
    println!("Found match for: '{}' ({})", blacklisted, subject);
    return true;
}

pub fn walk<P: AsRef<Path>>(path: P, blacklist_files: &Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        // println!("{}", entry.path().display());
        for val in blacklist_files {
            if compare_fs(entry.path().to_str().unwrap(), val) {
            // if entry.path().display().to_string().contains(val) {
                println!("DELETE: {}", entry.path().display());
                if entry.path().is_file() {
                    let _ = fs::remove_file(&entry.path());
                }
            }
        }
    }

    Ok(())
}

pub fn watch<P: AsRef<Path>>(path: P, blacklist_files: &Vec<String>) -> notify::Result<()> {
    println!("WATCH WITH BLACKLIST: {:?}", blacklist_files);

    let (tx, rx) = std::sync::mpsc::channel();

    // Automatically select the best implementation for your platform.
    // You can also access each implementation directly e.g. INotifyWatcher.
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    for res in rx {
        match res {
            Ok(event) => {
                // println!("{:?}", event.kind);
                if !event.kind.is_remove() {
                    // println!("changed: {:?}", event);
                    for pp in event.paths {
                        if pp.exists() {
                            match pp.to_str() {
                                Some(nn) => {
                                    for val in blacklist_files {
                                        if compare_fs(nn, val) {
                                            println!("DELETE: {}", nn);
                                            if pp.is_file() {
                                                let _ = fs::remove_file(&pp);
                                            }
                                        }
                                    }
                                },
                                None => println!("none..."),
                            }
                        }
                    }
                }
            },
            Err(e) => println!("watch error: {:?}", e),
        }
    }

    Ok(())
}
