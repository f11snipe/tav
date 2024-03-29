//! # tav
//!
//! `tav` is a minimal, portable terminal antivirus

use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;
use regex::Regex;
use serde::{Serialize, Deserialize};
use tracing::info;

pub mod filesystem;
pub mod processes;

pub mod cli;
pub mod cmd;
pub mod data;
pub use data::CmdExit;


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigGroup {
    pub watch: Option<Vec<String>>,
    pub prohibit: Option<HashMap<String, Vec<String>>>,
    pub blacklist: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigData {
    pub fs: ConfigGroup,
    pub ps: ConfigGroup,
}

pub fn compare_regex(subject: &str, blacklisted: &String) -> bool {
    let re = Regex::new(format!("(?mi){}", blacklisted).as_str()).unwrap();
    let Some(_) = re.captures(subject) else {
        return false;
    };
    info!("Found match for: '{}' ({})", blacklisted, subject);
    return true;
}

pub fn config(config_file: &str) -> Result<(), serde_yaml::Error> {
    let file = File::open(config_file).expect("Missing config file");
    let buf_reader = BufReader::new(file);
    let config: ConfigData = serde_yaml::from_reader(buf_reader)?;

    println!("Loaded Config: {:?}", config_file);
    dbg!(config);

    Ok(())
}

pub fn run(config_file: &str) -> Result<(), serde_yaml::Error> {
    let file = File::open(config_file).expect("Missing config file");
    let buf_reader = BufReader::new(file);
    let config: ConfigData = serde_yaml::from_reader(buf_reader)?;

    let fs_watch = &config.fs.watch.unwrap_or_else(|| Vec::new());
    let fs_blacklist = &config.fs.blacklist.unwrap_or_else(|| Vec::new());
    let ps_watch = &config.ps.watch.unwrap_or_else(|| Vec::new());
    let ps_blacklist = &config.ps.blacklist.unwrap_or_else(|| Vec::new());
    let ps_prohibit = &config.ps.prohibit.unwrap_or_else(|| HashMap::new());
    let mut handles = Vec::new();

    processes::handle(ps_watch, ps_blacklist, ps_prohibit, &mut handles);
    filesystem::handle(fs_watch, fs_blacklist, &mut handles);

    for h in handles {
        h.join().unwrap();
    }

    Ok(())
}
