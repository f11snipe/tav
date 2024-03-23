//! # tav
//!
//! `tav` is a minimal, portable terminal antivirus

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

pub mod files;

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
