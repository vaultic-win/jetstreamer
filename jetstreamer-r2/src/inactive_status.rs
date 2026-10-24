//! Conditional status-only retirement. Never establishes archive completion.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand};

mod canary227;
mod capped141;
mod full210;
