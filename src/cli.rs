// cli.rs
//
// Copyright (C) 2026 Rodolfo González González
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use clap::Parser;

/// Redact sensitive values in YAML files (or stdin), emitting safe placeholders.
/// Analogous to redactenv for .env files.
#[derive(Parser, Debug)]
#[command(name = "redactyaml", version, about, long_about = None)]
pub struct Args {
    /// Input file path, or "-" for stdin
    #[arg(value_name = "INPUT", default_value = "-")]
    pub input: String,

    /// Output file path (default: stdout)
    #[arg(short = 'o', long, value_name = "FILE", default_value = "-")]
    pub output: String,

    /// Redact everything, including booleans, numbers and common enums
    #[arg(long)]
    pub strict: bool,

    /// Remove comments (note: YAML parser may drop comments regardless)
    #[arg(long = "strip-comments")]
    pub strip_comments: bool,

    /// Do not redact RFC-1918 / loopback IP addresses
    #[arg(long = "keep-private-ips")]
    pub keep_private_ips: bool,

    /// Comma-separated list of exact key names to leave untouched
    #[arg(long, value_name = "KEYS")]
    pub keep: Option<String>,

    /// Comma-separated list of exact key names to always redact
    #[arg(long, value_name = "KEYS")]
    pub force: Option<String>,
}
