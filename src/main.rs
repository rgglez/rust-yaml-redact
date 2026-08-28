// main.rs
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

mod anonymiser;
mod classify;
mod cli;
mod io;
mod patterns;
mod yaml_redact;

use std::process;

use clap::Parser;
use saphyr::{LoadableYamlNode, Yaml, YamlEmitter, YamlOwned};

use crate::anonymiser::Anonymiser;
use crate::cli::Args;
use crate::io::{read_input, split_csv, write_output};
use crate::yaml_redact::redact_root;

fn main() {
    let args = Args::parse();

    // Read input
    let input = match read_input(&args.input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("redactyaml: cannot read {:?}: {}", args.input, e);
            process::exit(1);
        }
    };

    // Parse YAML using saphyr (single document). For multi-doc YAML we take only the first doc.
    // LoadableYamlNode provides load_from_str on YamlOwned when the trait is in scope.
    let docs_owned: Vec<YamlOwned> = match YamlOwned::load_from_str(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("redactyaml: cannot parse YAML: {}", e);
            process::exit(1);
        }
    };
    if docs_owned.is_empty() {
        // Nothing to do; emit nothing.
        if let Err(e) = write_output(&args.output, "") {
            eprintln!("redactyaml: cannot write {:?}: {}", args.output, e);
            process::exit(1);
        }
        eprintln!();
        eprintln!("[redactyaml] values redacted: 0  (by category: {{}})");
        return;
    }

    // Take the first document.
    let parsed_owned: YamlOwned = docs_owned.into_iter().next().unwrap();

    // Build keep/force sets
    let keep: std::collections::HashSet<String> =
        args.keep.as_deref().map(split_csv).unwrap_or_default();
    let force: std::collections::HashSet<String> =
        args.force.as_deref().map(split_csv).unwrap_or_default();

    // Redact
    let mut anon = Anonymiser::new(args.strict, args.keep_private_ips);
    let redacted = redact_root(parsed_owned, &mut anon, &keep, &force);

    // Serialize back to YAML using saphyr emitter.
    // We want plain output without a leading '---' to keep parity with previous behavior.
    let mut out_str = String::new();
    {
        let mut emitter = YamlEmitter::new(&mut out_str);
        // Convert owned -> borrowed form for the emitter.
        let doc: Yaml = (&redacted).into();
        // dump always emits a leading '---'.
        if let Err(e) = emitter.dump(&doc) {
            eprintln!("redactyaml: cannot serialize YAML: {}", e);
            process::exit(1);
        }
    }

    // Strip a leading '---\n' if present to keep output style similar to previous behavior.
    let mut output_yaml = if let Some(rest) = out_str.strip_prefix("---\n") {
        rest.to_string()
    } else if let Some(rest) = out_str.strip_prefix("---\r\n") {
        rest.to_string()
    } else {
        out_str
    };
    // Ensure a trailing newline for CLI niceness if not present.
    if !output_yaml.ends_with('\n') {
        output_yaml.push('\n');
    }

    // Write output
    if let Err(e) = write_output(&args.output, &output_yaml) {
        eprintln!("redactyaml: cannot write {:?}: {}", args.output, e);
        process::exit(1);
    }

    // Summary to stderr (do not pollute stdout)
    eprintln!();
    eprintln!(
        "[redactyaml] values redacted: {}  (by category: {:?})",
        anon.total_redacted(),
        anon.counters
    );
}
