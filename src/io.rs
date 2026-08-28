// io.rs
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

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Read entire content from path or stdin if path == "-".
pub fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
    }
}

/// Write content to path or stdout if path == "-".
pub fn write_output(path: &str, content: &str) -> io::Result<()> {
    if path == "-" {
        let mut stdout = io::stdout().lock();
        stdout.write_all(content.as_bytes())?;
        // Ensure a trailing newline for nice CLI behavior if content lacks one.
        if !content.ends_with('\n') {
            stdout.write_all(b"\n")?;
        }
        Ok(())
    } else {
        let mut f = File::create(Path::new(path))?;
        f.write_all(content.as_bytes())?;
        if !content.ends_with('\n') {
            f.write_all(b"\n")?;
        }
        Ok(())
    }
}

/// Split a comma-separated list into a set (trimmed, ignore empties).
pub fn split_csv(s: &str) -> std::collections::HashSet<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}
