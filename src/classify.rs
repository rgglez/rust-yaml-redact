// classify.rs
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

use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;

use crate::patterns::BOOL_LITERALS;
use saphyr::YamlOwned;

/// Classification of a scalar value for redaction purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueType {
    Empty,
    Bool,
    Int,
    Float,
    Email,
    Ip,
    Url,
    Path,
    Text,
}

static INTEGER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[+-]?\d+$").unwrap());

static FLOAT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[+-]?\d*\.\d+$").unwrap());

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap());

static SCHEME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.\-]*://").unwrap());

static WINDOWS_PATH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z]:\\").unwrap());

/// Classify a saphyr YAML node. `raw` is a precomputed textual form (used for
/// regex heuristics and for caching consistency with the original representation).
pub fn classify_yaml_scalar(v: &YamlOwned, raw: &str) -> ValueType {
    // Peel tags for classification purposes.
    if let YamlOwned::Tagged(_, inner) = v {
        return classify_yaml_scalar(inner, raw);
    }

    if v.is_null() {
        return ValueType::Empty;
    }

    // Native boolean scalar
    if v.as_bool().is_some() {
        return ValueType::Bool;
    }

    // Native integer/float
    if v.as_integer().is_some() {
        let t = raw.trim();
        if t.contains('.') || t.to_ascii_lowercase().contains('e') {
            return ValueType::Float;
        }
        return ValueType::Int;
    }
    if v.as_floating_point().is_some() {
        return ValueType::Float;
    }

    // String content or raw representation.
    let t = if let Some(s) = v.as_str() {
        s.trim().to_string()
    } else if let YamlOwned::Representation(s, _, _) = v {
        s.trim().to_string()
    } else {
        raw.trim().to_string()
    };

    if t.is_empty() {
        return ValueType::Empty;
    }
    let low = t.to_lowercase();

    if BOOL_LITERALS.iter().any(|b| *b == low) {
        return ValueType::Bool;
    }
    if INTEGER_RE.is_match(&t) {
        return ValueType::Int;
    }
    if FLOAT_RE.is_match(&t) {
        return ValueType::Float;
    }

    if EMAIL_RE.is_match(&t) {
        return ValueType::Email;
    }
    if SCHEME_RE.is_match(&t) {
        return ValueType::Url;
    }
    if t.parse::<IpAddr>().is_ok() {
        return ValueType::Ip;
    }

    if t.starts_with('/')
        || t.starts_with("~/")
        || t.starts_with("./")
        || t.starts_with("../")
        || WINDOWS_PATH_RE.is_match(&t)
    {
        return ValueType::Path;
    }

    ValueType::Text
}
