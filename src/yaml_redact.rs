// yaml_redact.rs
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

use std::collections::HashSet;

use saphyr::{MappingOwned, ScalarOwned, YamlOwned};

use crate::anonymiser::Anonymiser;
use crate::classify::{classify_yaml_scalar, ValueType};

/// Context flags propagated down the YAML tree.
#[derive(Clone, Copy, Default)]
pub(crate) struct Ctx {
    /// If true, do not redact anything in this subtree (honors --keep on an ancestor key).
    preserve: bool,
    /// If true, force-redact everything in this subtree (honors --force on an ancestor key).
    force_redact: bool,
}

/// Recursively redact a YAML tree using saphyr `YamlOwned`.
///
/// `current_key` is the nearest ancestor mapping key name (string), used for sensitivity.
/// For sequence items, the parent's key name is inherited.
pub(crate) fn redact_value(
    v: YamlOwned,
    current_key: Option<&str>,
    anon: &mut Anonymiser,
    keep: &HashSet<String>,
    force: &HashSet<String>,
    ctx: Ctx,
) -> YamlOwned {
    // Peel a single level of tag for traversal decisions; we re-wrap if needed.
    if let YamlOwned::Tagged(tag, inner) = v {
        let inner_redacted = redact_value(*inner, current_key, anon, keep, force, ctx);
        return YamlOwned::Tagged(tag, Box::new(inner_redacted));
    }

    match v {
        YamlOwned::Mapping(map) => {
            let mut out: MappingOwned = MappingOwned::new();
            for (k, val) in map {
                // Determine a string key name for sensitivity context if the key is a string scalar.
                let key_str = match &k {
                    YamlOwned::Value(ScalarOwned::String(s)) => Some(s.as_str()),
                    YamlOwned::Representation(s, _, _) => Some(s.as_str()),
                    _ => None,
                };

                // Exact key matches (string keys only) take effect at this level.
                let mut key_preserve = false;
                let mut key_force = false;
                if let Some(ks) = key_str {
                    key_preserve = keep.contains(ks);
                    key_force = force.contains(ks);
                }

                let next_ctx = Ctx {
                    preserve: ctx.preserve || key_preserve,
                    force_redact: ctx.force_redact || key_force,
                };

                // For nested structures, pass the string form of this key (if any) as the new current_key.
                let next_key = key_str.or(current_key);

                let redacted_val = redact_value(val, next_key, anon, keep, force, next_ctx);
                out.insert(k, redacted_val);
            }
            YamlOwned::Mapping(out)
        }
        YamlOwned::Sequence(seq) => {
            let out: Vec<YamlOwned> = seq
                .into_iter()
                .map(|item| redact_value(item, current_key, anon, keep, force, ctx))
                .collect();
            YamlOwned::Sequence(out)
        }
        scalar => redact_scalar(scalar, current_key, anon, ctx),
    }
}

fn redact_scalar(v: YamlOwned, key: Option<&str>, anon: &mut Anonymiser, ctx: Ctx) -> YamlOwned {
    // Preserve takes absolute precedence (from --keep on this key or an ancestor).
    if ctx.preserve {
        return v;
    }

    // Compute a stable "raw" textual form used for classification + caching.
    let raw = match &v {
        YamlOwned::Value(s) => match s {
            ScalarOwned::Null => String::new(),
            ScalarOwned::Boolean(b) => (if *b { "true" } else { "false" }).to_string(),
            ScalarOwned::Integer(i) => i.to_string(),
            ScalarOwned::FloatingPoint(f) => f.to_string(),
            ScalarOwned::String(s) => s.clone(),
        },
        YamlOwned::Representation(s, _, _) => s.clone(),
        YamlOwned::BadValue => String::new(),
        YamlOwned::Alias(_) => return v, // pass-through
        _ => return v,                   // sequences/mappings shouldn't reach here
    };

    // Determine sensitivity from current key (string key only).
    let sensitive = if ctx.force_redact {
        true
    } else if let Some(k) = key {
        is_sensitive_key(k)
    } else {
        false
    };

    let vt = classify_yaml_scalar(&v, &raw);

    // Non-strict pass-through for obviously safe values when not sensitive.
    if !sensitive && !anon.strict {
        match vt {
            ValueType::Bool | ValueType::Int | ValueType::Float => {
                return v;
            }
            ValueType::Text
                if crate::patterns::SAFE_TEXT_VALUES
                    .iter()
                    .any(|s| *s == raw.to_lowercase()) =>
            {
                return v;
            }
            _ => {}
        }
    }

    // Produce replacement.
    let placeholder = anon.placeholder(sensitive, vt, &raw);

    if sensitive {
        // Always a string scalar for sensitive secrets.
        YamlOwned::Value(ScalarOwned::String(placeholder))
    } else {
        // Non-sensitive strict placeholders use native scalars when possible.
        match vt {
            ValueType::Bool => YamlOwned::Value(ScalarOwned::Boolean(false)),
            ValueType::Int => YamlOwned::Value(ScalarOwned::Integer(0)),
            ValueType::Float => {
                YamlOwned::Value(ScalarOwned::FloatingPoint(ordered_float::OrderedFloat(0.0)))
            }
            // Email, Ip, Url, Path, Text, Empty -> string placeholder
            _ => YamlOwned::Value(ScalarOwned::String(placeholder)),
        }
    }
}

/// Case-insensitive substring match against SENSITIVE_PATTERNS (mirrors Go behavior).
fn is_sensitive_key(name: &str) -> bool {
    let low = name.to_lowercase();
    crate::patterns::SENSITIVE_PATTERNS
        .iter()
        .any(|p| low.contains(*p))
}

/// Public entry point used by main.
pub fn redact_root(
    v: YamlOwned,
    anon: &mut Anonymiser,
    keep: &HashSet<String>,
    force: &HashSet<String>,
) -> YamlOwned {
    redact_value(v, None, anon, keep, force, Ctx::default())
}

// Silence unused warnings at the top-level API surface while keeping the
// signatures stable for future extension / recursion.
#[allow(dead_code)]
fn _keep_force_symmetry(_keep: &HashSet<String>, _force: &HashSet<String>) {}
