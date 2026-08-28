// anonymiser.rs
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::classify::ValueType;

/// Cache key ensuring identical raw values map to identical placeholders.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    sensitive: bool,
    vtype: ValueType,
    raw: String,
}

/// Anonymiser holds redaction state, counters, and produces consistent placeholders.
pub struct Anonymiser {
    pub strict: bool,
    pub keep_private_ips: bool,
    cache: HashMap<CacheKey, String>,
    pub counters: HashMap<String, usize>,
}

impl Anonymiser {
    pub fn new(strict: bool, keep_private_ips: bool) -> Self {
        Self {
            strict,
            keep_private_ips,
            cache: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    fn next(&mut self, cat: &str) -> usize {
        let e = self.counters.entry(cat.to_string()).or_insert(0);
        *e += 1;
        *e
    }

    /// Total number of redactions performed.
    pub fn total_redacted(&self) -> usize {
        self.counters.values().sum()
    }

    fn anon_email(&mut self) -> String {
        format!("user{}@example.com", self.next("email"))
    }

    fn anon_ip(&mut self, original: &str) -> String {
        if let Ok(ip) = original.parse::<IpAddr>() {
            if self.keep_private_ips && (ip.is_loopback() || is_private_ip(&ip)) {
                return original.to_string();
            }
            let n = self.next("ip");
            if ip.is_ipv4() {
                // 203.0.113.0/24 — TEST-NET-3 (RFC 5737)
                return format!("203.0.113.{}", ((n - 1) % 254) + 1);
            } else {
                // 2001:db8::/32 (RFC 3849)
                return format!("2001:db8::{:x}", n);
            }
        }
        // Fallback for unparsable but classified as IP
        format!("203.0.113.{}", ((self.next("ip") - 1) % 254) + 1)
    }

    fn anon_url(&mut self, _original: &str) -> String {
        let n = self.next("url");
        // Keep scheme/port concept but replace host/path/credentials/query.
        // We emit https by default; scheme is not critical for redaction safety.
        format!("https://host{}.example.com", n)
    }

    fn anon_path(&mut self, original: &str) -> String {
        let n = self.next("path");
        let ext = Path::new(original)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e))
            .unwrap_or_default();
        format!("/redacted/path-{}{}", n, ext)
    }

    /// Return (and cache) a placeholder for (sensitive, type, raw).
    pub fn placeholder(&mut self, sensitive: bool, vt: ValueType, raw: &str) -> String {
        let key = CacheKey {
            sensitive,
            vtype: vt,
            raw: raw.to_string(),
        };
        if let Some(hit) = self.cache.get(&key) {
            return hit.clone();
        }

        let result = if sensitive {
            format!("REDACTED_{}", self.next("secret"))
        } else {
            match vt {
                ValueType::Email => self.anon_email(),
                ValueType::Ip => self.anon_ip(raw),
                ValueType::Url => self.anon_url(raw),
                ValueType::Path => self.anon_path(raw),
                ValueType::Bool => "false".to_string(),
                ValueType::Int => "0".to_string(),
                ValueType::Float => "0.0".to_string(),
                ValueType::Empty | ValueType::Text => {
                    format!("value_anon_{}", self.next("text"))
                }
            }
        };

        self.cache.insert(key, result.clone());
        result
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 (loopback handled separately)
            (o[0] == 10) || (o[0] == 172 && (o[1] & 0xf0) == 16) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.segments()[0] & 0xfe00 == 0xfc00, // fc00::/7 unique local (approx)
    }
}
