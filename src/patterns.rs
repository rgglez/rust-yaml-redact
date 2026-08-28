// patterns.rs
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

/// Lowercase substrings that, when present in a YAML mapping key, indicate the
/// value(s) under that key should be considered sensitive and always redacted.
pub const SENSITIVE_PATTERNS: &[&str] = &[
    "pass",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key",
    "private",
    "credential",
    "cred",
    "auth",
    "access",
    "session",
    "salt",
    "cert",
    "ssh",
    "dsn",
    "jwt",
    "bearer",
    "client_secret",
    "client_id",
    "signature",
    "sign",
    "encrypt",
    "license",
    "otp",
    "pin",
    "webhook",
    "database_url",
    "db_url",
    "smtp",
    "mail_pass",
    "aws",
    "gcp",
    "azure",
    "sentry",
];

/// Lowercase plain-text scalar values that are considered non-sensitive in
/// non-strict mode (safe to leave as-is when the key is not sensitive).
pub const SAFE_TEXT_VALUES: &[&str] = &[
    "production",
    "staging",
    "development",
    "dev",
    "prod",
    "test",
    "local",
    "debug",
    "info",
    "warn",
    "warning",
    "error",
    "critical",
    "trace",
    "verbose",
    "silent",
    "none",
    "null",
    "default",
    "auto",
    "enabled",
    "disabled",
    "utf-8",
    "utf8",
    "json",
    "text",
    "http",
    "https",
    "tcp",
    "udp",
    "localhost",
];

/// Values treated as booleans for classification in non-strict mode.
pub const BOOL_LITERALS: &[&str] = &["true", "false", "yes", "no", "on", "off", "0", "1"];
