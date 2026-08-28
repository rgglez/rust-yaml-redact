# redactyaml

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**`redactyaml`** reads a YAML file (or a stream) and writes a copy where every
sensitive scalar value is replaced by a safe placeholder, keeping the overall
structure intact (mapping keys, sequence order, quoting style for strings,
numbers, booleans, etc.).

The result is safe to paste into a chatbot or send over a messaging app.

It is the YAML counterpart of
[`redactenv`](https://github.com/rgglez/go-bash-env-redact), using the same
redaction rules and heuristics.

## Usage

```bash
redactyaml [OPTIONS] [INPUT]
```

- `INPUT` — YAML file to read, or `-` for stdin (default).
- `-o, --output <FILE>` — output file (default: stdout).
- `--strict` — redact everything, including booleans, numbers and common enums.
- `--strip-comments` — attempt to remove comments (note: the YAML parser may
  drop comments regardless; this flag is accepted for parity with `redactenv`).
- `--keep-private-ips` — do not redact RFC-1918 / loopback addresses
  (`10.x`, `192.168.x`, `127.0.0.1`, …).
- `--keep <list>` — comma-separated list of exact key names to leave untouched
  (ancestor keys affect the whole subtree).
- `--force <list>` — comma-separated list of exact key names to always redact
  (ancestor keys affect the whole subtree).

### Examples

Redact a file to stdout:

```bash
redactyaml config.yaml
```

Read from stdin, write to a file:

```bash
cat config.yaml | redactyaml - -o redacted.yaml
```

Keep a subtree and private IPs:

```bash
redactyaml --keep db --keep-private-ips config.yaml
```

Force-redact a whole subtree:

```bash
redactyaml --force secrets config.yaml
```

Strict mode (everything becomes a placeholder):

```bash
redactyaml --strict config.yaml
```

## Build

```bash
cargo build --release
```

The resulting binary is at:

```
target/release/redactyaml
```

Cross-compilation examples (choose the target you need):

```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Linux aarch64
cargo build --release --target aarch64-unknown-linux-gnu

# macOS (on macOS or with osxcross)
cargo build --release --target aarch64-apple-darwin

# Windows
cargo build --release --target x86_64-pc-windows-gnu
```

## Installation

Copy the binary to a directory in your `PATH`. For example:

```bash
sudo install -m 0755 target/release/redactyaml /usr/local/bin/
```

## Architecture

The program is a small, single-pass pipeline built around `serde_yaml`:

```
┌─────────────────────────────────────────────────────────────────┐
│                            main.rs                              │
│  Parse flags (clap) → read → parse YAML → redact tree → write   │
└───────┬───────────────────────────────┬─────────────────────────┘
        │                               │
        ▼                               ▼
   ┌──────────┐                   ┌──────────────────┐
   │   cli.rs │                   │   yaml_redact.rs │
   │  Args    │                   │  redact_root     │
   │          │                   │  redact_value    │
   └──────────┘                   │  redact_scalar   │
                                  └────────┬─────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ▼                      ▼                      ▼
             ┌──────────────┐      ┌───────────────┐     ┌────────────────┐
             │  classify.rs │      │ anonymiser.rs │     │   patterns.rs  │
             │classify_…    │◄─────│  Anonymiser   │     │ SENSITIVE_…    │
             │ValueType     │      │  placeholder  │     │ SAFE_TEXT…     │
             └──────────────┘      │  cache        │     │ BOOL_LITERALS  │
                                   └───────────────┘     └────────────────┘
                                           │
                                   ┌───────┴───────┐
                                   │     io.rs     │
                                   │ read_input    │
                                   │ write_output  │
                                   │ split_csv     │
                                   └───────────────┘
```

### Processing pipeline

1. **`main.rs`**
   Uses `clap` to parse flags, reads the input (file or stdin), parses a single
   YAML document via `serde_yaml`, builds `keep`/`force` sets, runs redaction,
   serializes the result, and writes it (file or stdout). A summary with counts
   is printed to stderr.

2. **`yaml_redact.rs`**
   Recursively walks the `serde_yaml::Value` tree.
   - For mappings, the current key name (and ancestor context) drives
     sensitivity decisions and `--keep`/`--force` inheritance.
   - For sequences, the parent key context is inherited.
   - Scalars are classified and optionally replaced.

3. **`classify.rs`**
   `classify_yaml_scalar` returns a `ValueType` (`Empty`, `Bool`, `Int`, `Float`,
   `Email`, `Ip`, `Url`, `Path`, `Text`) using native YAML node kinds plus
   textual heuristics (regex + IP parsing) to mirror the Go tool’s behavior.

4. **`anonymiser.rs`**
   `Anonymiser` decides when to redact and generates consistent placeholders:
   - Sensitive keys (or forced) become `REDACTED_N`.
   - Non-sensitive values produce type-preserving placeholders
     (`userN@example.com`, `203.0.113.x`, `https://hostN.example.com`,
     `/redacted/path-N.ext`, `value_anon_N`).
   - A cache ensures identical raw values map to identical placeholders across
     the document.
   - In non-strict mode, safe literals and enums pass through unchanged.

5. **`patterns.rs`**
   Static lists:
   - `SENSITIVE_PATTERNS` — lowercase substrings that mark a key as sensitive.
   - `SAFE_TEXT_VALUES` — lowercase enums left as-is in non-strict mode.
   - `BOOL_LITERALS` — accepted boolean-like tokens for classification.

6. **`io.rs`** and **`cli.rs`**
   Thin I/O helpers (stdin/stdout via `-`) and the `clap` CLI definition.

## Value detection strategy

Each scalar is classified by type and replaced by a placeholder of the same
type so the redacted file remains useful:

- A mapping key whose **name** contains any sensitive pattern
  (`password`, `token`, `secret`, `key`, `jwt`, `dsn`, `aws`, …) causes its
  value (and subtree) to be redacted as `REDACTED_N`.
- Emails become `userN@example.com`.
- IPv4 addresses become addresses from `203.0.113.0/24` (RFC 5737). IPv6 uses
  the `2001:db8::` prefix (RFC 3849). With `--keep-private-ips`, RFC-1918 and
  loopback addresses are left unchanged.
- URLs keep their scheme and port; host/path/credentials/query are replaced.
- Filesystem paths keep their extension.
- Repeated identical values always map to the same placeholder (consistent
  substitution), preserving relationships between variables.
- In **non-strict** mode, booleans, integers, floats, and common configuration
  enums (`production`, `debug`, `json`, `localhost`, …) are left as-is.

In **strict** mode every scalar is replaced (bools → `false`, ints → `0`,
floats → `0.0`, text → `value_anon_N` or a type-specific placeholder).

## Limitations

- Comment preservation depends on the YAML parser; `--strip-comments` is
  best-effort.
- Sensitive key detection is based on English substrings only.
- Only single-document YAML is processed in one invocation.
- Complex custom tags and anchors/aliases are not specially handled beyond
  what `serde_yaml` provides.

## License

Copyright (C) 2026 Rodolfo González González.

Released under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).
See the [LICENSE](LICENSE) file for details.
