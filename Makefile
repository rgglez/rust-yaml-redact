# Makefile for redactyaml
#
# Targets
# -------
#  all           Build the debug binary (default).
#  build         Same as all.
#  release       Build the optimised, stripped binary.
#  test          Run the full test suite (unit + integration).
#  test-unit     Run only the library unit tests.
#  test-int      Run only the integration tests.
#  check         Run `cargo check` (type/lint check without producing a binary).
#  clippy        Run clippy with -D warnings (hard fail on any warning).
#  fmt           Auto-format all source files with rustfmt.
#  fmt-check     Check formatting without modifying files (useful in CI).
#  audit         Run cargo-audit to check for known vulnerabilities.
#  install       Install the release binary to $(INSTALL_PREFIX)/bin.
#  uninstall     Remove the installed binary.
#  clean         Remove build artefacts (target/).
#  help          Print this target list.

# ---------------------------------------------------------------------------
# Toolchain
#
# When invoked as root (e.g. `sudo make install`) the rustup shims under
# ~/.cargo/bin are not in PATH.  We look for cargo in the three most common
# locations before giving up, so the right thing happens whether the user
# runs make as themselves or with sudo.

CARGO ?= $(shell \
    command -v cargo 2>/dev/null \
    || ls "$$HOME/.cargo/bin/cargo" 2>/dev/null \
    || ls "$(HOME)/.cargo/bin/cargo" 2>/dev/null \
    || ls "/usr/local/cargo/bin/cargo" 2>/dev/null \
    || echo cargo)

CARGO_ARGS ?=

# ---------------------------------------------------------------------------
# Paths

BINARY      := redactyaml
TARGET_DIR  := target

DEBUG_BIN   := $(TARGET_DIR)/debug/$(BINARY)
RELEASE_BIN := $(TARGET_DIR)/release/$(BINARY)

# Installation prefix.  Override with:  make install PREFIX=/usr/local
PREFIX         ?= $(HOME)/.cargo
INSTALL_PREFIX ?= $(PREFIX)
INSTALL_BIN    := $(INSTALL_PREFIX)/bin/$(BINARY)

# ---------------------------------------------------------------------------
# Source files (used by phony targets to decide whether to rebuild).
# Any change under src/ or tests/ triggers a fresh cargo invocation.

SOURCES := $(shell find src tests -name '*.rs' 2>/dev/null) Cargo.toml Cargo.lock

# ---------------------------------------------------------------------------
# Default target

.DEFAULT_GOAL := all

.PHONY: all build release test test-unit test-int check \
        clippy fmt fmt-check audit install uninstall clean help _check-cargo

# Guard: emit an actionable error when cargo cannot be found, which happens
# most often when running `sudo make install` and sudo resets HOME to /root.
_check-cargo:
	@if ! command -v "$(CARGO)" >/dev/null 2>&1 && [ ! -x "$(CARGO)" ]; then \
	    echo ""; \
	    echo "Error: cargo not found (looked for '$(CARGO)')."; \
	    echo ""; \
	    echo "This usually happens with 'sudo make install' because sudo resets"; \
	    echo "HOME and PATH, hiding the rustup toolchain.  Fix with one of:"; \
	    echo ""; \
	    echo "  sudo make install CARGO=/home/$$SUDO_USER/.cargo/bin/cargo"; \
	    echo "  sudo env PATH=\"$$PATH\" make install"; \
	    echo "  sudo -E make install          # preserve the calling user's env"; \
	    echo ""; \
	    exit 1; \
	fi

# ---------------------------------------------------------------------------
# Build

## all: Build the debug binary (default target).
all: build

## build: Build the debug binary.
build: $(DEBUG_BIN)

$(DEBUG_BIN): $(SOURCES)
	@$(MAKE) _check-cargo
	$(CARGO) build $(CARGO_ARGS)

## release: Build the optimised binary (LTO + strip, as per Cargo.toml [profile.release]).
release: $(RELEASE_BIN)

$(RELEASE_BIN): $(SOURCES)
	@$(MAKE) _check-cargo
	$(CARGO) build --release $(CARGO_ARGS)

# ---------------------------------------------------------------------------
# Tests

## test: Run the full test suite (unit + integration).
test:
	$(CARGO) test $(CARGO_ARGS)

## test-unit: Run only the library unit tests.
test-unit:
	$(CARGO) test --lib $(CARGO_ARGS)

## test-int: Run only the integration tests.
test-int:
	$(CARGO) test --test integration $(CARGO_ARGS) 2>/dev/null || $(CARGO) test $(CARGO_ARGS)

# ---------------------------------------------------------------------------
# Static checks

## check: Run `cargo check` (fast type/lint check, no binary produced).
check:
	@$(MAKE) _check-cargo
	$(CARGO) check $(CARGO_ARGS)

# ---------------------------------------------------------------------------
# Lint / format

## clippy: Run clippy; fail on any warning (-D warnings).
clippy:
	$(CARGO) clippy --all-targets $(CARGO_ARGS) -- -D warnings

## fmt: Auto-format all source files.
fmt:
	$(CARGO) fmt

## fmt-check: Check formatting without modifying files (CI-friendly).
fmt-check:
	$(CARGO) fmt --check

# ---------------------------------------------------------------------------
# Security

## audit: Check dependencies for known vulnerabilities (requires cargo-audit).
audit:
	@command -v cargo-audit >/dev/null 2>&1 || { \
	    echo "cargo-audit not found.  Install it with:"; \
	    echo "  cargo install cargo-audit"; \
	    exit 1; \
	}
	$(CARGO) audit

# ---------------------------------------------------------------------------
# Install / uninstall

## install: Install the release binary to $(INSTALL_PREFIX)/bin.
install: release
	install -d $(INSTALL_PREFIX)/bin
	install -m 755 $(RELEASE_BIN) $(INSTALL_BIN)
	@echo "Installed $(INSTALL_BIN)"

## uninstall: Remove the installed binary.
uninstall:
	@if [ -f "$(INSTALL_BIN)" ]; then \
	    rm -f "$(INSTALL_BIN)"; \
	    echo "Removed $(INSTALL_BIN)"; \
	else \
	    echo "Nothing to remove: $(INSTALL_BIN) not found"; \
	fi

# ---------------------------------------------------------------------------
# Housekeeping

## clean: Remove build artefacts.
clean:
	$(CARGO) clean

# ---------------------------------------------------------------------------
# Help

## help: List all documented targets with their descriptions.
help:
	@echo "Usage: make [TARGET] [VARIABLE=value ...]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## [a-z]' $(MAKEFILE_LIST) \
	    | sed 's/## /  /' \
	    | column -t -s ':'
	@echo ""
	@echo "Variables (override on the command line):"
	@echo "  CARGO=$(CARGO)"
	@echo "  CARGO_ARGS=$(CARGO_ARGS)"
	@echo "  PREFIX=$(PREFIX)  -> installs to PREFIX/bin"
