PACKAGE_NAME=charmedwoa-av
TARGET=aarch64-unknown-linux-gnu

.PHONY: all build check fmt lint test package clean install uninstall

all: build

build:
	cargo build --workspace --all-features

check:
	cargo check --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

package:
	./scripts/build_deb.sh

install:
	sudo dpkg -i artifacts/$(PACKAGE_NAME)_0.1.0_aarch64.deb

uninstall:
	sudo dpkg -r $(PACKAGE_NAME)

clean:
	cargo clean
