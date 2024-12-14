all: release

release:
	AYA_BUILD_EBPF=true cargo build --release

debug:
	AYA_BUILD_EBPF=true cargo build

test:
	cargo test

clean:
	cargo clean

