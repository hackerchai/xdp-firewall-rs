# Makefile

IMAGE_TAG = latest
SERVICE_NAME = xdp-firewall-rs
FULL_IMAGE_URL = hackerchai/$(SERVICE_NAME):$(IMAGE_TAG)
PLATFORM = linux/amd64
BUILD_ARGS = --platform $(PLATFORM)

release:
	cargo xtask build-ebpf --release
	cargo build --release

dev:
	cargo xtask build-ebpf
	RUST_LOG=info cargo xtask run

push: release
	docker build  -t $(FULL_IMAGE_URL) --push .
