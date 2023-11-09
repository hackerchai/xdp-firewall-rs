# xdp-firewall-rs

## Overview
This is a simple XDP firewall written in Rust. It is based on the [Aya](https://github.com/aya-rs/aya) and project structure generated by [aya-template](https://github.com/aya-rs/aya-template) via [cargo-generate](https://github.com/cargo-generate/cargo-generate).

## Usage
The program will load the eBPF program into the kernel and attach it to the `XDP` hook of the specified interface. It will then listen for incoming packets and drop any packets that are not allowed by the rules.

1. Create a file named `block.list` in the same directory as the binary. This file will contain the list of IP addresses that are not allowed to pass through the firewall. Each IP address should be on a separate line. For example:
   ```bash
   touch block.list
   ```
2. Add ip addresses in CIDR format to the `block.list` file:
   ```bash
   1.1.1.1/32
   192.168.1.1/32
   ```
3. Run the binary with `sudo`:
   ```bash
   sudo ./xdp-firewall-rs
    ```

## Prerequisites
**If you are developing on a Linux machine, you can use the following**
1. Install `rustup` following the instructions on https://rustup.rs/.
2. Install a rust stable toolchain: `rustup install stable`
3. Install a rust nightly toolchain: `rustup toolchain install nightly --component rust-src`
4. Ensure C compiler and linker are installed. On Ubuntu, you can install them with:
    ```bash
    sudo apt install build-essential
    sudo apt install pkg-config
    ```
5. Install bpf-linker: `cargo install bpf-linker`

## Build and Run

#### Clone

First clone the repository:
```bash
git clone https://github.com/hackerchai/xdp-firewall-rs
cd xdp-firewall-rs
```

#### Build eBPF

- debug build:
```bash
cargo xtask build-ebpf
````

- release build:
```bash
cargo xtask build-ebpf --release
```

#### Build Userspace

- debug build:
```bash
cargo build
```

- release build:
```bash
cargo build --release
```

#### Run
- run release binary
```bash
sudo ./target/release/xdp-firewall-rs
```


- run debug binary
```bash
sudo ./target/debug/xdp-firewall-rs
```

#### Run with logging

```bash
RUST_LOG=info cargo xtask run
```

## Cross Compilation
This program can be cross-compiled on a Mac(intel/arm64):

```bash
rustup target add x86_64-unknown-linux-musl
brew install FiloSottile/musl-cross/musl-cross
brew install llvm@16
LLVM_SYS_160_PREFIX=$(brew --prefix llvm) cargo install bpf-linker --no-default-features
cargo xtask build-ebpf --release
export CROSSARCH="x86_64"
RUSTFLAGS="-Clinker=${CROSSARCH}-linux-musl-ld -C link-arg=-s" cargo build --release --target=${CROSSARCH}-unknown-linux-musl
```

The cross-compiled binary can found at  `target/x86_64-unknown-linux-musl/release/xdp-firewall-rs`, which can be copied to a Linux server or VM and run there.