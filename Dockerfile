FROM ubuntu:latest

USER root
ENV RUST_LOG=info

COPY ./target/release/xdp-firewall-rs /ebpf/

WORKDIR /ebpf/
CMD ["./xdp-firewall-rs"]
