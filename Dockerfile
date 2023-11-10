FROM ubuntu:latest

USER root
ENV RUST_LOG=info

COPY ./target/release/xdp-firewall-rs /ebpf/
COPY ./block.list /ebpf/

WORKDIR /ebpf/
CMD ["./xdp-firewall-rs"]
