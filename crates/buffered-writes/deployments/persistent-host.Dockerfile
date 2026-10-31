# Versions: software-versions.json; details in software-version-consumers.md.
ARG RUST_IMAGE=docker.io/library/rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
FROM ${RUST_IMAGE} AS build
COPY --chmod=755 scripts/install-mold.sh /usr/local/bin/install-mold.sh
RUN /usr/local/bin/install-mold.sh
ENV RUSTFLAGS="-C link-arg=-B/opt/aux-mold-3.0.0/libexec/mold -C link-arg=-fuse-ld=bfd"
ENV LDFLAGS="-B/opt/aux-mold-3.0.0/libexec/mold"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/opt/aux-mold-3.0.0/bin/mold-cc
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=/opt/aux-mold-3.0.0/bin/mold-cc
WORKDIR /src
COPY Cargo.toml Cargo.lock README.md ./
COPY crates/ ./crates/
RUN cargo build --locked --release -p buffered-writes --example persistent-host

FROM ${RUNTIME_IMAGE}
COPY --from=build /src/target/release/examples/persistent-host /usr/local/bin/persistent-host
USER 65532:65532
ENV BUFFERED_WRITES_SHUTDOWN_GRACE_MS=10000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/persistent-host"]
