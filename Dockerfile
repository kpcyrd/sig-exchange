FROM rust:1-alpine3.24
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add musl-dev
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/sig-exchange /

FROM alpine:3.24
RUN apk add libgcc
COPY --from=0 /sig-exchange /
USER nobody
ENV BIND_ADDR=0.0.0.0:8000
ENTRYPOINT ["/sig-exchange"]
