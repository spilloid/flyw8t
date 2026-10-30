# flyw8t server image. Build from the repository root:
#   docker build -f deploy/compose/Dockerfile -t flyw8t-server .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# .cargo/config.toml defaults to the Windows MSVC target (for the agent); the server image
# is Linux, so the target is explicit.
RUN cargo build --release --locked -p flyw8t-server --target x86_64-unknown-linux-gnu

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home flyw8t
COPY --from=build /src/target/x86_64-unknown-linux-gnu/release/flyw8t-server /usr/local/bin/flyw8t-server
USER 10001
ENV FLYW8T_BIND=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/flyw8t-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/flyw8t-server"]
