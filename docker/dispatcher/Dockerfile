############################
# Build
############################
FROM rust:1 as build
COPY . /src
WORKDIR /src
RUN rustup component add rustfmt
RUN cargo build --release --bin dispatcher-server

############################
# Image
############################
FROM gcr.io/distroless/cc-debian11:nonroot

COPY --chown=nonroot:nonroot --from=build /src/target/release/dispatcher-server /app/

ENTRYPOINT ["/app/dispatcher-server"]
CMD ["--config=/config/dispatcher_config.json"]
