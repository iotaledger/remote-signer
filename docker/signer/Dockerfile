############################
# Build
############################
FROM rust:latest as build
COPY . /src
WORKDIR /src
RUN rustup component add rustfmt
RUN cargo build --release --bin signer-server

############################
# Image
############################
FROM gcr.io/distroless/cc-debian11:nonroot

COPY --chown=nonroot:nonroot --from=build /src/target/release/signer-server /app/

ENTRYPOINT ["/app/signer-server"]
CMD ["--config=/config/signer_config.json"]
