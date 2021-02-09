############################
# Build
############################
FROM rust:latest as build
COPY . .
RUN rustup component add rustfmt
RUN cargo install --bin signer-server --path . --root  /signer-install

############################
# Image
############################
FROM rust:latest
COPY --from=build /signer-install .

ENTRYPOINT ["/bin/signer-server"]
CMD ["--config=/config/signer_config.json"]
