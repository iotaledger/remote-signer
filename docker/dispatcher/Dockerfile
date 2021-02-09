############################
# Build
############################
FROM rust:latest as build
WORKDIR build
COPY . .
RUN rustup component add rustfmt
RUN cargo install --bin dispatcher-server --path . --root  /dispatcher-install

############################
# Image
############################
FROM gcr.io/distroless/base-debian10
COPY --from=build /dispatcher-install .

ENTRYPOINT ["/bin/dispatcher-server"]
CMD ["--config=/config/dispatcher_config.json"]
