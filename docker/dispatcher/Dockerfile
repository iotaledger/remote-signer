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
FROM gcr.io/distroless/base@sha256:5e0cc69445ed1d8a17198250a7249d56dd4b6966bb6b2118e60ae9194c310647
COPY --from=build /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/

COPY --from=build /src/target/release/dispatcher-server /

ENTRYPOINT ["/dispatcher-server"]
CMD ["--config=/config/dispatcher_config.json"]
