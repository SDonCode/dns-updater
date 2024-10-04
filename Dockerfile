FROM lukemathwalker/cargo-chef:latest AS chef

WORKDIR /app

FROM chef AS planner

RUN mkdir -p src
RUN echo 'fn main() { panic!("Dummy Image Called!")}' > ./src/main.rs

COPY ["Cargo.toml", "Cargo.lock", "./"]

RUN cargo chef prepare

FROM chef AS builder

RUN apt-get update

COPY --from=planner /app/recipe.json .
RUN cargo chef cook --release

COPY . .

RUN cargo build --release
RUN mv ./target/release /app

FROM debian:bookworm-slim AS runtime

RUN apt-get update
RUN apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin
COPY --from=builder /app/release/dns-updater .

ENTRYPOINT ["dns-updater"]
