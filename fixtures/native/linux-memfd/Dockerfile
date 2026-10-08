FROM docker.io/library/rust@sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d
RUN apt-get update && apt-get install -y --no-install-recommends strace=6.1-0.1 && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy --toolchain 1.88.0
