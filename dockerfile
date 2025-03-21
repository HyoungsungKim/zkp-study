FROM python:3.8-bullseye

# 필수 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends git cmake clang curl

# Rust 설치
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Circom 빌드 및 설치
WORKDIR /circom
RUN git clone https://github.com/iden3/circom.git . && \
    cargo build --release && \
    cp target/release/circom /usr/local/bin/

# Python 패키지 업데이트 및 Jupyter 설치
RUN pip install --upgrade pip && pip install jupyterlab
