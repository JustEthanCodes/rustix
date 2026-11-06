FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        just \
        python-is-python3 \
        qemu-system-x86 \
        xorriso \
    && rm -rf /var/lib/apt/lists/*
