#! /usr/bin/env bash

set -e

# cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target x86_64-unknown-linux-musl

# strip target/x86_64-unknown-linux-gnu/release/skanuvaty
strip target/x86_64-unknown-linux-musl/release/skanuvaty

# upx --lzma target/x86_64-unknown-linux-gnu/release/skanuvaty
upx --ultra-brute target/x86_64-unknown-linux-musl/release/skanuvaty
# 764K
