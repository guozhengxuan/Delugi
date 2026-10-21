#!/usr/bin/env bash
# Run INSIDE the task-owned Ubuntu22.04 ARM64 container, never on the host.
# The owner creates a bounded local VM/container; this script provisions only it.
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
test -f /run/.containerenv
test -d /workspace/benchmarks/baselines/shoal/.git
test ! -e /work/repo
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential clang libclang-dev llvm lld cmake pkg-config libssl-dev libudev-dev libdw-dev curl ca-certificates git unzip python3 time
mkdir -p /work/toolchain /work/evidence /work/repo/benchmarks/baselines /work/repo/benchmarks/patches /work/repo/scripts /work/repo/provenance
curl --fail --location --retry 2 https://sh.rustup.rs -o /work/toolchain/rustup-init.sh
sha256sum /work/toolchain/rustup-init.sh > /work/evidence/download-sha256.txt
export RUSTUP_HOME=/work/toolchain/rustup CARGO_HOME=/work/toolchain/cargo
sh /work/toolchain/rustup-init.sh -y --profile minimal --default-toolchain 1.75.0 --no-modify-path
# Native cached-packages regenerates tracked SDK sources and invokes rustfmt.
# Its build script ignores rustfmt's exit status, so a minimal toolchain alone
# silently leaves unformatted generated files and invalidates source receipts.
/work/toolchain/cargo/bin/rustup component add rustfmt --toolchain 1.75.0
curl --fail --location --retry 2 https://github.com/protocolbuffers/protobuf/releases/download/v21.4/protoc-21.4-linux-aarch_64.zip -o /work/toolchain/protoc.zip
sha256sum /work/toolchain/protoc.zip >> /work/evidence/download-sha256.txt
unzip -q /work/toolchain/protoc.zip -d /work/toolchain/protoc
cp -a /workspace/benchmarks/baselines/shoal /work/repo/benchmarks/baselines/shoal
cp -a /workspace/scripts/baselines /work/repo/scripts/baselines
cp /workspace/scripts/cohort_metrics.py /workspace/scripts/cohort_store.py /work/repo/scripts/
cp /workspace/provenance/baselines.json /work/repo/provenance/
cp /workspace/benchmarks/patches/shoal-cohort-2026-10-19.patch /work/repo/benchmarks/patches/
git config --global --add safe.directory /work/repo/benchmarks/baselines/shoal
export PATH=/work/toolchain/cargo/bin:/work/toolchain/protoc/bin:$PATH
rustc +1.75.0 --version --verbose > /work/evidence/rustc.txt
rustfmt +1.75.0 --version > /work/evidence/rustfmt.txt
protoc --version > /work/evidence/protoc.txt
uname -a > /work/evidence/kernel.txt
dpkg-query -W > /work/evidence/packages.txt
python3 /work/repo/scripts/baselines/native_artifacts.py shoal > /work/evidence/source-selection.json
df -B1 /work > /work/evidence/disk-before.txt
cat /proc/meminfo > /work/evidence/memory-before.txt
cat /proc/swaps > /work/evidence/swaps-before.txt
printf '%s\n' 'Bootstrap complete. Cargo compilation is a separate, coordinated step.'
