<!-- SPDX-License-Identifier: Apache-2.0 -->

# Trahens v1.5 P1 user-space implementation

`implementation/rust/` is the first interoperable implementation of the frozen P1 profile. It runs over UDP and keeps M2, W2, T1, fixed T2, R1, and route lifecycle responsibilities in separate crates.

## Executables

- `trahens-endpoint` — originates R1 discovery, validates the nested candidate chain, commits, redeems a capability, exchanges data, and closes.
- `trahens-relay` — replaces hop-local tokens/nonces/labels, blinds reply keys, forwards fixed-size cells, and holds bounded adjacent route state.
- `trahens-rendezvous` — creates signed gateway offers, verifies COMMIT, issues READY, atomically redeems capabilities, and echoes P1 test data.

## Workspace

```text
implementation/rust/
  crates/
    protocol-registry/
    codec-m2/
    wire-w2/
    crypto/
    state-machine/
    transport-t1/
    scheduling-t2/
    rendezvous-r1/
    node-runtime/
    conformance/
  bins/
    trahens-endpoint/
    trahens-relay/
    trahens-rendezvous/
  fuzz/
```

All protocol state transitions use typed events. The runtime uses bounded synchronous channels and registry-defined state limits. W2 replay state is committed only after authentication. Every retransmission receives fresh padding, sequence, tag, and ciphertext. Secret wrappers zeroize on drop.

## Build and test

Requirements: Rust 1.82 or newer, Linux for the namespace harness, and libsodium development files.

```bash
cargo test --manifest-path implementation/rust/Cargo.toml --all-targets
cargo build --release --manifest-path implementation/rust/Cargo.toml
sudo implementation/harness/netns-p1.sh --relays 2 --loss 5
sudo implementation/harness/netns-p1.sh --relays 12 --loss 0
```

The harness also requires `ip`, `tc`, `tcpdump`, and Python 3. It creates one namespace per process, captures each link, validates 1,052-byte UDP payloads, and writes aggregate metrics under `build/p1-harness/`.

## Claim boundary

This is an experimental interoperability prototype, not production software. C1 v2 reply ciphertext anonymity and the nested composition remain review obligations. D1 private directory behavior and adaptive T2/T3/T4 are outside the mandatory P1 path. See `spec/p1-prototype-profile-v1.5.md`.
