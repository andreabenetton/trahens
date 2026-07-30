# ADR 0034: Use one machine-readable protocol registry

## Status

Accepted for v1.5 P1.

## Context

The v1.4.1 review found a real interoperability defect: the normative C1 document named a v2 element domain while the implementation retained a v1 default. Existing CI regenerated vectors from the implementation and therefore compared code with itself. It could not detect prose/code drift.

## Decision

`spec/protocol-registry-v1.5.json` is the sole authority for stable profile, suite, message, frame, payload, and error identifiers; fixed widths and maxima; fixed-T2 parameters; C1 v2 domains; and field-protection classifications.

`tools/generate_protocol_registry.py` emits:

- `simulator/trahens_spec/generated.py`;
- `implementation/rust/crates/protocol-registry/src/generated.rs`;
- `spec/protocol-registry-v1.5.md`.

CI regenerates all three into temporary files and compares them byte-for-byte. Runtime codecs import generated constants rather than maintaining copies.

## Consequences

A registry change is a protocol change and produces a visible diff in every implementation binding. Prose may explain constants but may not redefine them. The registry does not make the whole prose specification executable; it removes the highest-risk class of silent numeric and domain-separator drift.
