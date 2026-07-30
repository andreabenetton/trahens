# Trahens simulator

The simulator is deterministic. It is a protocol-research and conformance model, not a packet-level performance benchmark or a cryptographic proof environment.

## Models and components

- `model.py` - bounded discovery, expanding rings, and U1 branch-local exploration.
- `event_model.py` - integrated E1 lifecycle with C1 or symbolic C2 eligibility, M2 messages, W2 cells, nested CANDIDATE, COMMIT/READY, expiry, cancellation, loss, duplication, tampering, and attacks.
- `trahens_crypto/c2_ideal.py` - executable C2 ideal functionality; simulation only.
- `trahens_crypto/c2_klinear.py` - exact k=2 arithmetic and canonical-encoding audit of the selected concrete construction; full rerandomization fails closed.
- `trahens_crypto/c1.py` - C1 negative-control eligibility and retained reply/signature components.
- `trahens_codec/m2w2.py` - suite-agile M2 messages, fixed W2 cells, link protection, and bounded reassembly.
- `c2_compare.py` - C1 ratio-tag and symbolic C2 mutation comparison.
- `fragmentation_compare.py` - logical size, cell count, route depth, and cell-loss comparison.
- `unlinkability_compare.py`, `lifecycle_compare.py`, and `tagging_compare.py` - structural, lifecycle, and negative-control experiments.

The event model retains full paths and legitimate/malicious classifications only for measurement. They are not protocol-visible fields.

## Commands

```bash
make test
make c2-symbolic-vectors
make c2-compare
make c2-k2-audit
make fragmentation-compare
make unlinkability-compare
make lifecycle-compare
make tagging-compare
```

## Integrated behavior

For C2, the model creates opaque 640-byte symbolic eligibility ciphertexts, permits only replay-equivalent public rerandomization through the ideal interface, and rejects arbitrary mutation before an honest relay emits a child branch. Candidate return, responder signatures, COMMIT, READY, adjacent-link AEAD, M2, W2, and reassembly continue to use executable concrete code.

The M2 suite identifier is repeated in every encrypted W2 fragment. Reassembly binds the first suite, rejects inconsistent fragments, and requires the complete M2 envelope to match before route semantics execute.

## Limitations

The C2 ideal functionality stores semantic ciphertext state in a process-local registry. It is not cryptography and cannot support a deployment or security claim. The separate C2-K2 module is an interoperability audit, not a network backend; its public full-rerandomization API deliberately raises `C2ConformanceGap`. The model uses abstract event delays and does not implement a real transport, mixing scheduler, or side-channel-resistant runtime. W2 equalizes cell length but does not hide fragment count or timing.
