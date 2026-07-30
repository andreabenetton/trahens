# Trahens simulator

The simulator is deterministic. It is a protocol-research and conformance model, not a packet-level performance benchmark or a cryptographic proof environment.

## Active model

- `trahens_sim/event_model.py` - integrated E1 lifecycle with R1 by default, M2 messages, W2 cells, nested CANDIDATE, COMMIT/READY, expiry, cancellation, loss, duplication, tampering, and attacks.
- `trahens_crypto/eligibility.py` - provider boundary, active R1 implementation, C1 negative control, symbolic C2 control, and disabled C2 k=2 provider.
- `trahens_codec/m2w2.py` - suite-agile M2 messages, fixed W2 cells, link protection, and bounded reassembly.
- `trahens_sim/r1_compare.py` - R1 literal-marker experiment and C1/C2 controls.

## Research components

- `trahens_crypto/c1.py` - C1 negative-control eligibility and retained reply/signature components.
- `trahens_crypto/c2_ideal.py` - executable C2 ideal functionality; simulation only.
- `trahens_crypto/c2_klinear.py` - exact k=2 arithmetic and encoding audit; full rerandomization fails closed.
- `tools/c2_k2_exhaustive_check.py` - exhaustive small-chain test of the literal finite-field reduction.

The event model retains complete paths and legitimate/malicious classifications only for measurement. They are not protocol-visible fields.

## Commands

```bash
make test
make r1-compare
make c2-k2-exhaustive
make fragmentation-compare
make unlinkability-compare
make lifecycle-compare
make paper
```

## Limitations

The R1 directory and gateway network are represented only by capability issuance and atomic redemption primitives; private lookup and distributed storage are not simulated. The C2 ideal functionality stores semantic ciphertext state in a process-local registry and is not cryptography. The C2 k=2 module is an audit, not a network backend. The model uses abstract event delays and has no real transport, traffic scheduler, side-channel-resistant runtime, or complete rendezvous handshake.
