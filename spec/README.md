# Specifications

The files in this directory are the evolving normative source for the protocol. The legacy paper is historical material and is not normative.

## Current documents

- [`core-v0.1.md`](core-v0.1.md) - scope, entities, processing rules, lifecycle, and limits.
- [`messages-v0.1.md`](messages-v0.1.md) - abstract message schemas and validation order.
- [`state-machines-v0.1.md`](state-machines-v0.1.md) - initiator, relay, and responder states.
- [`invariants.md`](invariants.md) - properties every implementation and simulation must check.

## Maturity

Core v0.1 is a design draft. It intentionally uses a stable discovery identifier to make loop suppression and resource accounting unambiguous. That identifier permits correlation by colluding relays and is not the final unlinkability design. Later revisions must either remove it or explicitly retain the weaker privacy property.
