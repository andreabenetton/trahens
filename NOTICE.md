# Notice

## Licensing

Trahens is released under two licenses, split by material type:

| Material | License | File |
|---|---|---|
| Source code — `implementation/`, `simulator/`, `tools/`, `formal/` | Apache License 2.0 | `LICENSE` |
| Specifications, documentation, and the current paper — `spec/`, `docs/`, `paper/rewrite/` | Creative Commons Attribution 4.0 International | `LICENSE-CC-BY-4.0.txt` |

Apache-2.0 was chosen for the code because its explicit patent grant
(section 3) matters for a protocol carrying cryptographic constructions:
independent implementers need that assurance to build on the registry,
codecs, and reference models. CC BY 4.0 was chosen for the written material
so the specifications and results can be redistributed and quoted with
attribution.

Files carry `SPDX-License-Identifier` headers recording which of the two
applies. Machine-readable formats that cannot hold comments — notably the
JSON registry and test-vector files — are covered by this notice rather than
by an embedded header, and follow the license of their directory.

## Excluded material

`paper/legacy/` is **not** covered by either grant above.

That directory holds an imported draft carrying both a "CONFIDENTIAL DRAFT"
watermark and LaTeX configuration for a Creative Commons Attribution 4.0
notice. Those signals conflict, and the conflict is unresolved. Until the
author explicitly settles the intended publication and licensing status of
that draft, the source and PDF in `paper/legacy/` remain confidential author
material and no license is granted for them.

## Attribution

When redistributing the specifications or paper under CC BY 4.0, retain the
project name, the author attribution, and a link to the source repository.
