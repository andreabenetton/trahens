#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print one limit from the active protocol registry.

The namespace harness builds some scenarios around registry limits: how long an
outage has to be to outlast a lifetime, how many cells a rekey trigger has to
sit under. A scenario that restates the number keeps passing after the registry
moves it, while no longer testing what its comment claims -- a green run that
has quietly stopped asserting anything. Reading the value is what keeps the two
together.

An unknown name is an error rather than a default: a typo that returned a
plausible number would produce exactly the silent pass this exists to prevent.
"""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "spec" / "protocol-registry-v1.8.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="limit name, e.g. route_ttl_ms")
    parser.add_argument("--registry", type=pathlib.Path, default=REGISTRY)
    arguments = parser.parse_args()

    limits = json.loads(arguments.registry.read_text()).get("limits", {})
    if arguments.name not in limits:
        print(
            f"{arguments.name} is not a limit in {arguments.registry.name}",
            file=sys.stderr,
        )
        return 1
    print(limits[arguments.name])
    return 0


if __name__ == "__main__":
    sys.exit(main())
