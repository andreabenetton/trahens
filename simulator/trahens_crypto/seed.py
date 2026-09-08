# SPDX-License-Identifier: Apache-2.0
"""The B1.2 signed seed manifest.

Implements `spec/seed-manifest-b12.md` and ADR 0050. A joiner has to learn a
candidate from somewhere, and until this the only thing that could fill the
candidate cache was an advertisement from a peer the joiner was already talking
to. A seed manifest names candidates it has not met.

Each entry carries an **advertisement key**, not a static admission key. That is
what makes the manifest checkable rather than merely followed: ADR 0049 binds an
advertisement key to whoever completes an admission exchange, so a joiner can
confirm afterwards that the node answering is the one the manifest meant.

It is a file, not a datagram: no first-byte discriminator, and no padding to a
fixed width. The advertisement is one cell wide because its length would
otherwise distinguish it on the wire; a file read from disk has no such observer.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from trahens_spec.generated import (
    BYTES_B12_SEED_ADDRESS_V4,
    BYTES_B12_SEED_ADDRESS_V6,
    BYTES_B12_SEED_SIGNATURE,
    BYTES_X25519_PUBLIC,
    DOMAIN_B12_SEED_MANIFEST,
    LIMIT_MAX_SEED_ENTRIES,
    LIMIT_SEED_MANIFEST_TTL_MS,
    VERSION,
)

FAMILY_V4 = 4
FAMILY_V6 = 6
_ADDRESS_BYTES = {FAMILY_V4: BYTES_B12_SEED_ADDRESS_V4, FAMILY_V6: BYTES_B12_SEED_ADDRESS_V6}


class SeedError(ValueError):
    """One outcome. A reader is never told which check refused a manifest."""


@dataclass(frozen=True)
class SeedEntry:
    """One candidate: where to try, and whose advertisement key to expect."""

    advertisement_key: bytes
    family: int
    address: bytes
    port: int

    def encode(self) -> bytes:
        if len(self.advertisement_key) != BYTES_X25519_PUBLIC:
            raise SeedError("advertisement key width")
        width = _ADDRESS_BYTES.get(self.family)
        if width is None or len(self.address) != width:
            raise SeedError("address does not match its family")
        if not 0 <= self.port <= 0xFFFF:
            raise SeedError("port out of range")
        return (
            self.advertisement_key
            + bytes([self.family])
            + self.address
            + self.port.to_bytes(2, "big")
        )


@dataclass(frozen=True)
class SeedManifest:
    version: int
    issued_ms: int
    expiry_ms: int
    entries: tuple[SeedEntry, ...]

    def body(self) -> bytes:
        if not self.entries or len(self.entries) > LIMIT_MAX_SEED_ENTRIES:
            raise SeedError("entry count out of range")
        if self.expiry_ms <= self.issued_ms:
            raise SeedError("a manifest that expires before it is issued")
        # Bounded ahead of issue, or the expiry would be decoration: an issuer
        # could otherwise write one that never lapses.
        if self.expiry_ms - self.issued_ms > LIMIT_SEED_MANIFEST_TTL_MS:
            raise SeedError("expiry beyond the permitted lifetime")
        out = bytes([self.version])
        out += self.issued_ms.to_bytes(8, "big")
        out += self.expiry_ms.to_bytes(8, "big")
        out += bytes([len(self.entries)])
        for entry in self.entries:
            out += entry.encode()
        return out


def encode(manifest: SeedManifest, signing_seed: bytes) -> bytes:
    """Sign the whole body, so no entry can be added, removed or reordered."""
    body = manifest.body()
    signature = Ed25519PrivateKey.from_private_bytes(signing_seed).sign(
        DOMAIN_B12_SEED_MANIFEST + body
    )
    return body + signature


def decode(document: bytes, seed_key: bytes, now_ms: int) -> SeedManifest:
    """Parse and verify against the seed key a joiner holds out of band.

    Every bound is checked before anything is allocated for it: the count is
    read and refused before entries are parsed, so a manifest cannot make a
    reader work for a number it chose.
    """
    if len(document) < BYTES_B12_SEED_SIGNATURE + 18:
        raise SeedError("too short to be a manifest")
    body, signature = (
        document[:-BYTES_B12_SEED_SIGNATURE],
        document[-BYTES_B12_SEED_SIGNATURE:],
    )
    try:
        Ed25519PublicKey.from_public_bytes(seed_key).verify(
            signature, DOMAIN_B12_SEED_MANIFEST + body
        )
    except Exception as error:  # noqa: BLE001 -- one outcome
        raise SeedError("seed manifest does not verify") from error

    version = body[0]
    if version != VERSION:
        raise SeedError("unsupported version")
    issued_ms = int.from_bytes(body[1:9], "big")
    expiry_ms = int.from_bytes(body[9:17], "big")
    count = body[17]
    if count == 0 or count > LIMIT_MAX_SEED_ENTRIES:
        raise SeedError("entry count out of range")
    if expiry_ms <= issued_ms or expiry_ms - issued_ms > LIMIT_SEED_MANIFEST_TTL_MS:
        raise SeedError("malformed lifetime")
    # Checked after the signature: an expired manifest is a real manifest that
    # has lapsed, and saying so before verifying would answer for documents
    # nobody signed.
    if now_ms >= expiry_ms:
        raise SeedError("manifest has expired")

    entries: list[SeedEntry] = []
    cursor = 18
    for _ in range(count):
        key = body[cursor : cursor + BYTES_X25519_PUBLIC]
        if len(key) != BYTES_X25519_PUBLIC:
            raise SeedError("truncated entry")
        cursor += BYTES_X25519_PUBLIC
        if cursor >= len(body):
            raise SeedError("truncated entry")
        family = body[cursor]
        cursor += 1
        width = _ADDRESS_BYTES.get(family)
        if width is None:
            raise SeedError("unknown address family")
        address = body[cursor : cursor + width]
        if len(address) != width:
            raise SeedError("truncated address")
        cursor += width
        port_bytes = body[cursor : cursor + 2]
        if len(port_bytes) != 2:
            raise SeedError("truncated port")
        cursor += 2
        entries.append(
            SeedEntry(key, family, address, int.from_bytes(port_bytes, "big"))
        )
    # Nothing may follow the entries the count declared. A reader that ignored a
    # tail would accept a document whose signed region it only partly read.
    if cursor != len(body):
        raise SeedError("trailing bytes after the declared entries")
    return SeedManifest(version, issued_ms, expiry_ms, tuple(entries))
