// SPDX-License-Identifier: Apache-2.0
//! Write a signed seed manifest.
//!
//! An operator's tool, and the harness's way of building the two manifests that
//! matter: an honest one naming a node's real advertisement key, and one signed
//! by the same trusted key that names the wrong one. The second is what makes
//! ADR 0049's transition observable — without a tool that can lie, there is no
//! way to check that a joiner notices.

use admission_b12::seed::{encode, FAMILY_V4, FAMILY_V6};
use admission_b12::{SeedEntry, SeedManifest};
use node_runtime::{parse_hex, structured_event, CliArgs};
use protocol_registry::VERSION;
use std::error::Error;
use std::net::IpAddr;
use std::path::PathBuf;
use trahens_crypto::signing_keypair;

/// `<advertisement key hex>@<address>:<port>`, comma-separated.
fn entries(value: &str) -> Result<Vec<SeedEntry>, Box<dyn Error>> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let (key, endpoint) = part
            .split_once('@')
            .ok_or("an entry is <advertisement-key>@<address>:<port>")?;
        let (address, port) = endpoint
            .rsplit_once(':')
            .ok_or("an entry is <advertisement-key>@<address>:<port>")?;
        let parsed: IpAddr = address.parse()?;
        let (family, octets) = match parsed {
            IpAddr::V4(v4) => (FAMILY_V4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (FAMILY_V6, v6.octets().to_vec()),
        };
        out.push(SeedEntry {
            advertisement_key: parse_hex::<32>(key)?,
            family,
            address: octets,
            port: port.parse::<u16>()?,
        });
    }
    Ok(out)
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse()?;
    let signing_seed = parse_hex::<32>(args.required("signing-seed")?)?;
    let (public, secret) = signing_keypair(&signing_seed)?;
    let issued_ms = args.u64_or("issued-ms", 0)?;
    let manifest = SeedManifest {
        version: VERSION,
        issued_ms,
        expiry_ms: issued_ms + args.u64_or("lifetime-ms", 3_600_000)?,
        entries: entries(args.required("entries")?)?,
    };
    let document = encode(&manifest, &secret)?;
    let out = PathBuf::from(args.required("out")?);
    std::fs::write(&out, &document)?;

    structured_event(
        "seed",
        "written",
        &[
            ("path", out.display().to_string()),
            ("entries", manifest.entries.len().to_string()),
            ("bytes", document.len().to_string()),
            // The key a joiner must be configured with to verify this.
            ("seed_public", node_runtime::hex(&public)),
        ],
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-seed: {error}");
        std::process::exit(1);
    }
}
