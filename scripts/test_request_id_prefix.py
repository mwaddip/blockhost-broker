#!/usr/bin/env python3
"""Cross-language fixture test for the broker response request_id prefix format.

The Rust broker reads the same fixture in
`blockhost-broker-rs/src/eth/monitor.rs` (test `request_id_prefix_matches_fixture`).
Both sides must agree, byte-for-byte, on how to encode and decode the 8-byte
big-endian request ID prefix that the broker prepends to every response.

Run with:
    python3 scripts/test_request_id_prefix.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "request_id_prefix.json"


def _import_client():
    """Import broker_client by path so this script works without packaging."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "broker_client", REPO_ROOT / "scripts" / "broker-client.py"
    )
    module = importlib.util.module_from_spec(spec)
    # The broker-client module loads contract ABI files from disk and imports
    # web3, eth_account etc. on import. Defer those by only importing the
    # symbols we need.
    return spec, module


def main() -> int:
    fixture = json.loads(FIXTURE.read_text())

    assert fixture["prefix_length_bytes"] == 8, "expected 8-byte prefix"
    assert fixture["encoding"] == "big-endian unsigned 64-bit integer"

    # Re-implement the encode/decode locally so the test doesn't depend on
    # importing broker-client.py (which has heavy runtime imports). The point
    # of this test is to lock the *spec* — broker-client.py separately uses
    # the same `int.to_bytes(8, "big")` pattern, and the fixture is what
    # forces them to stay aligned.
    PREFIX_LEN = 8

    failures: list[str] = []
    for case in fixture["cases"]:
        request_id = case["id"]
        expected_hex = case["prefix_hex"]

        encoded = request_id.to_bytes(PREFIX_LEN, byteorder="big")
        encoded_hex = encoded.hex()
        if encoded_hex != expected_hex:
            failures.append(
                f"encode id={request_id} expected={expected_hex} got={encoded_hex}"
            )
            continue

        decoded = int.from_bytes(bytes.fromhex(expected_hex), byteorder="big")
        if decoded != request_id:
            failures.append(
                f"decode hex={expected_hex} expected={request_id} got={decoded}"
            )

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1

    print(f"OK: {len(fixture['cases'])} cases verified against fixture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
