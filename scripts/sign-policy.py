#!/usr/bin/env python3
"""Sign a sanitize policy file with Ed25519.

Usage:
    # Generate a key pair (once):
    python sign-policy.py keygen --out-dir keys/

    # Sign a policy:
    python sign-policy.py sign --policy sanitize.yaml --key keys/policy.key --out-dir signed/

    # Verify a signature:
    python sign-policy.py verify --policy-dir signed/ --pubkey keys/policy.pub

The signed output directory contains:
    policy.json  — canonical JSON (this is what clients receive)
    policy.sig   — hex-encoded Ed25519 signature
    key_id       — key identifier (first 16 chars of pubkey hash)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

try:
    import yaml
except ImportError:
    yaml = None


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def cmd_keygen(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    key_path = out_dir / "policy.key"
    pub_path = out_dir / "policy.pub"

    key_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    key_path.chmod(0o600)

    pub_path.write_bytes(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    key_id = hashlib.sha256(
        public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).hexdigest()[:16]

    print(f"Key pair generated in {out_dir}/")
    print(f"  Private: {key_path}")
    print(f"  Public:  {pub_path}")
    print(f"  Key ID:  {key_id}")


def cmd_sign(args: argparse.Namespace) -> None:
    policy_path = Path(args.policy)
    key_path = Path(args.key)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if policy_path.suffix in (".yaml", ".yml"):
        if yaml is None:
            print("PyYAML required for YAML input: pip install pyyaml", file=sys.stderr)
            sys.exit(1)
        with open(policy_path) as f:
            policy_data = yaml.safe_load(f)
    else:
        with open(policy_path) as f:
            policy_data = json.load(f)

    private_key = load_pem_private_key(key_path.read_bytes(), password=None)
    public_key = private_key.public_key()

    canonical = _canonical_json(policy_data)
    signature = private_key.sign(canonical)

    key_id = hashlib.sha256(
        public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).hexdigest()[:16]

    (out_dir / "policy.json").write_bytes(canonical)
    (out_dir / "policy.sig").write_text(signature.hex())
    (out_dir / "key_id").write_text(key_id)

    print(f"Signed policy written to {out_dir}/")
    print(f"  Key ID: {key_id}")
    print(f"  Signature: {signature.hex()[:32]}...")


def cmd_verify(args: argparse.Namespace) -> None:
    policy_dir = Path(args.policy_dir)
    pubkey_path = Path(args.pubkey)

    policy_bytes = (policy_dir / "policy.json").read_bytes()
    sig_hex = (policy_dir / "policy.sig").read_text().strip()
    signature = bytes.fromhex(sig_hex)

    public_key = load_pem_public_key(pubkey_path.read_bytes())
    assert isinstance(public_key, Ed25519PublicKey)

    try:
        public_key.verify(signature, policy_bytes)
        print("Signature valid.")
    except Exception as e:
        print(f"Signature INVALID: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign sanitize policy files")
    sub = parser.add_subparsers(dest="command", required=True)

    kg = sub.add_parser("keygen", help="Generate Ed25519 key pair")
    kg.add_argument("--out-dir", required=True, help="Output directory for keys")

    sg = sub.add_parser("sign", help="Sign a policy file")
    sg.add_argument("--policy", required=True, help="Policy file (YAML or JSON)")
    sg.add_argument("--key", required=True, help="Private key PEM file")
    sg.add_argument("--out-dir", required=True, help="Output directory for signed policy")

    vf = sub.add_parser("verify", help="Verify a signed policy")
    vf.add_argument("--policy-dir", required=True, help="Directory with policy.json + policy.sig")
    vf.add_argument("--pubkey", required=True, help="Public key PEM file")

    args = parser.parse_args()
    {"keygen": cmd_keygen, "sign": cmd_sign, "verify": cmd_verify}[args.command](args)


if __name__ == "__main__":
    main()
