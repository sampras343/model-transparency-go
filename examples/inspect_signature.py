#!/usr/bin/env python3
"""
Inspect a Sigstore signature file and display its contents.

This script shows:
- Subject digest
- File count and list
- Serialization configuration
- Git files presence
"""

import json
import base64
import sys
from pathlib import Path
from typing import Dict, List


def load_signature(sig_path: str) -> Dict:
    """Load and parse a signature file."""
    with open(sig_path, 'r') as f:
        return json.load(f)


def decode_payload(signature: Dict) -> Dict:
    """Decode the base64-encoded DSSE payload."""
    payload_b64 = signature['dsseEnvelope']['payload']
    payload_json = base64.b64decode(payload_b64).decode('utf-8')
    return json.loads(payload_json)


def find_git_files(files: List[str]) -> List[str]:
    """Find git-related files in the list."""
    git_patterns = ['.git', '.gitattributes', '.github', '.gitignore', '.gitmodules']
    return [f for f in files if any(f.startswith(pattern) for pattern in git_patterns)]


def inspect_signature(sig_path: str):
    """Inspect and display signature file contents."""

    print("=" * 80)
    print(f"SIGNATURE INSPECTION: {sig_path}")
    print("=" * 80)
    print()

    # Load signature
    signature = load_signature(sig_path)
    payload = decode_payload(signature)

    # Subject
    print("1. SUBJECT")
    print("-" * 80)
    subject = payload['subject'][0]
    print(f"Name:   {subject['name']}")
    print(f"Digest: {subject['digest']['sha256']}")
    print()

    # Predicate type
    print("2. PREDICATE")
    print("-" * 80)
    print(f"Type: {payload['predicateType']}")
    print()

    # Files/Resources
    print("3. RESOURCES (Files)")
    print("-" * 80)
    resources = payload['predicate']['resources']
    files = sorted([r['name'] for r in resources])
    print(f"Total files: {len(files)}")

    # Count unique hashes
    hashes = set([r['digest'] for r in resources])
    print(f"Total unique hashes: {len(hashes)}")
    print()

    git_files = find_git_files(files)
    if git_files:
        print(f"⚠️  Contains {len(git_files)} git-related files:")
        for f in git_files:
            print(f"  • {f}")
        print()
    else:
        print("✅ No git-related files (correctly excluded)")
        print()

    print("File list:")
    for i, file in enumerate(files, 1):
        is_git = file in git_files
        marker = "⚠️ " if is_git else "  "
        print(f"{marker}{i:2d}. {file}")
    print()

    # Serialization
    print("4. SERIALIZATION CONFIGURATION")
    print("-" * 80)
    serialization = payload['predicate']['serialization']

    print(f"Method:         {serialization.get('method')}")
    print(f"Hash type:      {serialization.get('hash_type')}")
    print(f"Allow symlinks: {serialization.get('allow_symlinks')}")

    ignore_paths = serialization.get('ignore_paths', None)
    if ignore_paths is None:
        print(f"Ignore paths:   ❌ NOT SET (field missing)")
    elif not ignore_paths:
        print(f"Ignore paths:   [] (empty list)")
    else:
        print(f"Ignore paths:   ✅ SET ({len(ignore_paths)} entries)")
        for path in ignore_paths:
            print(f"  • {path}")

        # Check if git paths are in ignore_paths
        print()
        print("Git paths check:")
        git_path_patterns = ['.git', '.gitattributes', '.github', '.gitignore']
        for git_path in git_path_patterns:
            if git_path in ignore_paths:
                print(f"  ✅ {git_path} is in ignore_paths")
            else:
                print(f"  ❌ {git_path} is NOT in ignore_paths")
    print()

    # Verification material
    print("5. VERIFICATION MATERIAL")
    print("-" * 80)
    vm = signature['verificationMaterial']
    if 'publicKey' in vm:
        print(f"Type: Public Key")
        if 'hint' in vm['publicKey']:
            print(f"Hint: {vm['publicKey']['hint']}")
    elif 'x509CertificateChain' in vm:
        print(f"Type: X.509 Certificate Chain")
    else:
        print(f"Type: Unknown")
    print()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    issues = []
    if git_files:
        issues.append(f"Contains {len(git_files)} git files (should be excluded)")
    if ignore_paths is None:
        issues.append("Missing ignore_paths field in serialization")

    if issues:
        print("⚠️  POTENTIAL ISSUES:")
        for issue in issues:
            print(f"  • {issue}")
    else:
        print("✅ Signature looks correct:")
        print(f"  • {len(files)} files hashed")
        print(f"  • No git files included")
        print(f"  • ignore_paths field set with {len(ignore_paths)} entries")
    print()

    # Full decoded payload in JSON format
    print("=" * 80)
    print("FULL DECODED PAYLOAD (JSON)")
    print("=" * 80)
    print(json.dumps(payload, indent=2))
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python inspect_signature.py <signature.sig>")
        print()
        print("Example:")
        print("  python inspect_signature.py /tmp/model.sig")
        sys.exit(1)

    sig_path = sys.argv[1]

    if not Path(sig_path).exists():
        print(f"Error: File not found: {sig_path}")
        sys.exit(1)

    inspect_signature(sig_path)


if __name__ == "__main__":
    main()
