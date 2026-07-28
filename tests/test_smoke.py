"""
APEX PSI - SMOKE TEST (wired)
==============================
End-to-end proof that the verify API uses real LMS-W4-SHA256, not SHA-256.

Run:  python apex_smoke_test.py
Exit: 0 = all green, 1 = any failure.
"""
import json
import sys
from pathlib import Path

WORKSPACE = Path(r"C:\Users\apex1\.openhands")
sys.path.insert(0, str(WORKSPACE))

from APEX_GRAND_UNIFIED.TOOLS.apex_verify_api_wired import (
    HAS_PQ_SEAL, create_seal, verify_seal, _signer,
)


def banner(s):
    print()
    print("=" * 70)
    print(f"  {s}")
    print("=" * 70)


def expect(cond, msg):
    if cond:
        print(f"  [PASS] {msg}")
    else:
        print(f"  [FAIL] {msg}")
        sys.exit(1)


banner("PRE-FLIGHT")
expect(HAS_PQ_SEAL, "pq_seal.py imported (PostQuantumSigner available)")
expect(_signer is not None, "Signer instantiated")
print(f"  signer public key: {_signer.get_public_key_hex()[:40]}...")
print(f"  remaining sigs:     {_signer.get_remaining_signatures()}")

banner("TEST 1: create + verify a clean seal")
content = "APEX PSI - the truth protocol. Day 0 of the master plan."
seal = create_seal(content)
print(f"  seal_id:        {seal['seal_id']}")
print(f"  algorithm:      {seal['algorithm']}")
print(f"  pq_sig alg:     {seal['pq_signature']['algorithm']}")
print(f"  pq_sig leaves:  {len(seal['pq_signature']['wots_signature'])//2} bytes (W-OTS)")
print(f"  auth_path len:  {len(seal['pq_signature']['auth_path'])}")

verdict = verify_seal(content, seal_id=seal["seal_id"])
print(f"  verdict:        {json.dumps(verdict, indent=2)[:500]}")
expect(verdict["verified"] is True, "verify_seal returns verified=True on clean content")
expect(verdict["pq_verified"] is True, "PQ signature verified")
expect(verdict["registry_hit"] is True, "Anti-stripping registry hit")
expect(verdict["ineluctable"] is True, "ineluctable flag set when verified")

banner("TEST 2: tampered content is REJECTED")
tampered = "APEX PSI - tampered content. The protocol should reject this."
verdict2 = verify_seal(tampered, seal_id=seal["seal_id"])
print(f"  verdict:        {json.dumps(verdict2, indent=2)[:500]}")
expect(verdict2["verified"] is False, "verify_seal returns verified=False on tampered content")
expect(verdict2["reason"] in ("content_hash_mismatch", "pq_verified_false"),
       f"reason is one of the expected failure modes (got: {verdict2.get('reason')})")

banner("TEST 3: tampered signature is REJECTED")
seal_bad = json.loads(json.dumps(seal))  # deep copy
seal_bad["pq_signature"]["wots_signature"] = "00" * len(seal_bad["pq_signature"]["wots_signature"])
verdict3 = verify_seal(content, seal=seal_bad)
print(f"  verdict:        {json.dumps(verdict3, indent=2)[:500]}")
expect(verdict3["verified"] is False, "tampered signature is rejected")

banner("TEST 4: tampered public key is REJECTED")
seal_bad2 = json.loads(json.dumps(seal))
seal_bad2["signer_public_key"] = "aa" * 32
verdict4 = verify_seal(content, seal=seal_bad2)
print(f"  verdict:        {json.dumps(verdict4, indent=2)[:500]}")
expect(verdict4["verified"] is False, "tampered signer public key is rejected")

banner("TEST 5: anti-stripping registry persistence")
# Even if the seal_id is unknown, the content_hash should resolve via registry
verdict5 = verify_seal(content, seal_id="PSI-DOES-NOT-EXIST")
print(f"  verdict:        {json.dumps(verdict5, indent=2)[:500]}")
expect(verdict5["registry_hit"] is True,
       "Anti-stripping: content_hash resolves even when seal_id is unknown")

banner("TEST 6: cross-verify with full seal object (no store lookup)")
verdict6 = verify_seal(content, seal=seal)
print(f"  verdict:        {json.dumps(verdict6, indent=2)[:500]}")
expect(verdict6["verified"] is True, "Cross-verify with full seal dict works")

banner("ALL SMOKE TESTS PASSED - APEX PSI IS REAL")
print()
print("Summary:")
print(f"  - pq_seal.py cryptographic verification: WORKING")
print(f"  - LMS-W4-SHA256 sign/verify:             WORKING")
print(f"  - Tamper detection (content):            WORKING")
print(f"  - Tamper detection (signature):          WORKING")
print(f"  - Tamper detection (signer pk):          WORKING")
print(f"  - Anti-stripping registry:               WORKING")
print(f"  - Cross-verify with seal dict:           WORKING")
print()
print("The 'ineluctable' field is no longer aspirational. It is real.")
