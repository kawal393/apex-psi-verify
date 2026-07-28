"""
Minimal in-process crypto test. No HTTP server required.
Run with: python tests/test_crypto.py
"""
import os
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG))

# Use a temp home so we don't pollute the real keyring
import tempfile
os.environ["APEX_PSI_HOME"] = tempfile.mkdtemp(prefix="apex-psi-test-")

from apex_psi_verify.pq_seal import PostQuantumSigner, verify_pq_signature
import hashlib

def banner(s):
    print()
    print("=" * 60)
    print(f"  {s}")
    print("=" * 60)

banner("1. Generate a fresh LMS-W4-SHA256 signer")
signer = PostQuantumSigner()
pk = signer.get_public_key_hex()
print(f"  Public key: {pk[:32]}...")
print(f"  Remaining signatures: {signer.get_remaining_signatures()}")
assert signer.get_remaining_signatures() == 32, "Tree should have 32 leaves"
print("  [PASS] 32 leaves available")

banner("2. Sign a message")
msg = b"The price of bread is 1.20 EUR on 2026-07-16 at store 4421"
sig = signer.sign(msg)
print(f"  Algorithm: {sig['algorithm']}")
print(f"  Leaf index: {sig['leaf_index']}")
print(f"  W-OTS sig length: {len(sig['wots_signature'])} hex chars ({len(sig['wots_signature'])//2} bytes)")
print(f"  Auth path length: {len(sig['auth_path'])}")
assert sig["algorithm"] == "LMS-W4-SHA256"
assert len(sig["wots_signature"]) == 4352, "W-OTS+ sig is 2176 bytes hex = 4352 chars"
assert len(sig["auth_path"]) == 5
print("  [PASS] W-OTS+ sig is 2176 bytes (4352 hex), Merkle depth 5")

banner("3. Verify the signature")
ok = verify_pq_signature(msg, sig, pk)
print(f"  verify_pq_signature returned: {ok}")
assert ok is True
print("  [PASS] Signature verified")

banner("4. Tamper with the message -> must be rejected")
tampered = msg + b" TAMPERED"
ok2 = verify_pq_signature(tampered, sig, pk)
print(f"  verify_pq_signature(tampered) returned: {ok2}")
assert ok2 is False
print("  [PASS] Tampered content rejected")

banner("5. Tamper with the signature -> must be rejected")
bad_sig = dict(sig)
# Flip one byte in the middle of the wots sig
w = list(sig["wots_signature"])
w[2000] = "f" if w[2000] != "f" else "0"
bad_sig["wots_signature"] = "".join(w)
ok3 = verify_pq_signature(msg, bad_sig, pk)
print(f"  verify_pq_signature(bad-sig) returned: {ok3}")
assert ok3 is False
print("  [PASS] Tampered signature rejected")

banner("ALL CRYPTO TESTS PASSED")
print()
print("APEX PSI is post-quantum. The seal holds.")
