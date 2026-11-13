"""
example_python.py
=================
Create a seal and verify it in pure Python. No server.
"""
from apex_psi_verify.pq_seal import PostQuantumSigner, verify_pq_signature
import hashlib

# 1. Create a fresh signer (or load an existing one)
signer = PostQuantumSigner()
public_key = signer.get_public_key_hex()
print(f"Public key: {public_key[:32]}...")

# 2. Seal some content
content = "The Eiffel Tower is 330 m tall as of 2026-07-16."
sig = signer.sign(content.encode("utf-8"))

# 3. The seal object
seal = {
    "version": "2.0",
    "algorithm": "LMS-W4-SHA256",
    "content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    "signer_public_key": public_key,
    "pq_signature": sig,
}

# 4. Verify it
ok = verify_pq_signature(content.encode("utf-8"), sig, public_key)
print(f"Verified: {ok}")
assert ok, "Seal must verify"
print("Seal is valid.")
