# apex-psi-verify

**Post-quantum, hash-anchored content seal verifier.**

> *APEX PSI — a lightweight, neutral RFC 8785 reference implementation.*

`apex-psi-verify` seals content with a post-quantum hash-based signature and
checks it again independently. It implements:

- **LMS-W4-SHA256** (RFC 8554, NIST SP 800-208) for post-quantum security
- **W-OTS+** one-time signatures (W=4, 16 chain levels)
- **SHA-256 Merkle tree** (depth 5, 32 leaves)

Ed25519 is **not** implemented in this package. The classical Ed25519 signature
required by PSI-SEAL/1 rule R11 is created and checked by the PSI verifier in
[APEX-PSI/packages/psi-verifier](https://github.com/kawal393/APEX-PSI/tree/main/packages/psi-verifier),
which is the package to use for verifying published PSI receipts.

A 32-leaf LMS tree yields 32 seals before key rotation is required.
The verify API rotates automatically.

---

## Install

```bash
git clone https://github.com/kawal393/apex-psi-verify
cd apex-psi-verify
pip install -e .
```

No external runtime dependencies. Pure stdlib.

## Run the API

```bash
python -m apex_psi_verify
# -> APEX PSI verify API starting on http://127.0.0.1:5000
```

Or with Flask for production:

```bash
pip install -e ".[flask]"
FLASK_APP=apex_psi_verify.apex_verify_api flask run --port 5000
```

## Use in 30 seconds

```python
from apex_psi_verify.pq_seal import PostQuantumSigner, verify_pq_signature
import hashlib

signer = PostQuantumSigner()
public_key = signer.get_public_key_hex()

content = b"The price of bread is 1.20 EUR on 2026-07-16."
sig = signer.sign(content)

ok = verify_pq_signature(content, sig, public_key)
assert ok, "post-quantum seal failed to verify"
print("Verified.")
```

## HTTP API

| Endpoint                  | Method | Purpose |
| ------------------------- | ------ | ------- |
| `/health`                 | GET    | Service health + algorithm |
| `/v1/key`                 | GET    | Active signer public key |
| `/seal`                   | POST   | Create a new seal (body: `content`) |
| `/seal/<id>`              | GET    | Retrieve a stored seal |
| `/verify`                 | POST   | Verify (body: `content` + `seal_id` or `seal`) |
| `/registry/<hash>`        | GET    | Anti-stripping registry lookup |

## Tests

```bash
# In-process crypto test (no server)
python tests/test_crypto.py

# Live HTTP test (server must be running)
python tests/test_smoke.py
```

## Examples

- `examples/example_python.py` — pure-Python seal/verify
- `examples/example_curl.sh`   — full HTTP flow

## Protocol catalog

The 27 protocol specifications (industry + unification) live in the
companion repository
[`apex-psi-protocols`](https://github.com/kawal393/apex-psi-protocols).

## Cryptographic parameters

| Parameter      | Value |
| -------------- | ----- |
| Algorithm      | LMS-W4-SHA256 (hash) |
| Winternitz     | W=4, 16 chain levels, 68 chains |
| W-OTS sig size | 2176 bytes |
| Merkle depth   | 5 |
| Leaves/tree    | 32 |
| Hash function  | SHA-256 |
| Classical      | not implemented here (see the note above) |

These are conservative, NIST-approved parameters.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

See [CITATION.cff](CITATION.cff).

## Security

See [SECURITY.md](SECURITY.md).
