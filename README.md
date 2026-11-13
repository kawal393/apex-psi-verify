# apex-psi-verify

**The LMS-W4-SHA256 component of APEX PSI, and its standalone seal API.**

> *APEX PSI — a lightweight, neutral RFC 8785 reference implementation.*

## Read this first: which verifier do you want?

There are **three** packages that carry the APEX PSI verifier name. This table is
the only place that distinguishes them, so read it before you install anything.

| what you want | what to install | what it does |
|---|---|---|
| **Verify a published PSI-SEAL/1 receipt** | `pip install psi-verifier==1.6.0` | Ed25519 R11 enforced against your public key; an unverified post-quantum claim is reported `unverifiable`, never `verified` (R11.7); RFC 9162 inclusion proof checked (R13.1); RFC 9162 consistency proof checked, so one operator cannot show two histories of the same log (R13.2). **No registry, no network.** |
| **The same, for JavaScript/TypeScript** | `npm install apex-psi-verifier@1.6.0` | The Node implementation of the above. |
| **Work with LMS-W4-SHA256 itself** | this repo, from source | The hash-based post-quantum signer/verifier and its seal API. Source-only: **this package is not published on PyPI.** |

If you only want to verify receipts, you want `psi-verifier` — it is the one that
matches the specification. This repo is the post-quantum primitive it can be
combined with.

## What this repo is

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

## What the verdict means

The verdict separates two facts that are often fused and should not be:

- `verified` — **the mathematics**. The post-quantum signature checks out.
- `registry_hit` — **our vouch**. Whether the hash is in *this operator's*
  registry, i.e. whether we issued it. `null` means the registry was empty and
  the check could not be made.

A valid signature over a hash we have never seen is still a valid signature. A
verifier that reports `verified=false` for correct mathematics is not
verifying; it is looking things up. The canonical `psi-verifier` has no registry
and no network at all, and neither does this verdict.

## Run the outsider's-eye audit

This repository grades its own public footprint the way a stranger would —
registries, package identity, algorithm drift against the specification, whether
"offline" is true, key-budget disclosure, and absolute claims:

```bash
python scripts/outsider_eye_audit.py
```

It exits non-zero on any FAIL. A FAIL is a claim this project is not currently
entitled to make.

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
