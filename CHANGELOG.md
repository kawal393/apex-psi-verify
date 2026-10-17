# Changelog

## 1.0.1 (2026-10-18) — claim correction, no code path changed

- Removed the **Ed25519** label from seals, README, SECURITY.md, setup.py and the
  Python example. This package signs with LMS-W4-SHA256 over W-OTS+ only; it never
  created and never checked an Ed25519 signature, so seals are now labelled
  `LMS-W4-SHA256`. The `ed25519_verified` field named in a docstring does not exist
  in the returned verdict and the reference was removed.
- Verification still requires this package's own registry state (`registry_hit`),
  so it is not a standalone offline checker of published PSI-SEAL/1 receipts. Use
  the PSI verifier in APEX-PSI (`packages/psi-verifier`) for those.
- The 1.0.0 entry below is left as released, so the record keeps its shape.

## 1.0.0 (2026-07-28) — initial public release

- LMS-W4-SHA256 + Ed25519 hybrid signatures
- W-OTS+ (W=4) one-time signatures
- Merkle tree of depth 5 (32 leaves)
- Auto key rotation on tree exhaustion
- Anti-stripping registry
- HTTP verify API (Flask + stdlib fallback)
- In-process and HTTP smoke tests
- Apache 2.0 license
