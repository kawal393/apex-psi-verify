# Security Policy

## Reporting a vulnerability

Please email security@apex-psi.example.org with a subject starting
`[SECURITY]`. Do not open a public GitHub issue for security
findings.

We aim to acknowledge within 48 hours and provide a remediation
timeline within 7 days for critical issues.

## Cryptographic primitives

- **Ed25519** (RFC 8032) for the classical fast path
- **LMS-W4-SHA256** (RFC 8554, NIST SP 800-208) for post-quantum security
- **SHA-256** (FIPS 180-4) for content addressing

W-OTS+ parameters: `W=4`, 16 chain levels, 68 chains, 2176-byte
signature. Merkle tree depth 5, 32 leaves per tree.

## Key rotation

Each LMS tree provides exactly 32 seals. The verify API auto-rotates
to a new key epoch when the active tree is exhausted. Key epochs
are stored in `<APEX_PSI_HOME>/keyring/key_epoch_NNNNNN.json` and
the active pointer is `<APEX_PSI_HOME>/active_key.json`.

## Threat model

APEX PSI is designed to resist:

- Compromised signing key (mitigated by per-leaf W-OTS+ one-time
  use, post-quantum Merkle root)
- Quantum adversary (mitigated by LMS-W4-SHA256)
- Content tampering (mitigated by hash binding)
- Metadata stripping (mitigated by anti-stripping registry)

APEX PSI does **not** protect against:

- Compromise of the host running the signer
- Side-channel attacks on the signing implementation
- Loss of all key epochs (use the key backup procedure)
