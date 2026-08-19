from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import json
import base64
import secrets


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    # Derive a 32-byte key for Fernet using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    key = kdf.derive(passphrase)
    return base64.urlsafe_b64encode(key)


def encrypt_state(state: dict, path: str, passphrase_env: str = "APEX_PSI_KEY_PASSPHRASE") -> None:
    """
    Encrypt and write state to `path`. Requires an environment variable with the passphrase.
    The file format is JSON: {"salt": hex, "ciphertext": base64}
    """
    passphrase = os.environ.get(passphrase_env)
    if not passphrase:
        raise EnvironmentError(
            f"Passphrase env var {passphrase_env} not set. Refuse to write plaintext key material."
        )
    salt = secrets.token_bytes(16)
    key = _derive_key(passphrase.encode('utf-8'), salt)
    f = Fernet(key)
    plaintext = json.dumps(state, separators=(",", ":")).encode('utf-8')
    token = f.encrypt(plaintext)
    out = {"salt": salt.hex(), "ciphertext": base64.b64encode(token).decode('ascii')}
    with open(path, 'w') as fh:
        json.dump(out, fh)


def decrypt_state(path: str, passphrase_env: str = "APEX_PSI_KEY_PASSPHRASE") -> dict:
    """
    Read and decrypt file at `path` using passphrase from env.
    Returns the decoded state dict.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    data = json.load(open(path, 'r'))
    salt = bytes.fromhex(data['salt'])
    token = base64.b64decode(data['ciphertext'].encode('ascii'))
    passphrase = os.environ.get(passphrase_env)
    if not passphrase:
        raise EnvironmentError(f"Passphrase env var {passphrase_env} not set.")
    key = _derive_key(passphrase.encode('utf-8'), salt)
    f = Fernet(key)
    plaintext = f.decrypt(token)
    return json.loads(plaintext.decode('utf-8'))


# KMS hooks (pluggable)

def kms_encrypt_stub(state: dict) -> dict:
    """Placeholder for KMS encryption. Return a dict that can be saved to disk.
    Implementors should replace this with calls to AWS KMS, GCP KMS, or Vault."""
    raise NotImplementedError("KMS integration not configured")


def kms_decrypt_stub(data: dict) -> dict:
    """Placeholder for KMS decryption."""
    raise NotImplementedError("KMS integration not configured")
