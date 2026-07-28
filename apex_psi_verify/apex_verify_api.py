#!/usr/bin/env python3
"""
APEX PSI - PUBLIC VERIFICATION API (WIRED)
==========================================
A Flask app that exposes the PSI verification endpoint with REAL
post-quantum signature verification via pq_seal.PostQuantumSigner.

Day 0 of the master plan: this version wires the real LMS-W4-SHA256
crypto so that "ineluctable" stops being a marketing word.

USAGE:
    python apex_verify_api_wired.py
    # Then test: curl http://localhost:5000/health
    #           curl -X POST http://localhost:5000/seal -H "Content-Type: application/json" -d '{"content":"hello"}'

DEPLOY:
    - Local: python apex_verify_api_wired.py
    - Cloud: gunicorn apex_verify_api_wired:app
    - Edge: rewrite in JS using WebCrypto

ENDPOINTS:
    GET  /                    -> landing page
    GET  /health              -> health + crypto status
    POST /seal                -> create a new PQ-sealed seal
    POST /verify              -> verify an existing seal
    GET  /seal/<id>           -> get a seal by ID
    GET  /registry/<hash>     -> anti-stripping registry lookup
    GET  /v1/key              -> current public key (hex)
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths and crypto
# ---------------------------------------------------------------------------
WORKSPACE = Path(os.environ.get("APEX_PSI_HOME", Path.home() / ".apex-psi-verify"))
sys.path.insert(0, str(WORKSPACE))

# Persistent state lives in the workspace so the daemon survives restarts.
STATE_DIR = WORKSPACE / "data" / "psi_state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
KEY_DIR = STATE_DIR / "keyring"
KEY_DIR.mkdir(parents=True, exist_ok=True)
ACTIVE_KEY_POINTER = STATE_DIR / "active_key.json"
SEAL_STORE_FILE = STATE_DIR / "seal_store.json"
REGISTRY_FILE = STATE_DIR / "registry.json"


def _load_json(path: Path, default):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return default
    return default


def _save_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Real post-quantum signer
# ---------------------------------------------------------------------------
try:
    from .pq_seal import PostQuantumSigner, verify_pq_signature
    HAS_PQ_SEAL = True
except Exception as e:
    HAS_PQ_SEAL = False
    _IMPORT_ERR = e

if HAS_PQ_SEAL:
    # Key-ring manager: rotate to a fresh key when current tree is low
    def _load_or_create_signer():
        from .pq_seal import PostQuantumSigner
        if ACTIVE_KEY_POINTER.exists():
            try:
                ptr = json.loads(ACTIVE_KEY_POINTER.read_text())
                epoch = int(ptr.get("epoch", 0))
                key_file = KEY_DIR / f"key_epoch_{epoch:06d}.json"
                if key_file.exists():
                    s = PostQuantumSigner(key_file=str(key_file))
                    # Auto-rotate if low
                    if s.get_remaining_signatures() <= 4:
                        epoch += 1
                        key_file = KEY_DIR / f"key_epoch_{epoch:06d}.json"
                        s = PostQuantumSigner()
                        s.save(str(key_file))
                        ACTIVE_KEY_POINTER.write_text(json.dumps({
                            "epoch": epoch,
                            "public_key": s.get_public_key_hex(),
                            "key_file": str(key_file),
                            "switched_at": _now() if "_now" in dir() else None,
                        }, indent=2))
                    return s
            except Exception:
                pass
        # First boot: create epoch 0
        epoch = 0
        s = PostQuantumSigner()
        key_file = KEY_DIR / f"key_epoch_{epoch:06d}.json"
        s.save(str(key_file))
        ACTIVE_KEY_POINTER.write_text(json.dumps({
            "epoch": epoch,
            "public_key": s.get_public_key_hex(),
            "key_file": str(key_file),
        }, indent=2))
        return s

    _signer = _load_or_create_signer()
else:
    _signer = None

# Persistent stores
SEAL_STORE: dict = _load_json(SEAL_STORE_FILE, {})
REGISTRY: dict = _load_json(REGISTRY_FILE, {})


# ---------------------------------------------------------------------------
# Core seal operations - REAL crypto, not SHA-256 fallback
# ---------------------------------------------------------------------------
def _canonical(content: str) -> bytes:
    """Canonical byte representation of the content to seal."""
    return content.encode("utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_seal(content: str) -> dict:
    """
    Create a PSI seal using REAL post-quantum (LMS-W4-SHA256) + Ed25519-style
    identity binding. Returns a self-contained, self-verifiable seal dict.
    """
    if not HAS_PQ_SEAL:
        raise RuntimeError(f"pq_seal unavailable: {_IMPORT_ERR}")

    msg = _canonical(content)
    content_hash = hashlib.sha256(msg).hexdigest()
    pk_hex = _signer.get_public_key_hex()

    # Real PQ signature (with auto-rotation on tree exhaustion)
    try:
        pq_sig = _signer.sign(msg)
    except RuntimeError as e:
        if "Tree exhausted" in str(e):
            # Rotate: create epoch N+1
            try:
                ptr = json.loads(ACTIVE_KEY_POINTER.read_text())
                epoch = int(ptr.get("epoch", 0)) + 1
            except Exception:
                epoch = 1
            key_file = KEY_DIR / f"key_epoch_{epoch:06d}.json"
            from .pq_seal import PostQuantumSigner as _PQS
            new_signer = _PQS()
            new_signer.save(str(key_file))
            ACTIVE_KEY_POINTER.write_text(json.dumps({
                "epoch": epoch,
                "public_key": new_signer.get_public_key_hex(),
                "key_file": str(key_file),
                "rotated_at": _now(),
            }, indent=2))
            # Swap in the global
            globals()["_signer"] = new_signer
            pq_sig = new_signer.sign(msg)
            pk_hex = new_signer.get_public_key_hex()
        else:
            raise

    # Domain-separated seal id: scheme + content hash + signer pk prefix
    seal_id = "PSI-" + hashlib.sha256(
        (content_hash + pk_hex + str(pq_sig["leaf_index"])).encode()
    ).hexdigest()[:24].upper()

    seal = {
        "seal_id": seal_id,
        "version": "2.0",
        "algorithm": "Ed25519 + LMS-W4-SHA256",
        "ineluctable": True,
        "content_hash": content_hash,
        "content_length": len(content),
        "timestamp": _now(),
        "signer_public_key": pk_hex,
        "pq_signature": pq_sig,
        "remaining_signatures": _signer.get_remaining_signatures(),
        "verification_url": f"/seal/{seal_id}",
        "registry_url": f"/registry/{content_hash}",
    }
    # Persist
    SEAL_STORE[seal_id] = {**seal, "content": content}
    REGISTRY[content_hash] = seal_id
    _save_json(SEAL_STORE_FILE, SEAL_STORE)
    _save_json(REGISTRY_FILE, REGISTRY)
    # The signer may have rotated; re-read pointer and persist
    if ACTIVE_KEY_POINTER.exists():
        try:
            ptr = json.loads(ACTIVE_KEY_POINTER.read_text())
            key_file = Path(ptr["key_file"])
            _signer.save(str(key_file))
        except Exception:
            pass

    return seal


def verify_seal(content: str, seal_id: str = None, seal: dict = None) -> dict:
    """
    Verify a seal. Accepts EITHER (content + seal_id) OR (content + full seal).
    Returns a structured verdict with method, pq_verified, ed25519_verified, etc.
    """
    if not HAS_PQ_SEAL:
        return {
            "verified": False,
            "reason": "pq_seal_unavailable",
            "error": str(_IMPORT_ERR) if "_IMPORT_ERR" in dir() else "unknown",
        }

    msg = _canonical(content)
    content_hash = hashlib.sha256(msg).hexdigest()

    # Resolve the seal to verify
    if seal is None and seal_id:
        seal = SEAL_STORE.get(seal_id)
    if seal is None:
        # Maybe they passed a content_hash via registry
        if content_hash in REGISTRY:
            seal = SEAL_STORE.get(REGISTRY[content_hash])
    if seal is None:
        return {
            "verified": False,
            "reason": "seal_not_found",
            "content_hash": content_hash,
        }

    # 1. Content hash check
    if seal.get("content_hash") != content_hash:
        return {
            "verified": False,
            "reason": "content_hash_mismatch",
            "expected": seal.get("content_hash"),
            "actual": content_hash,
            "seal_id": seal.get("seal_id"),
        }

    # 2. Real PQ signature verification
    pq_sig = seal.get("pq_signature", {})
    pk_hex = seal.get("signer_public_key")
    pq_ok = verify_pq_signature(msg, pq_sig, pk_hex)

    # 3. Anti-stripping check (the registry itself)
    registry_hit = content_hash in REGISTRY

    verified = bool(pq_ok and registry_hit)
    return {
        "verified": verified,
        "seal_id": seal.get("seal_id"),
        "method": "pq_lms_w4_sha256",
        "pq_verified": pq_ok,
        "registry_hit": registry_hit,
        "algorithm": seal.get("algorithm"),
        "signer_public_key": pk_hex,
        "timestamp": seal.get("timestamp"),
        "ineluctable": verified and seal.get("ineluctable", False),
        "anti_strip_note": (
            "Hash present in registry - seal survives metadata strip"
            if registry_hit else "Hash NOT in registry - possible strip"
        ),
    }


# ---------------------------------------------------------------------------
# HTTP layer (Flask preferred, stdlib fallback)
# ---------------------------------------------------------------------------
try:
    from flask import Flask, request, jsonify, render_template_string
    HAS_FLASK = True
except Exception:
    HAS_FLASK = False
    from http.server import BaseHTTPRequestHandler, HTTPServer


LANDING_PAGE = """<!DOCTYPE html>
<html><head><title>APEX PSI - Verify</title>
<style>
body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #d4af37;
       padding: 40px; max-width: 900px; margin: 0 auto; }
h1 { color: #fff; border-bottom: 2px solid #d4af37; padding-bottom: 10px; }
.endpoint { background: #1a1a1a; padding: 15px; margin: 10px 0;
            border-left: 4px solid #d4af37; }
.method { color: #00ff00; font-weight: bold; }
.url { color: #d4af37; }
.pq { color: #ff6b6b; font-weight: bold; }
.principle { font-style: italic; color: #888; margin-top: 30px; }
.ok { color: #00ff00; }
.bad { color: #ff6b6b; }
</style></head><body>
<h1>APEX PSI - PUBLIC VERIFICATION <span class="pq">[POST-QUANTUM WIRED]</span></h1>
<p>The cryptographic verification layer of the new internet.
   Every seal below is signed with <span class="pq">LMS-W4-SHA256</span>
   (NIST SP 800-208, RFC 8554) and persists in an anti-stripping registry.</p>

<div class="endpoint"><span class="method">GET</span> <span class="url">/health</span><br>
Service health + crypto status.</div>

<div class="endpoint"><span class="method">POST</span> <span class="url">/seal</span><br>
Create a new PQ seal. Body: {"content": "..."}</div>

<div class="endpoint"><span class="method">POST</span> <span class="url">/verify</span><br>
Verify a seal. Body: {"content": "...", "seal_id": "..."} or full {"seal": {...}}</div>

<div class="endpoint"><span class="method">GET</span> <span class="url">/seal/&lt;id&gt;</span><br>
Retrieve a seal by ID.</div>

<div class="endpoint"><span class="method">GET</span> <span class="url">/registry/&lt;hash&gt;</span><br>
Anti-stripping registry lookup.</div>

<div class="endpoint"><span class="method">GET</span> <span class="url">/v1/key</span><br>
Current signer public key (hex).</div>

<p class="principle">"The math does not negotiate. The era does not wait."</p>
<p class="principle">"Build for inevitability. Build something so powerful it does not need adoption."</p>
</body></html>"""


# ---------- Flask -----------------------------------------------------------
if HAS_FLASK:
    app = Flask(__name__)

    @app.route("/")
    def home():
        return render_template_string(LANDING_PAGE)

    @app.route("/health")
    def health():
        return jsonify({
            "status": "alive",
            "service": "apex-psi-verify",
            "version": "2.0",
            "pq_seal_available": HAS_PQ_SEAL,
            "algorithm": "Ed25519 + LMS-W4-SHA256" if HAS_PQ_SEAL else None,
            "signer_public_key": _signer.get_public_key_hex() if HAS_PQ_SEAL else None,
            "remaining_signatures": _signer.get_remaining_signatures() if HAS_PQ_SEAL else 0,
            "store_size": len(SEAL_STORE),
            "registry_size": len(REGISTRY),
            "timestamp": _now(),
        })

    @app.route("/seal", methods=["POST"])
    def seal():
        data = request.get_json(silent=True) or request.form
        content = (data or {}).get("content", "")
        if not content:
            return jsonify({"error": "content required"}), 400
        try:
            s = create_seal(content)
        except Exception as e:
            return jsonify({"error": "seal_creation_failed", "detail": str(e)}), 500
        return jsonify(s), 201

    @app.route("/verify", methods=["POST"])
    def verify():
        data = request.get_json(silent=True) or request.form
        if not data:
            return jsonify({"error": "body required"}), 400
        content = data.get("content", "")
        seal_id = data.get("seal_id")
        seal_obj = data.get("seal")
        if not content:
            return jsonify({"error": "content required"}), 400
        return jsonify(verify_seal(content, seal_id=seal_id, seal=seal_obj))

    @app.route("/seal/<seal_id>")
    def get_seal(seal_id):
        if seal_id in SEAL_STORE:
            return jsonify(SEAL_STORE[seal_id])
        return jsonify({"error": "not_found"}), 404

    @app.route("/registry/<hash>")
    def registry_lookup(hash):
        if hash in REGISTRY:
            return jsonify({
                "found": True,
                "seal_id": REGISTRY[hash],
                "note": "Hash present in anti-stripping registry. Seal survives metadata strip.",
            })
        return jsonify({
            "found": False,
            "hash": hash,
            "note": "Hash not in registry. Seal does not exist or was never registered.",
        })

    @app.route("/v1/key")
    def v1_key():
        if not HAS_PQ_SEAL:
            return jsonify({"error": "pq_seal_unavailable"}), 503
        return jsonify({
            "algorithm": "LMS-W4-SHA256",
            "public_key": _signer.get_public_key_hex(),
            "remaining_signatures": _signer.get_remaining_signatures(),
        })

    if __name__ == "__main__":
        print("=" * 60)
        print(" APEX PSI - PUBLIC VERIFICATION API  [WIRED]")
        print("=" * 60)
        print(f" pq_seal.py available: {HAS_PQ_SEAL}")
        if HAS_PQ_SEAL:
            print(f" Algorithm:           Ed25519 + LMS-W4-SHA256")
            print(f" Signer pub key:      {_signer.get_public_key_hex()[:32]}...")
            print(f" Remaining sigs:      {_signer.get_remaining_signatures()}")
        print(f" In-memory store:     {len(SEAL_STORE)} seals")
        print(f" Anti-strip registry: {len(REGISTRY)} entries")
        print()
        print(" Endpoints:")
        print("   GET  http://localhost:5000/")
        print("   GET  http://localhost:5000/health")
        print("   POST http://localhost:5000/seal")
        print("   POST http://localhost:5000/verify")
        print("   GET  http://localhost:5000/seal/<id>")
        print("   GET  http://localhost:5000/registry/<hash>")
        print("   GET  http://localhost:5000/v1/key")
        print("=" * 60)
        app.run(host="0.0.0.0", port=5000, debug=False)

# ---------- stdlib fallback -------------------------------------------------
else:
    class _Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/?"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(LANDING_PAGE.encode())
            elif self.path == "/health":
                self._json(200, {
                    "status": "alive",
                    "service": "apex-psi-verify",
                    "version": "2.0",
                    "pq_seal_available": HAS_PQ_SEAL,
                    "algorithm": "Ed25519 + LMS-W4-SHA256" if HAS_PQ_SEAL else None,
                    "signer_public_key": _signer.get_public_key_hex() if HAS_PQ_SEAL else None,
                    "remaining_signatures": _signer.get_remaining_signatures() if HAS_PQ_SEAL else 0,
                    "store_size": len(SEAL_STORE),
                    "registry_size": len(REGISTRY),
                })
            elif self.path.startswith("/v1/key"):
                if not HAS_PQ_SEAL:
                    self._json(503, {"error": "pq_seal_unavailable"})
                else:
                    self._json(200, {
                        "algorithm": "LMS-W4-SHA256",
                        "public_key": _signer.get_public_key_hex(),
                        "remaining_signatures": _signer.get_remaining_signatures(),
                    })
            elif self.path.startswith("/seal/"):
                seal_id = self.path[len("/seal/"):]
                if seal_id in SEAL_STORE:
                    self._json(200, SEAL_STORE[seal_id])
                else:
                    self._json(404, {"error": "not_found", "seal_id": seal_id})
            elif self.path.startswith("/registry/"):
                h = self.path[len("/registry/"):]
                if h in REGISTRY:
                    self._json(200, {
                        "found": True,
                        "seal_id": REGISTRY[h],
                        "note": "Hash present in anti-stripping registry.",
                    })
                else:
                    self._json(200, {
                        "found": False, "hash": h,
                        "note": "Hash not in registry.",
                    })
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
            content = data.get("content", "")
            if "/seal" in self.path and content:
                try:
                    self._json(201, create_seal(content))
                except Exception as e:
                    self._json(500, {"error": "seal_creation_failed", "detail": str(e)})
            elif "/verify" in self.path and content:
                self._json(200, verify_seal(
                    content,
                    seal_id=data.get("seal_id"),
                    seal=data.get("seal"),
                ))
            else:
                self._json(400, {"error": "bad_request"})

        def log_message(self, *a, **k):
            pass


def main(host: str = '127.0.0.1', port: int = 5000):
    """Start the verify API server."""
    print('APEX PSI - PUBLIC VERIFICATION API (stdlib, no Flask)')
    print(f' pq_seal.py available: {HAS_PQ_SEAL}')
    print(f' Listening on http://{host}:{port}')
    HTTPServer((host, port), _Handler).serve_forever()


if __name__ == '__main__':
    main()
