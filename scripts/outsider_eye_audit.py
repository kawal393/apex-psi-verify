#!/usr/bin/env python3
"""Outsider's-eye audit of the APEX PSI verifier surface.

    python scripts/outsider_eye_audit.py

Why this exists: the 13 Nov 2026 outside audit graded the project 6.0/10 from a
crawl of artifacts alone - the IETF draft, the public repos, npm, and the live
/verify page. Nothing in our own routine ever asked the same question:
"if a stranger reads only the artifacts, what do they conclude, and which of
those conclusions is false?"

That question is now a script. It runs with no dependencies, prints a verdict per
check with the evidence that produced it, and exits non-zero if any check FAILS.
A FAIL here is not a bug in this script; it is a claim we are not currently
entitled to make.

Checks:
  1. registry-state   every published verifier package, its versions, whether a
                      broken release is still installable and unlabelled
  2. package-identity which package is "the verifier"? a stranger must not have
                      to guess which of several same-brand names is the offline one
  3. algorithm-record the PQ algorithm this repo declares, vs the algorithm the
                      spec names, vs the algorithm the code signs with
  4. offline-claim    does the thing we call "offline-verifiable" actually work
                      without the hosted operator?
  5. disclosure       is the key budget (leaves per key) stated where a reader
                      will see it?
  6. vocabulary       absolutes and sovereignty language on the public face
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 20

# The three public packages that carry the APEX PSI verifier brand. An auditor
# who types "apex psi verifier" will meet all of them.
NPM_PACKAGES = ["apex-psi-verifier"]
PYPI_PACKAGES = ["apex-psi-verify", "psi-verifier"]

# Algorithm of record per artifact. Check 3 compares these.
SPEC_ALGORITHM = "ML-DSA-65"
PQ_ALGORITHMS = ["ML-DSA-65", "LMS-W4-SHA256", "LMS", "SPHINCS", "Falcon"]
ED25519 = "Ed25519"

# Words that make a promise the artifact cannot keep.
BANNED = [
    "authoritative",
    "ineluctable",
    "sovereign",
    "inevitable",
    "tamper-proof",
    "immutable",
    "guaranteed",
    "digital truth",
    "truth",
    "100%",
]

results: list[tuple[str, str, str, str]] = []  # check, verdict, detail, evidence


def record(check: str, verdict: str, detail: str, evidence: str = "") -> None:
    results.append((check, verdict, detail, evidence))


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "apex-psi-outsider-eye-audit/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
# 1. registry-state
# --------------------------------------------------------------------------
def check_registry_state() -> None:
    for pkg in NPM_PACKAGES:
        try:
            data = fetch_json(f"https://registry.npmjs.org/{pkg}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            record("registry-state", "SKIP", f"{pkg}: registry unreachable ({type(e).__name__})")
            continue
        versions = data.get("versions", {})
        deprecated = [v for v, m in versions.items() if m.get("deprecated")]
        latest = data.get("dist-tags", {}).get("latest", "?")
        detail = f"{pkg}: {len(versions)} versions, latest={latest}"
        if deprecated:
            record("registry-state", "PASS", detail + f", deprecated={deprecated}")
        else:
            record(
                "registry-state",
                "FAIL",
                detail + ", NOTHING deprecated",
                "an old release is still installable with no machine-readable label",
            )

    for pkg in PYPI_PACKAGES:
        try:
            data = fetch_json(f"https://pypi.org/pypi/{pkg}/json")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                record(
                    "registry-state",
                    "FAIL",
                    f"{pkg}: NOT ON PyPI (404)",
                    "setup.py in this repo declares this exact name, so a stranger who follows the "
                    "README's own install path finds nothing published",
                )
            else:
                record("registry-state", "SKIP", f"{pkg}: index returned HTTP {e.code}")
            continue
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            record("registry-state", "SKIP", f"{pkg}: index unreachable ({type(e).__name__})")
            continue
        releases = sorted(data.get("releases", {}).keys())
        detail = f"{pkg}: {len(releases)} releases, latest={data['info']['version']}"
        record("registry-state", "PASS", detail, f"releases={releases}")

    # The name this repo's own setup.py declares must exist where it says it does.
    m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', read("setup.py"))
    if m:
        declared = m.group(1)
        try:
            fetch_json(f"https://pypi.org/pypi/{declared}/json")
            record("registry-state", "PASS", f"setup.py name '{declared}' is published on PyPI")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                record(
                    "registry-state",
                    "FAIL",
                    f"setup.py declares '{declared}' and PyPI has no such package (404)",
                    "the repo an auditor clones is installable only from source, so every claim "
                    "'pip install apex-psi-verify' is a dead end",
                )
            else:
                record("registry-state", "SKIP", f"setup.py name '{declared}': PyPI returned HTTP {e.code}")
        except Exception as e:
            record("registry-state", "SKIP", f"setup.py name '{declared}': {type(e).__name__}")


# --------------------------------------------------------------------------
# 2. package-identity
# --------------------------------------------------------------------------
def check_package_identity() -> None:
    """Several packages carry the verifier brand. Say which one is which."""
    names = NPM_PACKAGES + PYPI_PACKAGES
    detail = "branded verifier packages in public circulation: " + ", ".join(names)
    if len(names) > 1:
        record(
            "package-identity",
            "FAIL",
            detail,
            "a stranger searching for 'the APEX PSI verifier' meets more than one answer; "
            "the README must name the offline one explicitly",
        )
    else:
        record("package-identity", "PASS", detail)


# --------------------------------------------------------------------------
# 3. algorithm-record
# --------------------------------------------------------------------------
def check_algorithm_record() -> None:
    files = {
        "README.md": read("README.md"),
        "CHANGELOG.md": read("CHANGELOG.md"),
        "setup.py": read("setup.py"),
    }
    found: dict[str, list[str]] = {}
    for name, body in files.items():
        hits = sorted({a for a in PQ_ALGORITHMS if a.lower() in body.lower()})
        if hits:
            found[name] = hits

    if not found:
        record("algorithm-record", "FAIL", "no post-quantum algorithm named anywhere")
        return

    all_hits = sorted({a for hits in found.values() for a in hits})
    detail = "PQ algorithms named: " + ", ".join(f"{k}={v}" for k, v in found.items())
    if len(all_hits) > 1:
        record(
            "algorithm-record",
            "FAIL",
            detail + f"; spec names {SPEC_ALGORITHM}",
            "spec and code name different post-quantum algorithms - the drift a grader reads as "
            "architectural oscillation",
        )
    else:
        record("algorithm-record", "PASS", detail + f"; spec names {SPEC_ALGORITHM}")


# --------------------------------------------------------------------------
# 4. offline-claim
# --------------------------------------------------------------------------
def check_offline_claim() -> None:
    """If we call it offline-verifiable, it must verify with the host unreachable."""
    body = read("README.md")
    pkg = ROOT / "apex_psi_verify"
    src = ""
    for p in sorted(pkg.rglob("*.py")) if pkg.exists() else []:
        src += p.read_text(encoding="utf-8", errors="replace")

    # The decisive line: a verdict that requires registry membership is not an
    # offline verification - it is a lookup that happens to carry a signature.
    gated = re.search(r"verified\s*=\s*bool\([^)]*registry_hit[^)]*\)", src)
    if gated:
        line = next((l.strip() for l in src.splitlines() if "registry_hit" in l and "verified" in l), "")
        record(
            "offline-claim",
            "FAIL",
            "the verdict is gated on hosted registry membership, so a valid signature over an "
            "unregistered hash returns verified=false",
            (line or "verified = ... registry_hit ...")
            + "\n      this package cannot check a published receipt with the host down; the "
            "CHANGELOG says so, the brand says otherwise",
        )
        return

    if re.search(r"registry_hit|registry_state", src):
        record(
            "offline-claim",
            "FAIL",
            "the verdict path reads hosted registry state",
            "a stranger running this with the host down gets a different answer than our copy claims",
        )
        return

    if "offline" in body.lower():
        record("offline-claim", "FAIL", "README claims offline verification; no offline path found")
        return

    record("offline-claim", "PASS", "the verdict path does not read hosted state")


# --------------------------------------------------------------------------
# 5. disclosure
# --------------------------------------------------------------------------
def check_disclosure() -> None:
    body = read("README.md")
    if not body:
        record("disclosure", "FAIL", "README.md is missing")
        return
    m = re.search(r"(\d+)[- ]leaf", body)
    leaves = m.group(1) if m else None
    mentions_rotation = "rotat" in body.lower()
    if leaves and mentions_rotation:
        record("disclosure", "PASS", f"key budget disclosed: {leaves} leaves, rotation mentioned")
    else:
        record(
            "disclosure",
            "FAIL",
            f"leaves={leaves}, rotation_mentioned={mentions_rotation}",
            "the number of seals a key can produce is a fact a grader will compute from the code; "
            "it must be stated, not inferred",
        )


# --------------------------------------------------------------------------
# 6. vocabulary
# --------------------------------------------------------------------------
def check_vocabulary() -> None:
    hits: list[str] = []
    for rel in ("README.md", "CHANGELOG.md", "SECURITY.md", "setup.py"):
        body = read(rel)
        for line in body.splitlines():
            low = line.lower()
            for word in BANNED:
                if re.search(rf"\b{re.escape(word)}", low):
                    hits.append(f"{rel}: {word} -> {line.strip()[:90]}")
                    break
    if hits:
        record(
            "vocabulary",
            "FAIL",
            f"{len(hits)} absolute/sovereign claim(s) on the public face",
            "\n      ".join(hits[:8]),
        )
    else:
        record("vocabulary", "PASS", "no absolutes or sovereignty language on the public face")


def main() -> int:
    print("=" * 78)
    print("APEX PSI - OUTSIDER'S-EYE AUDIT")
    print("graded from artifacts only: registries, this repo's files, the words we publish")
    print("=" * 78)

    for fn in (
        check_registry_state,
        check_package_identity,
        check_algorithm_record,
        check_offline_claim,
        check_disclosure,
        check_vocabulary,
    ):
        try:
            fn()
        except Exception as e:  # a broken check must not hide the others
            record(fn.__name__, "ERROR", f"{type(e).__name__}: {e}")

    print()
    width = max(len(r[0]) for r in results)
    for check, verdict, detail, evidence in results:
        mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP", "ERROR": "ERR "}[verdict]
        print(f"[{mark}] {check.ljust(width)}  {detail}")
        if evidence:
            for line in evidence.splitlines():
                print(f"       {line}")

    fails = [r for r in results if r[1] == "FAIL"]
    errors = [r for r in results if r[1] == "ERROR"]
    print()
    print(f"{len(results) - len(fails) - len(errors)} passed, {len(fails)} failed, {len(errors)} errored")
    if fails:
        print()
        print("A FAIL is a claim we are not entitled to make. Fix the artifact or the copy - not the audit.")
    return 1 if (fails or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
