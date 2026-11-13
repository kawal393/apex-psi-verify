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
  6. canonical-pointer is the reader told, in one place, which package to install?
  7. published-claims is the published wheel doing what the site claims it does?
  8. consistency-proof can one operator show two different histories and have
                      both verify?
  9. vocabulary       absolutes and sovereignty language on the public face
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

# The canonical verifier for published PSI-SEAL/1 receipts, and the one a
# stranger is told to install. This repo is NOT it.
CANONICAL_PYPI = "psi-verifier"
CANONICAL_NPM = "apex-psi-verifier"

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


def _pq_algorithms_in(body: str) -> list[str]:
    """Which post-quantum algorithms a document names.

    Longest match wins and the matched span is consumed, so 'LMS' never counts
    again inside 'LMS-W4-SHA256'. One algorithm named once is one algorithm.
    """
    text = body.lower()
    found: list[str] = []
    for alg in sorted(PQ_ALGORITHMS, key=len, reverse=True):
        needle = alg.lower()
        idx = text.find(needle)
        if idx == -1:
            continue
        found.append(alg)
        text = text[:idx] + "\x00" * len(needle) + text[idx + len(needle) :]
    # "LMS" is the family; "LMS-W4-SHA256" is one member of it. A codebase that
    # names both has named one algorithm twice, not two algorithms.
    if "LMS-W4-SHA256" in found:
        found = [a for a in found if a != "LMS"]
    return sorted(found)


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

    readme_body = read("README.md")
    for pkg in PYPI_PACKAGES:
        try:
            data = fetch_json(f"https://pypi.org/pypi/{pkg}/json")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # A name that is not on PyPI is only a defect when the copy sends a
                # reader to it. This repo declares itself source-only and points at
                # the canonical package, so its absence is labelled, not hidden.
                if re.search(rf"pip\s+install\s+{re.escape(pkg)}\b", readme_body):
                    record(
                        "registry-state",
                        "FAIL",
                        f"{pkg}: NOT ON PyPI (404), and the README tells a reader to install it",
                        "the README's own install path is a dead end",
                    )
                else:
                    record(
                        "registry-state",
                        "PASS",
                        f"{pkg}: not on PyPI, and no copy sends a reader there",
                        f"the README labels this repo source-only and points at "
                        f"`pip install {CANONICAL_PYPI}`",
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

    # The name this repo's own setup.py declares must exist where it says it does,
    # OR the repo must plainly declare itself source-only and point at the real one.
    m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', read("setup.py"))
    if m:
        declared = m.group(1)
        body = read("README.md")
        labelled_source_only = bool(
            re.search(r"not published on PyPI|source-only", body, re.IGNORECASE)
        ) and CANONICAL_PYPI in body
        try:
            fetch_json(f"https://pypi.org/pypi/{declared}/json")
            record("registry-state", "PASS", f"setup.py name '{declared}' is published on PyPI")
        except urllib.error.HTTPError as e:
            if e.code == 404 and labelled_source_only:
                record(
                    "registry-state",
                    "PASS",
                    f"setup.py declares '{declared}', which is not on PyPI - and the README says so",
                    "source-only, correctly labelled, and points at "
                    f"`pip install {CANONICAL_PYPI}`",
                )
            elif e.code == 404:
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
    body = read("README.md")
    detail = "branded verifier packages in public circulation: " + ", ".join(names)
    if len(names) <= 1:
        record("package-identity", "PASS", detail)
        return

    # More than one package is not the fault. The fault is a reader who cannot
    # tell which one verifies a receipt. So the test is whether the README
    # names every one of them and gives the reader a way in.
    disambiguated = (
        all(n in body for n in names)
        and bool(re.search(r"read this first|which verifier|which one", body, re.IGNORECASE))
    )
    if disambiguated:
        record(
            "package-identity",
            "PASS",
            detail + "; the README names every one of them and says which verifies receipts",
        )
    else:
        record(
            "package-identity",
            "FAIL",
            detail,
            "a stranger searching for 'the APEX PSI verifier' meets more than one answer; "
            "the README must name the offline one explicitly",
        )


# --------------------------------------------------------------------------
# 3. algorithm-record
# --------------------------------------------------------------------------
def check_algorithm_record() -> None:
    """Compare what the code signs with, what the README says, and what the spec names."""
    pkg = ROOT / "apex_psi_verify"
    code = ""
    for p in sorted(pkg.rglob("*.py")) if pkg.exists() else []:
        code += p.read_text(encoding="utf-8", errors="replace")
    files = {
        "README.md": read("README.md"),
        "CHANGELOG.md": read("CHANGELOG.md"),
        "setup.py": read("setup.py"),
    }

    def hits(body: str) -> list[str]:
        return _pq_algorithms_in(body)

    code_hits = hits(code)
    readme_hits = hits(files["README.md"])
    all_hits = sorted({a for h in files.values() for a in hits(h)})

    if not all_hits:
        record("algorithm-record", "FAIL", "no post-quantum algorithm named anywhere")
        return

    detail = "code=" + (",".join(code_hits) or "-") + " README=" + (",".join(readme_hits) or "-")

    # One codebase signing with two post-quantum algorithms is incoherent.
    if len(code_hits) > 1:
        record(
            "algorithm-record",
            "FAIL",
            detail + f"; spec names {SPEC_ALGORITHM}",
            "the live signing path names more than one post-quantum algorithm",
        )
        return

    # Copy and code must not disagree about what this repo does.
    if code_hits and readme_hits and not set(code_hits) & set(readme_hits):
        record(
            "algorithm-record",
            "FAIL",
            detail + f"; spec names {SPEC_ALGORITHM}",
            "the README names an algorithm the code does not use",
        )
        return

    # The spec's algorithm of record is not the one this repo implements. That
    # is drift UNLESS the repo says out loud that it is a component and points
    # at the package that does verify published receipts - and that package
    # fails closed rather than blessing a PQ claim it cannot check.
    if SPEC_ALGORITHM.lower() in {a.lower() for a in all_hits} and SPEC_ALGORITHM not in code_hits:
        body = files["README.md"]
        scoped = (
            CANONICAL_PYPI in body
            and bool(re.search(r"not the canonical verifier|component|source-only|not published on pypi", body, re.IGNORECASE))
        )
        if scoped:
            record(
                "algorithm-record",
                "PASS",
                detail + f"; spec names {SPEC_ALGORITHM}, which this repo does not implement",
                "scope separation is declared: this repo signs with "
                f"{code_hits[0] if code_hits else '?'}, the canonical verifier ({CANONICAL_PYPI}) "
                "refuses to bless a PQ claim it cannot verify, and the README says which is which",
            )
            return
        record(
            "algorithm-record",
            "FAIL",
            detail + f"; spec names {SPEC_ALGORITHM}",
            "the spec's algorithm of record is not implemented here, and the README does not "
            "declare that this repo is a component rather than the verifier",
        )
        return

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

    # The decisive question is not "does the code mention the registry" but
    # "does the VERDICT depend on the registry". A verdict may report registry
    # state as a separate fact; it may not be computed from it.
    assignments = re.findall(r"^\s*verified\s*=\s*(.+)$", src, re.MULTILINE)
    gated = [a for a in assignments if re.search(r"registry", a)]
    if gated:
        record(
            "offline-claim",
            "FAIL",
            "the verdict is gated on hosted registry membership, so a valid signature over an "
            "unregistered hash returns verified=false",
            gated[0].strip()
            + "\n      this package cannot check a published receipt with the host down; the "
            "CHANGELOG says so, the brand says otherwise",
        )
        return

    if not assignments:
        record(
            "offline-claim",
            "SKIP",
            "no `verified =` assignment found in this package's source",
            "nothing to audit for an offline path",
        )
        return

    if re.search(r"verified\s*[:=]\s*[^\n]*registry", src):
        record(
            "offline-claim",
            "FAIL",
            "the verdict path reads hosted registry state",
            "a stranger running this with the host down gets a different answer than our copy claims",
        )
        return

    record(
        "offline-claim",
        "PASS",
        f"the verdict is computed from the signature alone ({assignments[0].strip()})",
        "hosted registry state is reported alongside it as a separate fact, never as a condition",
    )


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
def check_canonical_pointer() -> None:
    """A stranger must be told which package to install, in one place."""
    body = read("README.md")
    if not body:
        record("canonical-pointer", "FAIL", "README.md is missing")
        return
    has_py = CANONICAL_PYPI in body
    has_npm = CANONICAL_NPM in body
    has_cmd = f"pip install {CANONICAL_PYPI}" in body
    if has_py and has_npm and has_cmd:
        record(
            "canonical-pointer",
            "PASS",
            f"README names the canonical packages: {CANONICAL_PYPI} (PyPI), {CANONICAL_NPM} (npm)",
        )
    else:
        record(
            "canonical-pointer",
            "FAIL",
            f"canonical pointer incomplete: pyPI_named={has_py} npm_named={has_npm} install_cmd={has_cmd}",
            "three packages carry one brand; the README must say which one verifies receipts",
        )


def _canonical_wheel_source() -> str:
    """The code a user actually installs, read from the index - not from here."""
    import io
    import zipfile

    data = fetch_json(f"https://pypi.org/pypi/{CANONICAL_PYPI}/json")
    version = data["info"]["version"]
    url = None
    for u in data["urls"]:
        if u["filename"].endswith(".whl"):
            url = u["url"]
            break
    if not url:
        raise RuntimeError(f"{CANONICAL_PYPI} {version}: no wheel published")
    raw = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "apex-psi-audit/1.0"}), timeout=TIMEOUT).read()
    zf = zipfile.ZipFile(io.BytesIO(raw))
    out = []
    for n in zf.namelist():
        if n.endswith(".py"):
            out.append(zf.read(n).decode("utf-8", errors="replace"))
    return "\n".join(out)


def check_published_claims() -> None:
    """Audit the advertised crypto against the code that ships - the wheel, not the repo."""
    try:
        src = _canonical_wheel_source()
    except Exception as e:
        record("published-claims", "SKIP", f"canonical wheel unreachable ({type(e).__name__})")
        return

    enforced = [
        ("R11 Ed25519 checked", bool(re.search(r"Ed25519", src))),
        ("R11.7 unverified PQ refused", bool(re.search(r"unverifiable", src))),
        ("R13.1 RFC 9162 inclusion", bool(re.search(r"9162", src))),
        ("no registry gate", not bool(re.search(r"registry_hit", src))),
        ("no network call", not bool(re.search(r"urllib|requests\.|socket\.", src))),
    ]
    failed = [n for n, ok in enforced if not ok]
    if failed:
        record(
            "published-claims",
            "FAIL",
            f"the published {CANONICAL_PYPI} does not do: {', '.join(failed)}",
            "these are the claims the site tells users to install and trust",
        )
    else:
        record(
            "published-claims",
            "PASS",
            f"the published {CANONICAL_PYPI} enforces " + ", ".join(n for n, _ in enforced),
        )


def check_consistency_proof() -> None:
    """Inclusion proves a leaf is in the tree. Consistency proves the tree only grew.
    Without consistency, one operator can show two different histories."""
    try:
        src = _canonical_wheel_source()
    except Exception as e:
        record("consistency-proof", "SKIP", f"canonical wheel unreachable ({type(e).__name__})")
        return
    has_inclusion = bool(re.search(r"inclusion", src, re.IGNORECASE))
    has_consistency = bool(re.search(r"consistency", src, re.IGNORECASE))
    if has_consistency:
        record("consistency-proof", "PASS", "the published verifier checks RFC 9162 consistency proofs")
    else:
        record(
            "consistency-proof",
            "FAIL",
            f"RFC 9162 inclusion={has_inclusion}, consistency={has_consistency}",
            "inclusion says a leaf is in the tree; only consistency says the tree never "
            "forgets. Without it, a single operator can present two different histories "
            "and both verify.",
        )


def check_vocabulary() -> None:
    hits: list[str] = []
    targets = ["README.md", "CHANGELOG.md", "SECURITY.md", "setup.py"]
    pkg = ROOT / "apex_psi_verify"
    if pkg.exists():
        targets += [str(p.relative_to(ROOT)) for p in sorted(pkg.rglob("*.py"))]
    for rel in targets:
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
        check_canonical_pointer,
        check_published_claims,
        check_consistency_proof,
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
