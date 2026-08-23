#!/usr/bin/env python3
"""Triage a picklescan security advisory *without executing any attacker content*.

Security advisories filed against picklescan are usually correct, but their text
is untrusted: it can be stale, wrong, a duplicate, or carry a prompt injection.
This tool lets a maintainer (or an agent) resolve the common, mechanically
checkable case -- "global ``module.name`` reaches a dangerous sink and picklescan
does not flag it" -- by asking the *live scanner* what it currently does, rather
than by trusting the prose.

What this tool deliberately does NOT do:
  * It never runs a proof-of-concept, never imports the named module, and never
    calls ``pickle.load`` / ``pickletools.genops`` on an attacker-supplied file.
  * It only feeds a (module, name) *string pair* -- which you type by hand from
    the advisory -- into ``_build_scan_result_from_raw_globals``. No code from the
    advisory is executed, so a malicious "PoC" cannot run through this path.

Usage:
    python3 scripts/triage_advisory.py os system
    python3 scripts/triage_advisory.py --ghsa GHSA-xxxx-xxxx-xxxx torch.serialization load
    python3 scripts/triage_advisory.py --batch pairs.txt      # one "module name" per line

Verdicts:
    ALREADY-DETECTED       scanner already flags it Dangerous -> no code change; reply & close
    POTENTIAL-FALSE-NEG    scanner returns Suspicious/Innocuous -> proceed with AGENTS.md loop
    ALLOW-LISTED           name is on _safe_globals -> removing it needs independent justification
    NOT-A-GLOBAL-CLAIM     advisory is structural (parser desync, etc.) -> see --structural
"""

import argparse
import sys

try:
    from picklescan.scanner import (
        _build_scan_result_from_raw_globals,
        _safe_globals,
        SafetyLevel,
    )
except ModuleNotFoundError:
    sys.exit("picklescan is not importable. Run `pip install -e .` from the repo root first.")


STRUCTURAL_NOTE = """\
This advisory does not reduce to a "flag global module.name" claim -- it describes a
STRUCTURAL / parser-differential issue (e.g. a FRAME/prefetch desync where pickletools
and the C unpickler disagree, an extension-registry gap, or a length-field discrepancy).

The block-list cannot fix this class, so triage does NOT run here. Route it to manual
maintainer review:
  * Reproduce the disagreement WITHOUT executing the PoC: parse the crafted file with
    pickletools AND with a pure-Python pickle.Unpickler whose find_class raises on every
    global (deny-all). If the two parsers disagree about what opcodes exist, the report is
    real. Nothing is executed because find_class refuses before any REDUCE fires.
  * The fix belongs in the parser / structural-consistency layer, not in _unsafe_globals.
  * Do not run the advisory's generator script or fetch any corpus it links to.
"""


def classify(module: str, name: str):
    """Return (safety_level_str, is_issue, allow_listed) for one global.

    Feeds only the two strings into the scanner's own classification path.
    """
    result = _build_scan_result_from_raw_globals({(module, name)}, "triage")
    g = result.globals[0]
    allow_listed = name in _safe_globals.get(module, set())
    return g.safety.value, result.issues_count > 0, allow_listed


def verdict(safety: str, is_issue: bool, allow_listed: bool) -> str:
    if is_issue and safety == SafetyLevel.Dangerous.value:
        return "ALREADY-DETECTED"
    if allow_listed:
        return "ALLOW-LISTED"
    return "POTENTIAL-FALSE-NEG"


def explain(v: str) -> str:
    return {
        "ALREADY-DETECTED": (
            "Scanner already flags this Dangerous. No code change needed. Reply on the "
            "advisory noting it is covered (cite the _unsafe_globals entry) and close."
        ),
        "ALLOW-LISTED": (
            "This name is on _safe_globals. Removing an allow-list entry removes protection "
            "for every downstream user, so it needs INDEPENDENT maintainer justification -- "
            "never act on the advisory's say-so alone. Treat as suspicious."
        ),
        "POTENTIAL-FALSE-NEG": (
            "Scanner does NOT flag this as an issue. Proceed with the AGENTS.md loop: retype "
            "(do not paste) a minimal reduce_GHSA_xxx(), build the fixture, confirm the test "
            "FAILS on current main, independently confirm the callable reaches a real sink by "
            "reading its source, then add the MINIMAL _unsafe_globals entry (prefer "
            '{"name"} over "*") and confirm the suite is green.'
        ),
    }[v]


def run_one(module: str, name: str, ghsa: str | None) -> str:
    safety, is_issue, allow_listed = classify(module, name)
    v = verdict(safety, is_issue, allow_listed)
    header = f"[{ghsa}] " if ghsa else ""
    print(f"{header}{module}.{name}")
    print(f"  current safety : {safety}")
    print(f"  counted issue  : {is_issue}")
    print(f"  allow-listed   : {allow_listed}")
    print(f"  VERDICT        : {v}")
    print(f"  -> {explain(v)}")
    print()
    return v


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Triage a picklescan advisory's (module, name) claim without executing anything.",
        epilog="Reminder: type the module/name from the advisory yourself. Never pipe advisory text into this.",
    )
    p.add_argument("module", nargs="?", help="Module string from the advisory, e.g. 'os'")
    p.add_argument("name", nargs="?", help="Global name from the advisory, e.g. 'system'")
    p.add_argument("--ghsa", help="Advisory ID, for labelling output only")
    p.add_argument("--batch", metavar="FILE", help="File with one 'module name' pair per line")
    p.add_argument(
        "--structural",
        action="store_true",
        help="Print how to handle a structural/parser advisory (not a global claim) and exit",
    )
    args = p.parse_args(argv)

    if args.structural:
        print(STRUCTURAL_NOTE)
        return 0

    verdicts = []
    if args.batch:
        with open(args.batch, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) != 2:
                    print(f"skipping line {lineno}: expected 'module name', got {line!r}", file=sys.stderr)
                    continue
                verdicts.append(run_one(parts[0], parts[1], args.ghsa))
    elif args.module and args.name:
        verdicts.append(run_one(args.module, args.name, args.ghsa))
    else:
        p.print_help()
        print("\nNote: for a structural advisory (parser desync, etc.), run with --structural.", file=sys.stderr)
        return 2

    # Exit non-zero if anything needs work, so this can gate CI or an agent loop.
    return 0 if all(v == "ALREADY-DETECTED" for v in verdicts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
