#!/usr/bin/env python3
"""Record which pickle imports the most-downloaded Hugging Face models actually use.

picklescan runs in the Hugging Face Hub pipeline, so a block-list entry that is too
broad does not just produce a noisy warning -- it flags real models used by real
people. False positives are a production incident, and they are much harder to notice
from inside this repo than false negatives are.

This tool builds an empirical baseline of the imports that popular models legitimately
contain, so a proposed block-list change can be checked against reality before it ships:

    # 1. Collect (run in a Codespace; needs network access to huggingface.co)
    python3 tools/hf_import_stats.py collect --top 500

    # 2. Check the current block-list against the baseline, any time
    python3 tools/hf_import_stats.py check
    python3 tools/hf_import_stats.py check --fail-on-regression   # for CI

`check` classifies every recorded import against the CURRENT `_safe_globals` /
`_unsafe_globals` and compares it to the classification stored at collection time. An
import that was innocuous when collected and is dangerous now means a block-list change
would newly flag popular models -- that is the false-positive alarm.

Where the data comes from
-------------------------
The Hub already scans every uploaded file with picklescan and exposes the result as
metadata. This tool reads only that metadata:

  GET /api/models?sort=downloads&direction=-1   -> most-downloaded models
  GET /api/models/{repo_id}?securityStatus=true -> per-file pickle import scan

**It never downloads model weights, and never unpickles anything.** It reads JSON.

A note on schema stability: the security-status payload is an internal Hub field whose
exact nesting has changed across Hub versions. Rather than hardcode a path that will
silently start returning zero rows, the extractor walks the whole JSON tree and collects
any object carrying `module` + `name` (+ optional `safety`) keys, recording the JSON path
where it found each one. `collect --report-paths` prints those paths so you can confirm
the extraction is still hitting the right field. Use `--save-raw` to capture full
responses when the shape needs inspecting.

Trust note: model IDs and import strings are supplied by whoever uploaded the model.
They are sanitized to plain ASCII before being written into any report, on the same
reasoning as tools/download_advisories.py.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HF_HOST = "huggingface.co"
USER_AGENT = "picklescan-hf-import-stats"
DEFAULT_BASELINE = Path("tools/data/hf_import_baseline.json")

_ASCII_OK = re.compile(r"[^\x20-\x7E]")


def ascii_only(text: str) -> str:
    """Model-supplied strings are untrusted; keep them plain ASCII in reports."""
    return _ASCII_OK.sub("?", str(text or ""))


# --------------------------------------------------------------------------------------
# Hub API
# --------------------------------------------------------------------------------------


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).netloc != HF_HOST:
            raise urllib.error.URLError(f"refusing redirect off {HF_HOST}: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_StrictRedirectHandler)


def _get(url: str, token: str | None, retries: int = 4) -> tuple[object, str | None]:
    """GET JSON from the Hub, honoring Retry-After on 429/5xx."""
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    delay = 2.0
    for attempt in range(retries + 1):
        try:
            with _opener.open(urllib.request.Request(url, headers=headers), timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8")), _parse_next_link(resp.headers.get("Link"))
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = float(e.headers.get("Retry-After") or delay)
                print(f"  HTTP {e.code}; retrying in {wait:.0f}s", file=sys.stderr)
                time.sleep(wait)
                delay *= 2
                continue
            raise
        except urllib.error.URLError:
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError("unreachable")


def _parse_next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip().strip("<>")
        if any(s.strip() == 'rel="next"' for s in segments[1:]):
            if urllib.parse.urlparse(url).netloc == HF_HOST:
                return url
    return None


def list_top_models(limit: int, token: str | None, library: str | None) -> list[dict]:
    """Most-downloaded models first, paging until `limit` is reached."""
    params = {"sort": "downloads", "direction": "-1", "limit": str(min(limit, 100))}
    if library:
        params["filter"] = library
    url = f"https://{HF_HOST}/api/models?{urllib.parse.urlencode(params)}"
    models: list[dict] = []
    while url and len(models) < limit:
        payload, next_url = _get(url, token)
        if not isinstance(payload, list) or not payload:
            break
        models.extend(payload)
        url = next_url
        print(f"  listed {len(models)} models", file=sys.stderr)
    return models[:limit]


def fetch_security_status(repo_id: str, token: str | None) -> dict:
    url = f"https://{HF_HOST}/api/models/{urllib.parse.quote(repo_id)}?securityStatus=true"
    payload, _ = _get(url, token)
    return payload if isinstance(payload, dict) else {}


# --------------------------------------------------------------------------------------
# Extraction (path-agnostic, so Hub schema drift does not silently zero the results)
# --------------------------------------------------------------------------------------


def extract_imports(obj, path: str = "$") -> list[dict]:
    """Walk arbitrary JSON and collect every {module, name[, safety]} object found.

    Returns dicts with module, name, safety and the JSON path it was found at.
    """
    found: list[dict] = []
    if isinstance(obj, dict):
        module, name = obj.get("module"), obj.get("name")
        if isinstance(module, str) and isinstance(name, str) and "children" not in obj:
            found.append(
                {
                    "module": module,
                    "name": name,
                    "safety": obj.get("safety") if isinstance(obj.get("safety"), str) else None,
                    "path": path,
                }
            )
        for key, value in obj.items():
            found.extend(extract_imports(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            found.extend(extract_imports(value, f"{path}[{i}]" if i == 0 else f"{path}[]"))
    return found


# --------------------------------------------------------------------------------------
# picklescan classification
# --------------------------------------------------------------------------------------


def classify(module: str, name: str) -> str:
    """Ask the CURRENT picklescan block-list how it would classify this global."""
    try:
        from picklescan.scanner import _build_scan_result_from_raw_globals
    except ModuleNotFoundError:
        sys.exit("picklescan is not importable. Run `pip install -e .` from the repo root first.")
    result = _build_scan_result_from_raw_globals({(module, name)}, "hf-baseline")
    return result.globals[0].safety.value


# --------------------------------------------------------------------------------------
# collect
# --------------------------------------------------------------------------------------


def cmd_collect(args) -> int:
    token = args.token
    print(f"Listing top {args.top} models by downloads...", file=sys.stderr)
    try:
        models = list_top_models(args.top, token, args.library)
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code} from the Hub while listing models: {e.reason}")
    except urllib.error.URLError as e:
        sys.exit(
            f"Could not reach {HF_HOST}: {e.reason}\n"
            "`collect` needs outbound network access to huggingface.co. Run it somewhere\n"
            "with open egress (a Codespace); `check` works offline against a saved baseline."
        )
    print(f"Got {len(models)} models. Fetching security status...", file=sys.stderr)

    raw_dir = Path(args.save_raw) if args.save_raw else None
    if raw_dir:
        raw_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    errors: list[dict] = []

    def worker(model: dict) -> None:
        repo_id = model.get("id") or ""
        try:
            status = fetch_security_status(repo_id, token)
        except Exception as e:  # network/HTTP problems must not abort a long crawl
            errors.append({"model": ascii_only(repo_id), "error": ascii_only(str(e))[:200]})
            return
        if raw_dir:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", repo_id)[:120]
            (raw_dir / f"{safe}.json").write_text(json.dumps(status, indent=2), encoding="utf-8", errors="replace")
        imports = extract_imports(status)
        records.append(
            {
                "model": repo_id,
                "downloads": model.get("downloads") or 0,
                "likes": model.get("likes") or 0,
                "library": model.get("library_name"),
                "imports": imports,
            }
        )
        if args.sleep:
            time.sleep(args.sleep)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i, _ in enumerate(pool.map(worker, models), 1):
            if i % 25 == 0:
                print(f"  {i}/{len(models)}", file=sys.stderr)

    # Aggregate per (module, name).
    stats: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"models": 0, "occurrences": 0, "downloads": 0, "hub_safety": set(), "examples": []}
    )
    for rec in records:
        seen: set[tuple[str, str]] = set()
        for imp in rec["imports"]:
            key = (imp["module"], imp["name"])
            entry = stats[key]
            entry["occurrences"] += 1
            if imp.get("safety"):
                entry["hub_safety"].add(imp["safety"])
            if key not in seen:
                seen.add(key)
                entry["models"] += 1
                entry["downloads"] += rec["downloads"]
                if len(entry["examples"]) < 3:
                    entry["examples"].append(rec["model"])

    imports_out = []
    for (module, name), entry in sorted(stats.items(), key=lambda kv: (-kv[1]["models"], kv[0])):
        imports_out.append(
            {
                "module": module,
                "name": name,
                "models": entry["models"],
                "occurrences": entry["occurrences"],
                "downloads": entry["downloads"],
                "hub_safety": sorted(entry["hub_safety"]),
                "picklescan_safety_at_collection": classify(module, name),
                "examples": entry["examples"],
            }
        )

    paths = sorted({imp["path"] for rec in records for imp in rec["imports"]})
    baseline = {
        "schema": 1,
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": f"https://{HF_HOST}/api/models (securityStatus=true)",
        "models_requested": args.top,
        "models_listed": len(models),
        "models_with_imports": sum(1 for r in records if r["imports"]),
        "models_failed": len(errors),
        "library_filter": args.library,
        "extraction_paths": paths,
        "imports": imports_out,
        "errors": errors[:50],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    print(f"\nWrote {out} -- {len(imports_out)} distinct imports from {baseline['models_with_imports']} models", file=sys.stderr)
    if errors:
        print(f"{len(errors)} model(s) failed; see 'errors' in the baseline", file=sys.stderr)
    if args.report_paths:
        print("\nJSON paths imports were extracted from (confirm these look like Hub security fields):", file=sys.stderr)
        for p in paths[:20]:
            print(f"  {p}", file=sys.stderr)
    if not imports_out:
        print(
            "\nWARNING: zero imports extracted. Either these models carry no pickle files,\n"
            "or the Hub's security-status schema moved. Re-run with --save-raw and inspect.",
            file=sys.stderr,
        )
    return 0


# --------------------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------------------


def cmd_check(args) -> int:
    path = Path(args.baseline)
    if not path.exists():
        sys.exit(f"No baseline at {path}. Run `{sys.argv[0]} collect` in an environment with network access first.")
    baseline = json.loads(path.read_text(encoding="utf-8"))
    imports = baseline.get("imports") or []
    if not imports:
        sys.exit(f"Baseline {path} contains no imports.")

    regressions, dangerous_now, changed = [], [], []
    for entry in imports:
        module, name = entry["module"], entry["name"]
        was = entry.get("picklescan_safety_at_collection")
        now = classify(module, name)
        row = {**entry, "picklescan_safety_now": now, "was": was}
        if now != was:
            changed.append(row)
            if now == "dangerous" and was != "dangerous":
                regressions.append(row)
        if now == "dangerous":
            dangerous_now.append(row)

    def fmt(row: dict) -> str:
        ex = ", ".join(ascii_only(e) for e in row.get("examples", [])[:2])
        return (
            f"  {ascii_only(row['module'])}.{ascii_only(row['name'])}\n"
            f"      {row['models']} model(s), {row['downloads']:,} downloads"
            f" | was={row['was']} now={row['picklescan_safety_now']}"
            f" | hub={','.join(row.get('hub_safety') or ['-'])}\n"
            f"      e.g. {ex}"
        )

    print(
        f"Baseline: {path} (collected {baseline.get('collected_at')}, "
        f"{baseline.get('models_with_imports')} models, {len(imports)} distinct imports)\n"
    )

    if regressions:
        print(f"!! {len(regressions)} REGRESSION(S): imports popular models use that the block-list now flags Dangerous.")
        print("   Each one is a false positive that would fire on the Hugging Face Hub.\n")
        for row in sorted(regressions, key=lambda r: -r["downloads"]):
            print(fmt(row))
        print()
    else:
        print("No regressions: nothing that was safe at collection time is flagged Dangerous now.\n")

    if dangerous_now:
        print(
            f"{len(dangerous_now)} import(s) in the baseline classify as Dangerous today "
            f"({len(dangerous_now) - len(regressions)} of them already did at collection time):"
        )
        for row in sorted(dangerous_now, key=lambda r: -r["downloads"])[: args.limit]:
            print(fmt(row))
        print()

    other_changes = [c for c in changed if c not in regressions]
    if other_changes:
        print(f"{len(other_changes)} other classification change(s) since collection:")
        for row in other_changes[: args.limit]:
            print(f"  {ascii_only(row['module'])}.{ascii_only(row['name'])}: {row['was']} -> {row['picklescan_safety_now']}")
        print()

    if args.top:
        print(f"Top {args.top} most widely used imports in the baseline:")
        for row in imports[: args.top]:
            print(
                f"  {row['models']:>5} models  {ascii_only(row['module'])}.{ascii_only(row['name'])}"
                f"  [{row.get('picklescan_safety_at_collection')}]"
            )
        print()

    return 1 if (regressions and args.fail_on_regression) else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Baseline the pickle imports used by popular Hugging Face models, to catch block-list false positives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Reads Hub metadata only. Never downloads weights, never unpickles anything.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="Fetch from the Hub and write a baseline (needs network)")
    c.add_argument("--top", type=int, default=200, help="How many most-downloaded models to sample (default: 200)")
    c.add_argument("--out", default=str(DEFAULT_BASELINE), help=f"Baseline path (default: {DEFAULT_BASELINE})")
    c.add_argument("--library", help="Filter to a library, e.g. 'pytorch' or 'transformers'")
    c.add_argument("--token", help="Hugging Face token (optional; raises rate limits)")
    c.add_argument("--workers", type=int, default=8, help="Concurrent metadata requests (default: 8)")
    c.add_argument("--sleep", type=float, default=0.0, help="Seconds to sleep after each model (politeness)")
    c.add_argument("--save-raw", help="Directory to save raw API responses for schema inspection")
    c.add_argument("--report-paths", action="store_true", help="Print the JSON paths imports were extracted from")
    c.set_defaults(func=cmd_collect)

    k = sub.add_parser("check", help="Compare the current block-list against the baseline")
    k.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    k.add_argument("--fail-on-regression", action="store_true", help="Exit 1 if a previously-safe popular import is now Dangerous")
    k.add_argument("--limit", type=int, default=25, help="Max rows per section (default: 25)")
    k.add_argument("--top", type=int, default=0, help="Also list the N most widely used imports")
    k.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
