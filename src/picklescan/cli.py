import argparse
import json
import logging
import os
import re
import sys

from .scanner import ScanFilter, ScanResult, Severity, Verdict, scan_directory_path, _printable
from .scanner import scan_file_path
from .scanner import scan_url
from .scanner import scan_huggingface_model

_log = logging.getLogger("picklescan")


class Style:
    """ANSI colors for terminal output. The scanner itself never colors anything: only what the command line prints."""

    _codes = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles or not text:
            return text
        return f"\x1b[{';'.join(self._codes[s] for s in styles)}m{text}\x1b[0m"


def _enable_windows_colors(stream) -> bool:
    """Windows consoles show ANSI colors once asked to (ENABLE_VIRTUAL_TERMINAL_PROCESSING, Windows 10 and later)."""
    try:
        import ctypes
        import msvcrt

        kernel32 = ctypes.windll.kernel32
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = ctypes.c_uint32()
        return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)) and kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def color_enabled(choice: str, stream) -> bool:
    """--color always/never, or auto: colors on a terminal, unless NO_COLOR is set (https://no-color.org), or forced by FORCE_COLOR."""
    if choice != "auto":
        if choice == "always" and sys.platform == "win32":
            _enable_windows_colors(stream)
        return choice == "always"
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb" or not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    return sys.platform != "win32" or _enable_windows_colors(stream)


class _LogFormatter(logging.Formatter):
    """Colors the messages the scanner logs while it runs, by severity. What the scanned files can put in them (names, paths...) is
    escaped, except in the summary, which escapes it itself (records with picklescan_summary set)."""

    def __init__(self, style: Style):
        super().__init__()
        self.style = style

    def format(self, record: logging.LogRecord) -> str:
        if getattr(record, "picklescan_summary", False):
            return record.getMessage()
        message = _printable(record.getMessage())
        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)
        if record.levelno >= logging.ERROR or (record.levelno >= logging.WARNING and getattr(record, "picklescan_dangerous", False)):
            return self.style(message, "red")
        if record.levelno >= logging.WARNING:
            return self.style(message, "yellow")
        return message


_verdict_styles = {Verdict.SAFE: ("green", "bold"), Verdict.UNSAFE: ("red", "bold"), Verdict.UNVERIFIED: ("yellow", "bold")}
_safety_styles = {"dangerous": ("red", "bold"), "suspicious": ("yellow",), "innocuous": ("dim",)}
_summary = {"picklescan_summary": True}


def print_summary(show_globals: bool, sr: ScanResult, style: Style = Style(False)):
    def count(label: str, value: int, *styles: str) -> str:
        return f"{label}: {style(str(value), *styles) if value else value}"

    _log.info(
        "\n".join(
            [
                style("----------- SCAN SUMMARY -----------", "bold"),
                f"Scanned files: {sr.scanned_files}",
                count("Infected files", sr.infected_files, "red", "bold"),
                count("Suspicious globals", sr.suspicious_count, "yellow"),
                count("Dangerous globals", sr.issues_count, "red", "bold"),
                count("Scan errors", len(sr.errors), "red"),
                count("Not scanned", len(sr.skipped), "yellow"),
                f"Verdict: {style(sr.verdict().value, *_verdict_styles[sr.verdict()])}",
            ]
        ),
        extra=_summary,
    )
    for error in sr.errors:
        _log.info("\n" + error.format(style), extra=_summary)
    for skipped in sr.skipped:
        _log.info("\n" + skipped.format(style), extra=_summary)
    if show_globals and len(sr.globals) > 0:
        _log.info("\nAll globals found:", extra=_summary)
        for line in format_globals(sr.globals, style):
            _log.info(line, extra=_summary)


def result_to_json(sr: ScanResult) -> dict:
    def where(location) -> dict:
        return {"file": location.file, "members": list(location.members)} if location is not None else {"file": None, "members": []}

    return {
        "scanned_files": sr.scanned_files,
        "infected_files": sr.infected_files,
        "verdict": sr.verdict().value,
        "dangerous_globals": sr.issues_count,
        "suspicious_globals": sr.suspicious_count,
        "globals": [{"module": g.module, "name": g.name, "safety": g.safety.value, **where(g.location)} for g in sr.globals],
        # null when everything was scanned
        "errors": [
            {
                "kind": e.kind.value,
                "severity": e.severity.value,
                "message": e.message,
                "offset": e.offset,
                "help": e.help,
                **where(e.location),
            }
            for e in sr.errors
        ]
        or None,
        "skipped": [{"reason": s.reason, **where(s.location)} for s in sr.skipped],
    }


_safety_order = {"dangerous": 0, "suspicious": 1, "innocuous": 2}


def format_globals(globals, style: Style = Style(False)) -> list:
    """Imports grouped by file, then by archive member, most dangerous first. What the scanned files hold is escaped."""
    groups = {}  # file -> member path -> globals, in the order they were found
    for g in globals:
        file, members = (g.location.file, " > ".join(g.location.members)) if g.location is not None else ("(unknown location)", "")
        file, members = _printable(file), _printable(members)
        groups.setdefault(file, {}).setdefault(members, []).append(g)
    lines = []
    for file, by_member in groups.items():
        lines.append(f"  {style(file, 'bold')}")
        for members, found in by_member.items():
            indent = "    "
            if members:
                lines.append(f"    {style(members, 'dim')}")
                indent = "      "
            for g in sorted(found, key=lambda g: _safety_order[g.safety.value]):
                safety = g.safety.value
                lines.append(
                    f"{indent}{style(safety, *_safety_styles[safety])}{' ' * (10 - len(safety))} {_printable(f'{g.module}.{g.name}')}"
                )
    return lines


def main():
    _log.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(description="Security scanner detecting Python Pickle files performing suspicious actions.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--path", help="Path to the file or folder to scan", dest="path")
    group.add_argument("-u", "--url", help="URL to the file or folder to scan", dest="url")
    group.add_argument(
        "-hf",
        "--huggingface",
        help="Name of the Hugging Face model to scan",
        dest="huggingface_model",
    )
    parser.add_argument("-g", "--globals", help="list all globals found", action="store_true")
    parser.add_argument("--json", help="print the scan result as JSON, and nothing else", action="store_true")
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="colored output: auto (default) colors on a terminal, unless the NO_COLOR environment variable is set",
    )
    parser.set_defaults(globals=False)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Promote suspicious globals to dangerous (default-deny mode)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="REGEX",
        help="Don't scan file names matching regular expression. Can be used multiple times.",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="REGEX",
        help="Only scan file names matching regular expression. Can be used multiple times.",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="REGEX",
        dest="exclude_dir",
        help="Don't scan directory names matching regular expression. Can be used multiple times.",
    )
    parser.add_argument(
        "--include-dir",
        action="append",
        default=[],
        metavar="REGEX",
        dest="include_dir",
        help="Only scan directory names matching regular expression. Can be used multiple times.",
    )
    parser.add_argument(
        "-l",
        "--log",
        help="level of log messages to display (default: INFO)",
        dest="log_level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
    )

    args = parser.parse_args()

    style = Style(color_enabled(args.color, sys.stdout) and not args.json)
    # With --json, stdout holds the JSON document only: messages go to stderr
    handler = logging.StreamHandler(stream=sys.stderr if args.json else sys.stdout)
    handler.setFormatter(_LogFormatter(style))
    _log.addHandler(handler)
    if args.json and args.log_level is None:
        handler.setLevel(logging.CRITICAL)

    if "log_level" in args and args.log_level is not None:
        _log.setLevel(getattr(logging, args.log_level))
    if _log.getEffectiveLevel() == logging.INFO and not args.json:
        # Errors and skipped content are printed once, from the scan result, in the summary (printed at the INFO level)
        handler.addFilter(lambda record: not getattr(record, "picklescan_reported", False))

    scan_filter = ScanFilter(
        exclude=[re.compile(p) for p in args.exclude],
        include=[re.compile(p) for p in args.include],
        exclude_dir=[re.compile(p) for p in args.exclude_dir],
        include_dir=[re.compile(p) for p in args.include_dir],
    )

    try:
        if args.path is not None:
            path = args.path  # reported as given, like compilers and linters do
            if not os.path.exists(path):
                raise FileNotFoundError(f"Path {path} does not exist")
            if os.path.isdir(path):
                scan_result = scan_directory_path(path, scan_filter=scan_filter, strict=args.strict)
            else:
                scan_result = scan_file_path(path, strict=args.strict)
        elif args.url is not None:
            scan_result = scan_url(args.url, strict=args.strict)
        elif args.huggingface_model is not None:
            scan_result = scan_huggingface_model(args.huggingface_model, strict=args.strict)
        else:
            raise ValueError("Command line must include either a path, a URL, or a Hugging Face model")

        if args.json:
            print(json.dumps(result_to_json(scan_result), indent=2))
        else:
            print_summary(args.globals, scan_result, style)

        # a-la ClamAV: a scan that could not check everything (blocking errors) fails, even when it found malware. Warnings don't.
        if any(e.severity is Severity.ERROR for e in scan_result.errors):
            return 2
        return 1 if scan_result.verdict() is Verdict.UNSAFE else 0
    except Exception as e:
        _log.exception("Unhandled exception")
        if args.json:
            print(json.dumps({"fatal_error": f"{type(e).__name__}: {e}"}, indent=2))
        return 2


if __name__ == "__main__":
    sys.exit(main())
