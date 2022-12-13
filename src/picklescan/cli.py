import argparse
import logging
import os
import sys

from .scanner import ScanResult, scan_directory_path
from .scanner import scan_file_path
from .scanner import scan_url
from .scanner import scan_huggingface_model

_log = logging.getLogger("picklescan")


def print_summary(show_globals: bool, sr: ScanResult):
    _log.info(
        f"""----------- SCAN SUMMARY -----------
Scanned files: {sr.scanned_files}
Infected files: {sr.infected_files}
Dangerous globals: {sr.issues_count}"""
    )
    if show_globals and len(sr.globals) > 0:
        _log.info("All globals found:")
        for g in sr.globals:
            _log.info(f"  * {g.module}.{g.name} - {g.safety.value}")


def main():
    _log.setLevel(logging.INFO)
    _log.addHandler(logging.StreamHandler(stream=sys.stdout))

    parser = argparse.ArgumentParser(
        description="Security scanner detecting Python Pickle files performing suspicious actions."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p", "--path", help="Path to the file or folder to scan", dest="path"
    )
    group.add_argument(
        "-u", "--url", help="URL to the file or folder to scan", dest="url"
    )
    group.add_argument(
        "-hf",
        "--huggingface",
        help="Name of the Hugging Face model to scan",
        dest="huggingface_model",
    )
    parser.add_argument(
        "-g", "--globals", help="list all globals found", action="store_true"
    )
    parser.set_defaults(globals=False)
    parser.add_argument(
        "-l",
        "--log",
        help="level of log messages to display (default: INFO)",
        dest="log_level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
    )

    args = parser.parse_args()

    if "log_level" in args and args.log_level is not None:
        _log.setLevel(getattr(logging, args.log_level))

    try:
        if args.path is not None:
            path = os.path.abspath(args.path)
            if not os.path.exists(path):
                raise FileNotFoundError(f"Path {path} does not exist")
            if os.path.isdir(path):
                scan_result = scan_directory_path(path)
            else:
                scan_result = scan_file_path(path)
        elif args.url is not None:
            scan_result = scan_url(args.url)
        elif args.huggingface_model is not None:
            scan_result = scan_huggingface_model(args.huggingface_model)
        else:
            raise ValueError(
                "Command line must include either a path, a URL, or a Hugging Face model"
            )

        print_summary(args.globals, scan_result)

        if scan_result.scan_err:
            return 2
        return 0 if scan_result.issues_count == 0 else 1
    except Exception:
        _log.exception("Unhandled exception")
        return 2


if __name__ == "__main__":
    sys.exit(main())
