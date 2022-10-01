import argparse
import logging
import os
import sys

from .scanner import scan_directory_path
from .scanner import scan_file_path
from .scanner import scan_url
from .scanner import scan_huggingface_model

_log = logging.getLogger("picklescan")

def main():
    _log.setLevel(logging.INFO)
    _log.addHandler(logging.StreamHandler(stream=sys.stdout))

    parser = argparse.ArgumentParser(description="Security scanner detecting Python Pickle files performing suspicious actions.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--path", help="Path to the file or folder to scan", dest='path')
    group.add_argument("-u", "--url", help="URL to the file or folder to scan", dest='url')
    group.add_argument("-hf", "--huggingface", help="Name of the Hugging Face model to scan", dest='huggingface_model')
    parser.add_argument(
        "-l", "--log", help="level of log messages to display (default: INFO)", dest='log_level',
        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'])

    args = parser.parse_args()

    if "log_level" in args and args.log_level is not None:
        _log.setLevel(getattr(logging, args.log_level))

    try:
        if args.path is not None:
            path = os.path.abspath(args.path)
            if not os.path.exists(path):
                raise FileNotFoundError(f"Path {path} does not exist")
            if os.path.isdir(path):
                files_scanned_count, files_suspicious_count = scan_directory_path(path)
            else:
                files_scanned_count, files_suspicious_count = scan_file_path(path)
        elif args.url is not None:
            files_scanned_count, files_suspicious_count = scan_url(args.url)
        elif args.huggingface_model is not None:
            files_scanned_count, files_suspicious_count = scan_huggingface_model(args.huggingface_model)
        else:
            raise ValueError("Command line must include either a path, a URL, or a Hugging Face model")

        _log.info(f"""----------- SCAN SUMMARY -----------
Scanned files: {files_scanned_count}
Infected files: {files_suspicious_count}""")

        return 0 if files_suspicious_count == 0 else 1
    except Exception:
        _log.exception("Unhandled exception")
        return 2


if __name__ == '__main__':
    sys.exit(main())

