import argparse
import http.client
import io
import json
import logging
import os
import pickletools
import sys
import urllib.parse
import zipfile

_log = logging.getLogger("picklescan")

_suspicious_globals = {
    "__builtin__": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},  # Pickle versions 0, 1, 2 have those function under '__builtin__'
    "builtins": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},  # Pickle versions 3, 4 have those function under 'builtins'
    "webbrowser": "*",  # Includes webbrowser.open()
    "httplib": "*",  # Includes http.client.HTTPSConnection()
    "requests.api": "*",
    "aiohttp.client": "*",
    "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
    "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
    "socket": "*",
    "subprocess": "*",
    "sys": "*",
}

_pickle_file_extensions = {".pkl", ".pickle", ".joblib"}
_zip_file_extensions = {".zip", ".bin"}  # PyTorch's pytorch_model.bin are zip archives


def _http_get(url):
    _log.debug(f"Request: GET {url}")

    parsed_url = urllib.parse.urlparse(url)
    path_and_query = parsed_url.path + ("?" + parsed_url.query if len(parsed_url.query) > 0 else "")

    conn = http.client.HTTPSConnection(parsed_url.netloc)
    try:
        conn.request("GET", path_and_query)
        response = conn.getresponse()
        _log.debug(f"Response: status code {response.status} reason {response.reason}")
        if response.status == 302:  # Follow redirections
            return _http_get(response.headers["Location"])
        elif response.status >= 400:
            raise RuntimeError(f"HTTP {response.status} ({response.reason}) calling GET {parsed_url.scheme}://{parsed_url.netloc}{path_and_query}")
        return response.read()
    finally:
        conn.close()


def _list_globals(data):

    globals = set()

    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    pos = -1
    data = io.BytesIO(data)
    while pos < data.tell():
        pos = data.tell()

        # List opcodes
        try:
            ops = list(pickletools.genops(data))
        except Exception:
            break

        # Extract global imports
        for n in range(len(ops)):
            op = ops[n]
            op_name = op[0].name
            op_value = op[1]

            if op_name == "GLOBAL":
                globals.add(tuple(op_value.split(" ", 1)))
            elif op_name == "STACK_GLOBAL":
                values = []
                for offset in range(1, n):
                    if ops[n-offset][0].name == "MEMOIZE":
                        continue
                    if ops[n-offset][0].name != "SHORT_BINUNICODE":
                        raise TypeError(f"Unhandled op-code type {ops[n-offset][0].name} at position {n-offset}")
                    values.append(ops[n-offset][1])
                    if len(values) == 2:
                        break
                if len(values) != 2:
                    raise ValueError(f"Found {len(values)} values for STACK_GLOBAL at position {n} instead of 2.")
                globals.add((values[1], values[0]))

    return globals


def scan_pickle_bytes(data, file_id):
    """Disassemble a Pickle stream and report issues"""

    globals = _list_globals(data)
    _log.debug("Global imports in %s: %s", file_id, globals)

    issues_count = 0
    for g in globals:
        filter = _suspicious_globals.get(g[0])
        if filter is not None and (filter == "*" or g[1] in filter):
            _log.warning("%s: global import '%s %s' FOUND", file_id, g[0], g[1])
            issues_count += 1

    return issues_count


def scan_zip_bytes(data, file_id):
    issues_count = 0

    with zipfile.ZipFile(io.BytesIO(data), "r") as zip:
        file_names = zip.namelist()
        _log.debug("Files in archive %s: %s", file_id, file_names)
        for file_name in file_names:
            if os.path.splitext(file_name)[1] in _pickle_file_extensions:
                _log.debug("Scanning file %s in zip archive %s", file_name, file_id)
                with zip.open(file_name, "r") as file:
                    issues_count += scan_pickle_bytes(file.read(), f"{file_id}:{file_name}")

    return issues_count


def scan_bytes(data, file_id):
    return scan_zip_bytes(data, file_id) if zipfile.is_zipfile(io.BytesIO(data)) else scan_pickle_bytes(data, file_id)


def scan_huggingface_model(repo_id):
    # List model files
    model = json.loads(_http_get(f"https://huggingface.co/api/models/{repo_id}").decode("utf-8"))
    file_names = [file_name for file_name in (sibling.get("rfilename") for sibling in model["siblings"]) if file_name is not None]

    # Scan model files
    files_scanned_count = 0
    files_suspicious_count = 0
    for file_name in file_names:
        file_ext = os.path.splitext(file_name)[1]
        if file_ext not in _zip_file_extensions and file_ext not in _pickle_file_extensions:
            continue
        _log.debug("Scanning file %s in model %s", file_name, repo_id)
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
        issues_count = scan_bytes(_http_get(url), url)
        files_suspicious_count += 1 if issues_count > 0 else 0
        files_scanned_count += 1

    return files_scanned_count, files_suspicious_count


def scan_directory_path(path):
    files_scanned_count = 0
    files_suspicious_count = 0

    for base_path, _, file_names in os.walk(path):
        for file_name in file_names:
            file_ext = os.path.splitext(file_name)[1]
            if file_ext not in _zip_file_extensions and file_ext not in _pickle_file_extensions:
                continue
            file_path = os.path.join(base_path, file_name)
            _log.debug("Scanning file %s", file_path)
            with open(file_path, "rb") as file:
                data = file.read()
            issues_count = scan_bytes(data, file_path)
            files_suspicious_count += 1 if issues_count > 0 else 0
            files_scanned_count += 1

    return files_scanned_count, files_suspicious_count


def scan_file_path(path):
    with open(path, "rb") as file:
        data = file.read()
    issues_count = scan_bytes(data, path)
    return 1, 1 if issues_count > 0 else 0


def scan_url(url):
    issues_count = scan_bytes(_http_get(url), url)
    return 1, 1 if issues_count > 0 else 0


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
