from dataclasses import dataclass
from enum import Enum
import http.client
import io
import json
import logging
import os
import pickletools
from tarfile import TarError
from typing import List, Set, Tuple
import urllib.parse
import zipfile

from .torch import get_magic_number, InvalidMagicError, _is_zipfile, MAGIC_NUMBER, _should_read_directly


class SafetyLevel(Enum):
    Innocuous = "innocuous"
    Suspicious = "suspicious"
    Dangerous = "dangerous"


@dataclass
class Global:
    module: str
    name: str
    safety: SafetyLevel


@dataclass
class ScanResult:
    globals: List[Global]
    scanned_files: int = 0
    issues_count: int = 0
    infected_files: int = 0

    def merge(self, sr: "ScanResult"):
        self.globals.extend(sr.globals)
        self.scanned_files += sr.scanned_files
        self.issues_count += sr.issues_count
        self.infected_files += sr.infected_files


_log = logging.getLogger("picklescan")

_safe_globals = {
        "collections": {"OrderedDict"},
        "torch": {"LongStorage", "FloatStorage", "HalfStorage", "QUInt2x4Storage", "QUInt4x2Storage", "QInt32Storage", "QInt8Storage", "QUInt8Storage", "ComplexFloatStorage", "ComplexDoubleStorage", "DoubleStorage", "BFloat16Storage", "BoolStorage", "CharStorage", "ShortStorage", "IntStorage", "ByteStorage"},
        "torch._utils": {"_rebuild_tensor_v2"},
}

_unsafe_globals = {
    "__builtin__": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},  # Pickle versions 0, 1, 2 have those function under '__builtin__'
    "builtins": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},  # Pickle versions 3, 4 have those function under 'builtins'
    "webbrowser": "*",  # Includes webbrowser.open()
    "httplib": "*",  # Includes http.client.HTTPSConnection()
    "requests.api": "*",
    "aiohttp.client": "*",
    "os": "*",
    "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
    "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
    "socket": "*",
    "subprocess": "*",
    "sys": "*",
}

#
# TODO: handle methods loading other Pickle files (either mark as suspicious, or follow calls to scan other files [preventing infinite loops])
#
# pickle.loads()
# https://docs.python.org/3/library/pickle.html#pickle.loads
# pickle.load()
# https://docs.python.org/3/library/pickle.html#pickle.load
# numpy.load()
# https://numpy.org/doc/stable/reference/generated/numpy.load.html#numpy.load
# numpy.ctypeslib.load_library()
# https://numpy.org/doc/stable/reference/routines.ctypeslib.html#numpy.ctypeslib.load_library
# pandas.read_pickle()
# https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_pickle.html
# joblib.load()
# https://joblib.readthedocs.io/en/latest/generated/joblib.load.html
# torch.load()
# https://pytorch.org/docs/stable/generated/torch.load.html
# tf.keras.models.load_model()
# https://www.tensorflow.org/api_docs/python/tf/keras/models/load_model
#

_pytorch_file_extensions = {".bin", ".pt", ".pth", ".ckpt"}
_pickle_file_extensions = {".pkl", ".pickle", ".joblib"}
_zip_file_extensions = {".zip", ".npz"}


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


def _list_globals(data: io.BytesIO) -> Set[Tuple[str, str]]:

    globals = set()

    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    pos = -1
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


def scan_pickle_bytes(data: io.BytesIO, file_id) -> ScanResult:
    """Disassemble a Pickle stream and report issues"""

    globals = []
    raw_globals = _list_globals(data)
    _log.debug("Global imports in %s: %s", file_id, raw_globals)

    issues_count = 0
    for rg in raw_globals:
        g = Global(rg[0], rg[1], SafetyLevel.Dangerous)
        safe_filter = _safe_globals.get(g.module)
        unsafe_filter = _unsafe_globals.get(g.module)
        if unsafe_filter is not None and (unsafe_filter == "*" or g.name in unsafe_filter):
            g.safety = SafetyLevel.Dangerous
            _log.warning("%s: %s import '%s %s' FOUND", file_id, g.safety.value, g.module, g.name)
            issues_count += 1
        elif safe_filter is not None and (safe_filter == "*" or g.name in safe_filter):
            g.safety = SafetyLevel.Innocuous
        else:
            g.safety = SafetyLevel.Suspicious
        globals.append(g)

    return ScanResult(globals, 1, issues_count, 1 if issues_count > 0 else 0)


def scan_zip_bytes(data: io.BytesIO, file_id) -> ScanResult:
    result = ScanResult([])

    with zipfile.ZipFile(data, "r") as zip:
        file_names = zip.namelist()
        _log.debug("Files in archive %s: %s", file_id, file_names)
        for file_name in file_names:
            if os.path.splitext(file_name)[1] in _pickle_file_extensions:
                _log.debug("Scanning file %s in zip archive %s", file_name, file_id)
                with zip.open(file_name, "r") as file:
                    file_data = io.BytesIO(file.read())
                    result.merge(scan_pickle_bytes(file_data, f"{file_id}:{file_name}"))

    return result


def scan_pytorch(data, file_id) -> ScanResult:
    io_bytes = io.BytesIO(data)
    # new pytorch format
    if _is_zipfile(io_bytes):
        return scan_zip_bytes(data, file_id)
    # old pytorch format
    else:
        scan_result = ScanResult([])
        should_read_directly = _should_read_directly(io_bytes)
        if should_read_directly and io_bytes.tell() == 0:
            # try loading from tar
            try:
                # TODO: implement loading from tar
                raise TarError()
            except TarError:
                # file does not contain a tar
                io_bytes.seek(0)

        magic = get_magic_number(io_bytes)
        if magic != MAGIC_NUMBER:
            raise InvalidMagicError(magic, MAGIC_NUMBER)
        # XXX:
        #   I know this is strange, but somehow
        #   there are five pickle serialised in a row.
        #   I've checked the source code and tested
        #   unpickling manually and five seems
        #   to be the number.
        for _ in range(5):
            scan_result.merge(scan_pickle_bytes(io_bytes, file_id))
        scan_result.scanned_files = 1
        return scan_result


def scan_bytes(data, file_id) -> ScanResult:
    return scan_zip_bytes(io.BytesIO(data), file_id) if zipfile.is_zipfile(io.BytesIO(data)) else scan_pickle_bytes(io.BytesIO(data), file_id)


def scan_huggingface_model(repo_id):
    # List model files
    model = json.loads(_http_get(f"https://huggingface.co/api/models/{repo_id}").decode("utf-8"))
    file_names = [file_name for file_name in (sibling.get("rfilename") for sibling in model["siblings"]) if file_name is not None]

    # Scan model files
    scan_result = ScanResult([])
    for file_name in file_names:
        file_ext = os.path.splitext(file_name)[1]
        if file_ext not in _zip_file_extensions and file_ext not in _pickle_file_extensions and file_ext not in _pytorch_file_extensions:
            continue
        _log.debug("Scanning file %s in model %s", file_name, repo_id)
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
        data = _http_get(url)
        if file_ext in _pytorch_file_extensions:
            scan_result.merge(scan_pytorch(data, url))
        else:
            scan_result.merge(scan_bytes(data, url))

    return scan_result


def scan_directory_path(path) -> ScanResult:
    scan_result = ScanResult([])

    for base_path, _, file_names in os.walk(path):
        for file_name in file_names:
            file_ext = os.path.splitext(file_name)[1]
            if file_ext not in _zip_file_extensions and file_ext not in _pickle_file_extensions and file_ext not in _pytorch_file_extensions:
                continue
            file_path = os.path.join(base_path, file_name)
            _log.debug("Scanning file %s", file_path)
            with open(file_path, "rb") as file:
                data = file.read()
            if file_ext in _pytorch_file_extensions:
                scan_result.merge(scan_pytorch(data, file_path))
            else:
                scan_result.merge(scan_bytes(data, file_path))

    return scan_result


def scan_file_path(path) -> ScanResult:
    with open(path, "rb") as file:
        data = file.read()
    return scan_bytes(data, path)


def scan_url(url) -> ScanResult:
    return scan_bytes(_http_get(url), url)

