from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import http.client
import io
import json
import logging
import os
import pickletools
import re
from tarfile import TarError
from tempfile import TemporaryDirectory
from typing import IO, List, Optional, Set, Tuple
import urllib.parse
import zipfile
import zlib
from .relaxed_zipfile import RelaxedZipFile

from .torch import (
    get_magic_number,
    InvalidMagicError,
    _is_zipfile,
    MAGIC_NUMBER,
    _should_read_directly,
)


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
    scan_err: bool = False
    suspicious_count: int = 0

    def merge(self, sr: "ScanResult"):
        self.globals.extend(sr.globals)
        self.scanned_files += sr.scanned_files
        self.issues_count += sr.issues_count
        self.infected_files += sr.infected_files
        self.scan_err = self.scan_err or sr.scan_err
        self.suspicious_count += sr.suspicious_count


@dataclass
class ScanFilter:
    """Filtering options for directory scans, modeled after ClamAV clamscan.

    - ``exclude``: regexes matched against the full file path; matching files are skipped.
    - ``include``: regexes matched against the full file path; when set, only matching files are scanned.
    - ``exclude_dir``: regexes matched against directory paths; matching directories are not traversed.
    - ``include_dir``: regexes matched against directory paths; when set, only matching directories are traversed.

    Excludes always take precedence over includes.
    Multiple patterns of the same kind are combined with logical OR.
    """

    exclude: List[re.Pattern] = field(default_factory=list)
    include: List[re.Pattern] = field(default_factory=list)
    exclude_dir: List[re.Pattern] = field(default_factory=list)
    include_dir: List[re.Pattern] = field(default_factory=list)


class GenOpsError(Exception):
    def __init__(self, msg: str, globals: Optional[Set[Tuple[str, str]]]):
        self.msg = msg
        self.globals = globals
        super().__init__()

    def __str__(self) -> str:
        return self.msg


_log = logging.getLogger("picklescan")

_safe_globals = {
    "collections": {"OrderedDict"},
    "torch": {
        "LongStorage",
        "FloatStorage",
        "HalfStorage",
        "QUInt2x4Storage",
        "QUInt4x2Storage",
        "QInt32Storage",
        "QInt8Storage",
        "QUInt8Storage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "DoubleStorage",
        "BFloat16Storage",
        "BoolStorage",
        "CharStorage",
        "ShortStorage",
        "IntStorage",
        "ByteStorage",
    },
    "numpy": {
        "dtype",
        "ndarray",
    },
    "numpy._core.multiarray": {
        "_reconstruct",
    },
    "numpy.core.multiarray": {
        "_reconstruct",
    },
    "torch._utils": {"_rebuild_tensor_v2"},
}

_unsafe_globals = {
    "__builtin__": {
        # Pickle versions 0, 1, 2 have those function under '__builtin__'
        "eval",
        "compile",
        "getattr",
        "apply",
        "exec",
        "open",
        "breakpoint",
    },
    "builtins": {
        # Pickle versions 3, 4 have those function under 'builtins'
        "eval",
        "compile",
        "getattr",
        "apply",
        "exec",
        "open",
        "breakpoint",
    },
    # cloudpickle can reconstruct arbitrary callables via CodeType, enabling code execution
    "cloudpickle.cloudpickle": {
        "_builtin_type",  # Used to access CodeType for arbitrary code construction
        "_make_function",  # Creates functions from code objects
        "_function_setstate",  # Sets internal function state
        "_make_cell",  # Creates closure cells
        "_make_empty_cell",  # Creates empty closure cells
        "subimport",  # Imports arbitrary modules
    },
    "types": {"CodeType"},  # Can construct arbitrary code objects for execution
    "aiohttp": "*",
    "asyncio": "*",
    "bdb": "*",
    "commands": "*",  # Python 2 precursor to subprocess
    "ctypes": "*",  # Foreign function interface, can load DLLs, call C functions, manipulate raw memory
    "functools": {"partial"},  # functools.partial(os.system, "echo pwned")
    "httplib": "*",  # Includes http.client.HTTPSConnection()
    "logging": {"FileHandler"},  # logging.FileHandler can create arbitrary files on the filesystem
    "_io": {"FileIO"},  # io.FileIO is stored as _io.FileIO, can read arbitrary files bypassing builtins.open blocklist
    "numpy.f2py": "*",  # Multiple unsafe functions (e.g., getlincoef, _eval_length) that call eval on arbitrary strings
    "numpy.testing._private.utils": "*",  # runstring() in this module is a synonym for exec()
    "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
    "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
    "_operator": {
        "attrgetter",  # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
        "itemgetter",
        "methodcaller",
    },
    "operator": {
        "attrgetter",  # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
        "itemgetter",
        "methodcaller",
    },
    "os": "*",
    "requests.api": "*",
    "runpy": "*",  # Includes runpy._run_code
    "shutil": "*",
    "socket": "*",
    "ssl": "*",  # DNS exfiltration via ssl.get_server_certificate()
    "subprocess": "*",
    "sys": "*",
    "code": {"InteractiveInterpreter.runcode"},
    "cProfile": "*",  # cProfile.run() and cProfile.runctx() call exec() on arbitrary strings
    "distutils.file_util": "*",  # arbitrary file write via distutils.file_util.write_file()
    "doctest": {"debug_script"},
    "ensurepip": {"_run_pip"},
    "idlelib.autocomplete": {
        "AutoComplete.get_entity",
        "AutoComplete.fetch_completions",
    },
    "idlelib.calltip": {"Calltip.fetch_tip", "get_entity"},
    "idlelib.debugobj": {"ObjectTreeItem.SetText"},
    "idlelib.pyshell": {
        "ModifiedInterpreter.runcode",
        "ModifiedInterpreter.runcommand",
    },
    "idlelib.run": {"Executive.runcode"},
    "imaplib": {"IMAP4_stream"},  # IMAP4_stream executes commands via subprocess.Popen(command, shell=True)
    "lib2to3.pgen2.grammar": {"Grammar.loads"},
    "lib2to3.pgen2.pgen": {"ParserGenerator.make_label"},
    "pdb": "*",
    "pickle": "*",
    "_pickle": "*",
    "pip": "*",
    "pkgutil": {"resolve_name"},  # pkgutil.resolve_name can resolve any module:attribute, bypassing the entire blocklist
    "pty": "*",  # pty.spawn() allows executing arbitrary commands
    "profile": "*",  # profile.run() and profile.runctx() call exec() on arbitrary strings
    "pydoc": "*",  # pydoc.locate can import arbitrary modules, pydoc.pipepager allows command execution
    "test": "*",  # test.support.script_helper.assert_python_ok spawns arbitrary python subprocesses
    "timeit": "*",
    "torch._dynamo.guards": {"GuardBuilder.get"},
    "torch._inductor.codecache": {"compile_file"},  # compile_file('', '', ['sh', '-c','$(echo pwned)'])
    "torch.fx.experimental.symbolic_shapes": {"ShapeEnv.evaluate_guards_expression"},
    "torch.jit.unsupported_tensor_ops": {"execWrapper"},
    "torch.serialization": {"load"},  # pickle could be used to load a different file
    "torch.utils._config_module": {
        "ConfigModule.load_config"
    },  # allows storing a pickle inside a pickle (if this has valid use cases, scan the input bytes instead of flagging the global)
    "torch.utils.bottleneck.__main__": {"run_cprofile", "run_autograd_prof"},
    "torch.utils.collect_env": {"run"},
    "torch.utils.data.datapipes.utils.decoder": {
        "basichandlers"
    },  # allows storing a pickle inside a pickle (if this has valid use cases, scan the input bytes instead of flagging the global)
    "trace": {"Trace.run", "Trace.runctx"},
    "urllib.request": "*",  # urllib.request.urlopen can be used for SSRF and data exfiltration
    "uuid": "*",  # uuid._get_command_stdout executes arbitrary commands via subprocess.Popen
    "venv": "*",
    "webbrowser": "*",  # Includes webbrowser.open()
    "_osx_support": "*",  # _read_output and _find_build_tool execute commands via os.system
    "_aix_support": "*",  # _read_cmd_output executes commands via os.system
    "_pyrepl": "*",  # _pyrepl.pager.pipe_pager/tempfile_pager execute commands via subprocess/os.system
}

#
# TODO: handle methods loading other Pickle files (either mark as suspicious, or follow calls to scan other files [preventing infinite loops])
#
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

_numpy_file_extensions = {".npy"}  # Note: .npz is handled as zip files
_pytorch_file_extensions = {".bin", ".pt", ".pth", ".ckpt"}
_pickle_file_extensions = {".pkl", ".pickle", ".joblib", ".dat", ".data"}
_zip_file_extensions = {".zip", ".npz", ".7z"}
# Archives can contain archives (zip member disguised as .npy, 7z member disguised as .pkl, zip quines...). Each level recurses, so
# cap the nesting to keep the scan bounded, and report anything deeper as a scan error rather than silently skipping it.
_max_archive_depth = 8
# Read buffer wrapped around zip members: pickletools reads opcode by opcode, and ZipExtFile.read has a high per-call cost
_zip_member_buffer_size = 1 << 16
# Pickle members up to this size are read into memory before parsing, which is about twice as fast as parsing from the zip stream.
# Larger ones are parsed from the stream so that scanning a large pickle never holds all of it in memory.
_max_in_memory_pickle_member_size = 64 << 20
_zip_magic_bytes = (
    b"PK\x03\x04",  # local file header, the first record of any non-empty zip
    b"PK\x05\x06",  # end of central directory record, the only record of an empty zip
)
# Pickle files do not actually have magic bytes, but v2+ files
# start with a PROTO (\x80) opcode followed by a byte with the protocol version
_pickle_magic_bytes = {
    b"\x80\x00",
    b"\x80\x01",
    b"\x80\x02",
    b"\x80\x03",
    b"\x80\x04",
    b"\x80\x05",
}
_numpy_magic_bytes = b"\x93NUMPY"
_7z_magic_bytes = b"7z\xbc\xaf\x27\x1c"
# Extensions scanned without looking at the content first
_scanned_file_extensions = _zip_file_extensions | _pickle_file_extensions | _pytorch_file_extensions | _numpy_file_extensions
# Number of leading bytes read to decide whether a file is worth scanning
_probe_size = 16


def _should_scan(head: bytes, file_ext: Optional[str]) -> bool:
    """Decides from a file's extension and first bytes whether a directory or Hugging Face scan should scan it.

    Files with a known extension are always scanned. Others are scanned when their content looks like a format we can scan.
    Protocol 0 and 1 pickles have no magic bytes, so they are only picked up through their extension.
    """
    if file_ext in _scanned_file_extensions:
        return True
    if head.startswith((_numpy_magic_bytes, _7z_magic_bytes) + _zip_magic_bytes):
        return True
    # Protocol 2+ pickles start with PROTO. Also require a valid opcode right after it: other binary formats can start with the
    # same two bytes (a safetensors header length of 640 does), and for Hugging Face scans a false positive means a full download.
    return head[:2] in _pickle_magic_bytes and len(head) > 2 and chr(head[2]) in pickletools.code2op


def _is_7z_file(f: IO[bytes]) -> bool:
    read_bytes = []
    start = f.tell()

    byte = f.read(1)
    while byte != b"":
        read_bytes.append(byte)
        if len(read_bytes) == 6:
            break
        byte = f.read(1)
    f.seek(start)

    return b"".join(read_bytes) == _7z_magic_bytes


def _is_legacy_pytorch(data: IO[bytes]) -> bool:
    start = data.tell()
    try:
        magic = get_magic_number(data)
    except Exception:
        magic = None
    data.seek(start)
    return magic == MAGIC_NUMBER


_max_redirects = 10


def _http_get(url, max_bytes: Optional[int] = None, _redirects: int = 0) -> bytes:
    """GET url; with max_bytes, only its first max_bytes bytes (a Range request, and a bounded read if the server ignores it)."""
    _log.debug(f"Request: GET {url}" + ("" if max_bytes is None else f" (first {max_bytes} bytes)"))

    parsed_url = urllib.parse.urlparse(url)
    path_and_query = parsed_url.path + ("?" + parsed_url.query if len(parsed_url.query) > 0 else "")
    headers = {} if max_bytes is None else {"Range": f"bytes=0-{max_bytes - 1}"}

    connection = http.client.HTTPConnection if parsed_url.scheme == "http" else http.client.HTTPSConnection
    conn = connection(parsed_url.netloc)
    try:
        conn.request("GET", path_and_query, headers=headers)
        response = conn.getresponse()
        _log.debug(f"Response: status code {response.status} reason {response.reason}")
        if response.status in (301, 302, 303, 307, 308):  # Follow redirections
            location = response.headers.get("Location")
            if not location or _redirects >= _max_redirects:
                raise RuntimeError(f"HTTP {response.status} calling GET {url}: " + ("too many redirections" if location else "no Location"))
            # Hugging Face redirects small files to a relative location (/api/resolve-cache/...)
            return _http_get(urllib.parse.urljoin(url, location), max_bytes, _redirects + 1)
        elif response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} ({response.reason}) calling GET {parsed_url.scheme}://{parsed_url.netloc}{path_and_query}"
            )
        return response.read() if max_bytes is None else response.read(max_bytes)
    finally:
        conn.close()


class _SkippedBytes:
    """Stands in for a bytes argument too large to be a module or global name (tensor data, typically): only its size is kept.

    Used as a STACK_GLOBAL operand it reads as "unknown", like any other non-string operand, so the import is reported as dangerous.
    """

    __slots__ = ("size",)

    def __init__(self, size: int):
        self.size = size

    def __str__(self) -> str:
        return "unknown"

    def __repr__(self) -> str:
        return f"<{self.size} bytes skipped>"


# Bytes arguments larger than this are skipped instead of being loaded into memory
_max_kept_bytes_arg_size = 4096
_skip_chunk_size = 1 << 20


def _bytes_arg_reader(name: str, read_size, wrap=bytes):
    def reader(f: IO[bytes]):
        size = read_size(f)
        if size <= _max_kept_bytes_arg_size:
            data = f.read(size)
            if len(data) != size:
                raise ValueError(f"expected {size} bytes in a {name}, but only {len(data)} remain")
            return wrap(data)
        # Read through in chunks rather than seeking, so a truncated argument is detected like pickletools does
        remaining = size
        while remaining > 0:
            chunk = f.read(min(remaining, _skip_chunk_size))
            if not chunk:
                raise ValueError(f"expected {size} bytes in a {name}, but only {size - remaining} remain")
            remaining -= len(chunk)
        return _SkippedBytes(size)

    return reader


_arg_readers = {
    pickletools.bytes1: _bytes_arg_reader("bytes1", pickletools.read_uint1),
    pickletools.bytes4: _bytes_arg_reader("bytes4", pickletools.read_uint4),
    pickletools.bytes8: _bytes_arg_reader("bytes8", pickletools.read_uint8),
    pickletools.bytearray8: _bytes_arg_reader("bytearray8", pickletools.read_uint8, bytearray),
}


def _genops(data: IO[bytes]):
    """pickletools.genops, except that large bytes arguments are skipped instead of read into memory.

    Model weights pickled in-band (numpy arrays, raw tensor bytes...) are a few opcodes carrying gigabytes of arguments.
    """
    while True:
        pos = data.tell()
        code = data.read(1)
        opcode = pickletools.code2op.get(code.decode("latin-1"))
        if opcode is None:
            if code == b"":
                raise ValueError("pickle exhausted before seeing STOP")
            raise ValueError(f"at position {pos}, opcode {code!r} unknown")
        arg = None if opcode.arg is None else _arg_readers.get(opcode.arg, opcode.arg.reader)(data)
        yield opcode, arg, pos
        if code == b".":
            break


_memo_put_ops = {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}
_memo_get_ops = {"GET", "BINGET", "LONG_BINGET"}
_string_ops = {"SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8", "STRING", "BINSTRING", "SHORT_BINSTRING"}


def _stack_global_operand(op_name: str, op_value, memo: dict, pos) -> str:
    if op_name in _memo_get_ops:
        try:
            memo_key = int(op_value)
        except (ValueError, TypeError, IndexError) as e:
            _log.debug(f"Invalid memo key at position {pos}: (error: {e}), treating as unknown")
            return "unknown"
        if memo_key not in memo:
            _log.debug(f"Memo key {memo_key} not found at position {pos}, treating as unknown (potential evasion attempt)")
            return "unknown"
        memo_value = memo[memo_key]
        # Normalize memo value to string to prevent type confusion
        if not isinstance(memo_value, str):
            _log.debug(f"Memo value at position {pos} is not a string (type: {type(memo_value).__name__}), casting to string")
            memo_value = str(memo_value)
        return memo_value
    if op_name not in _string_ops:
        _log.debug("Presence of non-string opcode, categorizing as an unknown dangerous import")
        return "unknown"
    return op_value


def _list_globals(data: IO[bytes], multiple_pickles=True) -> Set[Tuple[str, str]]:
    globals = set()

    memo = {}
    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    last_byte = b"dummy"
    parsing_pkl_error = None
    malformed_pkl_error = None
    while last_byte != b"":
        # Opcodes are processed as they are parsed rather than collected first: their arguments can hold the model weights.
        # STACK_GLOBAL only needs the two latest opcodes that push a value (memo writes push nothing), so only those are kept.
        previous_op = None
        value_ops = deque(maxlen=2)
        stack_global_underflow = None
        try:
            for op, op_value, pos in _genops(data):
                op_name = op.name
                if op_name == "MEMOIZE":
                    if previous_op is not None:
                        memo[len(memo)] = previous_op[1]
                elif op_name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    if previous_op is not None:
                        memo[op_value] = previous_op[1]
                elif op_name in ("GLOBAL", "INST"):
                    globals.add(tuple(op_value.split(" ", 1)))
                elif op_name == "STACK_GLOBAL":
                    # Operands are resolved now, against the memo as it is when STACK_GLOBAL runs
                    values = [_stack_global_operand(name, value, memo, value_pos) for name, value, value_pos in reversed(value_ops)]
                    if len(values) == 2:
                        globals.add((values[1], values[0]))
                    elif stack_global_underflow is None:
                        stack_global_underflow = f"Found {len(values)} values for STACK_GLOBAL at position {pos} instead of 2."

                if op_name not in _memo_put_ops:
                    value_ops.append((op_name, op_value, pos))
                previous_op = (op_name, op_value)
        except Exception as e:
            _log.debug(f"Error parsing pickle: {e}", exc_info=True)
            parsing_pkl_error = str(e)
        else:
            # The unpickler rejects a STACK_GLOBAL with too few operands, so this pickle cannot load. Only report it when the rest
            # of the pickle parsed fine: random binary data trips over this regularly before hitting an invalid opcode, and should
            # keep being reported as "not a pickle" rather than as a scan error.
            if stack_global_underflow is not None and malformed_pkl_error is None:
                malformed_pkl_error = stack_global_underflow
        last_byte = data.read(1)
        if last_byte != b"":
            # Rewind the peeked byte so the next genops pass starts on it
            data.seek(-1, 1)

        if not multiple_pickles:
            break

        if parsing_pkl_error is not None:
            # XXX: given we can have multiple pickles in a file, we may have already successfully extracted globals from a valid pickle.
            # Thus return the already found globals in the error & let the caller decide what to do.
            # Additionally, we return the error at the end of the loop to scan imports in partially broken files,
            # which can unpickle and be dangerous regardless of being valid pickle.
            # A pickle known to be malformed is reported with its (possibly empty) globals rather than as "not a pickle" (None).
            globals_opt = globals if len(globals) > 0 or malformed_pkl_error is not None else None
            raise GenOpsError(parsing_pkl_error, globals_opt)

    if malformed_pkl_error is not None:
        raise GenOpsError(malformed_pkl_error, globals)

    return globals


def _build_scan_result_from_raw_globals(
    raw_globals: Set[Tuple[str, str]],
    file_id,
    scan_err=False,
    strict=False,
) -> ScanResult:
    globals = []
    suspicious_count = 0
    issues_count = 0
    for rg in raw_globals:
        g = Global(rg[0], rg[1], SafetyLevel.Dangerous)
        safe_filter = _safe_globals.get(g.module)
        unsafe_filter = _unsafe_globals.get(g.module)

        # If any parent module is marked as dangerous with "*", submodules are also dangerous
        if unsafe_filter is None and "." in g.module:
            module_parts = g.module.split(".")
            for i in range(1, len(module_parts)):
                parent_module = ".".join(module_parts[:i])
                if _unsafe_globals.get(parent_module) == "*":
                    unsafe_filter = "*"
                    break

        if "unknown" in g.module or "unknown" in g.name:
            g.safety = SafetyLevel.Dangerous
            _log.warning("%s: %s import '%s %s' FOUND", file_id, g.safety.value, g.module, g.name)
            issues_count += 1
        elif unsafe_filter is not None and (unsafe_filter == "*" or g.name in unsafe_filter):
            g.safety = SafetyLevel.Dangerous
            _log.warning("%s: %s import '%s %s' FOUND", file_id, g.safety.value, g.module, g.name)
            issues_count += 1
        elif safe_filter is not None and (safe_filter == "*" or g.name in safe_filter):
            g.safety = SafetyLevel.Innocuous
        elif strict:
            g.safety = SafetyLevel.Dangerous
            _log.warning(
                "%s: %s import '%s %s' FOUND (promoted by --strict)",
                file_id,
                g.safety.value,
                g.module,
                g.name,
            )
            issues_count += 1
        else:
            g.safety = SafetyLevel.Suspicious
            suspicious_count += 1
        globals.append(g)

    return ScanResult(globals, 1, issues_count, 1 if issues_count > 0 else 0, scan_err, suspicious_count)


def scan_pickle_bytes(data: IO[bytes], file_id, multiple_pickles=True, strict=False) -> ScanResult:
    """Disassemble a Pickle stream and report issues"""
    _log.debug(f"scan_pickle_bytes({file_id})")

    try:
        raw_globals = _list_globals(data, multiple_pickles)
    except GenOpsError as e:
        if e.globals is not None:
            # Found some globals before error - could be a malicious partial pickle
            _log.error(
                f"ERROR: parsing pickle in {file_id}: {e}",
                exc_info=_log.isEnabledFor(logging.DEBUG),
            )
            return _build_scan_result_from_raw_globals(e.globals, file_id, scan_err=True, strict=strict)
        else:
            # No globals found - likely not a pickle file at all
            _log.warning(f"WARNING: could not parse {file_id} as pickle: {e}")
            return ScanResult([], scanned_files=1, scan_err=False)

    _log.debug("Global imports in %s: %s", file_id, raw_globals)

    return _build_scan_result_from_raw_globals(raw_globals, file_id, strict=strict)


# XXX: it appears there is not way to get the byte stream for a given file within the 7z archive and thus forcing us to unzip to disk before scanning
def scan_7z_bytes(data: IO[bytes], file_id, strict=False, _depth=0) -> ScanResult:
    _log.debug(f"scan_7z_bytes({file_id})")

    if _depth > _max_archive_depth:
        _log.error(f"ERROR: {file_id} is nested more than {_max_archive_depth} archives deep, not scanning it")
        return ScanResult([], scanned_files=1, scan_err=True)

    try:
        import py7zr
    except ImportError:
        raise Exception("py7zr is required to scan 7z archives, install picklescan using: 'pip install picklescan[7z]'")
    result = ScanResult([])

    with py7zr.SevenZipFile(data, mode="r") as archive:
        file_names = archive.getnames()
        targets = [f for f in file_names if f.endswith(tuple(_pickle_file_extensions))]
        _log.debug("Files in 7z archive %s: %s", file_id, targets)
        with TemporaryDirectory() as tmpdir:
            archive.extract(path=tmpdir, targets=targets)
            for file_name in targets:
                file_path = os.path.join(tmpdir, file_name)
                _log.debug("Scanning file %s in 7z archive %s", file_name, file_id)
                if os.path.isfile(file_path):
                    with open(file_path, "rb") as file:
                        result.merge(scan_bytes(file, file_path, os.path.splitext(file_path)[1], strict=strict, _depth=_depth + 1))

            return result


def scan_zip_bytes(data: IO[bytes], file_id, strict=False, _depth=0) -> ScanResult:
    _log.debug(f"scan_zip_bytes({file_id})")

    if _depth > _max_archive_depth:
        _log.error(f"ERROR: {file_id} is nested more than {_max_archive_depth} archives deep, not scanning it")
        return ScanResult([], scanned_files=1, scan_err=True)

    result = ScanResult([])

    with RelaxedZipFile(data, "r") as zip:
        file_names = zip.namelist()
        _log.debug("Files in zip archive %s: %s", file_id, file_names)
        for file_name in file_names:
            try:
                # Members are wrapped in a BufferedReader: it makes the many small reads of the pickle parser cheap, lets us peek at the
                # magic bytes without reopening the member, and absorbs short backward seeks that would otherwise make ZipExtFile
                # rewind and decompress the member again from its start.
                with zip.open(file_name, "r") as member, io.BufferedReader(member, _zip_member_buffer_size) as file:
                    magic_bytes = file.peek(8)[:8]
                    file_ext = os.path.splitext(file_name)[1]
                    member_id = f"{file_id}:{file_name}"

                    # Magic bytes take precedence over the file extension
                    if magic_bytes.startswith(_numpy_magic_bytes):
                        _log.debug("Scanning file %s in zip archive %s", file_name, file_id)
                        # Not read in full: scan_numpy only reads the header of numeric arrays, which can be gigabytes
                        result.merge(scan_numpy(file, member_id, strict=strict, _depth=_depth + 1))

                    elif file_ext in _pickle_file_extensions or any(magic_bytes.startswith(mn) for mn in _pickle_magic_bytes):
                        _log.debug("Scanning file %s in zip archive %s", file_name, file_id)
                        # ZipExtFile never returns more than the declared size, so the in-memory copy is bounded too
                        if zip.getinfo(file_name).file_size <= _max_in_memory_pickle_member_size:
                            data, read_error = _read_until_error(file)
                            result.merge(scan_pickle_bytes(io.BytesIO(data), member_id, strict=strict))
                            if read_error is not None:
                                # Loaders reading the member as a stream run what precedes the corruption: that part was scanned
                                _log.warning("Invalid file %s in zip archive %s: %s", file_name, file_id, read_error)
                                result.scan_err = True
                        else:
                            result.merge(scan_pickle_bytes(file, member_id, strict=strict))

                    elif file_ext in _numpy_file_extensions:
                        _log.debug("Scanning file %s in zip archive %s", file_name, file_id)
                        result.merge(scan_numpy(file, member_id, strict=strict, _depth=_depth + 1))
            except (zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError, EOFError, OSError) as e:
                # Log decompression issues (password protected, corrupted, unsupported compression method...)
                _log.warning("Invalid file %s in zip archive %s: %s", file_name, file_id, str(e))
                result.scan_err = True

    return result


def _read_until_error(file: IO[bytes]) -> Tuple[bytes, Optional[Exception]]:
    """Reads a stream to its end, or up to a read error (corrupted compressed data...): what was read, and the error."""
    chunks = []
    try:
        while True:
            chunk = file.read(1 << 20)
            if not chunk:
                return b"".join(chunks), None
            chunks.append(chunk)
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as e:
        return b"".join(chunks), e


def scan_numpy(data: IO[bytes], file_id, strict=False, _depth=0) -> ScanResult:
    _log.debug(f"scan_numpy({file_id})")

    # Delay import to avoid dependency on NumPy
    import numpy as np

    # Code to distinguish from NumPy binary files and pickles.
    N = len(np.lib.format.MAGIC_PREFIX)
    magic = data.read(N)
    # If the file size is less than N, we need to make sure not
    # to seek past the beginning of the file
    data.seek(-min(N, len(magic)), 1)  # back-up
    if magic.startswith(_zip_magic_bytes):
        return scan_zip_bytes(data, file_id, strict=strict, _depth=_depth)
    elif magic == np.lib.format.MAGIC_PREFIX:
        # .npy file

        version = np.lib.format.read_magic(data)
        if version == (1, 0):
            _, _, dtype = np.lib.format.read_array_header_1_0(data)
        elif version in [(2, 0), (3, 0)]:
            _, _, dtype = np.lib.format.read_array_header_2_0(data)
        else:
            raise ValueError(f"Unsupported numpy format version: {version}")

        if dtype.hasobject:
            return scan_pickle_bytes(data, file_id, strict=strict)
        else:
            return ScanResult([], 1)
    else:
        return scan_pickle_bytes(data, file_id, strict=strict)


def scan_pytorch(data: IO[bytes], file_id, strict=False, _depth=0) -> ScanResult:
    _log.debug(f"scan_pytorch({file_id})")

    # new pytorch format
    if _is_zipfile(data):
        return scan_zip_bytes(data, file_id, strict=strict, _depth=_depth)
    elif _is_7z_file(data):
        return scan_7z_bytes(data, file_id, strict=strict, _depth=_depth)
    # old pytorch format
    else:
        scan_result = ScanResult([])
        should_read_directly = _should_read_directly(data)
        if should_read_directly and data.tell() == 0:
            # try loading from tar
            try:
                # TODO: implement loading from tar
                raise TarError()
            except TarError:
                # file does not contain a tar
                data.seek(0)

        magic = get_magic_number(data)
        if magic != MAGIC_NUMBER:
            # Magic number doesn't match or can't be extracted (None).
            # This could be a bypass attempt where the magic number is
            # embedded via __reduce__ (e.g., eval('MAGIC_NUMBER')) instead
            # of a literal INT/LONG. Scan the first pickle to check for
            # dangerous globals -- a legitimate magic pickle contains only
            # a simple integer and should have zero globals.
            data.seek(0)
            first_pickle_result = scan_pickle_bytes(data, file_id, multiple_pickles=False, strict=strict)
            if first_pickle_result.globals:
                _log.debug(
                    f"Potential PyTorch magic number bypass detected in {file_id}. Ignoring magic number and treating file as a pickle."
                )
                scan_result.merge(first_pickle_result)
            else:
                raise InvalidMagicError(magic, MAGIC_NUMBER, file_id)

        for _ in range(5):
            scan_result.merge(scan_pickle_bytes(data, file_id, multiple_pickles=False, strict=strict))
        scan_result.scanned_files = 1
        scan_result.infected_files = min(1, scan_result.infected_files)
        return scan_result


def scan_bytes(data: IO[bytes], file_id, file_ext: Optional[str] = None, strict=False, _depth=0) -> ScanResult:
    _log.debug(f"scan_bytes({file_id})")

    start = data.tell()
    magic_bytes = data.read(8)
    data.seek(start)
    is_zip = zipfile.is_zipfile(data)
    data.seek(start)

    result = _scan_bytes_by_content(data, file_id, file_ext, magic_bytes, is_zip, strict, _depth)

    # zipfile (and loaders built on it, like pandas.read_pickle on a .zip) locates an archive from its end record and ignores
    # anything in front of it, while pickle, NumPy and PyTorch loaders read from the first byte. A file holding a zip that does not
    # start at offset 0 is therefore read differently by each: scan the zip too, on top of the content found at the start.
    if is_zip and not magic_bytes.startswith(_zip_magic_bytes):
        _log.debug(f"{file_id} has data in front of a zip archive, scanning both")
        data.seek(start)
        try:
            result.merge(scan_zip_bytes(data, file_id, strict=strict, _depth=_depth))
        except zipfile.BadZipFile as e:
            # is_zipfile only checks for an end record: if no zip reader can open the archive, there is nothing to load from it
            _log.warning(f"WARNING: could not open the zip archive embedded in {file_id}: {e}")

    return result


def _scan_bytes_by_content(data: IO[bytes], file_id, file_ext, magic_bytes, is_zip, strict, _depth) -> ScanResult:
    start = data.tell()

    def is_legacy_pytorch() -> bool:
        return file_ext not in _pickle_file_extensions and _is_legacy_pytorch(data)

    if magic_bytes.startswith(_numpy_magic_bytes):
        return scan_numpy(data, file_id, strict=strict, _depth=_depth)

    if file_ext is not None and file_ext in _pytorch_file_extensions:
        try:
            return scan_pytorch(data, file_id, strict=strict, _depth=_depth)
        except InvalidMagicError as e:
            _log.warning(
                f"WARNING: Invalid PyTorch magic number for file {e}. Trying to scan as non-PyTorch file.",
                exc_info=_log.isEnabledFor(logging.DEBUG),
            )
            data.seek(start)

    if any(magic_bytes.startswith(mn) for mn in _pickle_magic_bytes):
        if is_legacy_pytorch():
            return scan_pytorch(data, file_id, strict=strict, _depth=_depth)
        return scan_pickle_bytes(data, file_id, strict=strict)

    # A zip with data in front of it is scanned by scan_bytes on top of the content at the start
    if is_zip and magic_bytes.startswith(_zip_magic_bytes):
        return scan_zip_bytes(data, file_id, strict=strict, _depth=_depth)
    elif _is_7z_file(data):
        return scan_7z_bytes(data, file_id, strict=strict, _depth=_depth)
    elif is_legacy_pytorch():
        return scan_pytorch(data, file_id, strict=strict, _depth=_depth)
    else:
        return scan_pickle_bytes(data, file_id, strict=strict)


def scan_huggingface_model(repo_id, strict=False):
    _log.debug(f"scan_huggingface_model({repo_id})")

    # List model files
    model = json.loads(_http_get(f"https://huggingface.co/api/models/{repo_id}").decode("utf-8"))
    file_names = [file_name for file_name in (sibling.get("rfilename") for sibling in model["siblings"]) if file_name is not None]

    # Scan model files
    scan_result = ScanResult([])
    for file_name in file_names:
        file_ext = os.path.splitext(file_name)[1]
        url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
        # Only the first bytes are fetched to decide, so that large non-pickle files (safetensors, GGUF...) are never downloaded
        if file_ext not in _scanned_file_extensions and not _should_scan(_http_get(url, max_bytes=_probe_size), file_ext):
            _log.debug("Skipping file %s in model %s: not a format we scan", file_name, repo_id)
            continue
        _log.debug("Scanning file %s in model %s", file_name, repo_id)
        data = io.BytesIO(_http_get(url))
        scan_result.merge(scan_bytes(data, url, file_ext, strict=strict))

    return scan_result


def _matches_any(patterns: List[re.Pattern], text: str) -> bool:
    """Return True if *text* matches at least one compiled regex in *patterns*."""
    return any(p.search(text) for p in patterns)


def scan_directory_path(path, scan_filter: Optional[ScanFilter] = None, strict=False) -> ScanResult:
    _log.debug(f"scan_directory_path({path})")

    scan_result = ScanResult([])

    for base_path, dir_names, file_names in os.walk(path):
        # --- directory filtering (prune in-place so os.walk skips them) ---
        if scan_filter is not None:
            filtered_dirs = []
            for d in dir_names:
                dir_path = os.path.join(base_path, d)
                if _matches_any(scan_filter.exclude_dir, dir_path):
                    _log.debug("Excluding directory %s (matched --exclude-dir)", dir_path)
                    continue
                if scan_filter.include_dir and not _matches_any(scan_filter.include_dir, dir_path):
                    _log.debug("Skipping directory %s (no --include-dir match)", dir_path)
                    continue
                filtered_dirs.append(d)
            dir_names[:] = filtered_dirs

        for file_name in file_names:
            file_ext = os.path.splitext(file_name)[1]
            file_path = os.path.join(base_path, file_name)

            # --- file filtering ---
            if scan_filter is not None:
                if _matches_any(scan_filter.exclude, file_path):
                    _log.debug("Excluding file %s (matched --exclude)", file_path)
                    continue
                if scan_filter.include and not _matches_any(scan_filter.include, file_path):
                    _log.debug("Skipping file %s (no --include match)", file_path)
                    continue

            # Not FIFOs, devices or broken links: opening a FIFO blocks until something writes to it
            if not os.path.isfile(file_path):
                _log.debug("Skipping %s: not a regular file", file_path)
                continue
            with open(file_path, "rb") as file:
                if not _should_scan(file.read(_probe_size), file_ext):
                    _log.debug("Skipping file %s: not a format we scan", file_path)
                    continue
                file.seek(0)
                _log.debug("Scanning file %s", file_path)
                scan_result.merge(scan_bytes(file, file_path, file_ext, strict=strict))

    return scan_result


def scan_file_path(path, strict=False) -> ScanResult:
    _log.debug(f"scan_file_path({path})")

    file_ext = os.path.splitext(path)[1]
    with open(path, "rb") as file:
        return scan_bytes(file, path, file_ext, strict=strict)


def scan_url(url, strict=False) -> ScanResult:
    _log.debug(f"scan_url({url})")

    return scan_bytes(io.BytesIO(_http_get(url)), url, strict=strict)
