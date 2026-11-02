import ast
import bz2
from dataclasses import dataclass, field
from enum import Enum
import gzip
import http.client
import io
import json
import logging
import lzma
import os
import pickletools
import re
import tarfile
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


class ScanErrorKind(Enum):
    """Why (part of) a file could not be scanned."""

    PARSE = "parse"  # pickle data could not be fully parsed: imports found before the error are still reported
    ARCHIVE = "archive"  # an archive, or a member of it, could not be read (corrupted, encrypted...)
    UNSUPPORTED = "unsupported"  # the format was recognized but this variant is not supported
    MISSING_DEPENDENCY = "missing_dependency"  # an optional package needed for this format is not installed
    LIMIT = "limit"  # a safety limit was reached (decompressed size, number of archive members...)
    IO = "io"  # the file could not be read
    INTERNAL = "internal"  # unexpected error in picklescan itself


@dataclass
class ScanError:
    file_id: str
    kind: ScanErrorKind
    message: str


@dataclass
class SkippedFile:
    """Content deliberately left unscanned, such as an archive nested in another one."""

    file_id: str
    reason: str


@dataclass
class ScanResult:
    globals: List[Global]
    scanned_files: int = 0
    issues_count: int = 0
    infected_files: int = 0
    # True when the scan is incomplete: see errors for what failed and why
    scan_err: bool = False
    suspicious_count: int = 0
    errors: List[ScanError] = field(default_factory=list)
    skipped: List[SkippedFile] = field(default_factory=list)

    def __post_init__(self):
        if self.errors:
            self.scan_err = True

    def add_error(self, file_id: str, kind: ScanErrorKind, message: str) -> "ScanResult":
        self.errors.append(ScanError(file_id, kind, message))
        self.scan_err = True
        return self

    def merge(self, sr: "ScanResult"):
        self.globals.extend(sr.globals)
        self.scanned_files += sr.scanned_files
        self.issues_count += sr.issues_count
        self.infected_files += sr.infected_files
        self.scan_err = self.scan_err or sr.scan_err
        self.suspicious_count += sr.suspicious_count
        self.errors.extend(sr.errors)
        self.skipped.extend(sr.skipped)


@dataclass
class ScanLimits:
    """Bounds on the work a scan does, so that a small crafted input cannot make it run nearly forever or exhaust memory or disk.

    - ``max_archive_depth``: archive levels opened. With the default of 1, the members of an archive are scanned, and archives found
      among them are reported in ``ScanResult.skipped`` instead of being opened. Model formats built on zip (PyTorch, .npz) and
      compressed files do not count as a level.
    - ``max_archive_members``: archive members scanned, over the whole scan.
    - ``max_decompressed_size``: bytes decompressed, over the whole scan (archive members, compressed files).
    - ``max_compression_layers``: compressed streams nested in each other (a .tar.gz has one).
    - ``max_npy_header_size``: size of a .npy header.
    """

    max_archive_depth: int = 1
    max_archive_members: int = 100_000
    max_decompressed_size: int = 32 << 30
    max_compression_layers: int = 2
    max_npy_header_size: int = 1 << 20


class FileFormat(Enum):
    """File formats told apart by content. Extensions are only used to break ties (see detect_file)."""

    PICKLE = "pickle"
    PYTORCH_LEGACY = "pytorch_legacy"  # torch.save(_use_new_zipfile_serialization=False): a sequence of pickles
    PYTORCH_ZIP = "pytorch_zip"  # torch.save: a zip archive holding a data.pkl pickle
    NUMPY = "numpy"  # .npy
    NUMPY_ZIP = "numpy_zip"  # .npz: a zip archive of .npy files
    ZIP = "zip"
    SEVEN_ZIP = "7z"
    TAR = "tar"
    COMPRESSED = "compressed"  # a single compressed stream (gzip, bz2, xz, lzma, zlib, zstd, lz4), see FileInfo.compression
    UNKNOWN = "unknown"  # none of the above. When scanning, still parsed as a pickle: protocol 0 and 1 pickles have no magic bytes


@dataclass
class FileInfo:
    """What a file contains."""

    file_id: str
    format: FileFormat
    compression: Optional[str] = None  # for COMPRESSED
    pickle_protocol: Optional[int] = None  # for PICKLE and PYTORCH_LEGACY, when known
    trailing_zip: bool = False  # a zip archive follows other content: zip readers find it from the end of the file
    members: List["FileInfo"] = field(default_factory=list)  # archive members, or the content of a compressed file
    note: Optional[str] = None  # why the content was not (fully) inspected


class _LimitExceeded(Exception):
    pass


class _MissingDependency(Exception):
    pass


class _ScanContext:
    """State shared by everything one scan opens: settings, limits, the work done so far and the results."""

    def __init__(self, strict: bool = False, limits: Optional[ScanLimits] = None, scan: bool = True):
        self.strict = strict
        self.limits = limits or ScanLimits()
        self.scan = scan  # False: only detect formats (detect_file)
        self.result = ScanResult([])
        self.decompressed = 0
        self.members = 0

    def count_decompressed(self, size: int):
        self.decompressed += size
        if self.decompressed > self.limits.max_decompressed_size:
            raise _LimitExceeded(f"decompressed more than {self.limits.max_decompressed_size} bytes (ScanLimits.max_decompressed_size)")

    def count_member(self):
        self.members += 1
        if self.members > self.limits.max_archive_members:
            raise _LimitExceeded(f"more than {self.limits.max_archive_members} archive members (ScanLimits.max_archive_members)")


def _error_result(file_id: str, kind: ScanErrorKind, message: str, scanned_files: int = 1) -> ScanResult:
    level = logging.WARNING if kind in (ScanErrorKind.MISSING_DEPENDENCY, ScanErrorKind.UNSUPPORTED) else logging.ERROR
    _log.log(level, f"{file_id}: {kind.value} error: {message}")
    return ScanResult([], scanned_files=scanned_files).add_error(file_id, kind, message)


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
_zip_file_extensions = {".zip", ".npz", ".7z", ".tar", ".tgz"}
_compressed_file_extensions = {".gz", ".bz2", ".xz", ".lzma", ".z", ".zst", ".lz4", ".tgz"}
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
_scanned_file_extensions = (
    _zip_file_extensions | _pickle_file_extensions | _pytorch_file_extensions | _numpy_file_extensions | _compressed_file_extensions
)
# Bytes read from the start of a file to tell its format (a tar header is 512 bytes)
_head_size = 512
# Number of leading bytes read to decide whether a file is worth scanning
_probe_size = 16


def _should_scan(head: bytes, file_ext: Optional[str]) -> bool:
    """Decides from a file's extension and first bytes whether a directory or Hugging Face scan should scan it.

    Files with a known extension are always scanned. Others are scanned when their content looks like a format we can scan.
    Protocol 0 and 1 pickles have no magic bytes, so they are only picked up through their extension.
    """
    if file_ext in _scanned_file_extensions:
        return True
    if head.startswith((_numpy_magic_bytes, _7z_magic_bytes) + _zip_magic_bytes) or _compression_of(head) is not None:
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
    """Stands in for a bytes argument too large to be a module or global name (tensor data, typically): only its size is kept."""

    __slots__ = ("size",)

    def __init__(self, size: int):
        self.size = size

    def __repr__(self) -> str:
        return f"<{self.size} bytes skipped>"


# Bytes arguments larger than this are skipped instead of being loaded into memory
_max_kept_bytes_arg_size = 4096
_skip_chunk_size = 1 << 20


def _bytes_arg_reader(name: str, prefix_reader, prefix_size: int, wrap=bytes):
    def reader(f: IO[bytes]):
        size = prefix_reader(f)
        if size <= _max_kept_bytes_arg_size:
            data = f.read(size)
            if len(data) != size:
                raise ValueError(f"expected {size} bytes in a {name}, but only {len(data)} remain")
            return wrap(data), prefix_size + size
        # Read through in chunks rather than seeking, so a truncated argument is detected like pickletools does
        remaining = size
        while remaining > 0:
            chunk = f.read(min(remaining, _skip_chunk_size))
            if not chunk:
                raise ValueError(f"expected {size} bytes in a {name}, but only {size - remaining} remain")
            remaining -= len(chunk)
        return _SkippedBytes(size), prefix_size + size

    return reader


def _counted_arg_reader(name: str, prefix_reader, prefix_size: int, convert, truncated_message=None):
    """Same checks and value as the pickletools reader for a length-prefixed argument, plus the number of bytes it took."""

    def reader(f: IO[bytes]):
        size = prefix_reader(f)
        if size < 0:
            raise ValueError(f"{name} byte count < 0: {size}")
        data = f.read(size)
        if len(data) != size:
            raise ValueError(truncated_message or f"expected {size} bytes in a {name}, but only {len(data)} remain")
        return convert(data), prefix_size + size

    return reader


def _utf8(data: bytes) -> str:
    return str(data, "utf-8", "surrogatepass")


def _latin1(data: bytes) -> str:
    return data.decode("latin-1")


# Readers returning (value, number of bytes read): counting is much cheaper than asking the stream for its position
_counted_arg_readers = {
    pickletools.bytes1: _bytes_arg_reader("bytes1", pickletools.read_uint1, 1),
    pickletools.bytes4: _bytes_arg_reader("bytes4", pickletools.read_uint4, 4),
    pickletools.bytes8: _bytes_arg_reader("bytes8", pickletools.read_uint8, 8),
    pickletools.bytearray8: _bytes_arg_reader("bytearray8", pickletools.read_uint8, 8, bytearray),
    pickletools.unicodestring1: _counted_arg_reader("unicodestring1", pickletools.read_uint1, 1, _utf8),
    pickletools.unicodestring4: _counted_arg_reader("unicodestring4", pickletools.read_uint4, 4, _utf8),
    pickletools.unicodestring8: _counted_arg_reader("unicodestring8", pickletools.read_uint8, 8, _utf8),
    pickletools.string1: _counted_arg_reader("string1", pickletools.read_uint1, 1, _latin1),
    pickletools.string4: _counted_arg_reader("string4", pickletools.read_int4, 4, _latin1),
    pickletools.long1: _counted_arg_reader(
        "long1", pickletools.read_uint1, 1, pickletools.decode_long, "not enough data in stream to read long1"
    ),
    pickletools.long4: _counted_arg_reader(
        "long4", pickletools.read_int4, 4, pickletools.decode_long, "not enough data in stream to read long4"
    ),
}
# Opcode byte -> (opcode, plain reader or None, counted reader or None, fixed argument size or None)
_opcode_table = {}
for _op in pickletools.opcodes:
    _arg = _op.arg
    if _arg is None:
        _opcode_table[_op.code.encode("latin-1")] = (_op, None, None, 0)
    elif _arg in _counted_arg_readers:
        _opcode_table[_op.code.encode("latin-1")] = (_op, None, _counted_arg_readers[_arg], None)
    elif _arg.n >= 0:
        _opcode_table[_op.code.encode("latin-1")] = (_op, _arg.reader, None, _arg.n)
    else:  # newline-terminated arguments (protocol 0): their size is only known by asking the stream
        _opcode_table[_op.code.encode("latin-1")] = (_op, _arg.reader, None, None)


def _genops(data: IO[bytes], frame_violations: Optional[List[str]] = None):
    """pickletools.genops, with two differences.

    Large bytes arguments are skipped instead of read into memory: model weights pickled in-band (numpy arrays, raw tensor bytes...)
    are a few opcodes carrying gigabytes of arguments.

    Framing is checked: pickletools reads opcodes sequentially and ignores FRAME, but CPython's C unpickler does not. When an
    opcode runs past the end of the current frame, the C unpickler (reading from a file object such as io.BytesIO, which is how
    torch.load reads data.pkl) drops what is left of the frame and reads the argument from after it, so it parses different opcodes
    than pickletools does. Leftover frame bytes after STOP are likewise skipped by the next pickle.load on the same file. Pickles
    written by pickle.dumps never do any of this, and the pure Python unpickler rejects them, so such violations are reported
    in frame_violations rather than emulated.
    """
    frame_end = None
    pos = data.tell()
    read = data.read
    while True:
        code = read(1)
        entry = _opcode_table.get(code)
        if entry is None:
            if code == b"":
                raise ValueError("pickle exhausted before seeing STOP")
            raise ValueError(f"at position {pos}, opcode {code!r} unknown")
        opcode, reader, counted_reader, size = entry
        if counted_reader is not None:
            arg, size = counted_reader(data)
            end_pos = pos + 1 + size
        elif reader is None:
            arg = None
            end_pos = pos + 1
        else:
            arg = reader(data)
            end_pos = pos + 1 + size if size is not None else data.tell()

        if frame_end is not None:
            if pos >= frame_end:
                frame_end = None  # the current frame has been fully consumed
            elif frame_violations is not None:
                if end_pos > frame_end:
                    frame_violations.append(f"{opcode.name} at position {pos} runs past the end of the frame at position {frame_end}")
                elif code == b"\x95":
                    frame_violations.append(f"FRAME at position {pos} starts before the end of the frame at position {frame_end}")
                elif code == b"." and end_pos < frame_end:
                    frame_violations.append(f"STOP at position {pos} leaves the frame ending at position {frame_end} unfinished")
        if code == b"\x95":
            frame_end = end_pos + arg

        yield opcode, arg, pos
        if code == b".":
            break
        pos = end_pos


_memo_put_ops = {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}
_memo_get_ops = {"GET", "BINGET", "LONG_BINGET"}
_string_ops = {"SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8", "STRING", "BINSTRING", "SHORT_BINSTRING"}
# Value of a stack or memo slot that is not a string known statically. Used as a STACK_GLOBAL operand, the import is reported as
# dangerous (see _build_scan_result_from_raw_globals).
_unknown = "unknown"
_not_string = object()  # value certainly not a string (number, container, bytes...)
_mark = object()  # MARK on the stack
# Types of values pushed by opcodes (pickletools metadata) that are certainly not strings
_not_string_types = {"None", "bool", "int", "int_or_bool", "float", "bytes", "bytearray", "tuple", "list", "dict", "set", "frozenset",
                     "buffer"}  # fmt: skip
# Reported, as a dangerous global, for pickles whose framing makes the C unpickler and pickletools parse different opcodes
_frame_violation_global = (_unknown, "pickle frame boundary violation")
_joblib_wrapper_globals = {("joblib.numpy_pickle", "NumpyArrayWrapper"), ("sklearn.externals.joblib.numpy_pickle", "NumpyArrayWrapper")}


class _KnownImport(tuple):
    """An import known to be a class or a function (not a string): what it returns when called is not a string either."""

    __slots__ = ()


def _import_value(imported: Tuple[str, str], trusted: bool = True):
    """Value pushed by an import: other imports than safe classes and functions can be strings (os.sep is one), and so can safe
    ones once the pickle has run code that could replace module attributes (trusted=False, see _Reading)."""
    module, name = imported
    safe = _safe_globals.get(module)
    if trusted and ((safe is not None and name in safe) or imported in _joblib_wrapper_globals):
        return _KnownImport(imported)
    return _unknown


class _Globals(set):
    """Imports found, plus those found only by alternative readings (reported only when dangerous, see _list_globals)."""

    def __init__(self, *args):
        super().__init__(*args)
        self.alternative = set()


class _Reading:
    """One way the unpickler can read the pickle: its stack and memo, as far as they can be told without loading anything. Values
    are strings known statically, _not_string, _KnownImport, _unknown, or _mark.

    Where the unpickler would fail (stack underflow, missing memo slot...), the reading goes on with _unknown values rather than
    stop: imports found after such a point are reported too, erring on the side of reporting.

    Safe imports are known not to be strings only while the pickle has called nothing but safe classes and functions, and only
    given state (BUILD) to what they returned: anything else can replace module or class attributes (BUILD on a module or a class,
    setattr...), after which a safe import, or calling one, can return a string."""

    __slots__ = ("stack", "memo", "trusted")

    def __init__(self):
        self.stack = []
        self.memo = {}
        self.trusted = True

    def copy(self) -> "_Reading":
        reading = _Reading()
        reading.stack, reading.memo, reading.trusted = list(self.stack), dict(self.memo), self.trusted
        return reading

    def distrust(self):
        self.trusted = False
        self.stack[:] = [_unknown if isinstance(v, _KnownImport) else v for v in self.stack]
        self.memo.update((k, _unknown) for k, v in self.memo.items() if isinstance(v, _KnownImport))

    def pop(self):
        if not self.stack or self.stack[-1] is _mark:
            return _unknown  # stack underflow, or popping past a MARK
        return self.stack.pop()

    def pop_mark(self) -> list:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i] is _mark:
                items = self.stack[i + 1 :]
                del self.stack[i:]
                return items
        items = self.stack[:]  # no MARK
        self.stack.clear()
        return items

    def apply(self, op, arg, pos) -> Optional[Tuple[str, str]]:
        """Applies an opcode. Returns what STACK_GLOBAL imports, if it is one the unpickler would run."""
        name, stack = op.name, self.stack
        effect = _opcode_effects.get(name)
        if effect is not None:
            pops_mark, pops, pushes = effect
            if pops_mark:
                self.pop_mark()
            if pops:
                if name in _item_ops and self.trusted and (len(stack) < pops or stack[-pops] is not _not_string):
                    self.distrust()  # adding items calls methods (extend, __setitem__...) of something that may not be a container
                if len(stack) >= pops and _mark not in stack[-pops:]:
                    del stack[-pops:]
                else:
                    for _ in range(pops):
                        self.pop()
            stack.extend(pushes)
            return None
        if name == "MEMOIZE":
            self.memo[len(self.memo)] = stack[-1] if stack and stack[-1] is not _mark else _unknown
            return None
        if name in _memo_get_ops:
            key = _memo_key(arg, pos)
            if key not in self.memo:
                _log.debug(f"Memo key {key} not found at position {pos}, treating as unknown (potential evasion attempt)")
            stack.append(self.memo.get(key, _unknown))
            return None
        if name in _string_ops:
            stack.append(arg if isinstance(arg, str) else _unknown)
            return None
        if name == "MARK":
            stack.append(_mark)
            return None
        if name in _memo_put_ops:
            self.memo[_memo_key(arg, pos)] = stack[-1] if stack and stack[-1] is not _mark else _unknown
            return None
        if name == "DUP":
            stack.append(stack[-1] if stack and stack[-1] is not _mark else self.pop())
            return None
        if name == "BUILD":
            self.pop()
            if self.trusted and (not stack or stack[-1] is not _not_string):
                self.distrust()  # state given to something that may be a module or a class
            return None  # the object stays on the stack
        if name == "STACK_GLOBAL":
            if len(stack) < 2 or stack[-1] is _mark or stack[-2] is _mark:
                self.pop()
                self.pop()
                stack.append(_unknown)
                return None  # not two operands: the unpickler fails here, nothing is imported
            global_name, module = self.pop(), self.pop()
            if any(v is _not_string or isinstance(v, _KnownImport) for v in (module, global_name)):
                stack.append(_unknown)
                return None  # "STACK_GLOBAL requires str": the unpickler fails here, nothing is imported
            imported = (module if isinstance(module, str) else _unknown, global_name if isinstance(global_name, str) else _unknown)
            stack.append(_import_value(imported, self.trusted))
            return imported
        if name == "GLOBAL":
            stack.append(_import_value(tuple(arg.split(" ", 1)), self.trusted))
            return None
        if name in ("EXT1", "EXT2", "EXT4"):
            if self.trusted:
                self.distrust()  # imports whatever the copyreg extension registry maps the code to
            stack.append(_unknown)
            return None
        # REDUCE, NEWOBJ, NEWOBJ_EX, OBJ, INST: calling a safe class or function does not return a string
        if name == "OBJ":
            items = self.pop_mark()
            callable_value = items[0] if items else _unknown
        elif name == "INST":
            self.pop_mark()
            callable_value = _import_value(tuple(arg.split(" ", 1)), self.trusted)
        else:
            for _ in range(1 if name != "NEWOBJ_EX" else 2):
                self.pop()
            callable_value = self.pop()
        if self.trusted and not isinstance(callable_value, _KnownImport):
            self.distrust()  # calling something unknown can replace module or class attributes
        stack.append(_not_string if isinstance(callable_value, _KnownImport) else _unknown)
        return None


# Opcodes that add items to the object below them, calling its methods
_item_ops = {"APPEND", "APPENDS", "SETITEM", "SETITEMS", "ADDITEMS"}
# Opcodes _Reading.apply handles specifically
_reading_ops = (
    {"MEMOIZE", "MARK", "DUP", "BUILD", "STACK_GLOBAL", "GLOBAL", "EXT1", "EXT2", "EXT4", "REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST"}
    | _memo_put_ops
    | _memo_get_ops
    | _string_ops
)


def _opcode_effect(op) -> Tuple[bool, int, tuple]:
    """Effect on the stack of an opcode, from pickletools' description of it: whether it pops down to a MARK, how many values it
    pops (below the MARK if any), and the values it pushes."""
    before = op.stack_before
    pops_mark = pickletools.markobject in before
    pops = before.index(pickletools.markobject) if pops_mark else len(before)
    return pops_mark, pops, tuple(_not_string if pushed.name in _not_string_types else _unknown for pushed in op.stack_after)


_opcode_effects = {op.name: _opcode_effect(op) for op in pickletools.opcodes if op.name not in _reading_ops}


def _memo_key(op_value, pos):
    try:
        return int(op_value)
    except (ValueError, TypeError) as e:
        _log.debug(f"Invalid memo key at position {pos}: (error: {e}), treating as unknown")
        return None


def _list_globals(data: IO[bytes], multiple_pickles=True) -> Set[Tuple[str, str]]:
    """Imports made by the pickles in data.

    The unpickler's stack and memo are modeled (_Reading) to know what STACK_GLOBAL imports. Two readings are followed:
    - each pickle has a stack and memo of its own, as for pickle.load (a PROTO in the middle of a pickle is a no-op, as for the
      C unpickler),
    - a PROTO in the middle of a pickle starts a pickle embedded in it, with a stack and memo of its own, after which the enclosing
      pickle resumes: joblib writes object arrays this way, and reads them with an Unpickler of their own.
    The first reading is what pickle.load does, so it is reported; the second one is a guess anyone can trigger by writing a PROTO,
    so imports found by it only are reported when dangerous. GLOBAL and INST imports are reported whatever the reading.
    """
    globals = _Globals()
    resumed = None  # second reading of the pickle resuming after an embedded one
    enclosing = []  # second reading: readings of the pickles embedded ones are in
    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    last_byte = b"dummy"
    parsing_pkl_error = None
    malformed_pkl_error = None
    while last_byte != b"":
        # Opcodes are processed as they are parsed rather than collected first: their arguments can hold the model weights
        reading = _Reading()
        nested = resumed  # the second reading, once it differs from the first one
        resumed = None
        stack_global_underflow = None
        frame_violations = []
        first_op = True
        try:
            for op, op_value, pos in _genops(data, frame_violations):
                op_name = op.name
                if op_name in ("GLOBAL", "INST"):
                    globals.add(tuple(op_value.split(" ", 1)))
                elif op_name == "PROTO" and not first_op:
                    enclosing.append(nested if nested is not None else reading.copy())
                    nested = _Reading()
                first_op = False
                if op_name == "STACK_GLOBAL" and stack_global_underflow is None:
                    top = reading.stack[-2:]
                    operands = top[::-1].index(_mark) if _mark in top else len(top)  # values above the nearest MARK
                    if operands < 2:
                        stack_global_underflow = f"Found {operands} values for STACK_GLOBAL at position {pos} instead of 2."
                imported = reading.apply(op, op_value, pos)
                if imported is not None:
                    globals.add(imported)
                if nested is not None:
                    imported = nested.apply(op, op_value, pos)
                    if imported is not None:
                        globals.alternative.add(imported)
        except (_LimitExceeded, _MissingDependency):
            raise
        except Exception as e:
            _log.debug(f"Error parsing pickle: {e}", exc_info=True)
            parsing_pkl_error = str(e)
        else:
            if enclosing:
                resumed = enclosing.pop()  # second reading: the embedded pickle is done, the enclosing one resumes
            # The unpickler rejects a STACK_GLOBAL with too few operands, so this pickle cannot load. Only report it when the rest
            # of the pickle parsed fine: random binary data trips over this regularly before hitting an invalid opcode, and should
            # keep being reported as "not a pickle" rather than as a scan error.
            if stack_global_underflow is not None and malformed_pkl_error is None:
                malformed_pkl_error = stack_global_underflow
        if frame_violations:
            # Reported even if pickletools later fails to parse this pickle: the C unpickler may well parse it differently
            _log.debug(f"Pickle frame violation: {frame_violations[0]}")
            globals.add(_frame_violation_global)
            if malformed_pkl_error is None:
                malformed_pkl_error = frame_violations[0]
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
            found = len(globals) > 0 or len(globals.alternative) > 0
            globals_opt = globals if found or malformed_pkl_error is not None else None
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
    alternative = set(getattr(raw_globals, "alternative", ())) - set(raw_globals)
    for rg in list(raw_globals) + sorted(alternative):
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
        if rg in alternative and g.safety is not SafetyLevel.Dangerous:
            if g.safety is SafetyLevel.Suspicious:
                suspicious_count -= 1
            continue  # found by an alternative reading only: reported when dangerous
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
            result = _build_scan_result_from_raw_globals(e.globals, file_id, strict=strict)
            return result.add_error(file_id, ScanErrorKind.PARSE, str(e))
        else:
            # No globals found - likely not a pickle file at all
            _log.warning(f"WARNING: could not parse {file_id} as pickle: {e}")
            return ScanResult([], scanned_files=1, scan_err=False)

    _log.debug("Global imports in %s: %s", file_id, raw_globals)

    return _build_scan_result_from_raw_globals(raw_globals, file_id, strict=strict)


def _cheaply_seekable(f) -> bool:
    """True for streams where seeking costs nothing (local files, memory): unlike archive members or decompressed streams."""
    if isinstance(f, (io.BytesIO, io.FileIO)) or getattr(f, "_picklescan_cheap_seek", False):
        return True
    raw = getattr(f, "raw", None)
    return isinstance(f, io.BufferedReader) and (isinstance(raw, io.FileIO) or getattr(raw, "_picklescan_cheap_seek", False))


# --------------------------------------------------------------------------------------------------------------------------------
# Compressed streams. pandas.read_pickle decompresses by extension and joblib.load by magic bytes, before unpickling.


def _check_decompress(make_decompressor, head: bytes) -> bool:
    try:
        make_decompressor().decompress(head)
        return True
    except Exception:
        return False


def _check_gzip(head: bytes) -> bool:
    """Whether gzip.GzipFile (pandas, joblib) reads the head without error: it accepts headers zlib rejects (reserved flags)."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(head), mode="rb") as file:
            file.read(1)
        return True
    except EOFError:
        return True  # the head is only the start of the stream
    except Exception:
        return False


def _zfile_length(head: bytes) -> Optional[int]:
    """Uncompressed size in a joblib < 0.9.3 header, parsed as joblib does (int() also accepts spaces, signs, underscores...)."""
    try:
        return int(head[2 : 2 + _zfile_length_size], 16)
    except ValueError:
        return None


# Compressions whose magic bytes are short or absent: a pickle can start the same way
_weak_compressions = {"zlib", "lzma", "zfile"}


def _compression_of(head: bytes, file_ext: Optional[str] = None) -> Optional[str]:
    """Name of the compression format the data starts with, if any. Magic bytes are confirmed by decompressing the head."""
    if head.startswith(b"\x1f\x8b"):
        return "gzip" if _check_gzip(head) else None
    if head.startswith(b"BZh"):
        return "bz2" if _check_decompress(bz2.BZ2Decompressor, head) else None
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz" if _check_decompress(lambda: lzma.LZMADecompressor(lzma.FORMAT_XZ), head) else None
    # A zstd frame, or a skippable frame (the decompressors pandas uses skip them)
    if head.startswith(b"\x28\xb5\x2f\xfd") or (head[1:4] == b"\x2a\x4d\x18" and head[0] & 0xF0 == 0x50):
        return "zstd"
    if head.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if head.startswith(b"ZF") and _zfile_length(head) is not None:  # joblib reads any file starting with ZF this way
        return "zfile"
    if head[:1] == b"\x78" and len(head) > 1 and (head[0] << 8 | head[1]) % 31 == 0:
        return "zlib" if _check_decompress(zlib.decompressobj, head) else None
    # .lzma (lzma_alone) has no magic bytes: a properties byte, then the dictionary and uncompressed sizes. joblib only reads the
    # usual \x5d\x00 start, lzma.LZMAFile (pandas, for .xz files) any valid properties.
    if head.startswith(b"\x5d\x00") or (file_ext is not None and file_ext.lower() == ".xz" and head[:1] and head[0] < 225):
        return "lzma" if _check_decompress(lambda: lzma.LZMADecompressor(lzma.FORMAT_ALONE), head) else None
    return None


# joblib < 0.9.3 compressed files: b"ZF" + the hexadecimal size of the data, padded to the length of hex(2**64), then zlib data
_zfile_length_size = len(hex(2**64))


class _ZlibReader(io.RawIOBase):
    """Decompresses a zlib stream (joblib's zlib compression), seekable by restarting decompression like gzip.GzipFile."""

    def __init__(self, f: IO[bytes]):
        self._f = f
        self._start = f.tell()
        self._reset()

    def _reset(self):
        self._f.seek(self._start)
        self._decompressor = zlib.decompressobj()
        self._buffer = b""
        self._pos = 0
        self._eof = False

    def readable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, b) -> int:
        while len(self._buffer) < len(b) and not self._eof:
            data = self._decompressor.unconsumed_tail or self._f.read(1 << 16)
            if not data:
                self._eof = True
                break
            self._buffer += self._decompressor.decompress(data, 1 << 20)
            self._eof = self._decompressor.eof
        chunk = self._buffer[: len(b)]
        self._buffer = self._buffer[len(chunk) :]
        b[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            offset += self._pos
        elif whence != io.SEEK_SET:
            raise io.UnsupportedOperation("cannot seek from the end of a zlib stream")
        if offset < self._pos:
            self._reset()
        while self._pos < offset and self.read(min(offset - self._pos, 1 << 20)):
            pass
        return self._pos


def _open_decompressed(data: IO[bytes], compression: str) -> IO[bytes]:
    if compression == "gzip":
        return gzip.GzipFile(fileobj=data, mode="rb")
    if compression == "bz2":
        return bz2.BZ2File(data, mode="rb")
    if compression == "xz":
        return lzma.LZMAFile(data, format=lzma.FORMAT_XZ)
    if compression == "lzma":
        return lzma.LZMAFile(data, format=lzma.FORMAT_ALONE)
    if compression == "zlib":
        return _ZlibReader(data)
    if compression == "zfile":
        data.read(2 + _zfile_length_size)  # what joblib reads, whatever it holds
        if data.read(1) != b" ":  # joblib <= 0.8.4 headers were one character wider
            data.seek(-1, io.SEEK_CUR)
        return _ZlibReader(data)
    if compression == "zstd":
        try:
            from compression import zstd  # Python 3.14+

            return zstd.ZstdFile(data)
        except ImportError:
            pass
        try:
            import zstandard

            return zstandard.ZstdDecompressor().stream_reader(data, read_across_frames=True, closefd=False)
        except ImportError:
            raise _MissingDependency("zstd decompression requires Python 3.14+ or the zstandard package")
    if compression == "lz4":
        try:
            import lz4.frame

            return lz4.frame.LZ4FrameFile(data)
        except ImportError:
            raise _MissingDependency("lz4 decompression requires the lz4 package")
    raise ValueError(f"unknown compression {compression}")


class _CountingReader(io.RawIOBase):
    """Raw stream over a decompressing file object, charging what it produces to the scan's decompression budget."""

    def __init__(self, f, ctx: _ScanContext):
        self._f = f
        self._ctx = ctx

    def readable(self):
        return True

    def seekable(self):
        return self._f.seekable()

    def readinto(self, b) -> int:
        # read1: one decompression step, so that the data before a corruption is returned before the error is raised
        data = getattr(self._f, "read1", self._f.read)(len(b))
        b[: len(data)] = data
        self._ctx.count_decompressed(len(data))
        return len(data)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        position = self._f.tell()
        if whence == io.SEEK_END:
            # Decompressing streams find their end by decompressing everything: done here, in counted reads
            while self.read(1 << 20):
                pass
            position = self._f.tell()
        new_position = self._f.seek(offset, whence)
        # Decompressing streams seek forward by decompressing, and backward by decompressing again from the start
        self._ctx.count_decompressed(new_position - position if new_position >= position else new_position)
        return new_position

    def tell(self) -> int:
        return self._f.tell()

    def close(self):
        if not self.closed:
            try:
                self._f.close()
            finally:
                super().close()


def _counted(f, ctx: _ScanContext) -> io.BufferedReader:
    # The buffer also makes the many small reads of the pickle parser cheap, lets us peek at magic bytes, and absorbs the short
    # backward seeks that would otherwise make a decompressing stream (ZipExtFile, GzipFile...) start over from the beginning.
    return io.BufferedReader(_CountingReader(f, ctx), _zip_member_buffer_size)


# --------------------------------------------------------------------------------------------------------------------------------
# NumPy .npy files, parsed without NumPy: np.load unpickles what follows the header when the array dtype holds Python objects.

_npy_plain_type = re.compile(r"[<>|=]?(\?|[biufcmMSUVa]\d*)(\[\w+\])?")


def _npy_may_hold_objects(descr) -> bool:
    """False only when the dtype description certainly holds no Python object (in doubt, the data is scanned as a pickle)."""
    if isinstance(descr, str):
        return _npy_plain_type.fullmatch(descr) is None
    if isinstance(descr, list):  # structured dtype: [(name, format), (name, format, shape)...]
        try:
            return any(_npy_may_hold_objects(field[1]) for field in descr)
        except (TypeError, IndexError):
            return True
    return True


def _read_npy_header(data: IO[bytes], file_id: str, ctx: _ScanContext):
    """Reads a .npy header like np.lib.format does. Returns the dtype description, or a ScanResult when the file cannot be read."""
    magic = data.read(len(_numpy_magic_bytes) + 2)
    major = magic[-2] if len(magic) == len(_numpy_magic_bytes) + 2 else None
    if major == 1:
        size_bytes, encoding = 2, "latin1"
    elif major in (2, 3):
        size_bytes, encoding = 4, ("latin1" if major == 2 else "utf8")
    else:
        version = tuple(magic[-2:]) if major is not None else None
        return _error_result(file_id, ScanErrorKind.UNSUPPORTED, f"unsupported numpy format version: {version}")
    header_size = int.from_bytes(data.read(size_bytes), "little")
    if header_size > ctx.limits.max_npy_header_size:
        return _error_result(file_id, ScanErrorKind.LIMIT, f".npy header of {header_size} bytes (ScanLimits.max_npy_header_size)")
    header = data.read(header_size)
    try:
        return ast.literal_eval(header.decode(encoding))["descr"]
    except Exception:
        return None  # unreadable description: np.load may still manage, so the data is scanned


def _scan_numpy(data: IO[bytes], file_id: str, ctx: _ScanContext) -> ScanResult:
    descr = _read_npy_header(data, file_id, ctx)
    if isinstance(descr, ScanResult):
        return descr
    if descr is not None and not _npy_may_hold_objects(descr):
        return ScanResult([], 1)
    return scan_pickle_bytes(data, file_id, strict=ctx.strict)


# --------------------------------------------------------------------------------------------------------------------------------
# Format detection and the traversal shared by scanning (scan_bytes) and detection (detect_file)


def _zip_format(data: IO[bytes]) -> FileFormat:
    start = data.tell()
    try:
        with RelaxedZipFile(data, "r") as zip:
            names = zip.namelist()
    except Exception:
        return FileFormat.ZIP  # reported when the archive is scanned
    finally:
        data.seek(start)
    if any(name == "data.pkl" or name.endswith("/data.pkl") for name in names):
        return FileFormat.PYTORCH_ZIP
    if names and all(name.endswith(".npy") for name in names):
        return FileFormat.NUMPY_ZIP
    return FileFormat.ZIP


def _is_tar_header(head: bytes) -> bool:
    if len(head) < tarfile.BLOCKSIZE:
        return False
    try:
        tarfile.TarInfo.frombuf(head[: tarfile.BLOCKSIZE], tarfile.ENCODING, "surrogateescape")
        return True
    except tarfile.HeaderError:
        return False


def _sniff(data: IO[bytes], head: bytes, file_ext: Optional[str]) -> Tuple[FileFormat, Optional[str]]:
    """Format of the stream (positioned at its start), and its compression for COMPRESSED."""
    if head.startswith(_numpy_magic_bytes):
        return FileFormat.NUMPY, None
    if head.startswith(_7z_magic_bytes):
        return FileFormat.SEVEN_ZIP, None
    if head.startswith(_zip_magic_bytes):
        return _zip_format(data), None
    compression = _compression_of(head, file_ext)
    if compression is not None:
        return FileFormat.COMPRESSED, compression
    if _is_tar_header(head):
        return FileFormat.TAR, None
    # The PyTorch magic number is attacker-controlled: never let it downgrade a file that claims to be a pickle to the legacy
    # PyTorch scan, which only reads the fixed number of pickles such a file holds
    if file_ext not in _pickle_file_extensions and _is_legacy_pytorch(data):
        return FileFormat.PYTORCH_LEGACY, None
    if head[:2] in _pickle_magic_bytes:
        return FileFormat.PICKLE, None
    return FileFormat.UNKNOWN, None


def _may_start_pickle(head: bytes) -> bool:
    """Whether a file of another format could also be a loadable pickle (polyglot), judging from its first byte.

    A tar file starts with a member name, which can be any opcodes. PERSID (zip) needs a persistent_load the plain unpickler lacks,
    and a STACK_GLOBAL (NumPy) first has nothing to pop.
    """
    return head[:1] not in (b"", b"P", b"\x93") and head[:1].decode("latin-1") in pickletools.code2op


def _inner_extension(file_id: str) -> Optional[str]:
    """Extension of a compressed file's content: .pkl for model.pkl.gz, .tar for model.tgz."""
    stem, ext = os.path.splitext(file_id)
    if ext.lower() == ".tgz":
        return ".tar"
    return os.path.splitext(stem)[1] if ext.lower() in _compressed_file_extensions else None


def _classify_pickle(data: IO[bytes]) -> Tuple[FileFormat, Optional[int]]:
    """Detection only: a stream without magic bytes is a PICKLE if its first pickle parses up to STOP."""
    start = data.tell()
    protocol = 0
    try:
        for op, arg, _ in _genops(data):
            protocol = max(protocol, arg if op.name == "PROTO" else op.proto)
        return FileFormat.PICKLE, protocol
    except (_LimitExceeded, _MissingDependency):
        raise
    except Exception:
        return FileFormat.UNKNOWN, None
    finally:
        data.seek(start)


def _walk(
    data: IO[bytes], file_id: str, file_ext: Optional[str], ctx: _ScanContext, depth: int, layers: int, size: Optional[int] = None
) -> FileInfo:
    """Detects the format of a stream and handles it accordingly: scanned into ctx.result when ctx.scan, only described otherwise."""
    start = data.tell()
    head = data.read(_head_size)
    data.seek(start)
    fmt, compression = _sniff(data, head, file_ext)
    info = FileInfo(file_id, fmt, compression=compression)
    if fmt is FileFormat.PICKLE:
        info.pickle_protocol = head[1]
    elif fmt is FileFormat.PYTORCH_LEGACY and head[:1] == b"\x80":
        info.pickle_protocol = head[1]

    try:
        _walk_format(data, info, file_ext, ctx, depth, layers, size)
    except _LimitExceeded as e:
        info.note = str(e)
        if ctx.scan:
            ctx.result.merge(_error_result(file_id, ScanErrorKind.LIMIT, str(e), 0))
    except _MissingDependency as e:
        info.note = str(e)
        if ctx.scan:
            ctx.result.merge(_error_result(file_id, ScanErrorKind.MISSING_DEPENDENCY, str(e)))

    # Polyglots: loaders reading from the first byte and loaders reading the end of the file can see different formats, and
    # loaders of different formats can read the same first bytes differently. Only checked where seeking is free (a member of an
    # archive is checked when it is scanned as a file of its own, once extracted), and for compressions without proper magic bytes.
    cheap_seek = _cheaply_seekable(data)
    if (
        fmt not in (FileFormat.PICKLE, FileFormat.UNKNOWN, FileFormat.PYTORCH_LEGACY)
        and _may_start_pickle(head)
        and ctx.scan
        and (cheap_seek or (compression in _weak_compressions and data.seekable()))
    ):
        data.seek(start)
        found = scan_pickle_bytes(data, file_id, strict=ctx.strict)
        # Most such files are not pickles, whatever opcodes their first bytes read as: only what would be dangerous is reported
        dangerous = [g for g in found.globals if g.safety is SafetyLevel.Dangerous]
        if dangerous:
            ctx.result.merge(ScanResult(dangerous, 0, len(dangerous), 1))
    if fmt is not FileFormat.TAR and cheap_seek and _is_tar_header(head):
        # torch.load tries legacy files as tar archives before anything else
        _log.debug(f"{file_id} is also a tar archive, scanning both")
        data.seek(start)
        info.members.append(_walk_archive(data, FileInfo(file_id, FileFormat.TAR), ctx, depth, _walk_tar_members))
    # Zip readers find an archive from the end of the file. Not in tar and 7z archives: what is at their end is a member.
    if fmt not in (FileFormat.ZIP, FileFormat.PYTORCH_ZIP, FileFormat.NUMPY_ZIP, FileFormat.TAR, FileFormat.SEVEN_ZIP) and cheap_seek:
        data.seek(start)
        if zipfile.is_zipfile(data):
            data.seek(start)
            try:
                RelaxedZipFile(data, "r").close()
                info.trailing_zip = True
            except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError) as e:
                # is_zipfile only looks for an end record: if no zip reader can open the archive, there is nothing to load from it
                _log.warning(f"WARNING: could not open the zip archive at the end of {file_id}: {e}")
        if info.trailing_zip:
            _log.debug(f"{file_id} has data in front of a zip archive, scanning both")
            data.seek(start)
            info.members.append(_walk_archive(data, FileInfo(file_id, FileFormat.ZIP), ctx, depth, _walk_zip_members))
    data.seek(start)
    return info


def _walk_format(data, info: FileInfo, file_ext, ctx: _ScanContext, depth: int, layers: int, size: Optional[int]):
    fmt, file_id = info.format, info.file_id
    if fmt is FileFormat.NUMPY:
        if ctx.scan:
            ctx.result.merge(_scan_numpy(data, file_id, ctx))
    elif fmt in (FileFormat.PYTORCH_ZIP, FileFormat.NUMPY_ZIP):
        # Model files that happen to be zip archives: a model file in an archive is opened one level deeper than other archives
        _walk_archive(data, info, ctx, depth, _walk_zip_members, extra_level=True)
    elif fmt is FileFormat.ZIP:
        _walk_archive(data, info, ctx, depth, _walk_zip_members)
    elif fmt is FileFormat.SEVEN_ZIP:
        _walk_archive(data, info, ctx, depth, _walk_7z_members)
    elif fmt is FileFormat.TAR:
        _walk_archive(data, info, ctx, depth, _walk_tar_members)
    elif fmt is FileFormat.COMPRESSED:
        if layers >= ctx.limits.max_compression_layers:
            raise _LimitExceeded(
                f"more than {ctx.limits.max_compression_layers} nested compressed streams (ScanLimits.max_compression_layers)"
            )
        compressed_start = data.tell()
        read_error = None
        try:
            with _counted(_open_decompressed(data, info.compression), ctx) as content:
                if ctx.scan:
                    # Small content is decompressed in memory, up to a corruption if any: loaders run what precedes it
                    content_bytes, read_error = _read_until_error(content, _max_in_memory_pickle_member_size + 1)
                    if len(content_bytes) <= _max_in_memory_pickle_member_size:
                        content = io.BytesIO(content_bytes)
                    else:
                        read_error = None
                        data.seek(compressed_start)
                        content = _counted(_open_decompressed(data, info.compression), ctx)
                with content:
                    info.members.append(_walk(content, file_id, _inner_extension(file_id), ctx, depth, layers + 1))
        except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError, RuntimeError) as e:
            read_error = e
        if read_error is not None:
            info.note = f"cannot decompress {info.compression} data: {read_error}"
            if ctx.scan:
                ctx.result.merge(_error_result(file_id, ScanErrorKind.ARCHIVE, info.note, 0 if info.members else 1))
    elif fmt is FileFormat.PYTORCH_LEGACY:
        if ctx.scan:
            ctx.result.merge(_scan_pytorch_legacy(data, file_id, ctx))
    elif ctx.scan:
        # PICKLE, and UNKNOWN: protocol 0 and 1 pickles have no magic bytes. Data that is not a pickle fails to parse before any
        # import, which is reported as "not a pickle" rather than as an error.
        read_error = None
        if size is not None and size <= _max_in_memory_pickle_member_size and not _cheaply_seekable(data):
            # Archive member: parsing from memory is about twice as fast. Loaders reading the member as a stream run what precedes a
            # corruption, so what could be read is scanned.
            content, read_error = _read_until_error(data)
            data = io.BytesIO(content)
        ctx.result.merge(scan_pickle_bytes(data, file_id, strict=ctx.strict))
        if read_error is not None:
            message = f"cannot read past byte {data.getbuffer().nbytes}: {read_error}"
            ctx.result.merge(_error_result(file_id, ScanErrorKind.ARCHIVE, message, 0))
    elif fmt is FileFormat.UNKNOWN:
        info.format, info.pickle_protocol = _classify_pickle(data)


def _walk_archive(data, info: FileInfo, ctx: _ScanContext, depth: int, walk_members, extra_level: bool = False) -> FileInfo:
    if depth >= ctx.limits.max_archive_depth + extra_level:
        info.note = f"{info.format.value} archive nested in another archive: not opened (ScanLimits.max_archive_depth)"
        if ctx.scan:
            _log.info(f"{info.file_id}: {info.note}")
            ctx.result.skipped.append(SkippedFile(info.file_id, info.note))
        return info
    walk_members(data, info, ctx, depth + 1)
    return info


def _walk_zip_members(data, info: FileInfo, ctx: _ScanContext, depth: int):
    model_file = info.format in (FileFormat.PYTORCH_ZIP, FileFormat.NUMPY_ZIP)
    try:
        zip = RelaxedZipFile(data, "r")
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError) as e:
        info.note = f"cannot open zip archive: {e}"
        if ctx.scan:
            ctx.result.merge(_error_result(info.file_id, ScanErrorKind.ARCHIVE, info.note))
        return
    with zip:
        names = zip.namelist()
        _log.debug("Files in zip archive %s: %s", info.file_id, names)
        storage_records = _torch_storage_records(names) if info.format is FileFormat.PYTORCH_ZIP else ()
        seen_offsets = set()
        for member in zip.infolist():
            ctx.count_member()
            # Several directory entries can point at the same data: scan it once
            if member.is_dir() or member.header_offset in seen_offsets:
                continue
            seen_offsets.add(member.header_offset)
            member_id = f"{info.file_id}:{member.filename}"
            member_ext = os.path.splitext(member.filename)[1]
            if member.filename in storage_records:
                continue  # raw tensor data, never unpickled
            try:
                with _counted(zip.open(member, "r"), ctx) as file:
                    if model_file and member_ext not in _pickle_file_extensions and not _known_by_content(file.peek(_head_size)):
                        continue  # torch.load and np.load read nothing else than pickles and arrays, never text or raw data
                    _log.debug("Scanning file %s in zip archive %s", member.filename, info.file_id)
                    info.members.append(_walk(file, member_id, member_ext, ctx, depth, 0, size=member.file_size))
            except (zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError, EOFError, OSError, ValueError) as e:
                # Decompression issues: password protected, corrupted, unsupported compression method...
                info.members.append(FileInfo(member_id, FileFormat.UNKNOWN, note=f"cannot read zip member: {e}"))
                if ctx.scan:
                    ctx.result.merge(_error_result(member_id, ScanErrorKind.ARCHIVE, f"cannot read zip member: {e}", 0))


def _torch_storage_records(names: List[str]) -> Set[str]:
    """Members of a torch.save zip holding raw tensor data: {root}/data/{key}, next to {root}/data.pkl."""
    roots = {name[: -len("data.pkl")] for name in names if name == "data.pkl" or name.endswith("/data.pkl")}
    return {name for name in names if any(name.startswith(f"{root}data/") and "/" not in name[len(root) + 5 :] for root in roots)}


def _known_by_content(head: bytes) -> bool:
    """Whether the head starts with the magic bytes of a format we scan."""
    return (
        head.startswith((_numpy_magic_bytes, _7z_magic_bytes) + _zip_magic_bytes)
        or head[:2] in _pickle_magic_bytes
        or _compression_of(head) is not None
        or _is_tar_header(head)
    )


def _read_until_error(file: IO[bytes], limit: int = -1) -> Tuple[bytes, Optional[Exception]]:
    """Reads a stream to its end (or limit bytes), or up to a read error (corrupted compressed data...): what was read, and the error."""
    chunks = []
    size = 0
    read = getattr(file, "read1", file.read)  # one read at a time, so that what is read before an error is kept
    try:
        while size != limit:
            chunk = read(1 << 20 if limit < 0 else min(1 << 20, limit - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except (_LimitExceeded, _MissingDependency):
        raise
    except Exception as e:  # each decompressor has errors of its own (zstd, lz4...)
        return b"".join(chunks), e
    return b"".join(chunks), None


# XXX: it appears there is no way to get the byte stream of a file within a 7z archive, forcing us to extract to disk before scanning
def _walk_7z_members(data, info: FileInfo, ctx: _ScanContext, depth: int):
    try:
        import py7zr
    except ImportError:
        raise _MissingDependency("py7zr is required to scan 7z archives: pip install picklescan[7z]")
    try:
        with py7zr.SevenZipFile(data, mode="r") as archive:
            members = [m for m in archive.list() if not m.is_directory]
            for member in members:
                ctx.count_member()
            ctx.count_decompressed(sum(m.uncompressed or 0 for m in members))
            _log.debug("Files in 7z archive %s: %s", info.file_id, [m.filename for m in members])
            with TemporaryDirectory() as tmpdir:
                archive.extractall(path=tmpdir)
                root = os.path.realpath(tmpdir)
                for member in members:
                    path = os.path.realpath(os.path.join(tmpdir, member.filename))
                    member_id = f"{info.file_id}:{member.filename}"
                    if not path.startswith(root + os.sep) or not os.path.isfile(path):
                        note = "not a regular file of the archive (link, special file...): not scanned"
                        info.members.append(FileInfo(member_id, FileFormat.UNKNOWN, note=note))
                        if ctx.scan:
                            ctx.result.skipped.append(SkippedFile(member_id, note))
                        continue
                    with open(path, "rb") as file:
                        info.members.append(_walk(file, member_id, os.path.splitext(member.filename)[1], ctx, depth, 0))
    except (_LimitExceeded, _MissingDependency):
        raise
    except Exception as e:
        info.note = f"cannot read 7z archive: {e}"
        if ctx.scan:
            ctx.result.merge(_error_result(info.file_id, ScanErrorKind.ARCHIVE, info.note))


def _walk_tar_members(data, info: FileInfo, ctx: _ScanContext, depth: int):
    try:
        with tarfile.open(fileobj=data, mode="r:") as tar:
            while True:
                member = tar.next()
                tar.members = []  # TarFile keeps every member it reads otherwise
                if member is None:
                    break
                ctx.count_member()
                if not member.isfile():
                    continue
                member_id = f"{info.file_id}:{member.name}"
                with tar.extractfile(member) as file:
                    info.members.append(_walk(file, member_id, os.path.splitext(member.name)[1], ctx, depth, 0, size=member.size))
    except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError) as e:
        info.note = f"cannot read tar archive: {e}"
        if ctx.scan:
            ctx.result.merge(_error_result(info.file_id, ScanErrorKind.ARCHIVE, info.note))


def _scan_pytorch_legacy(data: IO[bytes], file_id: str, ctx: _ScanContext) -> ScanResult:
    """torch.load of a legacy file reads a fixed sequence of pickles (magic number, protocol version, system info, the object, the
    storage keys), then raw storage data that is not a pickle."""
    scan_result = ScanResult([])
    for _ in range(5):
        scan_result.merge(scan_pickle_bytes(data, file_id, multiple_pickles=False, strict=ctx.strict))
    scan_result.scanned_files = 1
    scan_result.infected_files = min(1, scan_result.infected_files)
    return scan_result


def _scan(data: IO[bytes], file_id: str, file_ext: Optional[str], strict: bool, limits: Optional[ScanLimits]) -> ScanResult:
    ctx = _ScanContext(strict=strict, limits=limits)
    _walk(data, file_id, file_ext, ctx, depth=0, layers=0)
    return ctx.result


# --------------------------------------------------------------------------------------------------------------------------------
# Public scanners for a given format


def scan_7z_bytes(data: IO[bytes], file_id, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    _log.debug(f"scan_7z_bytes({file_id})")
    ctx = _ScanContext(strict=strict, limits=limits)
    try:
        _walk_7z_members(data, FileInfo(file_id, FileFormat.SEVEN_ZIP), ctx, depth=1)
    except _MissingDependency as e:
        ctx.result.merge(_error_result(file_id, ScanErrorKind.MISSING_DEPENDENCY, str(e)))
    except _LimitExceeded as e:
        ctx.result.merge(_error_result(file_id, ScanErrorKind.LIMIT, str(e), 0))
    return ctx.result


def scan_zip_bytes(data: IO[bytes], file_id, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    _log.debug(f"scan_zip_bytes({file_id})")
    ctx = _ScanContext(strict=strict, limits=limits)
    try:
        _walk_zip_members(data, FileInfo(file_id, _zip_format(data)), ctx, depth=1)
    except _LimitExceeded as e:
        ctx.result.merge(_error_result(file_id, ScanErrorKind.LIMIT, str(e), 0))
    return ctx.result


def scan_numpy(data: IO[bytes], file_id, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    """Scans a .npy file, or an .npz file. NumPy is not needed."""
    _log.debug(f"scan_numpy({file_id})")
    start = data.tell()
    magic = data.read(len(_numpy_magic_bytes))
    data.seek(start)
    if magic.startswith(_zip_magic_bytes):
        return scan_zip_bytes(data, file_id, strict=strict, limits=limits)
    if magic == _numpy_magic_bytes:
        return _scan_numpy(data, file_id, _ScanContext(strict=strict, limits=limits))
    return scan_pickle_bytes(data, file_id, strict=strict)


def scan_pytorch(data: IO[bytes], file_id, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    _log.debug(f"scan_pytorch({file_id})")

    # new pytorch format
    if _is_zipfile(data):
        return scan_zip_bytes(data, file_id, strict=strict, limits=limits)
    elif _is_7z_file(data):
        return scan_7z_bytes(data, file_id, strict=strict, limits=limits)
    # old pytorch format
    start = data.tell()
    magic = get_magic_number(data)
    if magic != MAGIC_NUMBER:
        # Magic number doesn't match or can't be extracted (None). This could be a bypass attempt where the magic number is
        # embedded via __reduce__ (e.g., eval('MAGIC_NUMBER')) instead of a literal INT/LONG. Scan the first pickle to check for
        # dangerous globals -- a legitimate magic pickle contains only a simple integer and should have zero globals.
        first_pickle_result = scan_pickle_bytes(data, file_id, multiple_pickles=False, strict=strict)
        if not first_pickle_result.globals:
            raise InvalidMagicError(magic, MAGIC_NUMBER, file_id)
        _log.debug(f"Potential PyTorch magic number bypass detected in {file_id}. Ignoring magic number and treating file as a pickle.")
        data.seek(start)
        return scan_pickle_bytes(data, file_id, strict=strict)
    return _scan_pytorch_legacy(data, file_id, _ScanContext(strict=strict, limits=limits))


def scan_bytes(data: IO[bytes], file_id, file_ext: Optional[str] = None, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    """Scans a stream of any supported format, told apart by content (file_ext only breaks ties)."""
    _log.debug(f"scan_bytes({file_id})")
    return _scan(data, file_id, file_ext, strict, limits)


def scan_huggingface_model(repo_id, strict=False, limits: Optional[ScanLimits] = None):
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
        scan_result.merge(_isolated(lambda: scan_bytes(io.BytesIO(_http_get(url)), url, file_ext, strict=strict, limits=limits), url))

    return scan_result


def _isolated(scan, file_id: str) -> ScanResult:
    """Runs one file's scan so that a failure is recorded for that file instead of aborting a multi-file scan."""
    try:
        return scan()
    except OSError as e:
        return _error_result(file_id, ScanErrorKind.IO, str(e))
    except Exception as e:
        _log.exception(f"Unexpected error scanning {file_id}")
        return _error_result(file_id, ScanErrorKind.INTERNAL, f"{type(e).__name__}: {e}")


def _matches_any(patterns: List[re.Pattern], text: str) -> bool:
    """Return True if *text* matches at least one compiled regex in *patterns*."""
    return any(p.search(text) for p in patterns)


def scan_directory_path(path, scan_filter: Optional[ScanFilter] = None, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
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

            def scan_one(file_path=file_path, file_ext=file_ext) -> ScanResult:
                with open(file_path, "rb") as file:
                    if not _should_scan(file.read(_probe_size), file_ext):
                        _log.debug("Skipping file %s: not a format we scan", file_path)
                        return ScanResult([])
                    file.seek(0)
                    _log.debug("Scanning file %s", file_path)
                    return scan_bytes(file, file_path, file_ext, strict=strict, limits=limits)

            scan_result.merge(_isolated(scan_one, file_path))

    return scan_result


def scan_file_path(path, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    _log.debug(f"scan_file_path({path})")

    file_ext = os.path.splitext(path)[1]
    with open(path, "rb") as file:
        return scan_bytes(file, path, file_ext, strict=strict, limits=limits)


def scan_url(url, strict=False, limits: Optional[ScanLimits] = None) -> ScanResult:
    _log.debug(f"scan_url({url})")

    return scan_bytes(io.BytesIO(_http_get(url)), url, strict=strict, limits=limits)


def detect_file(data: IO[bytes], file_id: str = "", file_ext: Optional[str] = None, limits: Optional[ScanLimits] = None) -> FileInfo:
    """Tells what a stream contains, and for archives and compressed files, what their content is, without scanning anything.

    Archives are inspected down to ``limits.max_archive_depth`` levels. Content without magic bytes is reported as PICKLE when its
    first pickle parses up to STOP, UNKNOWN otherwise.
    """
    return _walk(data, file_id, file_ext, _ScanContext(limits=limits, scan=False), depth=0, layers=0)


def detect_file_path(path, limits: Optional[ScanLimits] = None) -> FileInfo:
    with open(path, "rb") as file:
        return detect_file(file, path, os.path.splitext(path)[1], limits=limits)
