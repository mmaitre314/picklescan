import ast
import bz2
from dataclasses import dataclass, field
from enum import Enum
import errno
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
from tempfile import TemporaryDirectory, TemporaryFile
from typing import IO, Callable, List, Optional, Set, Tuple
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


@dataclass(frozen=True)
class Location:
    """Where something was found: a file (path or URL) and, for content inside archives or compressed files, the archive members
    leading to it, outermost first."""

    file: str
    members: Tuple[str, ...] = ()

    def member(self, name: str) -> "Location":
        return Location(self.file, self.members + (name,))

    def __str__(self) -> str:
        return self.file + "".join(f":{member}" for member in self.members)

    def describe(self) -> str:
        """file.zip (inner/model.pkl), with " > " between nesting levels."""
        return f"{self.file} ({' > '.join(self.members)})" if self.members else self.file


def _location(file_id) -> Location:
    return file_id if isinstance(file_id, Location) else Location(str(file_id))


@dataclass
class Global:
    module: str
    name: str
    safety: SafetyLevel
    location: Optional[Location] = field(default=None, compare=False)  # where the import was found


class ScanErrorKind(Enum):
    """Why (part of) a file could not be scanned."""

    PARSE = "parse"  # pickle data could not be fully parsed: imports found before the error are still reported
    ARCHIVE = "archive"  # an archive, or a member of it, could not be read (corrupted, encrypted...)
    UNSUPPORTED = "unsupported"  # the format was recognized but this variant is not supported
    MISSING_DEPENDENCY = "missing_dependency"  # an optional package needed for this format is not installed
    LIMIT = "limit"  # a safety limit was reached (decompressed size, number of archive members...)
    IO = "io"  # the file could not be read
    INTERNAL = "internal"  # unexpected error in picklescan itself


def _plain(text: str, *styles: str) -> str:
    return text


def _printable(text: str) -> str:
    """text with control and formatting characters (escape sequences, newlines, bidirectional overrides...) escaped: names and
    messages come from the scanned files, and must not be able to change what a terminal shows."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in text)


# Extra attributes of the log records of dangerous findings (see cli)
_dangerous = {"picklescan_dangerous": True}


# What each kind of error means for the scan result
_error_help = {
    ScanErrorKind.PARSE: "imports found up to this point are reported; what follows was not scanned",
    ScanErrorKind.ARCHIVE: "the content that could not be read was not scanned",
    ScanErrorKind.UNSUPPORTED: "this content was not scanned",
    ScanErrorKind.MISSING_DEPENDENCY: "this content was not scanned",
    ScanErrorKind.LIMIT: "the rest of this content was not scanned; raise the limit (ScanLimits) if the file is trusted",
    ScanErrorKind.IO: "this file was not scanned",
    ScanErrorKind.INTERNAL: "this file was not scanned; this is a bug in picklescan, please report it",
}


@dataclass
class ScanError:
    location: Location
    kind: ScanErrorKind
    message: str
    offset: Optional[int] = None  # byte offset in the (decompressed) content, where known
    help: Optional[str] = None

    def __post_init__(self):
        self.location = _location(self.location)
        if self.help is None:
            self.help = _error_help[self.kind]

    @property
    def file_id(self) -> str:
        return str(self.location)

    def format(self, style: Callable[..., str] = _plain) -> str:
        """Multi-line description, in the style of compiler diagnostics. style(text, *styles) can add colors (see cli)."""
        where = _printable(self.location.describe()) + (f", offset {self.offset}" if self.offset is not None else "")
        return (
            f"{style(f'error[{self.kind.value}]', 'red', 'bold')}{style(':', 'bold')} {style(_printable(self.message), 'bold')}\n"
            f" {style('-->', 'cyan')} {where}\n"
            f"  {style('= note:', 'cyan')} {self.help}"
        )


@dataclass
class SkippedFile:
    """Content deliberately left unscanned, such as an archive nested in another one."""

    location: Location
    reason: str

    def __post_init__(self):
        self.location = _location(self.location)

    @property
    def file_id(self) -> str:
        return str(self.location)

    def format(self, style: Callable[..., str] = _plain) -> str:
        where = _printable(self.location.describe())
        return f"{style('skipped', 'yellow', 'bold')}{style(':', 'bold')} {style(_printable(self.reason), 'bold')}\n {style('-->', 'cyan')} {where}"


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

    def add_error(self, file_id, kind: ScanErrorKind, message: str, offset: Optional[int] = None) -> "ScanResult":
        self.errors.append(ScanError(_location(file_id), kind, message, offset))
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
    location: Optional[Location] = field(default=None, compare=False, repr=False)

    def __post_init__(self):
        if self.location is None:
            self.location = _location(self.file_id)
        self.file_id = str(self.location)


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


# Marks log records about errors and skipped content, which are also in the scan result: the command line prints those from the
# result instead (see cli), so that each is shown once
_reported = {"picklescan_reported": True}


def _error_result(file_id, kind: ScanErrorKind, message: str, scanned_files: int = 1, offset: Optional[int] = None) -> ScanResult:
    level = logging.WARNING if kind in (ScanErrorKind.MISSING_DEPENDENCY, ScanErrorKind.UNSUPPORTED) else logging.ERROR
    _log.log(level, f"{_location(file_id).describe()}: {kind.value} error: {message}", extra=_reported)
    return ScanResult([], scanned_files=scanned_files).add_error(file_id, kind, message, offset)


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
    def __init__(self, msg: str, globals: Optional[Set[Tuple[str, str]]], offset: Optional[int] = None):
        self.msg = msg
        self.globals = globals
        self.offset = offset
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
# Bytes read from the start of a file to tell its format (a tar header is 512 bytes)
_head_size = 512


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


class _HTTPError(OSError):
    pass


def _http_open(url: str, byte_range: Optional[Tuple[int, int]] = None, connection=None, _redirects: int = 0):
    """Sends GET url, following redirections: (connection, response, final URL). The caller reads the response, and closes the
    connection or reuses it for the same host (connection: one to reuse, when it is for the host of url)."""
    _log.debug(f"Request: GET {url}" + ("" if byte_range is None else f" bytes {byte_range[0]}-{byte_range[1]}"))
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise _HTTPError(f"cannot GET {url}: only http and https URLs are supported")
    path_and_query = (parsed_url.path or "/") + ("?" + parsed_url.query if len(parsed_url.query) > 0 else "")
    headers = {} if byte_range is None else {"Range": f"bytes={byte_range[0]}-{byte_range[1]}"}
    if connection is None:
        connection = (http.client.HTTPConnection if parsed_url.scheme == "http" else http.client.HTTPSConnection)(parsed_url.netloc)
    try:
        connection.request("GET", path_and_query, headers=headers)
        response = connection.getresponse()
        _log.debug(f"Response: status code {response.status} reason {response.reason}")
        if response.status in (301, 302, 303, 307, 308):  # Follow redirections
            location = response.getheader("Location")
            response.read()
            connection.close()
            if not location or _redirects >= _max_redirects:
                raise _HTTPError(f"HTTP {response.status} calling GET {url}: " + ("too many redirections" if location else "no Location"))
            # Hugging Face redirects small files to a relative location (/api/resolve-cache/...)
            return _http_open(urllib.parse.urljoin(url, location), byte_range, None, _redirects + 1)
        if response.status >= 400 and not (response.status == 416 and byte_range is not None):
            raise _HTTPError(f"HTTP {response.status} ({response.reason}) calling GET {url}")
        return connection, response, url
    except BaseException:
        connection.close()
        raise


def _http_get(url) -> bytes:
    connection, response, _ = _http_open(url)
    try:
        return response.read()
    finally:
        connection.close()


class _RemoteFile(io.RawIOBase):
    """A file over HTTP(S), downloaded with Range requests as a scan reads it: what a scan skips (tensor data, archive members it
    does not open...) is never downloaded. Downloaded data is kept in a temporary file, not in memory. When the server does not
    serve ranges, the whole file is downloaded at once."""

    _picklescan_cheap_seek = True
    _block_size = 1 << 16
    _max_readahead = 64 << 20

    def __init__(self, url: str):
        self._cache = TemporaryFile()
        self._fetched = set()  # indices of the blocks in the cache
        self._pos = 0
        self._consumed = 0  # end of the last read
        self._readahead = 1
        self._next_block = None  # block following the last ones fetched
        self._connection = None
        try:
            self._connection, response, self._url = _http_open(url, (0, self._block_size - 1))
            total = None
            if response.status == 206:
                start, end, total = self._content_range(response)
                if start != 0:
                    raise _HTTPError(f"{self._url}: got bytes {start}-{end} instead of the start of the file")
            if response.status == 416:
                total = self._content_range(response, unsatisfied=True)[2]
                response.read()
                if total not in (None, 0):
                    raise _HTTPError(f"{self._url}: cannot read the start of a file of {total} bytes")
                self._size = 0
            elif total is None:
                # Ranges not served (or the size not told): the whole file
                self._size = self._download(response)
                self._fetched.update(range(0, -(-self._size // self._block_size)))
            else:
                self._size = total
                self._store(0, response.read(), end - start + 1)
        except BaseException:
            self.close()
            raise

    def _content_range(self, response, unsatisfied: bool = False) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        content_range = response.getheader("Content-Range") or ""
        match = re.fullmatch(r"bytes (?:(\d+)-(\d+)|\*)/(\d+|\*)", content_range.strip())
        if match is None or (match.group(1) is None) != unsatisfied:
            if unsatisfied and not content_range:
                return None, None, None
            raise _HTTPError(f"{self._url}: invalid Content-Range {content_range!r}")
        start, end, total = (None if g in (None, "*") else int(g) for g in match.groups())
        if start is not None and (end < start or (total is not None and end >= total)):
            raise _HTTPError(f"{self._url}: invalid Content-Range {content_range!r}")
        return start, end, total

    def _download(self, response) -> int:
        size = 0
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                return size
            self._cache.write(chunk)
            size += len(chunk)

    def _store(self, offset: int, data: bytes, expected: int):
        if len(data) != expected:
            raise _HTTPError(f"{self._url}: got {len(data)} bytes instead of {expected} at offset {offset}")
        self._cache.seek(offset)
        self._cache.write(data)
        end = offset + len(data)
        # Whole blocks only, and the last one at the end of the file
        last = -(-end // self._block_size) if end >= self._size else end // self._block_size
        self._fetched.update(range(offset // self._block_size, last))

    def _request(self, start: int, end: int):
        for attempt in (0, 1):
            try:
                self._connection, response, _ = _http_open(self._url, (start, end), self._connection)
                break
            except (http.client.RemoteDisconnected, ConnectionError, http.client.CannotSendRequest):
                self._connection = None  # the server closed the connection kept open: reconnect once
                if attempt:
                    raise
        if response.status != 206:
            response.read()
            raise _HTTPError(f"{self._url}: HTTP {response.status} to a Range request after a 206")
        got_start, got_end, total = self._content_range(response)
        if (got_start, got_end) != (start, end) or total not in (None, self._size):
            raise _HTTPError(f"{self._url}: got bytes {got_start}-{got_end}/{total} instead of {start}-{end}/{self._size}")
        self._store(start, response.read(), end - start + 1)

    def _ensure(self, start: int, end: int):
        first, last = start // self._block_size, (end - 1) // self._block_size
        for block in range(first, last + 1):
            if block in self._fetched:
                continue
            # Reading on from where the last request ended, after reading what it fetched: fetch more and more at once
            sequential = block == self._next_block and self._consumed >= block * self._block_size
            self._readahead = min(self._readahead * 2, self._max_readahead // self._block_size) if sequential else 1
            stop = block
            while stop <= max(last, block + self._readahead - 1) and stop not in self._fetched and stop * self._block_size < self._size:
                stop += 1
            self._request(block * self._block_size, min(stop * self._block_size, self._size) - 1)
            self._next_block = stop

    def readable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, b) -> int:
        size = max(0, min(len(b), self._size - self._pos))
        if size == 0:
            return 0
        self._ensure(self._pos, self._pos + size)
        self._cache.seek(self._pos)
        data = self._cache.read(size)
        b[: len(data)] = data
        self._pos += len(data)
        self._consumed = self._pos
        return len(data)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        position = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._size}[whence] + offset
        if position < 0:
            raise OSError(errno.EINVAL, f"negative seek position {position}")  # as for files: zipfile relies on it
        self._pos = position
        return self._pos

    def tell(self) -> int:
        return self._pos

    def close(self):
        if not self.closed:
            self._cache.close()
            if self._connection is not None:
                self._connection.close()
        super().close()


def _scan_remote_file(url: str, file_ext: Optional[str], strict: bool, limits: Optional[ScanLimits]) -> ScanResult:
    with _RemoteFile(url) as raw, io.BufferedReader(raw, 1 << 16) as file:
        return scan_bytes(file, url, file_ext, strict=strict, limits=limits)


class _OpcodeError(ValueError):
    """A pickle parsing error, at the opcode starting at position."""

    def __init__(self, position: int, message: str):
        super().__init__(message)
        self.position = position


class _SkippedBytes:
    """Stands in for an argument too large to be a module or global name (tensor data, typically): only its size is kept.

    As a value it is unknown: used as a STACK_GLOBAL operand, the import is reported as dangerous.
    """

    __slots__ = ("size",)

    def __init__(self, size: int):
        self.size = size

    def __repr__(self) -> str:
        return f"<{self.size} bytes skipped>"


# Arguments larger than these are skipped instead of being loaded into memory: bytes are never names, and names are never this long
_max_kept_bytes_arg_size = 4096
_max_kept_string_size = 1 << 10
# Numbers in protocol 0 lines, whitespace aside: longer ones are no valid memo index anyway
_max_kept_number_size = 64
# Strings the memo keeps alive, in total for a pickle: beyond, what the memo stores reads as unknown
_max_memo_string_bytes = 64 << 20
_skip_chunk_size = 1 << 20


def _skip(f: IO[bytes], size: int, name: str):
    """Moves past an argument without reading it when it is large and seeking is free, reads through it in chunks otherwise."""
    if size >= _skip_chunk_size and _cheaply_seekable(f):
        pos = f.tell()
        remaining = f.seek(0, io.SEEK_END) - pos
        if remaining < size:
            raise ValueError(f"expected {size} bytes in a {name}, but only {remaining} remain")
        f.seek(pos + size)
        return
    remaining = size
    while remaining > 0:
        chunk = f.read(min(remaining, _skip_chunk_size))
        if not chunk:
            raise ValueError(f"expected {size} bytes in a {name}, but only {size - remaining} remain")
        remaining -= len(chunk)


def _bytes_arg_reader(name: str, prefix_reader, prefix_size: int, wrap=bytes):
    def reader(f: IO[bytes]):
        size = prefix_reader(f)
        if size <= _max_kept_bytes_arg_size:
            data = f.read(size)
            if len(data) != size:
                raise ValueError(f"expected {size} bytes in a {name}, but only {len(data)} remain")
            return wrap(data), prefix_size + size
        _skip(f, size, name)
        return _SkippedBytes(size), prefix_size + size

    return reader


def _counted_arg_reader(name: str, prefix_reader, prefix_size: int, convert, truncated_message=None):
    """Same checks and value as the pickletools reader for a length-prefixed argument, plus the number of bytes it took."""

    def reader(f: IO[bytes]):
        size = prefix_reader(f)
        if size < 0:
            raise ValueError(f"{name} byte count < 0: {size}")
        if size > _max_kept_string_size:
            _skip(f, size, name)
            return _SkippedBytes(size), prefix_size + size
        data = f.read(size)
        if len(data) != size:
            raise ValueError(truncated_message or f"expected {size} bytes in a {name}, but only {len(data)} remain")
        return convert(data), prefix_size + size

    return reader


def _read_line(f: IO[bytes]) -> Tuple[Optional[bytes], int]:
    """A line, or None when it is longer than _max_kept_string_size (then consumed without being kept), and the bytes read."""
    line = f.readline(_max_kept_string_size + 1)
    consumed = len(line)
    if line.endswith(b"\n") or len(line) <= _max_kept_string_size:
        return line, consumed
    while not line.endswith(b"\n"):
        line = f.readline(_skip_chunk_size)
        if not line:
            raise ValueError("no newline found when trying to read a line argument")
        consumed += len(line)
    return None, consumed


def _read_number_line(f: IO[bytes]) -> Tuple[Optional[bytes], int]:
    """A number on a line, as the C unpickler reads it, and the bytes read: the line ends at its first NUL byte (it is read as a C
    string), and the leading whitespace the unpicklers ignore is left out. None when what is left is longer than
    _max_kept_number_size (whitespace aside): whitespace and what follows a NUL byte can make a line of any length.
    """
    kept, consumed, too_long, ended = b"", 0, False, False
    while True:
        chunk = f.readline(_skip_chunk_size)
        if not chunk:
            raise ValueError("no newline found when trying to read a line argument")
        consumed += len(chunk)
        end = chunk.endswith(b"\n")
        if not too_long and not ended:
            body = chunk[:-1] if end else chunk
            if b"\0" in body:
                body, ended = body.split(b"\0", 1)[0], True
            kept += body.lstrip() if not kept else body
            if len(kept) > _max_kept_number_size:
                core = kept.rstrip()
                # Trailing whitespace is kept as a single space: anything after it makes the number invalid, as it should
                kept = core + b" " if len(core) < len(kept) else core
                too_long = len(core) > _max_kept_number_size
        if end:
            return (None if too_long else kept), consumed


def _parse_int_line(text: bytes):
    """INT, PUT and GET arguments, accepted as soon as a CPython unpickler accepts them: the C unpickler parses INT like strtol
    (base prefixes are accepted), PUT and GET in base 10, the Python unpickler with int(..., 0)."""
    if text in (b"00", b"01"):
        return text == b"01"
    for base in (10, 0):
        try:
            return int(text, base)
        except ValueError:
            pass
    raise ValueError(f"invalid literal for an integer argument: {text!r}")


def _parse_long_line(text: bytes) -> int:
    text = text.strip()
    for base in (10, 0):
        try:
            return int(text[:-1] if text.endswith(b"L") else text, base)
        except ValueError:
            pass
    raise ValueError(f"invalid literal for a LONG argument: {text!r}")


def _number_line_arg_reader(parse):
    """The reader of a number on a line (protocol 0: INT, LONG, FLOAT, PUT, GET), accepting what any CPython unpickler accepts.
    pickletools is stricter: rejecting what an unpickler accepts would stop parsing where loading goes on."""

    def reader(f: IO[bytes]):
        text, consumed = _read_number_line(f)
        if text is None:
            return _SkippedBytes(consumed), consumed
        return parse(text), consumed

    return reader


def _line_arg_reader(read_from_lines, line_count: int = 1):
    """The pickletools reader for a newline-terminated argument (protocol 0), fed lines read with a bounded size."""

    def reader(f: IO[bytes]):
        lines, consumed = [], 0
        for _ in range(line_count):
            line, size = _read_line(f)
            lines.append(line)
            consumed += size
        if any(line is None for line in lines):
            return _SkippedBytes(consumed), consumed
        return read_from_lines(io.BytesIO(b"".join(lines))), consumed

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
    pickletools.stringnl: _line_arg_reader(pickletools.read_stringnl),
    pickletools.stringnl_noescape: _line_arg_reader(pickletools.read_stringnl_noescape),
    pickletools.stringnl_noescape_pair: _line_arg_reader(pickletools.read_stringnl_noescape_pair, line_count=2),
    pickletools.unicodestringnl: _line_arg_reader(pickletools.read_unicodestringnl),
    pickletools.decimalnl_short: _number_line_arg_reader(_parse_int_line),
    pickletools.decimalnl_long: _number_line_arg_reader(_parse_long_line),
    pickletools.floatnl: _number_line_arg_reader(lambda text: float(text.strip())),
}
# Opcode byte -> (opcode, plain reader or None, counted reader or None, fixed argument size or None)
_opcode_table = {}
for _op in pickletools.opcodes:
    _arg = _op.arg
    if _arg is None:
        _opcode_table[_op.code.encode("latin-1")] = (_op, None, None, 0)
    elif _arg in _counted_arg_readers:
        _opcode_table[_op.code.encode("latin-1")] = (_op, None, _counted_arg_readers[_arg], None)
    else:
        assert _arg.n >= 0, f"no counted reader for {_arg.name}"
        _opcode_table[_op.code.encode("latin-1")] = (_op, _arg.reader, None, _arg.n)


def _genops(data: IO[bytes], frame_violations: Optional[List[str]] = None, joblib_reads: Optional[list] = None):
    """pickletools.genops, with two differences.

    Large bytes arguments are skipped instead of read into memory: model weights pickled in-band (numpy arrays, raw tensor bytes...)
    are a few opcodes carrying gigabytes of arguments.

    Framing is checked: pickletools reads opcodes sequentially and ignores FRAME, but CPython's C unpickler does not. When an
    opcode runs past the end of the current frame, the C unpickler (reading from a file object such as io.BytesIO, which is how
    torch.load reads data.pkl) drops what is left of the frame and reads the argument from after it, so it parses different opcodes
    than pickletools does. Leftover frame bytes after STOP are likewise skipped by the next pickle.load on the same file. Pickles
    written by pickle.dumps never do any of this, and the pure Python unpickler rejects them, so such violations are reported
    in frame_violations rather than emulated.

    After an opcode is yielded, the consumer can append what joblib reads from the file right after it to joblib_reads (see
    _JoblibTracker.step): raw array data is skipped, after a padding byte and the padding it announces when aligned.
    """
    frame_end = None
    pos = data.tell()
    read = data.read
    while True:
        code = read(1)
        entry = _opcode_table.get(code)
        if entry is None:
            if code == b"":
                raise _OpcodeError(pos, f"pickle data ends at position {pos} before a STOP opcode (truncated, or not a pickle)")
            raise _OpcodeError(pos, f"unknown opcode {code!r} at position {pos}")
        opcode, reader, counted_reader, size = entry
        try:
            if counted_reader is not None:
                arg, size = counted_reader(data)
                end_pos = pos + 1 + size
            elif reader is None:
                arg = None
                end_pos = pos + 1
            else:
                arg = reader(data)
                end_pos = pos + 1 + size
        except (_LimitExceeded, _MissingDependency):
            raise
        except Exception as e:
            raise _OpcodeError(pos, f"invalid argument for {opcode.name} at position {pos}: {e}") from e

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
        if joblib_reads:
            aligned, size = joblib_reads.pop()
            if frame_end is not None and pos < frame_end and frame_violations is not None:
                # joblib reads from the file, after the frame its unpickler has already read: not from here
                frame_violations.append(f"joblib reads data at position {pos}, before the end of the frame at position {frame_end}")
            if aligned:
                padding = read(1)
                if not padding:
                    raise ValueError("pickle exhausted before joblib array padding")
                _skip(data, padding[0], "joblib array padding")
                pos += 1 + padding[0]
            if size is not None:
                _skip(data, size, "joblib array data")
                pos += size


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


def _global_arg(arg) -> Tuple[str, str]:
    """What a GLOBAL or INST imports: a line too long to be kept (_SkippedBytes) imports something unknown."""
    return tuple(arg.split(" ", 1)) if isinstance(arg, str) else (_unknown, _unknown)


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

    __slots__ = ("stack", "memo", "trusted", "memo_lost", "memo_string_bytes")

    def __init__(self):
        self.stack = []
        self.memo = {}
        self.trusted = True
        self.memo_lost = False  # a memo write went to a slot not known statically: any slot can hold anything
        self.memo_string_bytes = 0

    def copy(self) -> "_Reading":
        reading = _Reading()
        reading.stack, reading.memo, reading.trusted = list(self.stack), dict(self.memo), self.trusted
        reading.memo_lost, reading.memo_string_bytes = self.memo_lost, self.memo_string_bytes
        return reading

    def memo_put(self, key):
        value = self.stack[-1] if self.stack and self.stack[-1] is not _mark else _unknown
        if key is None:
            self.memo_lost = True
        elif isinstance(value, str) and value is not _unknown:
            self.memo_string_bytes += len(value)
            self.memo[key] = value if self.memo_string_bytes <= _max_memo_string_bytes else _unknown
        else:
            self.memo[key] = value

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
            self.memo_put(len(self.memo))
            return None
        if name in _memo_get_ops:
            key = _memo_key(arg, pos)
            if key not in self.memo:
                _log.debug(f"Memo key {key} not found at position {pos}, treating as unknown (potential evasion attempt)")
            stack.append(_unknown if self.memo_lost else self.memo.get(key, _unknown))
            return None
        if name in _string_ops:
            stack.append(arg if isinstance(arg, str) else _unknown)
            return None
        if name == "MARK":
            stack.append(_mark)
            return None
        if name in _memo_put_ops:
            self.memo_put(_memo_key(arg, pos))
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
            stack.append(_import_value(_global_arg(arg), self.trusted))
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
            callable_value = _import_value(_global_arg(arg), self.trusted)
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


# --------------------------------------------------------------------------------------------------------------------------------
# joblib arrays. joblib.load pickles a NumpyArrayWrapper in place of each array, and reads the array data from the file right after
# that wrapper's BUILD: as raw bytes, or as a pickle of its own (read with a fresh Unpickler) when the array holds Python objects.
# To read the file like joblib does, the values that decide what is read are tracked once a class involved shows up. Anything that
# would make joblib read data in a way that cannot be told for sure is an error, rather than a guess: parsing on would mean parsing
# raw data as opcodes, or skipping opcodes as raw data.

_joblib_wrapper_paths = {"joblib.numpy_pickle.NumpyArrayWrapper", "sklearn.externals.joblib.numpy_pickle.NumpyArrayWrapper"}
# Functions creating an instance of the class given as their first argument (copy_reg: Python 2 names, mapped by fix_imports)
_instance_constructor_paths = {
    f"{module}.{name}" for module in ("copyreg", "copy_reg") for name in ("_reconstructor", "__newobj__", "__newobj_ex__")
}
_joblib_wrapper_state_keys = {"subclass", "shape", "order", "dtype", "allow_mmap", "numpy_array_alignment_bytes"}
# Containers are only tracked up to this many items: the values joblib reads its arrays with are small
_max_tracked_container_items = 64
_before = object()  # value pushed before tracking started
_opaque = object()  # value that cannot be told


class _JoblibError(ValueError):
    pass


class _Global:
    """An imported class or function, by its full dotted path (protocol 4 names can be dotted: joblib's unpickler resolves them)."""

    __slots__ = ("path",)

    def __init__(self, module: str, name: str):
        self.path = f"{module}.{name}"

    def is_wrapper(self) -> bool:
        return self.path in _joblib_wrapper_paths or any(self.path.startswith(f"{path}.") for path in _joblib_wrapper_paths)


class _Object:
    """The result of calling callable with args (REDUCE, OBJ, INST), or of creating an instance of a class (NEWOBJ); state is what
    BUILD gives it. Nothing is ever called."""

    __slots__ = ("callable", "args", "new", "state", "built")

    def __init__(self, callable, args, new: bool):
        self.callable, self.args, self.new, self.state, self.built = callable, args, new, None, False

    def instance_class(self):
        """The class this is an instance of, when it can be told: _before when it may not be, _opaque when it cannot."""
        if self.new:
            return self.callable
        if isinstance(self.callable, _Global):
            if self.callable.path in _instance_constructor_paths and isinstance(self.args, tuple) and self.args:
                return self.args[0]
            return _before  # what a function returns: not a joblib wrapper, which only the above create
        return self.callable if self.callable is _before else _opaque

    def is_wrapper(self) -> bool:
        cls = self.instance_class()
        return isinstance(cls, _Global) and cls.is_wrapper()


class _WrapperArgs(tuple):
    """Arguments holding a joblib wrapper class: only allowed for the constructors creating an instance of it."""

    __slots__ = ()


class _Container:
    """A list, dict or set as far as it is tracked: its first items (dicts: string keys only), or opaque beyond."""

    __slots__ = ("kind", "items", "opaque")

    def __init__(self, kind: str):
        self.kind, self.items, self.opaque = kind, ([] if kind != "dict" else {}), False

    def add(self, values: list):
        if self.opaque:
            return
        if self.kind == "dict":
            for key, value in zip(values[::2], values[1::2]):
                if type(key) is not str:  # never hashed: a crafted key could make hashing recurse
                    self.opaque = True
                    return
                self.items[key] = value
        else:
            self.items.extend(values)
        if len(self.items) > _max_tracked_container_items:
            self.opaque, self.items = True, None


class _JoblibTracker:
    """A deliberately dumb model of joblib's unpickler: one step per opcode, in order, with no jumps, no loops and no calls."""

    def __init__(self, memo_lost: bool):
        self.stack = []
        self.memo = {}
        self.memo_lost = memo_lost

    def push(self, value):
        self.stack.append(value)

    def peek(self):
        return self.stack[-1] if self.stack and self.stack[-1] is not _mark else _before if not self.stack else _opaque

    def pop_raw(self):
        if not self.stack:
            return _before
        return _opaque if self.stack[-1] is _mark else self.stack.pop()

    def pop(self):
        """A value the unpickler hands to something: joblib wrappers and their classes cannot be."""
        value = self.pop_raw()
        _check_use(value)
        return value

    def pop_mark(self, check: bool = True) -> list:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i] is _mark:
                items = self.stack[i + 1 :]
                del self.stack[i:]
                break
        else:
            items, self.stack[:] = self.stack[:], []  # the MARK was pushed before tracking started
        if check:
            for item in items:
                _check_use(item)
        return items

    def step(self, op, arg, imported, memoize_key) -> Optional[Tuple[bool, Optional[int]]]:
        """Applies an opcode (imported: what it imports, memoize_key: the slot MEMOIZE writes). Returns what joblib reads from the
        file right after it, if anything: (aligned, size of raw data), or (False, None) for a pickle of its own."""
        name, push, pop = op.name, self.push, self.pop
        if name in ("PROTO", "FRAME", "STOP"):
            return None
        if name in _memo_put_ops:
            key = memoize_key if name == "MEMOIZE" else _memo_key(arg, None)
            if key is None:
                self.memo_lost = True
            else:
                self.memo[key] = self.peek()
        elif name in _memo_get_ops:
            push(_opaque if self.memo_lost else self.memo.get(_memo_key(arg, None), _before))
        elif name == "MARK":
            push(_mark)
        elif name in ("NONE", "NEWTRUE", "NEWFALSE"):
            push(None if name == "NONE" else name == "NEWTRUE")
        elif name in ("GLOBAL", "INST", "STACK_GLOBAL"):
            if name == "STACK_GLOBAL":
                pop(), pop()
            cls = _Global(*imported) if imported is not None and _unknown not in imported else _opaque
            if name == "INST":
                push(self.call(cls, tuple(self.pop_mark()), new=False))
            else:
                push(cls)
        elif name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX"):
            if name == "NEWOBJ_EX":
                pop()
            args, callable = self.pop_raw(), self.pop_raw()
            push(self.call(callable, args, new=name != "REDUCE"))
        elif name == "OBJ":
            items = self.pop_mark()
            push(self.call(items[0], tuple(items[1:]), new=False) if items else _opaque)
        elif name == "BUILD":
            state = pop()
            target = self.peek()
            if isinstance(target, _Object):
                cls = target.instance_class()
                if not (isinstance(cls, _Global) or cls is _before):
                    raise _JoblibError("cannot tell whether joblib reads array data after an object of a class not known statically")
                if target.is_wrapper():
                    if target.built:
                        raise _JoblibError("joblib NumpyArrayWrapper given state twice")
                    target.built = True
                    self.stack[-1] = _opaque  # joblib replaces the wrapper with the array it reads
                    return _joblib_array_read(state)
                target.state = state
            elif target is _opaque:
                raise _JoblibError("cannot tell whether joblib reads array data after an object not known statically")
            elif isinstance(target, _Global):
                # Attributes of a class or module (joblib's own, which decide what it reads) replaced
                raise _JoblibError("cannot tell what joblib reads once state is given to a class or a module")
        elif name in ("TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "EMPTY_TUPLE"):
            if name == "TUPLE":
                items = self.pop_mark(check=False)
            else:
                items = [self.pop_raw() for _ in range("_123".index(name[-1]) if name != "EMPTY_TUPLE" else 0)][::-1]
            if any(_holds_wrapper(item) for item in items):
                push(_WrapperArgs(items))
            else:
                for item in items:
                    _check_use(item)
                push(tuple(items) if len(items) <= _max_tracked_container_items else _opaque)
        elif name in ("EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET", "LIST", "DICT", "FROZENSET"):
            kind = {"EMPTY_LIST": "list", "LIST": "list", "EMPTY_DICT": "dict", "DICT": "dict"}.get(name, "set")
            container = _Container(kind)
            if name in ("LIST", "DICT", "FROZENSET"):
                container.add(self.pop_mark())
            push(container)
        elif name in ("APPEND", "APPENDS", "SETITEM", "SETITEMS", "ADDITEMS"):
            if name in ("APPEND", "SETITEM"):
                items = [pop() for _ in range(1 if name == "APPEND" else 2)][::-1]
            else:
                items = self.pop_mark()
            target = self.peek()
            if isinstance(target, _Container):
                target.add(items)
        elif name == "DUP":
            push(self.peek())
        elif name == "POP":
            self.pop_raw()  # discarded: nothing is done with it
        elif name == "POP_MARK":
            self.pop_mark(check=False)  # discarded
        elif op.arg is not None and not op.stack_before and len(op.stack_after) == 1 and name not in ("PERSID", "EXT1", "EXT2", "EXT4"):
            push(arg if isinstance(arg, (str, int, float)) else _opaque)  # constants (bytes are of no use)
        else:
            # Anything else (persistent ids, extensions, buffers...): stack effect only, values that cannot be told
            before = op.stack_before
            if pickletools.markobject in before:
                self.pop_mark()
                before = before[: before.index(pickletools.markobject)]
            for _ in before:
                pop()
            self.stack.extend(_opaque for _ in op.stack_after)
        return None

    def call(self, callable, args, new: bool) -> _Object:
        if isinstance(args, _WrapperArgs):
            # Only constructors creating an instance of the wrapper class may get it, as their first argument
            constructor = isinstance(callable, _Global) and callable.path in _instance_constructor_paths
            if not constructor or not isinstance(args[0], _Global) or new:
                raise _JoblibError("joblib NumpyArrayWrapper class used otherwise than to create an instance of it")
            for item in args[1:]:
                _check_use(item)
            if callable.path.endswith("._reconstructor") and not (
                len(args) > 1 and isinstance(args[1], _Global) and args[1].path in ("builtins.object", "__builtin__.object")
            ):  # noqa: E501
                raise _JoblibError("joblib NumpyArrayWrapper created through a base class other than object")
        else:
            _check_use(args)
            if not new:
                _check_use(callable)  # calling the wrapper class (or one of its attributes) creates an instance too
            elif isinstance(callable, _Object) and callable.is_wrapper():
                raise _JoblibError("joblib NumpyArrayWrapper used otherwise than as an array")
        return _Object(callable, args, new)


def _activates_joblib_tracking(imported: Tuple[str, str]) -> bool:
    """Whether an import is one of the classes joblib reads arrays with (or a constructor creating instances of them)."""
    path = f"{imported[0]}.{imported[1]}"
    return path == "numpy.dtype" or path in _instance_constructor_paths or _Global(*imported).is_wrapper()


def _holds_wrapper(value) -> bool:
    return isinstance(value, _Global) and value.is_wrapper()


def _check_use(value):
    """joblib wrapper classes and instances are only allowed where joblib's own files have them."""
    if isinstance(value, _WrapperArgs) or _holds_wrapper(value):
        raise _JoblibError("joblib NumpyArrayWrapper class used otherwise than to create an instance of it")
    if isinstance(value, _Object) and value.is_wrapper():
        raise _JoblibError("joblib NumpyArrayWrapper used otherwise than as an array")


def _dtype_layout(dtype) -> Optional[Tuple[int, bool]]:
    """(itemsize, holds Python objects) of a numpy.dtype pickled as numpy does, None if it cannot be told for sure."""
    if not (isinstance(dtype, _Object) and not dtype.new and isinstance(dtype.callable, _Global) and dtype.callable.path == "numpy.dtype"):
        return None
    if type(dtype.args) is not tuple or not dtype.args or type(dtype.args[0]) is not str:
        return None
    match = re.fullmatch(r"[<>|=]?([biufcmMOSUVa])(\d*)", dtype.args[0])
    if match is None:
        return None
    kind, digits = match.groups()
    if kind == "O":
        return 0, True
    state = dtype.state
    if kind in "SUVa":
        # numpy takes the size and the flags (bit 1: holds objects) from the state, whatever the description says
        if type(state) is not tuple or len(state) < 8 or not all(type(state[i]) in (int, bool) for i in (5, 7)):
            return None
        elsize, flags = state[5], state[7]
        return (elsize, bool(flags & 1)) if 0 < elsize < 1 << 31 else None
    # Builtin kinds: the size is the one in the description, and the state does not change it unless it has fields
    if not digits or (state is not None and (type(state) is not tuple or len(state) < 5 or state[3] is not None or state[4] is not None)):
        return None
    return int(digits), False


def _joblib_array_read(state) -> Tuple[bool, Optional[int]]:
    """What joblib reads after a NumpyArrayWrapper given this state (see NumpyArrayWrapper.read_array)."""
    if not isinstance(state, _Container) or state.kind != "dict" or state.opaque or not set(state.items) <= _joblib_wrapper_state_keys:
        raise _JoblibError("cannot tell what joblib reads after a NumpyArrayWrapper: its state is not a dict of known keys")
    shape, layout = state.items.get("shape"), _dtype_layout(state.items.get("dtype"))
    alignment = state.items.get("numpy_array_alignment_bytes")
    if layout is None or type(shape) is not tuple or alignment in (_before, _opaque):
        raise _JoblibError("cannot tell what joblib reads after a NumpyArrayWrapper: its shape or dtype is not known statically")
    itemsize, has_object = layout
    if has_object:
        return False, None  # a pickle of its own
    count = 1
    for n in shape:
        if type(n) not in (int, bool) or n < 0:
            raise _JoblibError("cannot tell what joblib reads after a NumpyArrayWrapper: its shape is not made of sizes")
        count *= n
        if count >= 1 << 63:  # joblib computes the size with 64-bit integers
            raise _JoblibError("cannot tell what joblib reads after a NumpyArrayWrapper: its size overflows")
    return alignment is not None, count * itemsize


def _memo_key(op_value, pos):
    try:
        return int(op_value)
    except (ValueError, TypeError) as e:
        _log.debug(f"Invalid memo key at position {pos}: (error: {e}), treating as unknown")
        return None


def _list_globals(data: IO[bytes], multiple_pickles=True) -> Set[Tuple[str, str]]:
    """Imports made by the pickles in data.

    Files of joblib arrays are read like joblib.load does, raw array data skipped (see _JoblibTracker). What pickle.load would do
    with them is then also checked, reading that data as opcodes: imports found this way are reported when dangerous.
    """
    start = data.tell()
    joblib_reads = []
    error = None
    try:
        globals = _read_globals(data, multiple_pickles, joblib_reads)
    except GenOpsError as e:
        error, globals = e, e.globals
    if joblib_reads and globals is not None:
        data.seek(start)
        try:
            plain = _read_globals(data, multiple_pickles, None)
        except GenOpsError as e:
            plain = e.globals or ()
        globals.alternative.update(plain, getattr(plain, "alternative", ()))
    if error is not None:
        raise error
    return globals


def _read_globals(data: IO[bytes], multiple_pickles: bool, joblib_reads: Optional[list]) -> Set[Tuple[str, str]]:
    """Imports made by the pickles in data, read like joblib.load does when joblib_reads is a list (what joblib reads from the file
    is appended to it), like pickle.load does otherwise.

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
    joblib_outer = []  # reading and tracker of the pickle a joblib object array pickle is embedded in
    tracker = None
    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    last_byte = b"dummy"
    parsing_pkl_error = None
    malformed_pkl_error = None
    error_offset = None
    while last_byte != b"":
        # Opcodes are processed as they are parsed rather than collected first: their arguments can hold the model weights
        if joblib_outer:
            reading, tracker = joblib_outer.pop()  # the joblib object array pickle is done, the pickle it is in resumes
        else:
            reading, tracker = _Reading(), None
        nested = resumed  # the second reading, once it differs from the first one
        resumed = None
        stack_global_underflow = None
        frame_violations = []
        first_op = True
        reads = [] if joblib_reads is not None else None
        try:
            for op, op_value, pos in _genops(data, frame_violations, reads):
                op_name = op.name
                imported = None
                if op_name in ("GLOBAL", "INST"):
                    imported = _global_arg(op_value)
                    globals.add(imported)
                elif op_name == "PROTO" and not first_op:
                    enclosing.append(nested if nested is not None else reading.copy())
                    nested = _Reading()
                first_op = False
                if op_name == "STACK_GLOBAL" and stack_global_underflow is None:
                    top = reading.stack[-2:]
                    operands = top[::-1].index(_mark) if _mark in top else len(top)  # values above the nearest MARK
                    if operands < 2:
                        stack_global_underflow = (f"STACK_GLOBAL at position {pos} has {operands} operand(s) instead of 2", pos)
                memoize_key = len(reading.memo) if tracker is not None and op_name == "MEMOIZE" else None
                if op_name == "STACK_GLOBAL":
                    imported = reading.apply(op, op_value, pos)
                    if imported is not None:
                        globals.add(imported)
                else:
                    reading.apply(op, op_value, pos)
                if nested is not None:
                    nested_import = nested.apply(op, op_value, pos)
                    if nested_import is not None:
                        globals.alternative.add(nested_import)
                if imported is not None and tracker is None and reads is not None and not joblib_outer:
                    if _activates_joblib_tracking(imported):
                        tracker = _JoblibTracker(reading.memo_lost)
                if tracker is not None:
                    try:
                        read = tracker.step(op, op_value, imported, memoize_key)
                    except _JoblibError as e:
                        raise _OpcodeError(pos, f"{e} ({op_name} at position {pos})") from e
                    if read is not None:
                        reads.append(read)
                        joblib_reads.append(read)
                        if read[1] is None:
                            # An array of Python objects: joblib reads it as a pickle of its own, with a fresh Unpickler
                            joblib_outer.append((reading, tracker))
                            reading, tracker = _Reading(), None
        except (_LimitExceeded, _MissingDependency):
            raise
        except Exception as e:
            _log.debug(f"Error parsing pickle: {e}", exc_info=True)
            parsing_pkl_error = str(e)
            error_offset = e.position if isinstance(e, _OpcodeError) else None
        else:
            if enclosing:
                resumed = enclosing.pop()  # second reading: the embedded pickle is done, the enclosing one resumes
            # The unpickler rejects a STACK_GLOBAL with too few operands, so this pickle cannot load. Only report it when the rest
            # of the pickle parsed fine: random binary data trips over this regularly before hitting an invalid opcode, and should
            # keep being reported as "not a pickle" rather than as a scan error.
            if stack_global_underflow is not None and malformed_pkl_error is None:
                malformed_pkl_error, error_offset = stack_global_underflow
        if frame_violations:
            # Reported even if pickletools later fails to parse this pickle: the C unpickler may well parse it differently
            _log.debug(f"Pickle frame violation: {frame_violations[0]}")
            globals.add(_frame_violation_global)
            if malformed_pkl_error is None:
                malformed_pkl_error = frame_violations[0]
                error_offset = int(re.search(r"at position (\d+)", frame_violations[0]).group(1))
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
            raise GenOpsError(parsing_pkl_error, globals_opt, error_offset)

    if malformed_pkl_error is not None:
        raise GenOpsError(malformed_pkl_error, globals, error_offset)

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
    location = _location(file_id)
    alternative = set(getattr(raw_globals, "alternative", ())) - set(raw_globals)
    for rg in list(raw_globals) + sorted(alternative):
        g = Global(rg[0], rg[1], SafetyLevel.Dangerous, location)
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
            _log.warning("%s: %s import %s.%s FOUND", location.describe(), g.safety.value, g.module, g.name, extra=_dangerous)
            issues_count += 1
        elif unsafe_filter is not None and (unsafe_filter == "*" or g.name in unsafe_filter):
            g.safety = SafetyLevel.Dangerous
            _log.warning("%s: %s import %s.%s FOUND", location.describe(), g.safety.value, g.module, g.name, extra=_dangerous)
            issues_count += 1
        elif safe_filter is not None and (safe_filter == "*" or g.name in safe_filter):
            g.safety = SafetyLevel.Innocuous
        elif strict:
            g.safety = SafetyLevel.Dangerous
            _log.warning(
                "%s: %s import %s.%s FOUND (promoted by --strict)", location.describe(), g.safety.value, g.module, g.name, extra=_dangerous
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


def _importable_name(name: str) -> bool:
    return all(part.isidentifier() for part in name.split("."))


def scan_pickle_bytes(data: IO[bytes], file_id, multiple_pickles=True, strict=False, _without_magic=False) -> ScanResult:
    """Disassemble a Pickle stream and report issues"""
    _log.debug(f"scan_pickle_bytes({file_id})")

    try:
        raw_globals = _list_globals(data, multiple_pickles)
    except GenOpsError as e:
        if e.globals is not None and _without_magic:
            # Content without pickle magic bytes that fails to parse is most likely not a pickle at all: text such as Python
            # source parses as a few opcodes ("import os" reads as INST importing "mport os") before failing. Imports with names
            # the import system cannot resolve are dropped; unknown operands and frame violations are kept.
            kept = {g for g in e.globals if g == _frame_violation_global or (_importable_name(g[0]) and _importable_name(g[1]))}
            e.globals = kept or None
        if e.globals is not None:
            # Found some globals before error - could be a malicious partial pickle
            _log.error(
                f"{_location(file_id).describe()}: error parsing pickle: {e}", exc_info=_log.isEnabledFor(logging.DEBUG), extra=_reported
            )
            result = _build_scan_result_from_raw_globals(e.globals, file_id, strict=strict)
            return result.add_error(file_id, ScanErrorKind.PARSE, str(e), e.offset)
        else:
            # No globals found - likely not a pickle file at all
            _log.debug(f"{_location(file_id).describe()}: not a pickle ({e})")
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
    # torch.save and torch.jit.save put everything in a single folder, with the pickle and a format version
    roots = {name.split("/", 1)[0] for name in names}
    root = next(iter(roots)) if len(roots) == 1 else None
    if root is not None and f"{root}/data.pkl" in names and (f"{root}/version" in names or f"{root}/.data/version" in names):
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
    info = FileInfo(str(file_id), fmt, compression=compression, location=_location(file_id))
    file_id = info.location
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
        info.members.append(_walk_archive(data, FileInfo(str(file_id), FileFormat.TAR, location=file_id), ctx, depth, _walk_tar_members))
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
            info.members.append(
                _walk_archive(data, FileInfo(str(file_id), FileFormat.ZIP, location=file_id), ctx, depth, _walk_zip_members)
            )
    data.seek(start)
    return info


def _walk_format(data, info: FileInfo, file_ext, ctx: _ScanContext, depth: int, layers: int, size: Optional[int]):
    fmt, file_id = info.format, info.location
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
                    info.members.append(
                        _walk(
                            content,
                            file_id,
                            _inner_extension(file_id.members[-1] if file_id.members else file_id.file),
                            ctx,
                            depth,
                            layers + 1,
                        )
                    )
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
        ctx.result.merge(scan_pickle_bytes(data, file_id, strict=ctx.strict, _without_magic=fmt is FileFormat.UNKNOWN))
        if read_error is not None:
            message = f"cannot read past byte {data.getbuffer().nbytes}: {read_error}"
            ctx.result.merge(_error_result(file_id, ScanErrorKind.ARCHIVE, message, 0))
    elif fmt is FileFormat.UNKNOWN:
        info.format, info.pickle_protocol = _classify_pickle(data)


def _walk_archive(data, info: FileInfo, ctx: _ScanContext, depth: int, walk_members, extra_level: bool = False) -> FileInfo:
    if depth >= ctx.limits.max_archive_depth + extra_level:
        info.note = f"{info.format.value} archive nested in another archive: not opened (ScanLimits.max_archive_depth)"
        if ctx.scan:
            _log.info(f"{info.location.describe()}: {info.note}", extra=_reported)
            ctx.result.skipped.append(SkippedFile(info.location, info.note))
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
            ctx.result.merge(_error_result(info.location, ScanErrorKind.ARCHIVE, info.note))
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
            member_id = info.location.member(member.filename)
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
                info.members.append(FileInfo(str(member_id), FileFormat.UNKNOWN, note=f"cannot read zip member: {e}", location=member_id))
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
                    member_id = info.location.member(member.filename)
                    if not path.startswith(root + os.sep) or not os.path.isfile(path):
                        note = "not a regular file of the archive (link, special file...): not scanned"
                        info.members.append(FileInfo(str(member_id), FileFormat.UNKNOWN, note=note, location=member_id))
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
            ctx.result.merge(_error_result(info.location, ScanErrorKind.ARCHIVE, info.note))


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
                member_id = info.location.member(member.name)
                with tar.extractfile(member) as file:
                    info.members.append(_walk(file, member_id, os.path.splitext(member.name)[1], ctx, depth, 0, size=member.size))
    except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError) as e:
        info.note = f"cannot read tar archive: {e}"
        if ctx.scan:
            ctx.result.merge(_error_result(info.location, ScanErrorKind.ARCHIVE, info.note))


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

    # Scan model files. Every file is scanned by content (protocol 0 and 1 pickles have no magic bytes, and extensions can lie): a
    # file that is not a pickle fails to parse within its first bytes, so only those are downloaded
    scan_result = ScanResult([])
    for file_name in file_names:
        url = f"https://huggingface.co/{repo_id}/resolve/main/{urllib.parse.quote(file_name)}"
        _log.debug("Scanning file %s in model %s", file_name, repo_id)
        scan_result.merge(_isolated(lambda: _scan_remote_file(url, os.path.splitext(file_name)[1], strict, limits), url))

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

            # Every file is scanned by content: protocol 0 and 1 pickles have no magic bytes, and extensions can lie. Files that are
            # not pickles fail to parse within their first bytes.
            def scan_one(file_path=file_path, file_ext=file_ext) -> ScanResult:
                with open(file_path, "rb") as file:
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

    return _scan_remote_file(url, os.path.splitext(urllib.parse.urlparse(url).path)[1] or None, strict, limits)


def detect_file(data: IO[bytes], file_id: str = "", file_ext: Optional[str] = None, limits: Optional[ScanLimits] = None) -> FileInfo:
    """Tells what a stream contains, and for archives and compressed files, what their content is, without scanning anything.

    Archives are inspected down to ``limits.max_archive_depth`` levels. Content without magic bytes is reported as PICKLE when its
    first pickle parses up to STOP, UNKNOWN otherwise.
    """
    return _walk(data, file_id, file_ext, _ScanContext(limits=limits, scan=False), depth=0, layers=0)


def detect_file_path(path, limits: Optional[ScanLimits] = None) -> FileInfo:
    with open(path, "rb") as file:
        return detect_file(file, path, os.path.splitext(path)[1], limits=limits)
