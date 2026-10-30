import http.client
from collections import OrderedDict
import importlib
import bz2
import collections
import gzip
import io
import lzma
import tarfile
import json
import os
import pickle
import re
import struct
import sys
import zlib
from typing import Union
from unittest import TestCase

import pytest
import zipfile

from picklescan.cli import main
import picklescan.scanner as scanner_module
from picklescan.scanner import (
    Global,
    SafetyLevel,
    ScanFilter,
    FileFormat,
    Location,
    ScanErrorKind,
    ScanLimits,
    ScanResult,
    _http_get,
    _list_globals,
    _build_scan_result_from_raw_globals,
    _unsafe_globals,
    scan_bytes,
    scan_pickle_bytes,
    scan_zip_bytes,
    scan_directory_path,
    scan_file_path,
    scan_url,
    scan_huggingface_model,
    scan_numpy,
    scan_pytorch,
    detect_file,
)
from picklescan.relaxed_zipfile import RelaxedZipFile
from picklescan.torch import MAGIC_NUMBER

_root_path = os.path.dirname(__file__)


class Malicious1:
    def __reduce__(self):
        return eval, ("print('456')",)


class Malicious2:
    def __reduce__(self):
        return os.system, ("ls -la",)


class Suspicious:
    def __reduce__(self):
        import collections

        return collections.Counter, ([1, 2, 3],)


class HTTPResponse:
    def __init__(self, status, data=None, headers=None):
        self.status = status
        self.reason = "mock reason"
        self.data = data
        self.headers = headers or {}
        self.offset = 0

    def read(self, amt=None):
        data = bytes(self.data or b"")
        chunk = data[self.offset :] if amt is None else data[self.offset : self.offset + amt]
        self.offset += len(chunk)
        return chunk

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


def _malicious_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zip:
        zip.writestr("archive/data.pkl", pickle.dumps(Malicious1()))
    return bytes(buffer.getbuffer())


# Files of a mock Hugging Face repo, to check that files are picked by content rather than extension
_sniffing_repo_files = {
    "model": _malicious_zip(),  # extensionless zip
    "weights.data-00000": pickle.dumps(Malicious1()),  # unknown extension, pickle content
    "legacy": pickle.dumps(Malicious1(), protocol=0),  # no extension, and protocol 0 pickles have no magic bytes
    "model.safetensors": (640).to_bytes(8, "little") + b"x" * (20 << 20),  # header length starts with \x80\x02, like a pickle
    "README.md": b"# Totally harmless",
}
_served_bytes = collections.Counter()  # bytes of each file of the mock Hugging Face repo sent so far
_served_by_path = collections.Counter()  # bytes sent so far, by URL path


class MockHTTPSConnection:
    def __init__(self, host):
        self.host = host
        self.response = None

    def request(self, method, path_and_query, headers=None):
        self._request(method, path_and_query)
        # Range requests, for every URL
        range_header = (headers or {}).get("Range")
        if range_header is not None and self.response.status == 200 and "/norange/" not in path_and_query:
            data = bytes(self.response.data)
            start, end = (int(n) for n in range_header[len("bytes=") :].split("-"))
            if start >= len(data):
                self.response = HTTPResponse(416, b"")
            else:
                chunk = data[start : end + 1]
                total = "*" if "/unknowntotal/" in path_and_query else len(data)
                content_range = f"bytes {start}-{start + len(chunk) - 1}/{total}"
                if "/badrange/" in path_and_query:
                    content_range = f"bytes {start + 1}-{start + len(chunk)}/{len(data)}"
                self.response = HTTPResponse(206, chunk, {"Content-Range": content_range})
        sniffing_prefix = "/mock/sniffing-model/resolve/main/"
        if path_and_query.startswith(sniffing_prefix):
            _served_bytes[path_and_query[len(sniffing_prefix) :]] += len(self.response.data or b"")
        _served_by_path[path_and_query] += len(self.response.data or b"")

    def _request(self, method, path_and_query):
        assert self.response is None
        target = f"{method} https://{self.host}{path_and_query}"
        sniffing_prefix = "GET https://huggingface.co/mock/sniffing-model/resolve/main/"
        if target.startswith(sniffing_prefix):
            self.response = HTTPResponse(200, _sniffing_repo_files[target[len(sniffing_prefix) :]])
        elif target == "GET https://huggingface.co/api/models/mock/sniffing-model":
            siblings = [{"rfilename": name} for name in _sniffing_repo_files]
            self.response = HTTPResponse(200, json.dumps({"siblings": siblings}).encode())
        elif target == "GET https://localhost/mock/norange/pickle/malicious":  # a server ignoring Range requests
            self.response = HTTPResponse(200, pickle.dumps(Malicious1()))
        elif target in ("GET https://localhost/mock/unknowntotal/pickle/malicious", "GET https://localhost/mock/badrange/pickle/malicious"):
            self.response = HTTPResponse(200, pickle.dumps(Malicious1()))
        elif target == "GET https://localhost/mock/empty":
            self.response = HTTPResponse(200, b"")
        elif target == "GET https://huggingface.co/api/models/mock/quoted-model":
            self.response = HTTPResponse(200, json.dumps({"siblings": [{"rfilename": "dir/my model#1.pkl"}]}).encode())
        elif target == "GET https://huggingface.co/mock/quoted-model/resolve/main/dir/my%20model%231.pkl":
            self.response = HTTPResponse(200, pickle.dumps(Malicious1()))
        elif target == "GET https://localhost/mock/weights/malicious":
            self.response = HTTPResponse(200, pickle.dumps([b"\x00" * (8 << 20), Malicious1()], protocol=4))
        elif target == "GET https://localhost/mock/200":
            self.response = HTTPResponse(200, b"mock123")
        elif target == "GET https://localhost/mock/400":
            self.response = HTTPResponse(400)
        elif target == "GET https://localhost/mock/pickle/benign":
            self.response = HTTPResponse(200, pickle.dumps({"a": 0, "b": 1, "c": 2}))
        elif target == "GET https://localhost/mock/redirect/relative":  # like Hugging Face's small files
            self.response = HTTPResponse(307, b"", {"Location": "/mock/pickle/malicious"})
        elif target == "GET https://localhost/mock/redirect/loop":
            self.response = HTTPResponse(302, b"", {"Location": "/mock/redirect/loop"})
        elif target == "GET https://localhost/mock/pickle/malicious":
            self.response = HTTPResponse(200, pickle.dumps(Malicious2()))
        elif target == "GET https://localhost/mock/zip/benign":
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as zip:
                zip.writestr("data.pkl", pickle.dumps({"a": 0, "b": 1, "c": 2}))
            self.response = HTTPResponse(200, buffer.getbuffer())
        elif target == "GET https://localhost/mock/zip/malicious":
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as zip:
                zip.writestr("data.pkl", pickle.dumps(Malicious1()))
            self.response = HTTPResponse(200, buffer.getbuffer())
        elif target == "GET https://huggingface.co/api/models/ykilcher/totally-harmless-model":
            self.response = HTTPResponse(200, b'{"siblings": [{"rfilename": "pytorch_model.bin"}]}')
        elif target == "GET https://huggingface.co/ykilcher/totally-harmless-model/resolve/main/pytorch_model.bin":
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as zip:
                zip.writestr("archive/data.pkl", pickle.dumps(Malicious1()))
            self.response = HTTPResponse(200, buffer.getbuffer())
        else:
            raise ValueError(f"No mock for request '{target}'")

    def getresponse(self):
        response = self.response
        self.response = None
        return response

    def close(self):
        pass


http.client.HTTPSConnection = MockHTTPSConnection


def assert_scan(
    filename: str,
    globals: list[Global],
    issues_count: Union[int, None] = None,
    infected_files: int = 1,
):
    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/{filename}"),
        ScanResult(
            globals=globals,
            scanned_files=1,
            issues_count=(issues_count if issues_count is not None else sum(g.safety == SafetyLevel.Dangerous for g in globals)),
            infected_files=infected_files,
        ),
    )


def compare_scan_results(sr1: ScanResult, sr2: ScanResult):
    test_case = TestCase()
    assert sr1.scanned_files == sr2.scanned_files
    assert sr1.issues_count == sr2.issues_count
    assert sr1.infected_files == sr2.infected_files
    assert sr1.scan_err == sr2.scan_err
    test_case.assertCountEqual(sr1.globals, sr2.globals)


def test_http_get():
    assert _http_get("https://localhost/mock/200") == b"mock123"

    with pytest.raises(OSError):
        _http_get("https://localhost/mock/400")


def test_list_globals():
    assert _list_globals(io.BytesIO(pickle.dumps(Malicious1()))) == {("builtins", "eval")}


def test_scan_pickle_bytes():
    assert scan_pickle_bytes(io.BytesIO(pickle.dumps(Malicious1())), "file.pkl") == ScanResult(
        [Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )


def test_scan_pickle_bytes_strict():
    data = io.BytesIO(pickle.dumps(Suspicious()))

    assert scan_pickle_bytes(data, "file.pkl") == ScanResult([Global("collections", "Counter", SafetyLevel.Suspicious)], 1, 0, 0, False, 1)

    data.seek(0)
    assert scan_pickle_bytes(data, "file.pkl", strict=True) == ScanResult(
        [Global("collections", "Counter", SafetyLevel.Dangerous)], 1, 1, 1
    )


def test_build_scan_result_suspicious_count():
    # A single suspicious global is counted as suspicious, not dangerous
    result = _build_scan_result_from_raw_globals({("collections", "Counter")}, "file.pkl")
    assert result == ScanResult(
        [Global("collections", "Counter", SafetyLevel.Suspicious)],
        1,
        0,
        0,
        False,
        1,
    )
    assert result.suspicious_count == 1
    assert result.issues_count == 0
    assert result.infected_files == 0


def test_build_scan_result_multiple_suspicious():
    # Multiple suspicious globals each increment suspicious_count
    result = _build_scan_result_from_raw_globals(
        {("collections", "Counter"), ("mymodule", "myfunc")},
        "file.pkl",
    )
    assert result.suspicious_count == 2
    assert result.issues_count == 0
    assert result.infected_files == 0
    assert all(g.safety == SafetyLevel.Suspicious for g in result.globals)


def test_build_scan_result_dangerous_not_suspicious():
    # Dangerous globals must not be counted as suspicious
    result = _build_scan_result_from_raw_globals({("builtins", "eval")}, "file.pkl")
    assert result.suspicious_count == 0
    assert result.issues_count == 1
    assert result.infected_files == 1


def test_build_scan_result_innocuous_not_suspicious():
    # Innocuous (safe-listed) globals must not be counted as suspicious
    result = _build_scan_result_from_raw_globals({("collections", "OrderedDict")}, "file.pkl")
    assert result.suspicious_count == 0
    assert result.issues_count == 0
    assert result.globals[0].safety == SafetyLevel.Innocuous


def test_build_scan_result_strict_no_suspicious():
    # In strict mode suspicious globals are promoted to dangerous, so suspicious_count stays 0
    result = _build_scan_result_from_raw_globals({("collections", "Counter")}, "file.pkl", strict=True)
    assert result.suspicious_count == 0
    assert result.issues_count == 1
    assert result.globals[0].safety == SafetyLevel.Dangerous


def test_build_scan_result_mixed_globals():
    # Mix of dangerous, suspicious and innocuous globals reports independent counts
    result = _build_scan_result_from_raw_globals(
        {
            ("builtins", "eval"),
            ("collections", "Counter"),
            ("collections", "OrderedDict"),
        },
        "file.pkl",
    )
    assert result.suspicious_count == 1
    assert result.issues_count == 1
    assert result.infected_files == 1


def test_unsafe_globals_entries_are_wildcard_or_collection():
    # Regression guard for the whole class of bug fixed here: a bare string value makes
    # `g.name in unsafe_filter` a SUBSTRING match rather than an equality check, so any
    # global whose name is a substring of the entry gets flagged Dangerous. Every value
    # must be either the "*" wildcard or a collection of exact names.
    for module, names in _unsafe_globals.items():
        if names == "*":
            continue
        assert not isinstance(
            names, str
        ), f"_unsafe_globals['{module}'] is the bare string {names!r}, wrap it in a set to avoid substring matching: {{{names!r}}}"
        assert all(isinstance(n, str) for n in names), f"_unsafe_globals['{module}'] must contain only strings"


def test_unsafe_globals_exact_name_match_only():
    # Names that are substrings of a block-listed name must NOT be flagged. picklescan
    # runs in the Hugging Face Hub pipeline, so an over-broad match flags real models.
    for module, name in [
        ("functools", "art"),
        ("functools", "a"),
        ("functools", "partia"),
        ("torch.serialization", "oa"),
        ("torch.serialization", "loa"),
        ("torch._inductor.codecache", "compile"),
        ("torch._inductor.codecache", "file"),
    ]:
        result = _build_scan_result_from_raw_globals({(module, name)}, "file.pkl")
        assert result.globals[0].safety != SafetyLevel.Dangerous, f"{module}.{name} must not be flagged Dangerous"
        assert result.issues_count == 0


def test_unsafe_globals_still_flag_exact_names():
    # The fix must not weaken detection: the real block-listed names stay Dangerous.
    for module, name in [
        ("functools", "partial"),
        ("torch.serialization", "load"),
        ("torch._inductor.codecache", "compile_file"),
    ]:
        result = _build_scan_result_from_raw_globals({(module, name)}, "file.pkl")
        assert result.globals[0].safety == SafetyLevel.Dangerous, f"{module}.{name} must be flagged Dangerous"
        assert result.issues_count == 1


def test_scan_result_merge_suspicious_count():
    # merge() accumulates suspicious_count across results
    sr1 = _build_scan_result_from_raw_globals({("collections", "Counter")}, "a.pkl")
    sr2 = _build_scan_result_from_raw_globals({("mymodule", "myfunc")}, "b.pkl")
    sr1.merge(sr2)
    assert sr1.suspicious_count == 2


def test_scan_zip_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zip:
        zip.writestr("data.pkl", pickle.dumps(Malicious1()))

    assert scan_zip_bytes(io.BytesIO(buffer.getbuffer()), "test.zip") == ScanResult(
        [Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )


def test_scan_numpy():
    with open(f"{_root_path}/data2/object_array.npy", "rb") as f:
        compare_scan_results(
            scan_numpy(io.BytesIO(f.read()), "object_array.npy"),
            ScanResult(
                [
                    Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
                    Global("numpy", "ndarray", SafetyLevel.Innocuous),
                    Global("numpy", "dtype", SafetyLevel.Innocuous),
                ],
                scanned_files=1,
                issues_count=0,
                infected_files=0,
            ),
        )

    with open(f"{_root_path}/data2/int_array.npy", "rb") as f:
        compare_scan_results(
            scan_numpy(io.BytesIO(f.read()), "int_array.npy"),
            ScanResult(
                [],
                scanned_files=1,
                issues_count=0,
                infected_files=0,
            ),
        )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/dns_exfiltration.npy"),
        ScanResult(
            [
                Global("numpy._core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
                Global("numpy", "ndarray", SafetyLevel.Innocuous),
                Global("numpy", "dtype", SafetyLevel.Innocuous),
                Global("ssl", "get_server_certificate", SafetyLevel.Dangerous),
            ],
            scanned_files=1,
            issues_count=1,
            infected_files=1,
        ),
    )


def test_scan_pytorch():
    scan_result = ScanResult(
        [
            Global("torch", "FloatStorage", SafetyLevel.Innocuous),
            Global("collections", "OrderedDict", SafetyLevel.Innocuous),
            Global("torch._utils", "_rebuild_tensor_v2", SafetyLevel.Innocuous),
        ],
        1,
        0,
        0,
    )
    with open(f"{_root_path}/data/pytorch_model.bin", "rb") as f:
        compare_scan_results(scan_pytorch(io.BytesIO(f.read()), "pytorch_model.bin"), scan_result)
    with open(f"{_root_path}/data/new_pytorch_model.bin", "rb") as f:
        compare_scan_results(scan_pytorch(io.BytesIO(f.read()), "pytorch_model.bin"), scan_result)

    # Legacy PyTorch file with magic number bypass via eval/__reduce__
    # The magic number is produced dynamically via eval('0x1950A86A20F9469CFC6C')
    # instead of a literal INT/LONG, bypassing get_magic_number().
    # The scanner should detect both the eval in the magic pickle and the
    # os.system in the malicious payload pickle.
    magic_bypass_result = ScanResult(
        [
            Global("__builtin__", "eval", SafetyLevel.Dangerous),
            Global("posix", "system", SafetyLevel.Dangerous),
        ],
        1,
        2,
        1,
    )
    with open(f"{_root_path}/data/pytorch_magic_bypass.pt", "rb") as f:
        compare_scan_results(
            scan_pytorch(io.BytesIO(f.read()), "pytorch_magic_bypass.pt"),
            magic_bypass_result,
        )


def test_scan_file_path():
    safe = ScanResult([], 1, 0, 0)
    compare_scan_results(scan_file_path(f"{_root_path}/data/benign0_v3.pkl"), safe)

    pytorch = ScanResult(
        [
            Global("torch", "FloatStorage", SafetyLevel.Innocuous),
            Global("collections", "OrderedDict", SafetyLevel.Innocuous),
            Global("torch._utils", "_rebuild_tensor_v2", SafetyLevel.Innocuous),
        ],
        1,
        0,
        0,
    )
    compare_scan_results(scan_file_path(f"{_root_path}/data/pytorch_model.bin"), pytorch)

    malicious0 = ScanResult(
        [
            Global("__builtin__", "compile", SafetyLevel.Dangerous),
            Global("__builtin__", "globals", SafetyLevel.Suspicious),
            Global("__builtin__", "dict", SafetyLevel.Suspicious),
            Global("__builtin__", "apply", SafetyLevel.Dangerous),
            Global("__builtin__", "getattr", SafetyLevel.Dangerous),
            Global("__builtin__", "eval", SafetyLevel.Dangerous),
        ],
        1,
        4,
        1,
    )
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious0.pkl"), malicious0)

    malicious1_v0 = ScanResult([Global("__builtin__", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_v0.pkl"), malicious1_v0)

    malicious1 = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_v3.pkl"), malicious1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_v4.pkl"), malicious1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1.zip"), malicious1)
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_central_directory.zip"),
        malicious1,
    )
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_0x1.zip"), malicious1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_0x20.zip"), malicious1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_0x40.zip"), malicious1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1.7z"), malicious1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious1_wrong_ext.zip"), malicious1)

    malicious2 = ScanResult([Global("posix", "system", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious2_v0.pkl"), malicious2)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious2_v3.pkl"), malicious2)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious2_v4.pkl"), malicious2)

    malicious3 = ScanResult([Global("httplib", "HTTPSConnection", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious3.pkl"), malicious3)

    malicious4 = ScanResult([Global("requests.api", "get", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious4.pickle"), malicious4)

    malicious5 = ScanResult([Global("aiohttp.client", "ClientSession", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious5.pickle"), malicious5)

    malicious6 = ScanResult([Global("requests.api", "get", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious6.pkl"), malicious6)

    malicious7 = ScanResult([Global("socket", "create_connection", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious7.pkl"), malicious7)

    malicious8 = ScanResult([Global("subprocess", "run", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious8.pkl"), malicious8)

    malicious9 = ScanResult([Global("sys", "exit", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious9.pkl"), malicious9)

    malicious10 = ScanResult([Global("__builtin__", "exec", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious10.pkl"), malicious10)

    # bad_pytorch.pt is a PNG file with .pt extension - scanner should recognize it's not a valid pickle
    # and report it as scanned (scanned_files=1) but without errors (scan_err=False) since no threats were found
    bad_pytorch = ScanResult([], 1, 0, 0, False)
    compare_scan_results(scan_file_path(f"{_root_path}/data/bad_pytorch.pt"), bad_pytorch)

    # Legacy PyTorch file with magic number bypass via eval/__reduce__
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/pytorch_magic_bypass.pt"),
        ScanResult(
            [
                Global("__builtin__", "eval", SafetyLevel.Dangerous),
                Global("posix", "system", SafetyLevel.Dangerous),
            ],
            1,
            2,
            1,
        ),
    )

    malicious14 = ScanResult([Global("runpy", "_run_code", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_file_path(f"{_root_path}/data/malicious14.pkl"), malicious14)

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/malicious21.pkl"),
        ScanResult(
            [
                Global("timeit", "timeit", SafetyLevel.Dangerous),
            ],
            scanned_files=1,
            issues_count=1,
            infected_files=1,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/malicious22.pkl"),
        ScanResult(
            [
                Global("numpy.testing._private.utils", "runstring", SafetyLevel.Dangerous),
            ],
            scanned_files=1,
            issues_count=1,
            infected_files=1,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/malicious23.pkl"),
        ScanResult(
            [
                Global("os", "system", SafetyLevel.Dangerous),
            ],
            scanned_files=1,
            issues_count=1,
            infected_files=1,
        ),
    )

    assert_scan(
        "GHSA-4r9r-ch6f-vxmx.pkl",
        [Global("torch.utils.bottleneck.__main__", "run_cprofile", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-86cj-95qr-2p4f.pkl",
        [Global("torch._dynamo.guards", "GuardBuilder.get", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-f4x7-rfwp-v3xw.pkl",
        [
            Global(
                "torch.fx.experimental.symbolic_shapes",
                "ShapeEnv.evaluate_guards_expression",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-f745-w6jp-hpxx.pkl",
        [Global("torch.utils.collect_env", "run", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-jhph-76pp-mggw.pkl",
        [
            Global("torch.utils.collect_env", "run", SafetyLevel.Dangerous),
            Global("torch.utils.collect_env", "run_and_read_all", SafetyLevel.Suspicious),
        ],
    )
    assert_scan(
        "GHSA-h3qp-7fh3-f8h4.pkl",
        [
            Global(
                "torch.utils.data.datapipes.utils.decoder",
                "basichandlers",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-vr7h-p6mm-wpmh.pkl",
        [Global("torch.jit.unsupported_tensor_ops", "execWrapper", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-vv6j-3g6g-2pvj.pkl",
        [
            Global(
                "torch.utils._config_module",
                "ConfigModule.load_config",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan("GHSA-5qwp-399c-mjwf.pkl", [Global("trace", "Trace.run", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-g344-hcph-8vgg.pkl",
        [Global("trace", "Trace.runctx", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-x696-vm39-cp64.pkl",
        [Global("profile", "Profile.run", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-6vqj-c2q5-j97w.pkl",
        [Global("profile", "Profile.runctx", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-f54q-57x4-jg88.pkl",
        [Global("lib2to3.pgen2.grammar", "Grammar.loads", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-3vg9-h568-4w9m.pkl",
        [Global("idlelib.debugobj", "ObjectTreeItem.SetText", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-6w4w-5w54-rjvr.pkl",
        [Global("idlelib.autocomplete", "AutoComplete.get_entity", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-7cq8-mj8x-j263.pkl",
        [
            Global(
                "idlelib.autocomplete",
                "AutoComplete.fetch_completions",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-cj3c-v495-4xqh.pkl",
        [Global("code", "InteractiveInterpreter.runcode", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-8r4j-24qv-fmq9.pkl",
        [Global("idlelib.calltip", "Calltip.fetch_tip", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-9xph-j2h6-g47v.pkl",
        [Global("idlelib.calltip", "get_entity", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-4whj-rm5r-c2v8.pkl",
        [
            Global(
                "torch.utils.bottleneck.__main__",
                "run_autograd_prof",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-xp4f-hrf8-rxw7.pkl",
        [Global("ensurepip", "_run_pip", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-p9w7-82w4-7q8m.pkl",
        [
            Global(
                "lib2to3.pgen2.pgen",
                "ParserGenerator.make_label",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-m869-42cg-3xwr.pkl",
        [Global("idlelib.run", "Executive.runcode", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-j343-8v2j-ff7w.pkl",
        [
            Global(
                "idlelib.pyshell",
                "ModifiedInterpreter.runcommand",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-3gf5-cxq9-w223.pkl",
        [Global("idlelib.pyshell", "ModifiedInterpreter.runcode", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-fqq6-7vqf-w3fg.pkl",
        [Global("doctest", "debug_script", SafetyLevel.Dangerous)],
    )
    assert_scan("GHSA-9w88-8rmg-7g2p.pkl", [Global("cProfile", "runctx", SafetyLevel.Dangerous)])
    assert_scan("GHSA-49gj-c84q-6qm9.pkl", [Global("cProfile", "run", SafetyLevel.Dangerous)])
    assert_scan("GHSA-7wx9-6375-f5wh.pkl", [Global("profile", "run", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-q77w-mwjj-7mqx.pkl",
        [
            Global(
                "asyncio.unix_events",
                "_UnixSubprocessTransport._start",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-jgw4-cr84-mqxg.bin",
        [
            Global(
                "asyncio.unix_events",
                "_UnixSubprocessTransport._start",
                SafetyLevel.Dangerous,
            )
        ],
    )
    assert_scan(
        "GHSA-m273-6v24-x4m4.pkl",
        [Global("distutils.file_util", "write_file", SafetyLevel.Dangerous)],
    )
    assert_scan("GHSA-4675-36f9-wf6r.pkl", [Global("ctypes", "CDLL", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-84r2-jw7c-4r5q.pkl",
        [
            Global("pydoc", "locate", SafetyLevel.Dangerous),
            Global("operator", "methodcaller", SafetyLevel.Dangerous),
        ],
    )
    assert_scan("GHSA-vqmv-47xg-9wpr.pkl", [Global("pty", "spawn", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-r8g5-cgf2-4m4m.pkl",
        [Global("numpy.f2py.crackfortran", "getlincoef", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "malicious1_crc.zip",
        [Global("builtins", name="eval", safety=SafetyLevel.Dangerous)],
    )
    assert_scan(
        "keyerror-exploit.pkl",
        [
            Global("os", "system", SafetyLevel.Dangerous),
            Global("unknown", "os", SafetyLevel.Dangerous),
        ],
    )
    assert_scan(
        "type-confusion-exploit.pkl",
        [
            # the memo slot used as module name holds an int: "STACK_GLOBAL requires str", nothing is imported there
            Global("os", "system", SafetyLevel.Dangerous),
        ],
    )
    assert_scan(
        "GHSA-955r-x9j8-7rhh.pkl",
        [
            Global("_operator", "methodcaller", SafetyLevel.Dangerous),
            Global("builtins", "__import__", SafetyLevel.Suspicious),
        ],
    )
    assert_scan(
        "GHSA-46h3-79wf-xr6c.pkl",
        [
            Global("_operator", "attrgetter", SafetyLevel.Dangerous),
            Global("builtins", "__import__", SafetyLevel.Suspicious),
        ],
    )
    assert_scan("io_FileIO.pkl", [Global("_io", "FileIO", SafetyLevel.Dangerous)])
    assert_scan(
        "urllib_request_urlopen.pkl",
        [Global("urllib.request", "urlopen", SafetyLevel.Dangerous)],
    )
    # logging.FileHandler can create arbitrary files on the filesystem
    assert_scan(
        "logging_FileHandler.pkl",
        [Global("logging", "FileHandler", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-vvpj-8cmc-gx39.pkl",
        [Global("pkgutil", "resolve_name", SafetyLevel.Dangerous)],
    )
    # types.CodeType can construct arbitrary code objects for execution
    assert_scan("types_CodeType.pkl", [Global("types", "CodeType", SafetyLevel.Dangerous)])
    # cloudpickle uses _make_function and _builtin_type with CodeType to reconstruct arbitrary callables
    assert_scan(
        "cloudpickle_codeinjection.pkl",
        [
            Global("cloudpickle.cloudpickle", "_function_setstate", SafetyLevel.Dangerous),
            Global("cloudpickle.cloudpickle", "_builtin_type", SafetyLevel.Dangerous),
            Global("cloudpickle.cloudpickle", "_make_function", SafetyLevel.Dangerous),
            Global("cloudpickle.cloudpickle", "_make_cell", SafetyLevel.Dangerous),
            Global("cloudpickle.cloudpickle", "_make_empty_cell", SafetyLevel.Dangerous),
            Global("cloudpickle.cloudpickle", "subimport", SafetyLevel.Dangerous),
        ],
    )
    # GHSA-g38g-8gr9-h9xp: Multiple stdlib modules with direct RCE not in blocklist
    assert_scan(
        "GHSA-g38g-8gr9-h9xp-uuid.pkl",
        [Global("uuid", "_get_command_stdout", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-g38g-8gr9-h9xp-osx-support.pkl",
        [Global("_osx_support", "_read_output", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-g38g-8gr9-h9xp-aix-support.pkl",
        [Global("_aix_support", "_read_cmd_output", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-g38g-8gr9-h9xp-imaplib.pkl",
        [Global("imaplib", "IMAP4_stream", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-g38g-8gr9-h9xp-pyrepl-pager.pkl",
        [Global("_pyrepl.pager", "pipe_pager", SafetyLevel.Dangerous)],
    )
    assert_scan(
        "GHSA-g38g-8gr9-h9xp-test.pkl",
        [Global("test.support.script_helper", "assert_python_ok", SafetyLevel.Dangerous)],
    )


def test_scan_file_path_npz():
    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/object_arrays.npz"),
        ScanResult(
            [
                Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
                Global("numpy", "ndarray", SafetyLevel.Innocuous),
                Global("numpy", "dtype", SafetyLevel.Innocuous),
            ]
            * 2,
            scanned_files=2,
            issues_count=0,
            infected_files=0,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/int_arrays.npz"),
        ScanResult(
            [],
            scanned_files=2,
            issues_count=0,
            infected_files=0,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/object_arrays_compressed.npz"),
        ScanResult(
            [
                Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
                Global("numpy", "ndarray", SafetyLevel.Innocuous),
                Global("numpy", "dtype", SafetyLevel.Innocuous),
            ]
            * 2,
            scanned_files=2,
            issues_count=0,
            infected_files=0,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/int_arrays_compressed.npz"),
        ScanResult(
            [],
            scanned_files=2,
            issues_count=0,
            infected_files=0,
        ),
    )


def test_scan_bytes_content_over_extension():
    """Files whose extension does not match their content are dispatched on magic bytes, not extension (common with mislabeled uploads)."""
    npy_result = ScanResult(
        [
            Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
            Global("numpy", "ndarray", SafetyLevel.Innocuous),
            Global("numpy", "dtype", SafetyLevel.Innocuous),
        ],
        scanned_files=1,
        issues_count=0,
        infected_files=0,
    )
    with open(f"{_root_path}/data2/object_array.npy", "rb") as f:
        npy_bytes = f.read()
    # numpy content wearing a pickle/pytorch/no extension must reach scan_numpy, not crash the pickle parser on \x93 (STACK_GLOBAL)
    for file_ext in (".pkl", ".bin", None):
        compare_scan_results(
            scan_bytes(io.BytesIO(npy_bytes), f"mislabeled{file_ext or ''}", file_ext),
            npy_result,
        )

    # npz (zip) content wearing a .npy extension is scanned as a zip archive
    with open(f"{_root_path}/data2/object_arrays.npz", "rb") as f:
        npz_bytes = f.read()
    npz_result = ScanResult(
        [
            Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
            Global("numpy", "ndarray", SafetyLevel.Innocuous),
            Global("numpy", "dtype", SafetyLevel.Innocuous),
        ]
        * 2,
        scanned_files=2,
        issues_count=0,
        infected_files=0,
    )
    compare_scan_results(scan_bytes(io.BytesIO(npz_bytes), "mislabeled.npy", ".npy"), npz_result)
    # same content handed straight to scan_numpy (e.g. a zip member) routes to the zip scanner instead of raising
    compare_scan_results(scan_numpy(io.BytesIO(npz_bytes), "mislabeled.npy"), npz_result)

    # pickle content wearing a .npy extension is scanned as pickle
    compare_scan_results(
        scan_bytes(io.BytesIO(pickle.dumps(Malicious1())), "mislabeled.npy", ".npy"),
        ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1),
    )


def test_scan_zip_bytes_member_content_over_extension():
    """A zip member with numpy content and a pickle extension is scanned as numpy."""
    with open(f"{_root_path}/data2/object_array.npy", "rb") as f:
        npy_bytes = f.read()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zip:
        zip.writestr("data.pkl", npy_bytes)

    compare_scan_results(
        scan_zip_bytes(io.BytesIO(buffer.getbuffer()), "test.zip"),
        ScanResult(
            [
                Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
                Global("numpy", "ndarray", SafetyLevel.Innocuous),
                Global("numpy", "dtype", SafetyLevel.Innocuous),
            ],
            scanned_files=1,
            issues_count=0,
            infected_files=0,
        ),
    )


def test_scan_file_path_extensionless_pytorch(tmp_path):
    """PyTorch files without an extension are detected by content: zip format via magic bytes, legacy format via its pickled
    serialization magic number, so neither ends up on the generic multi-pickle path with scan_err set."""
    expected = ScanResult(
        [
            Global("torch", "FloatStorage", SafetyLevel.Innocuous),
            Global("collections", "OrderedDict", SafetyLevel.Innocuous),
            Global("torch._utils", "_rebuild_tensor_v2", SafetyLevel.Innocuous),
        ],
        scanned_files=1,
        issues_count=0,
        infected_files=0,
    )
    for fixture in ("pytorch_model.bin", "new_pytorch_model.bin"):
        with open(f"{_root_path}/data/{fixture}", "rb") as f:
            target = tmp_path / f"extensionless_{fixture.split('.')[0]}"
            target.write_bytes(f.read())
        result = scan_file_path(str(target))
        compare_scan_results(result, expected)
        assert result.scan_err is False


def test_stack_global_underflow_does_not_crash():
    # Not a pickle: reported like any other unparsable input (no globals, no error flag), not raised
    result = scan_pickle_bytes(io.BytesIO(b"\x93NUMPY\x01\x00v\x00"), "not_a_pickle")
    compare_scan_results(result, ScanResult([], scanned_files=1, issues_count=0, infected_files=0))


def test_stack_global_underflow_keeps_found_globals():
    # A malformed STACK_GLOBAL appended after a valid malicious pickle must not wipe the findings: pickle.load stops at the first
    # STOP and runs the payload regardless of the trailing bytes
    result = scan_pickle_bytes(io.BytesIO(pickle.dumps(Malicious1()) + b"\x93"), "malicious_with_trailer.pkl")
    compare_scan_results(result, ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1, scan_err=True))


def test_stack_global_underflow_in_valid_pickle_is_flagged_and_scan_continues():
    # The unpickler rejects this first pickle, so it is a scan error, not "not a pickle"; later pickles are still scanned
    malformed = b"\x80\x04\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(malformed), "malformed.pkl"), ScanResult([], 1, 0, 0, scan_err=True))
    compare_scan_results(
        scan_pickle_bytes(io.BytesIO(malformed + pickle.dumps(Malicious1())), "malformed_then_malicious.pkl"),
        ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1, scan_err=True),
    )
    # same within a single pickle: the STACK_GLOBAL after the malformed one is still extracted
    single = b"\x80\x04\x93\x8c\x08builtins\x8c\x04eval\x93."
    compare_scan_results(
        scan_pickle_bytes(io.BytesIO(single), "single.pkl"),
        ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1, scan_err=True),
    )


def test_scan_pickle_bytes_large_arguments_stay_out_of_memory():
    """Weights pickled in-band are huge opcode arguments: scanning must not hold them, nor the list of opcodes, in memory."""
    import tracemalloc

    payload = io.BytesIO(pickle.dumps([b"\x00" * (50 << 20), bytearray(b"\x01" * (50 << 20)), Malicious1()], protocol=5))
    tracemalloc.start()
    try:
        result = scan_pickle_bytes(payload, "weights.pkl")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    compare_scan_results(result, ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1))
    assert peak < 8 << 20, f"peak memory {peak / 2**20:.1f} MiB"


def test_stack_global_operands_that_are_not_strings():
    # "STACK_GLOBAL requires str": bytes (even large ones, which are not kept) or numbers as operands import nothing
    blob = b"B" + (5000).to_bytes(4, "little") + b"x" * 5000
    data = b"\x80\x04" + blob + b"\x94" + b"\x8c\x0bcollections" + b"h\x00" + b"\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(data), "bytes_operand.pkl"), ScanResult([], 1, 0, 0))
    data = b"\x80\x04K\x2a\x94\x8c\x06system" + b"h\x00\x8c\x06system\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(data), "int_operand.pkl"), ScanResult([], 1, 0, 0))
    # ... while operands that could be strings at load time (the result of a call, of an unsafe import) are unknown
    data = b"\x80\x04\x8c\x08builtins\x8c\x03str\x93\x8c\x02os\x85R\x94\x8c\x06system\x93."
    result = scan_pickle_bytes(io.BytesIO(data), "call_operand.pkl")
    assert Global("unknown", "system", SafetyLevel.Dangerous) in result.globals


def test_safe_imports_after_module_attributes_may_have_changed():
    # BUILD on a module replaces its attributes: torch._utils._rebuild_tensor_v2 (a safe import) then returns the string "os"
    data = (
        b"\x80\x04\x8c\x05torch\x8c\x06_utils\x93}\x8c\x12_rebuild_tensor_v2\x8c\x02oss" + b"b0"
        b"\x8c\x0ctorch._utils\x8c\x12_rebuild_tensor_v2\x93\x8c\x06system\x93N\x85R."
    )
    result = scan_pickle_bytes(io.BytesIO(data), "module_override.pkl")
    assert Global("unknown", "system", SafetyLevel.Dangerous) in result.globals
    # same through a call to something else than a safe class or function
    data = (
        b"\x80\x04\x8c\x08builtins\x8c\x07setattr\x93\x8c\x05torch\x8c\x06_utils\x93\x8c\x12_rebuild_tensor_v2\x8c\x02os\x87R0"
        b"\x8c\x0ctorch._utils\x8c\x12_rebuild_tensor_v2\x93\x8c\x06system\x93N\x85R."
    )
    assert Global("unknown", "system", SafetyLevel.Dangerous) in scan_pickle_bytes(io.BytesIO(data), "setattr.pkl").globals


def test_safe_imports_after_items_were_added_to_something_else_than_a_container():
    # SETITEMS on a module calls its __setitem__, APPENDS its extend: arbitrary code, like a call, after which safe imports can
    # return strings
    data = (
        b"\x80\x04\x8c\x08whatever\x8c\x06module\x93(\x8c\x01k\x8c\x01vu0"
        b"\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R\x8c\x06system\x93N\x85R."
    )
    assert Global("unknown", "system", SafetyLevel.Dangerous) in scan_pickle_bytes(io.BytesIO(data), "setitems.pkl").globals
    # items added to actual containers are fine
    data = b"\x80\x04}(\x8c\x01k\x8c\x01vu0\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R\x8c\x06system\x93N\x85R."
    assert Global("unknown", "system", SafetyLevel.Dangerous) not in scan_pickle_bytes(io.BytesIO(data), "dict.pkl").globals


def test_safe_imports_imported_before_attributes_may_have_changed():
    # collections.OrderedDict (a safe class) is kept in the memo, its __new__ replaced through BUILD, then it is called: its result
    # can be a string
    data = (
        b"\x80\x04\x8c\x0bcollections\x8c\x0bOrderedDict\x93\x94N}\x8c\x07__new__\x8c\x08whatever\x8c\x01x\x93s\x86b0"
        b"h\x00\x8c\x02os\x85R\x8c\x06system\x93N\x85R."
    )
    assert Global("unknown", "system", SafetyLevel.Dangerous) in scan_pickle_bytes(io.BytesIO(data), "class_override.pkl").globals


def test_memo_follows_the_unpickler():
    # A PROTO in the middle of a pickle is a no-op for the unpickler: the memo carries on, and MEMOIZE numbers slots after the
    # ones already written. os.system must not read as collections.OrderedDict.
    data = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x9400" b"\x80\x04\x8c\x0bcollections\x94\x8c\x0bOrderedDict\x9400h\x00h\x01\x93N\x85R."
    assert Global("os", "system", SafetyLevel.Dangerous) in scan_pickle_bytes(io.BytesIO(data), "mid_proto.pkl").globals
    # FRAME has no effect on the stack: pickle.dumps can start a frame between a module name and a global name
    data = pickle.dumps(["x" * 65513, OrderedDict()], protocol=4)
    compare_scan_results(
        scan_pickle_bytes(io.BytesIO(data), "framed.pkl"),
        ScanResult([Global("collections", "OrderedDict", SafetyLevel.Innocuous)], 1, 0, 0),
    )


def test_memo_stores_top_of_stack():
    """Memo writes store the value on top of the stack. After a GET or a POP, that is not the previous opcode's argument: resolving
    STACK_GLOBAL operands through the memo must not turn os.system into an innocent-looking name."""
    os_system = Global("os", "system", SafetyLevel.Dangerous)
    # the values pushed by BINGET 0 / BINGET 1 are memoized again, then fetched for STACK_GLOBAL
    after_get = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94h\x00\x94h\x01\x94h\x02h\x03\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(after_get), "after_get.pkl"), ScanResult([os_system], 1, 1, 1))
    # POP leaves 'os' on top of the stack, which MEMOIZE stores
    after_pop = b"\x80\x04\x8c\x02os\x8c\x04junk0\x94\x8c\x06systemh\x00\x8c\x06system\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(after_pop), "after_pop.pkl"), ScanResult([os_system], 1, 1, 1))


def test_joblib_embedded_pickles_keep_their_own_memo():
    """joblib writes object arrays as a complete pickle in the middle of the outer one, read with a fresh Unpickler: the outer
    pickle's memo must not be overwritten by the embedded one's when resolving the outer pickle's imports."""
    for protocol in (2, 3, 4, 5):
        result = scan_file_path(f"{_root_path}/data2/joblib_object_array_p{protocol}.joblib")
        assert result.issues_count == 0, (protocol, result.globals)
        assert all("unknown" not in g.module and "unknown" not in g.name for g in result.globals), (protocol, result.globals)
        assert Global("joblib.numpy_pickle", "NumpyArrayWrapper", SafetyLevel.Suspicious) in result.globals


def _framed(frame: bytes, after: bytes = b"") -> bytes:
    return b"\x80\x04\x95" + len(frame).to_bytes(8, "little") + frame + after


_frame_violation = Global("unknown", "pickle frame boundary violation", SafetyLevel.Dangerous)


def test_frame_boundary_violations_are_dangerous():
    """The C unpickler drops the rest of a frame when an opcode runs past its end, and parses what follows the frame instead:
    pickletools and the C unpickler then see different opcodes. pickle.dumps never writes such pickles."""
    # pickletools sees a string then a BINBYTES swallowing the payload; the C unpickler (on io.BytesIO) sees os.system
    payload = b"\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R."
    after = b"Y" * 12 + b"B" + len(payload).to_bytes(4, "little") + payload + b"."
    hidden_payload = _framed(b"\x8c\x11" + b"X" * 5, after)
    compare_scan_results(
        scan_pickle_bytes(io.BytesIO(hidden_payload), "hidden.pkl"), ScanResult([_frame_violation], 1, 1, 1, scan_err=True)
    )

    # a string read across the end of the frame: reported both as a frame violation and as the import pickletools reads
    straddling = _framed(b"\x8c\x06socket\x94\x8c\x11c", b"reate_connection\x94\x93.")
    result = scan_pickle_bytes(io.BytesIO(straddling), "straddling.pkl")
    assert _frame_violation in result.globals and Global("socket", "create_connection", SafetyLevel.Dangerous) in result.globals
    assert result.scan_err

    # a frame starting inside another one, and STOP before the end of the frame
    nested = _framed(b"\x95" + (1).to_bytes(8, "little") + b"N" + b"N", b".")
    early_stop = _framed(b"N.N.")  # the next pickle.load on the same file starts after the frame, not after the first STOP
    for data in (nested, early_stop):
        result = scan_pickle_bytes(io.BytesIO(data), "frames.pkl")
        assert _frame_violation in result.globals and result.scan_err, data


def test_framed_pickles_from_pickle_dumps_are_not_flagged():
    for protocol in (4, 5):
        # several frames, plus large bytes written outside of frames
        data = pickle.dumps([{"k": i, "s": "x" * 100} for i in range(5000)] + [b"y" * 200_000, OrderedDict(a=1)], protocol=protocol)
        assert data.count(b"\x95") > 2
        compare_scan_results(
            scan_pickle_bytes(io.BytesIO(data), "framed.pkl"),
            ScanResult([Global("collections", "OrderedDict", SafetyLevel.Innocuous)], 1, 0, 0),
        )


def test_scan_file_path_legacy_pytorch_magic_in_pickle_file(tmp_path):
    # The legacy PyTorch magic number is attacker-controlled; it must not downgrade a .pkl file to the capped legacy PyTorch scan,
    # which would stop before the payload hidden after five benign pickles
    blob = pickle.dumps(MAGIC_NUMBER, protocol=2) + b"".join(pickle.dumps(i, protocol=2) for i in range(5)) + pickle.dumps(Malicious1())
    target = tmp_path / "padded.pkl"
    target.write_bytes(blob)
    compare_scan_results(scan_file_path(str(target)), ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1))


def _nested_zip(depth: int, member_name: str = "nested.zip") -> bytes:
    """A malicious pickle wrapped in `depth` zips."""
    data = b""
    for _ in range(depth):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zip:
            if data:
                zip.writestr(member_name, data)
            else:
                zip.writestr("payload.pkl", pickle.dumps(Malicious1()))
        data = buffer.getvalue()
    return data


def test_scan_nested_zip_archives():
    eval_found = [Global("builtins", "eval", SafetyLevel.Dangerous)]
    # The members of an archive are scanned, archives among them are reported as skipped rather than opened
    result = scan_bytes(io.BytesIO(_nested_zip(1)), "nested.zip", ".zip")
    compare_scan_results(result, ScanResult(eval_found, 1, 1, 1))
    result = scan_bytes(io.BytesIO(_nested_zip(3)), "nested.zip", ".zip")
    compare_scan_results(result, ScanResult([], 0, 0, 0))
    assert [s.file_id for s in result.skipped] == ["nested.zip:nested.zip"]
    # A model file (here an .npz) in an archive is opened one level deeper than other archives, model files in model files too
    result = scan_bytes(io.BytesIO(_nested_zip(50, member_name="nested.npy")), "nested.npz", ".npz")
    compare_scan_results(result, ScanResult([], 0, 0, 0))
    assert [s.file_id for s in result.skipped] == ["nested.npz:nested.npy:nested.npy"]
    # Opening more levels is a setting
    compare_scan_results(
        scan_bytes(io.BytesIO(_nested_zip(3)), "nested.zip", ".zip", limits=ScanLimits(max_archive_depth=3)),
        ScanResult(eval_found, 1, 1, 1),
    )
    # Many directory entries pointing at the same member are scanned once (fan-out)
    duplicated = _duplicate_zip_entries(_zip_bytes([("data.pkl", pickle.dumps(Malicious1()))]), 1000)
    compare_scan_results(scan_bytes(io.BytesIO(duplicated), "duplicated.zip", ".zip"), ScanResult(eval_found, 1, 1, 1))


def _duplicate_zip_entries(zip_data: bytes, count: int) -> bytes:
    end = zip_data.rindex(b"PK\x05\x06")
    _, _, _, _, entries, cd_size, cd_offset, _ = struct.unpack("<4sHHHHIIH", zip_data[end : end + 22])
    assert entries == 1
    cd = zip_data[cd_offset : cd_offset + cd_size] * count
    return zip_data[:cd_offset] + cd + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, count, count, len(cd), cd_offset, 0)


def _nested_7z(depth: int) -> bytes:
    """A malicious pickle wrapped in `depth` 7z archives, each inner archive stored under a `.pkl` name."""
    py7zr = pytest.importorskip("py7zr")
    data = pickle.dumps(Malicious1())
    for _ in range(depth):
        buffer = io.BytesIO()
        with py7zr.SevenZipFile(buffer, "w") as archive:
            archive.writestr(data, "nested.pkl")
        data = buffer.getvalue()
    return data


def test_scan_nested_7z_archives():
    eval_found = [Global("builtins", "eval", SafetyLevel.Dangerous)]
    compare_scan_results(scan_bytes(io.BytesIO(_nested_7z(1)), "nested.7z", ".7z"), ScanResult(eval_found, 1, 1, 1))
    result = scan_bytes(io.BytesIO(_nested_7z(3)), "nested.7z", ".7z")
    compare_scan_results(result, ScanResult([], 0, 0, 0))
    assert [s.file_id for s in result.skipped] == ["nested.7z:nested.pkl"]  # findings are reported under the archive's name
    compare_scan_results(
        scan_bytes(io.BytesIO(_nested_7z(3)), "nested.7z", ".7z", limits=ScanLimits(max_archive_depth=3)), ScanResult(eval_found, 1, 1, 1)
    )


def _zip_bytes(members, compression=zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as zip:
        for name, data in members:
            zip.writestr(name, data)
    return buffer.getvalue()


def test_scan_bytes_pickle_zip_polyglots():
    """zipfile finds an archive from its end record and ignores what precedes it, while pickle/numpy/PyTorch loaders read from the
    first byte: when both are present, both must be scanned."""

    def finds_eval(result: ScanResult) -> bool:
        # protocol 0-2 pickles name the builtins module __builtin__
        return result.infected_files == 1 and any(g.name == "eval" and g.safety == SafetyLevel.Dangerous for g in result.globals)

    benign_zip = _zip_bytes([("data.pkl", pickle.dumps({"a": 1}))])
    malicious_zip = _zip_bytes([("data.pkl", pickle.dumps(Malicious1()))])
    with open(f"{_root_path}/data2/object_array.npy", "rb") as f:
        npy_bytes = f.read()

    for ext in (".pkl", ".zip", ".npy", ".pt", None):
        for protocol in (0, 4):  # protocol 0 has no PROTO opcode, so no pickle magic bytes
            # pickle.load / legacy torch.load run the pickle in front of the zip
            assert finds_eval(scan_bytes(io.BytesIO(pickle.dumps(Malicious1(), protocol=protocol) + benign_zip), "polyglot", ext))
            # zipfile-based loaders run the zip behind the pickle
            assert finds_eval(scan_bytes(io.BytesIO(pickle.dumps({"a": 1}, protocol=protocol) + malicious_zip), "polyglot", ext))
        # same behind a NumPy file
        assert finds_eval(scan_bytes(io.BytesIO(npy_bytes + malicious_zip), "polyglot", ext))


def test_scan_bytes_plain_zip_scanned_once():
    compare_scan_results(
        scan_bytes(io.BytesIO(_zip_bytes([("data.pkl", pickle.dumps(Malicious1()))])), "plain.zip", ".zip"),
        ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1),
    )


def _corrupt_crc(zip_data: bytes, member_data: bytes) -> bytes:
    crc = zlib.crc32(member_data).to_bytes(4, "little")
    assert zip_data.count(crc) == 2  # local file header + central directory
    return zip_data.replace(crc, (zlib.crc32(member_data) ^ 0xFFFFFFFF).to_bytes(4, "little"))


def test_scan_bytes_end_record_without_archive():
    # zipfile.is_zipfile only looks for an end record: when no archive can be opened from it, there is nothing a zip loader reads
    end_record = b"PK\x05\x06" + (0).to_bytes(4, "little") + (1).to_bytes(2, "little") * 2 + (46).to_bytes(4, "little") + bytes(6)
    result = scan_bytes(io.BytesIO(pickle.dumps(OrderedDict()) + end_record), "end_record.pkl", ".pkl")
    assert Global("collections", "OrderedDict", SafetyLevel.Innocuous) in result.globals
    assert not any(error.kind is ScanErrorKind.ARCHIVE for error in result.errors)


def test_scan_zip_bytes_corrupt_crc_with_trailing_data():
    """PyTorch ignores zip CRCs and stops unpickling at STOP: a bad CRC and bytes after the pickle must not hide its globals."""
    for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        for trailer, scan_err in ((b"", False), (b"X", True), (b"X" * 100, True)):
            member = pickle.dumps(Malicious1()) + trailer
            zip_data = _corrupt_crc(_zip_bytes([("archive/data.pkl", member)], compression), member)
            compare_scan_results(
                scan_zip_bytes(io.BytesIO(zip_data), "corrupt_crc.zip"),
                ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1, scan_err=scan_err),
            )


def test_relaxed_zipfile_crc_stays_disabled_after_rewind():
    member = b"x" * 100_000
    zip_data = _corrupt_crc(_zip_bytes([("member", member)]), member)
    with RelaxedZipFile(io.BytesIO(zip_data)) as zip, zip.open("member") as file:
        assert file.read() == member
        file.seek(0)  # resets the member: on Python 3.12+ this used to restore the CRC check
        assert file.read() == member


def _error_kinds(result: ScanResult):
    return sorted((e.kind for e in result.errors), key=lambda k: k.value)


def test_errors_are_structured():
    # parse error after an import: the import is reported, and the error says what went wrong
    result = scan_pickle_bytes(io.BytesIO(pickle.dumps(Malicious1()) + b"\xff"), "trailing_garbage.pkl")
    assert result.issues_count == 1 and result.scan_err
    assert _error_kinds(result) == [ScanErrorKind.PARSE]
    assert result.errors[0].file_id == "trailing_garbage.pkl" and "opcode" in result.errors[0].message

    # unreadable zip member: reported instead of only logged
    member = pickle.dumps(list(range(10000)))
    zip_data = bytearray(_zip_bytes([("archive/data.pkl", member)], zipfile.ZIP_DEFLATED))
    zip_data[60:80] = b"\xff" * 20  # corrupt the deflate stream
    result = scan_bytes(io.BytesIO(bytes(zip_data)), "corrupt.zip", ".zip")
    assert _error_kinds(result) == [ScanErrorKind.ARCHIVE]
    assert result.errors[0].file_id == "corrupt.zip:archive/data.pkl"

    # unsupported NumPy format version
    result = scan_bytes(io.BytesIO(b"\x93NUMPY\x09\x00" + b"\x00" * 64), "future.npy", ".npy")
    assert _error_kinds(result) == [ScanErrorKind.UNSUPPORTED]


def test_missing_py7zr_is_an_error_not_an_exception(monkeypatch):
    monkeypatch.setitem(sys.modules, "py7zr", None)
    result = scan_file_path(f"{_root_path}/data/malicious1.7z")
    assert _error_kinds(result) == [ScanErrorKind.MISSING_DEPENDENCY]
    assert result.globals == []


def test_scan_directory_path_isolates_failures(tmp_path, monkeypatch):
    (tmp_path / "a.pkl").write_bytes(pickle.dumps(Malicious1()))
    (tmp_path / "b.pkl").write_bytes(pickle.dumps({"benign": True}))
    original = scanner_module.scan_bytes

    def flaky_scan_bytes(data, file_id, *args, **kwargs):
        if file_id.endswith("b.pkl"):
            raise RuntimeError("boom")
        return original(data, file_id, *args, **kwargs)

    monkeypatch.setattr(scanner_module, "scan_bytes", flaky_scan_bytes)
    result = scan_directory_path(str(tmp_path))
    assert result.issues_count == 1  # a.pkl was still scanned
    assert _error_kinds(result) == [ScanErrorKind.INTERNAL]
    assert result.errors[0].file_id.endswith("b.pkl") and "boom" in result.errors[0].message


_eval_found = Global("builtins", "eval", SafetyLevel.Dangerous)


def _finds_eval(result: ScanResult) -> bool:
    return result.infected_files == 1 and any(g.name == "eval" and g.safety == SafetyLevel.Dangerous for g in result.globals)


def test_compressed_pickles_are_decompressed(tmp_path):
    # joblib.load decompresses by magic bytes
    for compress in ("zlib", "gzip", "bz2", "lzma", "xz"):
        result = scan_file_path(f"{_root_path}/data2/joblib_malicious_{compress}.joblib")
        assert _finds_eval(result) and not result.scan_err, (compress, result)
    # pandas.read_pickle decompresses by extension
    for ext, opener in ((".pkl.gz", gzip.open), (".pkl.bz2", bz2.open), (".pkl.xz", lzma.open)):
        path = tmp_path / f"model{ext}"
        with opener(path, "wb") as f:
            f.write(pickle.dumps(Malicious1()))
        result = scan_file_path(str(path))
        assert _finds_eval(result) and not result.scan_err, (ext, result)


def test_compressed_headers_as_loaders_read_them(tmp_path):
    payload = pickle.dumps(Malicious1())
    # gzip.GzipFile ignores reserved header flags, which zlib rejects
    data = bytearray(gzip.compress(payload))
    data[3] |= 0xE0
    assert _finds_eval(scan_bytes(io.BytesIO(bytes(data)), "model.pkl.gz"))
    # joblib parses the size in its old zlib header with int(), which accepts spaces
    data = b"ZF" + f"{len(payload):#x}".rjust(19).encode() + zlib.compress(payload)
    assert detect_file(io.BytesIO(data)).compression == "zfile"
    assert _finds_eval(scan_bytes(io.BytesIO(data), "model.joblib"))
    # lzma.LZMAFile (pandas, .xz files) reads lzma_alone streams with any valid properties
    compressor = lzma.LZMACompressor(lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "lc": 4, "lp": 0, "pb": 2}])
    data = compressor.compress(payload) + compressor.flush()
    assert data[:1] != b"\x5d"
    assert _finds_eval(scan_bytes(io.BytesIO(data), "model.pkl.xz", ".xz"))
    # zstd streams can start with a skippable frame
    skippable = b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little") + b"skip"
    assert detect_file(io.BytesIO(skippable + b"\x28\xb5\x2f\xfd" + bytes(64))).compression == "zstd"


def test_truncated_compressed_pickles():
    # What precedes a corruption is decompressed, and loaders run it
    for compress in (gzip.compress, bz2.compress, lzma.compress):
        result = scan_bytes(io.BytesIO(compress(pickle.dumps(Malicious1()))[:-8]), "model.pkl.gz")
        assert _finds_eval(result) and _error_kinds(result) == [ScanErrorKind.ARCHIVE], (compress, result)


def test_decompression_through_seeks_is_counted():
    ctx = scanner_module._ScanContext(limits=ScanLimits(max_decompressed_size=1 << 20))
    with scanner_module._counted(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(bytes(4 << 20)))), ctx) as file:
        with pytest.raises(scanner_module._LimitExceeded):
            file.seek(0, io.SEEK_END)
    ctx = scanner_module._ScanContext(limits=ScanLimits(max_decompressed_size=1 << 20))
    with scanner_module._counted(gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(bytes(4 << 20)))), ctx) as file:
        with pytest.raises(scanner_module._LimitExceeded):
            file.seek(2 << 20)


def test_compression_without_decompressor(monkeypatch):
    monkeypatch.setitem(sys.modules, "compression.zstd", None)
    monkeypatch.setitem(sys.modules, "zstandard", None)
    result = scan_bytes(io.BytesIO(b"\x28\xb5\x2f\xfd" + b"\x00" * 64), "model.pkl.zst")
    assert _error_kinds(result) == [ScanErrorKind.MISSING_DEPENDENCY]


def _tar_bytes(members, mode="w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_scan_tar_archives():
    members = [("model/weights.bin", b"\x00" * 1000), ("model/model.pkl", pickle.dumps(Malicious1())), ("README.md", b"# model")]
    for mode, name in (("w", "model.tar"), ("w:gz", "model.tar.gz"), ("w:bz2", "model.tar.bz2"), ("w:xz", "model.tar.xz")):
        result = scan_bytes(io.BytesIO(_tar_bytes(members, mode)), name)
        compare_scan_results(result, ScanResult([_eval_found], 3, 1, 1))
        assert not result.scan_err
    # a tar file starts with the name of its first member, which pickle.load reads as opcodes
    polyglot = _tar_bytes([(pickle.dumps(Malicious1(), protocol=0).decode("latin-1")[:99], b"")])
    assert _finds_eval(scan_bytes(io.BytesIO(polyglot), "polyglot.tar"))


def test_scan_tar_polyglots():
    # A tar archive whose first member name starts like a zip: zip readers fail, tarfile (torch.load, pandas) reads the members
    data = _tar_bytes([("PK\x03\x04" + "x" * 20, b""), ("model.pkl", pickle.dumps(Malicious1()))])
    result = scan_bytes(io.BytesIO(data), "polyglot.tar")
    assert _finds_eval(result)


def test_archive_members_are_all_counted():
    limits = ScanLimits(max_archive_members=5)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for i in range(10):
            info = tarfile.TarInfo(f"dir{i}")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
    assert _error_kinds(scan_bytes(io.BytesIO(buffer.getvalue()), "dirs.tar", limits=limits)) == [ScanErrorKind.LIMIT]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zip:
        for i in range(10):
            zip.writestr(f"dir{i}/", b"")
    assert _error_kinds(scan_bytes(io.BytesIO(buffer.getvalue()), "dirs.zip", limits=limits)) == [ScanErrorKind.LIMIT]


def test_model_zip_members():
    payload = pickle.dumps(Malicious1())
    members = [
        ("archive/data.pkl", pickle.dumps(OrderedDict())),
        ("archive/version", b"3\n"),
        ("archive/data/0", payload),  # raw tensor data: torch.load never unpickles it
        ("archive/code/model.py", b"class Model:\n    pass\n"),  # text: neither
        ("archive/extra/payload.pkl.gz", gzip.compress(payload)),  # a zip with a data.pkl is not only read by torch.load
    ]
    result = scan_bytes(io.BytesIO(_zip_bytes(members)), "model.pt")
    compare_scan_results(result, ScanResult([Global("collections", "OrderedDict", SafetyLevel.Innocuous), _eval_found], 2, 1, 1))
    assert not result.scan_err


def test_scan_limits():
    # decompression budget (data is only decompressed as far as it is parsed: the bomb holds a pickle with a large argument)
    bomb = gzip.compress(pickle.dumps(b"\x00" * (20 << 20)))
    assert len(bomb) < 100_000
    result = scan_bytes(io.BytesIO(bomb), "bomb.gz", limits=ScanLimits(max_decompressed_size=1 << 20))
    assert _error_kinds(result) == [ScanErrorKind.LIMIT]
    # compressed streams inside compressed streams
    layered = gzip.compress(gzip.compress(gzip.compress(pickle.dumps(Malicious1()))))
    result = scan_bytes(io.BytesIO(layered), "layered.gz")
    assert _error_kinds(result) == [ScanErrorKind.LIMIT]
    assert _finds_eval(scan_bytes(io.BytesIO(layered), "layered.gz", limits=ScanLimits(max_compression_layers=3)))
    # number of archive members
    many = _zip_bytes([(f"{i}.txt", b"x") for i in range(20)])
    result = scan_bytes(io.BytesIO(many), "many.zip", limits=ScanLimits(max_archive_members=10))
    assert _error_kinds(result) == [ScanErrorKind.LIMIT]


def test_scan_numpy_without_numpy(monkeypatch):
    monkeypatch.setitem(sys.modules, "numpy", None)
    result = scan_file_path(f"{_root_path}/data2/object_array.npy")
    assert {(g.module, g.name) for g in result.globals} == {
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy", "ndarray"),
        ("numpy", "dtype"),
    }
    compare_scan_results(scan_file_path(f"{_root_path}/data2/int_array.npy"), ScanResult([], 1))
    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/object_arrays_compressed.npz"), scan_file_path(f"{_root_path}/data2/object_arrays.npz")
    )


def test_scan_numpy_unclear_dtype_is_scanned():
    # a dtype description we cannot vouch for is treated as possibly holding objects: the data after the header is scanned
    header = b"{'descr': 'weird', 'fortran_order': False, 'shape': (1,), }"
    header += b" " * (63 - len(header) % 64) + b"\n"
    data = b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + pickle.dumps(Malicious1())
    assert _finds_eval(scan_bytes(io.BytesIO(data), "weird.npy"))


def test_detect_file():
    detected = detect_file(io.BytesIO(pickle.dumps({"a": 1}, protocol=4)), "x.pkl")
    assert (detected.format, detected.pickle_protocol) == (FileFormat.PICKLE, 4)
    detected = detect_file(io.BytesIO(pickle.dumps({"a": 1}, protocol=0)), "x")
    assert (detected.format, detected.pickle_protocol) == (FileFormat.PICKLE, 0)
    assert detect_file(io.BytesIO(b"# not a pickle"), "README.md").format == FileFormat.UNKNOWN
    with open(f"{_root_path}/data/pytorch_model.bin", "rb") as f:
        assert detect_file(f, "pytorch_model.bin").format == FileFormat.PYTORCH_LEGACY
    with open(f"{_root_path}/data/new_pytorch_model.bin", "rb") as f:
        detected = detect_file(f, "new_pytorch_model.bin")
    assert detected.format == FileFormat.PYTORCH_ZIP and [m.format for m in detected.members] == [FileFormat.PICKLE]
    with open(f"{_root_path}/data2/object_arrays.npz", "rb") as f:
        assert [m.format for m in detect_file(f, "a.npz").members] == [FileFormat.NUMPY, FileFormat.NUMPY]
    # a .tar.gz: compressed stream > tar archive > members
    detected = detect_file(io.BytesIO(_tar_bytes([("m.pkl", pickle.dumps(1)), ("inner.zip", _zip_bytes([("x", b"")]))], "w:gz")), "a.tgz")
    assert (detected.format, detected.compression) == (FileFormat.COMPRESSED, "gzip")
    tar = detected.members[0]
    assert tar.format == FileFormat.TAR and [m.format for m in tar.members] == [FileFormat.PICKLE, FileFormat.ZIP]
    assert "nested" in tar.members[1].note and tar.members[1].members == []


def test_parser_resource_bounds():
    """Arguments the parser does not need are neither kept in memory nor, where seeking is free, even read."""
    import tracemalloc

    # a protocol 0 line with no end, megabytes long
    endless_line = io.BytesIO(b"S'" + b"a" * (50 << 20))
    tracemalloc.start()
    try:
        result = scan_pickle_bytes(endless_line, "endless_line.pkl")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    compare_scan_results(result, ScanResult([], 1, 0, 0))
    assert peak < 8 << 20, f"peak memory {peak / 2**20:.1f} MiB"

    # names too long to be kept are unknown, which makes the import dangerous
    long_module = b"\x80\x04X" + (100_000).to_bytes(4, "little") + b"o" * 100_000 + b"\x8c\x06system\x93."
    compare_scan_results(
        scan_pickle_bytes(io.BytesIO(long_module), "long_module.pkl"),
        ScanResult([Global("unknown", "system", SafetyLevel.Dangerous)], 1, 1, 1),
    )
    long_global = b"c" + b"o" * 100_000 + b"\nsystem\n."
    compare_scan_results(
        scan_pickle_bytes(io.BytesIO(long_global), "long_global.pkl"),
        ScanResult([Global("unknown", "unknown", SafetyLevel.Dangerous)], 1, 1, 1),
    )

    # large arguments are skipped by seeking
    class CountingBytesIO(io.BytesIO):
        bytes_read = 0

        def read(self, size=-1):
            data = super().read(size)
            CountingBytesIO.bytes_read += len(data)
            return data

    data = CountingBytesIO(pickle.dumps([b"\x00" * (50 << 20), Malicious1()], protocol=4))
    assert _finds_eval(scan_pickle_bytes(data, "weights.pkl"))
    assert CountingBytesIO.bytes_read < 1 << 20


def test_parser_bounds_edges(monkeypatch):
    cap = scanner_module._max_kept_string_size
    os_system = Global("os", "system", SafetyLevel.Dangerous)
    unknown_system = Global("unknown", "system", SafetyLevel.Dangerous)

    # strings up to the cap are kept, longer ones are unknown
    def stack_global(module: bytes) -> bytes:
        return b"\x80\x04X" + len(module).to_bytes(4, "little") + module + b"\x8c\x06system\x93."

    assert scan_pickle_bytes(io.BytesIO(stack_global(b"os".ljust(cap, b"x"))), "a.pkl").globals[0].module == "os".ljust(cap, "x")
    assert scan_pickle_bytes(io.BytesIO(stack_global(b"os".ljust(cap + 1, b"x"))), "a.pkl").globals == [unknown_system]
    # same for lines
    line = b"c" + b"os".ljust(cap, b"x") + b"\nsystem\n."
    assert scan_pickle_bytes(io.BytesIO(line), "a.pkl").globals[0].module == "os".ljust(cap, "x")
    line = b"c" + b"os".ljust(cap + 1, b"x") + b"\nsystem\n."
    assert scan_pickle_bytes(io.BytesIO(line), "a.pkl").globals == [Global("unknown", "unknown", SafetyLevel.Dangerous)]

    # the unpicklers ignore whitespace around numbers, which can make a line of any length: a padded PUT index still overwrites
    # its slot (here 0, holding a harmless string, with 'os')
    padding = b" " * (1 << 20)
    data = b"(S'builtins'\np0\n0S'os'\np" + padding + b"0" + padding + b"\n0g0\nS'system'\n\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(data), "padded.pkl"), ScanResult([os_system], 1, 1, 1))
    # a PUT to a slot that cannot be told makes every slot unknown
    data = b"(S'builtins'\np0\n0S'os'\np" + b"1" * 100 + b"\n0g0\nS'system'\n\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(data), "lost.pkl"), ScanResult([unknown_system], 1, 1, 1))

    # past the memo budget, what the memo stores is unknown
    monkeypatch.setattr(scanner_module, "_max_memo_string_bytes", 10)
    data = b"\x80\x04\x8c\x0aabcdefghij\x940\x8c\x02os\x940h\x01\x8c\x06system\x93."
    compare_scan_results(scan_pickle_bytes(io.BytesIO(data), "budget.pkl"), ScanResult([unknown_system], 1, 1, 1))
    monkeypatch.setattr(scanner_module, "_max_memo_string_bytes", 12)
    compare_scan_results(scan_pickle_bytes(io.BytesIO(data), "budget.pkl"), ScanResult([os_system], 1, 1, 1))

    # small arguments are read through rather than skipped by seeking
    class SeekCountingBytesIO(io.BytesIO):
        seeks = 0

        def seek(self, *args):
            SeekCountingBytesIO.seeks += 1
            return super().seek(*args)

    data = SeekCountingBytesIO(pickle.dumps([b"\x00" * 10_000] * 100, protocol=4))
    scan_pickle_bytes(data, "small.pkl")
    assert SeekCountingBytesIO.seeks < 5


def test_joblib_array_data_is_skipped():
    """joblib reads numeric array data as raw bytes right after each NumpyArrayWrapper's BUILD: skipped like joblib does, so that
    parsing goes on after it (array data is not opcodes)."""
    wrapper = Global("joblib.numpy_pickle", "NumpyArrayWrapper", SafetyLevel.Suspicious)
    numpy_globals = [Global("numpy", "dtype", SafetyLevel.Innocuous), Global("numpy", "ndarray", SafetyLevel.Innocuous)]
    for name in ("p2", "p3", "p4", "p5", "compressed"):
        result = scan_file_path(f"{_root_path}/data2/joblib_arrays_{name}.joblib")
        assert not result.scan_err, (name, result.errors)
        codecs = [Global("_codecs", "encode", SafetyLevel.Suspicious)] if name == "p2" else []  # protocol 2 bytes
        compare_scan_results(result, ScanResult([wrapper] + numpy_globals + codecs, 1, 0, 0, suspicious_count=1 + len(codecs)))
    result = scan_file_path(f"{_root_path}/data2/joblib_arrays_then_malicious.joblib")
    assert _finds_eval(result) and not result.scan_err, result


def test_joblib_array_of_unknown_size_is_an_error():
    # A NumpyArrayWrapper whose state cannot be told: joblib would read array data of a size we don't know, so we stop rather
    # than parse that data as opcodes
    wrapper = b"\x8c\x13joblib.numpy_pickle\x8c\x11NumpyArrayWrapper\x93)\x81"
    state = b"}(\x8c\x05shape\x8c\x07unknown\x8c\x05dtype\x8c\x03?!?u"  # shape is a string
    data = b"\x80\x04" + wrapper + state + b"b" + b"\x00" * 64 + pickle.dumps(Malicious1())
    result = scan_pickle_bytes(io.BytesIO(data), "unknown_size.joblib")
    assert _error_kinds(result) == [ScanErrorKind.PARSE] and "joblib" in result.errors[0].message


def _u(text: str) -> bytes:
    return b"\x8c" + bytes([len(text)]) + text.encode()


_float32_dtype = (
    _u("numpy")
    + _u("dtype")
    + b"\x93"
    + _u("f4")
    + b"\x89\x88\x87R"  # numpy.dtype("f4", False, True)
    + b"(K\x03"
    + _u("<")
    + b"NNNJ\xff\xff\xff\xffJ\xff\xff\xff\xffK\x00tb"  # its state, set by BUILD
)
_wrapper_class = _u("joblib.numpy_pickle") + _u("NumpyArrayWrapper") + b"\x93"
_wrapper_state = b"}(" + _u("shape") + b"K\x04\x85" + _u("dtype") + _float32_dtype + b"ub"  # BUILD: joblib reads 4 float32 here
_eval_call = _u("builtins") + _u("eval") + b"\x93" + _u("1") + b"\x85R"


def test_joblib_tracking_follows_object_creation():
    # created through copyreg.__newobj__ rather than NEWOBJ: the 16 bytes of array data are still skipped (they would not parse)
    via_newobj = _u("copyreg") + _u("__newobj__") + b"\x93" + _wrapper_class + b"\x85R"
    data = b"\x80\x04" + via_newobj + _wrapper_state + b"\xff" * 16 + b"0" + _eval_call + b"."
    result = scan_pickle_bytes(io.BytesIO(data), "newobj.joblib")
    assert _finds_eval(result) and not result.scan_err, result

    # a subclass of the wrapper created while unpickling would make joblib read array data too: it cannot be told apart, so it is
    # an error rather than a guess
    subclass = _u("builtins") + _u("type") + b"\x93" + _u("X") + _wrapper_class + b"\x85}\x87R"  # type("X", (wrapper,), {})
    data = b"\x80\x04" + subclass + b")\x81" + _wrapper_state + b"\xff" * 16 + b"0" + _eval_call + b"."
    result = scan_pickle_bytes(io.BytesIO(data), "subclass.joblib")
    assert _error_kinds(result) == [ScanErrorKind.PARSE] and "used otherwise" in result.errors[0].message


def test_joblib_tracking_resists_crafted_structures():
    # keys made of deeply nested tuples are never hashed (CPython's tuple hash recurses without limit)
    nested = b"N" + b"\x85" * 200_000
    data = b"\x80\x04" + _wrapper_class + b"0}" + nested + b"Ns" + b"0" + _eval_call + b"."
    result = scan_pickle_bytes(io.BytesIO(data), "nested.joblib")
    assert _finds_eval(result), result
    # a dtype whose field refers to itself, through the memo: fields are not looked into (numpy takes the size from the state)
    cyclic_dtype = _u("numpy") + _u("dtype") + b"\x93" + _u("V4") + b"\x89\x88\x87R\x94"  # memo 1 (memo 0: the wrapper class)
    cyclic_state = b"(K\x03" + _u("|") + b"NN}" + _u("a") + b"h\x01K\x00\x86sK\x04K\x01K\x00tb"  # fields: {"a": (itself, 0)}
    state = b"}(" + _u("shape") + b"K\x01\x85" + _u("dtype") + cyclic_dtype + cyclic_state + b"ub"
    data = b"\x80\x04" + _wrapper_class + b"\x94)\x81" + state + b"\x00" * 4 + b"0" + _eval_call + b"."
    result = scan_pickle_bytes(io.BytesIO(data), "cyclic.joblib")
    assert _finds_eval(result) and not result.scan_err, result


def _joblib_error(data: bytes) -> str:
    result = scan_pickle_bytes(io.BytesIO(b"\x80\x04" + data + b"0" + _eval_call + b"."), "crafted.joblib")
    assert _error_kinds(result) == [ScanErrorKind.PARSE], result
    return result.errors[0].message


def test_joblib_wrappers_are_only_recognized_as_joblib_writes_them():
    data_16 = b"\xff" * 16
    # created otherwise than through NEWOBJ or copyreg: calling the class, or giving it to another function
    assert "used otherwise" in _joblib_error(_wrapper_class + b"(NNNNtR" + _wrapper_state + data_16)
    object_new = _u("builtins") + _u("object.__new__") + b"\x93"
    assert "used otherwise" in _joblib_error(object_new + _wrapper_class + b"\x85R" + _wrapper_state + data_16)
    # an attribute of the class
    wrapper_new = _u("joblib.numpy_pickle") + _u("NumpyArrayWrapper.__new__") + b"\x93"
    assert "used otherwise" in _joblib_error(wrapper_new + _wrapper_class + b"\x85R" + _wrapper_state + data_16)
    # the class or an instance kept in a container
    assert "used otherwise" in _joblib_error(b"]" + _wrapper_class + b"a")
    assert "used otherwise" in _joblib_error(b"]" + _wrapper_class + b")\x81a")
    # given state twice (the second time, through the memo)
    twice = _wrapper_class + b")\x81\x94" + _wrapper_state + data_16 + b"0h\x00" + _wrapper_state
    assert "twice" in _joblib_error(twice + data_16)
    # state joblib does not write: unknown keys, slot state, a shape too large for joblib's 64-bit sizes
    unknown_key = b"}(" + _u("shape") + b"K\x04\x85" + _u("dtype") + _float32_dtype + _u("other") + b"Nub"
    assert "known keys" in _joblib_error(_wrapper_class + b")\x81" + unknown_key + data_16)
    slot_state = b"N" + _wrapper_state[:-1] + b"\x86b"
    assert "known keys" in _joblib_error(_wrapper_class + b")\x81" + slot_state + data_16)
    huge = b"}(" + _u("shape") + b"\x8a\x05\x00\x00\x00\x00\x01\x8a\x05\x00\x00\x00\x00\x01\x86" + _u("dtype") + _float32_dtype + b"ub"
    assert "overflows" in _joblib_error(_wrapper_class + b")\x81" + huge)
    # state given to joblib's module or class: what joblib reads then depends on it
    module_state = _u("joblib") + _u("numpy_pickle") + b"\x93N}" + _u("NumpyArrayWrapper") + b"N" + b"s\x86b0"
    assert "class or a module" in _joblib_error(_wrapper_class + b"0" + module_state)
    # a class known only from a call: it could be the wrapper class
    getattr_class = _u("builtins") + _u("getattr") + b"\x93" + _u("x") + _u("y") + b"\x86R"
    assert "not known statically" in _joblib_error(_wrapper_class + b"0" + getattr_class + b")\x81" + _wrapper_state + data_16)


def test_joblib_array_data_is_also_read_as_opcodes():
    # pickle.load reads the array data joblib skips as opcodes: what it imports there is reported when dangerous
    data = b"\x80\x04" + _wrapper_class + b")\x81" + _wrapper_state + b"cos\nsystem\n0" + b"\x00" * 4 + b"0."
    result = scan_pickle_bytes(io.BytesIO(data), "both.joblib")
    assert Global("os", "system", SafetyLevel.Dangerous) in result.globals and not result.scan_err, result


def test_findings_and_errors_have_locations(tmp_path):
    inner = _zip_bytes([("deep.pkl", pickle.dumps(Malicious1()))])
    outer = _zip_bytes([("model/payload.pkl", pickle.dumps(Malicious1()) + b"\xff"), ("inner.zip", inner)])
    result = scan_bytes(io.BytesIO(outer), "model.zip", limits=ScanLimits(max_archive_depth=2))
    locations = sorted(g.location.describe() for g in result.globals)
    assert locations == ["model.zip (inner.zip > deep.pkl)", "model.zip (model/payload.pkl)"]
    (error,) = result.errors
    assert error.location == Location("model.zip", ("model/payload.pkl",)) and error.file_id == "model.zip:model/payload.pkl"
    assert error.offset == len(pickle.dumps(Malicious1()))
    assert error.format().splitlines() == [
        f"error[parse]: unknown opcode b'\\xff' at position {error.offset}",
        f" --> model.zip (model/payload.pkl), offset {error.offset}",
        "  = note: imports found up to this point are reported; what follows was not scanned",
    ]
    skipped = scan_bytes(io.BytesIO(outer), "model.zip").skipped
    assert [s.format() for s in skipped] == [
        "skipped: zip archive nested in another archive: not opened (ScanLimits.max_archive_depth)\n --> model.zip (inner.zip)"
    ]


def test_pytorch_zip_detection_requires_its_layout():
    # a data.pkl member alone does not make a zip a PyTorch file (whose other members would not be scanned)
    generic = _zip_bytes([("archive/data.pkl", pickle.dumps(1)), ("archive/notes.pkl.gz", gzip.compress(pickle.dumps(Malicious1())))])
    assert detect_file(io.BytesIO(generic), "x.zip").format == FileFormat.ZIP
    assert _finds_eval(scan_bytes(io.BytesIO(generic), "x.zip"))
    with open(f"{_root_path}/data/new_pytorch_model.bin", "rb") as f:
        assert detect_file(f, "x.bin").format == FileFormat.PYTORCH_ZIP


def test_main_module_exit_code():
    import subprocess

    command = [sys.executable, "-m", "picklescan", "-p", f"{_root_path}/data/malicious1_v4.pkl"]
    assert subprocess.run(command, capture_output=True).returncode == 1


def test_scan_directory_path():
    sr = ScanResult(
        globals=[
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("httplib", "HTTPSConnection", SafetyLevel.Dangerous),
            Global("collections", "OrderedDict", SafetyLevel.Innocuous),
            Global("torch._utils", "_rebuild_tensor_v2", SafetyLevel.Innocuous),
            Global("torch", "FloatStorage", SafetyLevel.Innocuous),
            Global("subprocess", "run", SafetyLevel.Dangerous),
            Global("posix", "system", SafetyLevel.Dangerous),
            Global("posix", "system", SafetyLevel.Dangerous),
            Global("requests.api", "get", SafetyLevel.Dangerous),
            Global("posix", "system", SafetyLevel.Dangerous),
            Global("aiohttp.client", "ClientSession", SafetyLevel.Dangerous),
            Global("__builtin__", "eval", SafetyLevel.Dangerous),
            Global("sys", "exit", SafetyLevel.Dangerous),
            Global("__builtin__", "eval", SafetyLevel.Dangerous),
            Global("__builtin__", "compile", SafetyLevel.Dangerous),
            Global("__builtin__", "dict", SafetyLevel.Suspicious),
            Global("__builtin__", "apply", SafetyLevel.Dangerous),
            Global("__builtin__", "getattr", SafetyLevel.Dangerous),
            Global("__builtin__", "getattr", SafetyLevel.Dangerous),
            Global("__builtin__", "globals", SafetyLevel.Suspicious),
            Global("requests.api", "get", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("runpy", "_run_code", SafetyLevel.Dangerous),
            Global("socket", "create_connection", SafetyLevel.Dangerous),
            Global("collections", "OrderedDict", SafetyLevel.Innocuous),
            Global("torch._utils", "_rebuild_tensor_v2", SafetyLevel.Innocuous),
            Global("torch", "FloatStorage", SafetyLevel.Innocuous),
            Global("unknown", "unknown", SafetyLevel.Dangerous),  # sys_module_override_sploit.pkl
            Global("torch._utils", "_rebuild_tensor", SafetyLevel.Suspicious),
            Global("torch", "_utils", SafetyLevel.Suspicious),
            Global("__builtin__", "exec", SafetyLevel.Dangerous),
            Global("os", "system", SafetyLevel.Dangerous),
            Global("os", "system", SafetyLevel.Dangerous),
            Global("operator", "attrgetter", SafetyLevel.Dangerous),
            Global("builtins", "__import__", SafetyLevel.Suspicious),
            Global("pickle", "loads", SafetyLevel.Dangerous),
            Global("_pickle", "loads", SafetyLevel.Dangerous),
            Global("_codecs", "encode", SafetyLevel.Suspicious),
            Global("bdb", "Bdb", SafetyLevel.Dangerous),
            Global("bdb", "Bdb", SafetyLevel.Dangerous),
            Global("bdb", "Bdb.run", SafetyLevel.Dangerous),
            Global("builtins", "exec", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("venv", "create", SafetyLevel.Dangerous),
            Global("torch._inductor.codecache", "compile_file", SafetyLevel.Dangerous),
            Global("pydoc", "pipepager", SafetyLevel.Dangerous),
            Global("torch.serialization", "load", SafetyLevel.Dangerous),
            Global("functools", "partial", SafetyLevel.Dangerous),
            Global("pip", "main", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            # pytorch_magic_bypass.pt: magic number bypass via eval + malicious os.system payload
            Global("__builtin__", "eval", SafetyLevel.Dangerous),
            Global("posix", "system", SafetyLevel.Dangerous),
        ],
        scanned_files=46,  # the member of benign_password_protected.zip is scanned (encrypted, it is not a pickle)
        issues_count=45,
        infected_files=38,
        # scan_err=True because some files (broken_model.pkl, malicious-invalid-bytes.pkl) have partial parsing errors
        scan_err=True,
    )
    compare_scan_results(scan_directory_path(f"{_root_path}/data/"), sr)


def test_http_redirects():
    assert _http_get("https://localhost/mock/redirect/relative") == pickle.dumps(Malicious2())
    with pytest.raises(OSError, match="too many redirections"):
        _http_get("https://localhost/mock/redirect/loop")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_scan_directory_path_skips_special_files(tmp_path):
    (tmp_path / "a.pkl").write_bytes(pickle.dumps(Malicious1()))
    os.mkfifo(tmp_path / "pipe.pkl")  # opening it would block until something writes to it
    (tmp_path / "broken.pkl").symlink_to(tmp_path / "missing")
    compare_scan_results(scan_directory_path(str(tmp_path)), ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1))


def test_scan_zip_bytes_corrupted_after_payload():
    # Loaders reading a member as a stream run what precedes the corruption: it is scanned, and the scan is flagged
    member = pickle.dumps([Malicious1(), bytes(range(256)) * 20_000])
    zip_data = bytearray(_zip_bytes([("data.pkl", member)], zipfile.ZIP_DEFLATED))
    zip_data[len(zip_data) // 2 : len(zip_data) // 2 + 64] = b"\xff" * 64
    result = scan_zip_bytes(io.BytesIO(bytes(zip_data)), "corrupt.zip")
    assert Global("builtins", "eval", SafetyLevel.Dangerous) in result.globals
    assert result.scan_err


def test_scan_url():
    safe = ScanResult([], 1, 0, 0)
    compare_scan_results(scan_url("https://localhost/mock/pickle/benign"), safe)
    compare_scan_results(scan_url("https://localhost/mock/zip/benign"), safe)

    malicious = ScanResult([Global(os.name, "system", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_url("https://localhost/mock/pickle/malicious"), malicious)

    malicious_zip = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_url("https://localhost/mock/zip/malicious"), malicious_zip)


def test_remote_files():
    eval_found = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    # a range answered without the size of the file: the whole file is downloaded
    compare_scan_results(scan_url("https://localhost/mock/unknowntotal/pickle/malicious"), eval_found)
    # an empty file answers range requests with 416
    compare_scan_results(scan_url("https://localhost/mock/empty"), ScanResult([], 1, 0, 0))
    # a range other than the one requested is an error
    with pytest.raises(OSError, match="Content-Range"):
        scan_url("https://localhost/mock/badrange/pickle/malicious")
    # file names are quoted in Hugging Face URLs
    result = scan_huggingface_model("mock/quoted-model")
    assert [g.name for g in result.globals] == ["eval"] and not result.scan_err, result
    # seeking before the start of the file fails like for local files
    with scanner_module._RemoteFile("https://localhost/mock/pickle/benign") as remote:
        with pytest.raises(OSError):
            remote.seek(-100, io.SEEK_END)


def test_scan_huggingface_model():
    eval_sr = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_huggingface_model("ykilcher/totally-harmless-model"), eval_sr)


def test_scan_huggingface_model_by_content():
    _served_bytes.clear()
    result = scan_huggingface_model("mock/sniffing-model")
    evals = [Global("builtins", "eval", SafetyLevel.Dangerous)] * 2 + [Global("__builtin__", "eval", SafetyLevel.Dangerous)]
    compare_scan_results(result, ScanResult(evals, 5, 3, 3))
    # every file is scanned by content, but only what the scan reads is downloaded: not the 20 MB of the safetensors file
    assert set(_served_bytes) == set(_sniffing_repo_files)
    assert _served_bytes["model.safetensors"] <= 2 << 20


def test_scan_directory_path_by_content(tmp_path):
    for name, data in _sniffing_repo_files.items():
        (tmp_path / name).write_bytes(data)
    with open(f"{_root_path}/data2/object_array.npy", "rb") as f:
        (tmp_path / "array.npy").write_bytes(f.read())  # .npy files used to be skipped by directory scans
    (tmp_path / "array_without_extension").write_bytes((tmp_path / "array.npy").read_bytes())
    numpy_globals = [
        Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous),
        Global("numpy", "ndarray", SafetyLevel.Innocuous),
        Global("numpy", "dtype", SafetyLevel.Innocuous),
    ]
    evals = [Global("builtins", "eval", SafetyLevel.Dangerous)] * 2 + [Global("__builtin__", "eval", SafetyLevel.Dangerous)]
    compare_scan_results(scan_directory_path(str(tmp_path)), ScanResult(evals + numpy_globals * 2, 7, 3, 3))


def test_scan_url_reads_only_what_it_needs():
    _served_by_path.clear()
    assert _finds_eval(scan_url("https://localhost/mock/weights/malicious"))
    assert _served_by_path["/mock/weights/malicious"] < 1 << 20  # the 8 MB of in-band weights are skipped, not downloaded
    assert _finds_eval(scan_url("https://localhost/mock/norange/pickle/malicious"))  # no Range support: downloaded in full


def test_text_is_not_reported_as_pickle(tmp_path):
    # Text parses as a few opcodes before failing ("import os" reads as INST importing "mport os"): not a pickle, no error
    (tmp_path / "modeling.py").write_bytes(b"import os\nimport sys\n\nclass Model:\n    pass\n")
    (tmp_path / "LICENSE").write_bytes(b"copyright 2024 someone\nall rights reserved\n")
    result = scan_directory_path(str(tmp_path))
    compare_scan_results(result, ScanResult([], 2, 0, 0))
    # ... while a protocol 0 pickle cut short still is: the unpickler runs what comes before the point where it fails
    (tmp_path / "weights").write_bytes(pickle.dumps(Malicious1(), protocol=0)[:-1] + b"\xff")
    result = scan_directory_path(str(tmp_path))
    assert _finds_eval(result) and _error_kinds(result) == [ScanErrorKind.PARSE]


def test_cli_colors():
    import subprocess

    command = [sys.executable, "-m", "picklescan", "-p", f"{_root_path}/data/malicious1_v4.pkl", "-g"]
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "FORCE_COLOR")}
    colored = subprocess.run(command + ["--color", "always"], capture_output=True, text=True, env=env).stdout
    assert "\x1b[31;1m1\x1b[0m" in colored  # infected files count
    assert "\x1b[31;1mdangerous\x1b[0m" in colored
    # not a terminal (auto), NO_COLOR, or never: plain text
    for extra, extra_env in (([], {}), ([], {"NO_COLOR": "1"}), (["--color", "never"], {})):
        plain = subprocess.run(command + extra, capture_output=True, text=True, env={**env, **extra_env}).stdout
        assert "\x1b[" not in plain and "Infected files: 1" in plain
    forced = subprocess.run(command, capture_output=True, text=True, env={**env, "FORCE_COLOR": "1"}).stdout
    assert "\x1b[" in forced


def test_cli_escapes_what_files_contain(tmp_path):
    import subprocess

    # names from the scanned file can hold escape sequences and newlines: they must not reach the terminal as such
    path = tmp_path / "escapes.pkl"
    path.write_bytes(b"cos\x1b[2J\nsystem\x07\n.")
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "FORCE_COLOR")}
    for color in ("always", "never"):
        command = [sys.executable, "-m", "picklescan", "-p", str(path), "-g", "--color", color]
        output = subprocess.run(command, capture_output=True, text=True, env=env).stdout
        assert "\x1b[2J" not in output and "\\x1b[2J" in output and "\x07" not in output and "\\x07" in output, output
    # dangerous findings are colored from the log record, not from what the message says
    command = [sys.executable, "-m", "picklescan", "-p", f"{_root_path}/data/malicious1_v4.pkl", "--color", "always"]
    output = subprocess.run(command, capture_output=True, text=True, env=env).stdout
    assert output.startswith("\x1b[31m") and "dangerous import" in output.splitlines()[0], output


def test_main():
    argv = sys.argv
    try:
        sys.argv = ["picklescan", "-u", "https://localhost/mock/pickle/benign"]
        assert main() == 0
        importlib.import_module("picklescan.__main__")
    finally:
        sys.argv = argv


def test_pickle_files():
    with open(f"{_root_path}/data/malicious13a.pkl", "rb") as file:
        assert pickle.load(file) == 12345
    with open(f"{_root_path}/data/malicious13b.pkl", "rb") as file:
        assert pickle.load(file) == 12345


def test_invalid_bytes_err():
    malicious_invalid_bytes = ScanResult([Global("os", "system", SafetyLevel.Dangerous)], 1, 1, 1, True)
    with open(f"{_root_path}/data/malicious-invalid-bytes.pkl", "rb") as file:
        compare_scan_results(
            scan_pickle_bytes(file, f"{_root_path}/data/malicious-invalid-bytes.pkl"),
            malicious_invalid_bytes,
        )


def test_not_a_pickle_file():
    """Test scanning a binary file that starts with pickle GLOBAL opcode but has invalid UTF-8.
    This reproduces the 'utf-8' codec can't decode byte error seen with files like vitpose_h_wholebody_data.bin.
    The scanner should handle this gracefully: file is scanned, no threats found, no error.
    """
    # File is not a valid pickle, but scanner should not error - just report no threats
    not_a_pickle = ScanResult([], scanned_files=1, issues_count=0, infected_files=0, scan_err=False)
    compare_scan_results(scan_file_path(f"{_root_path}/data/not_a_pickle.bin"), not_a_pickle)


# ---------------------------------------------------------------------------
# Tests for scan_directory_path with ScanFilter (--include/--exclude support)
# ---------------------------------------------------------------------------


def test_scan_directory_exclude_file():
    """--exclude skips files whose full path matches the regex."""
    # Exclude all .zip files – only .pkl/.pickle/.pt/.bin/.7z remain
    sf = ScanFilter(exclude=[re.compile(r"\.zip$")])
    sr = scan_directory_path(f"{_root_path}/data/", scan_filter=sf)
    # No .zip file should have been scanned
    assert sr.scanned_files > 0
    # The unfiltered scan has 44 scanned files (from test_scan_directory_path);
    # we just verify that some files were dropped.
    unfiltered = scan_directory_path(f"{_root_path}/data/")
    assert sr.scanned_files < unfiltered.scanned_files


def test_scan_directory_include_file():
    """--include restricts scans to files whose path matches the regex."""
    # Only scan benign .pkl files
    sf = ScanFilter(include=[re.compile(r"benign0_v3\.pkl$")])
    sr = scan_directory_path(f"{_root_path}/data/", scan_filter=sf)
    assert sr.scanned_files == 1
    assert sr.issues_count == 0


def test_scan_directory_exclude_wins_over_include():
    """Excludes always take precedence over includes (ClamAV semantics)."""
    sf = ScanFilter(
        include=[re.compile(r"benign0_v3\.pkl$")],
        exclude=[re.compile(r"benign")],
    )
    sr = scan_directory_path(f"{_root_path}/data/", scan_filter=sf)
    assert sr.scanned_files == 0


def test_scan_directory_exclude_dir():
    """--exclude-dir prevents traversal into matching directories."""
    # Scanning the parent tests/ directory but excluding 'data2'
    sf = ScanFilter(exclude_dir=[re.compile(r"data2"), re.compile(r"__pycache__")])
    sr = scan_directory_path(f"{_root_path}/", scan_filter=sf)
    # Should still find files in data/ but none from data2/ (every file is scanned by content, so __pycache__ is excluded too)
    assert sr.scanned_files > 0
    # Compare with an include_dir that only allows data/
    sf2 = ScanFilter(include_dir=[re.compile(r"/data$")])
    sr2 = scan_directory_path(f"{_root_path}/", scan_filter=sf2)
    assert sr2.scanned_files > 0
    # Both should give the same set of scanned files (only data/)
    assert sr.scanned_files == sr2.scanned_files


def test_scan_directory_include_dir():
    """--include-dir restricts which directories are traversed."""
    # Only descend into data2/
    sf = ScanFilter(include_dir=[re.compile(r"data2")])
    sr = scan_directory_path(f"{_root_path}/", scan_filter=sf)
    assert sr.scanned_files > 0

    # Verify data/ files are NOT included by scanning only data/ and comparing
    sf_data_only = ScanFilter(include_dir=[re.compile(r"/data$")])
    sr_data = scan_directory_path(f"{_root_path}/", scan_filter=sf_data_only)
    # data2 results should differ from data-only results
    assert sr.scanned_files != sr_data.scanned_files


def test_scan_directory_multiple_patterns():
    """Multiple patterns of the same kind are combined with logical OR."""
    sf = ScanFilter(
        include=[re.compile(r"benign0_v3\.pkl$"), re.compile(r"benign0_v4\.pkl$")],
    )
    sr = scan_directory_path(f"{_root_path}/data/", scan_filter=sf)
    assert sr.scanned_files == 2
    assert sr.issues_count == 0


def test_scan_directory_no_filter():
    """Passing no filter (None) gives the same result as default behaviour."""
    sr_none = scan_directory_path(f"{_root_path}/data/", scan_filter=None)
    sr_default = scan_directory_path(f"{_root_path}/data/")
    assert sr_none.scanned_files == sr_default.scanned_files
    assert sr_none.issues_count == sr_default.issues_count


def test_scan_directory_empty_filter():
    """An empty ScanFilter (no patterns) behaves like no filter at all."""
    sf = ScanFilter()
    sr = scan_directory_path(f"{_root_path}/data/", scan_filter=sf)
    sr_default = scan_directory_path(f"{_root_path}/data/")
    assert sr.scanned_files == sr_default.scanned_files
