import http.client
import importlib
import io
import os
import pickle
import sys
from typing import Union
from unittest import TestCase

import pytest
import zipfile

from picklescan.cli import main
from picklescan.scanner import (
    Global,
    SafetyLevel,
    ScanResult,
    _http_get,
    _list_globals,
    scan_pickle_bytes,
    scan_zip_bytes,
    scan_directory_path,
    scan_file_path,
    scan_url,
    scan_huggingface_model,
    scan_numpy,
    scan_pytorch,
)

_root_path = os.path.dirname(__file__)


class Malicious1:
    def __reduce__(self):
        return eval, ("print('456')",)


class Malicious2:
    def __reduce__(self):
        return os.system, ("ls -la",)


class HTTPResponse:
    def __init__(self, status, data=None):
        self.status = status
        self.reason = "mock reason"
        self.data = data

    def read(self):
        return self.data


class MockHTTPSConnection:
    def __init__(self, host):
        self.host = host
        self.response = None

    def request(self, method, path_and_query):
        assert self.response is None
        target = f"{method} https://{self.host}{path_and_query}"
        if target == "GET https://localhost/mock/200":
            self.response = HTTPResponse(200, b"mock123")
        elif target == "GET https://localhost/mock/400":
            self.response = HTTPResponse(400)
        elif target == "GET https://localhost/mock/pickle/benign":
            self.response = HTTPResponse(200, pickle.dumps({"a": 0, "b": 1, "c": 2}))
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
            issues_count=issues_count if issues_count is not None else sum(g.safety == SafetyLevel.Dangerous for g in globals),
            infected_files=infected_files,
        ),
    )


def compare_scan_results(sr1: ScanResult, sr2: ScanResult):
    test_case = TestCase()
    assert sr1.scanned_files == sr2.scanned_files
    assert sr1.issues_count == sr2.issues_count
    assert sr1.infected_files == sr2.infected_files
    test_case.assertCountEqual(sr1.globals, sr2.globals)


def test_http_get():
    assert _http_get("https://localhost/mock/200") == b"mock123"

    with pytest.raises(RuntimeError):
        _http_get("https://localhost/mock/400")


def test_list_globals():
    assert _list_globals(io.BytesIO(pickle.dumps(Malicious1()))) == {("builtins", "eval")}


def test_scan_pickle_bytes():
    assert scan_pickle_bytes(io.BytesIO(pickle.dumps(Malicious1())), "file.pkl") == ScanResult(
        [Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )


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
    assert_scan("GHSA-86cj-95qr-2p4f.pkl", [Global("torch._dynamo.guards", "GuardBuilder.get", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-f4x7-rfwp-v3xw.pkl",
        [Global("torch.fx.experimental.symbolic_shapes", "ShapeEnv.evaluate_guards_expression", SafetyLevel.Dangerous)],
    )
    assert_scan("GHSA-f745-w6jp-hpxx.pkl", [Global("torch.utils.collect_env", "run", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-jhph-76pp-mggw.pkl",
        [
            Global("torch.utils.collect_env", "run", SafetyLevel.Dangerous),
            Global("torch.utils.collect_env", "run_and_read_all", SafetyLevel.Suspicious),
        ],
    )
    assert_scan("GHSA-h3qp-7fh3-f8h4.pkl", [Global("torch.utils.data.datapipes.utils.decoder", "basichandlers", SafetyLevel.Dangerous)])
    assert_scan("GHSA-vr7h-p6mm-wpmh.pkl", [Global("torch.jit.unsupported_tensor_ops", "execWrapper", SafetyLevel.Dangerous)])
    assert_scan("GHSA-vv6j-3g6g-2pvj.pkl", [Global("torch.utils._config_module", "ConfigModule.load_config", SafetyLevel.Dangerous)])
    assert_scan("GHSA-5qwp-399c-mjwf.pkl", [Global("trace", "Trace.run", SafetyLevel.Dangerous)])
    assert_scan("GHSA-g344-hcph-8vgg.pkl", [Global("trace", "Trace.runctx", SafetyLevel.Dangerous)])
    assert_scan("GHSA-x696-vm39-cp64.pkl", [Global("profile", "Profile.run", SafetyLevel.Dangerous)])
    assert_scan("GHSA-6vqj-c2q5-j97w.pkl", [Global("profile", "Profile.runctx", SafetyLevel.Dangerous)])
    assert_scan("GHSA-f54q-57x4-jg88.pkl", [Global("lib2to3.pgen2.grammar", "Grammar.loads", SafetyLevel.Dangerous)])
    assert_scan("GHSA-3vg9-h568-4w9m.pkl", [Global("idlelib.debugobj", "ObjectTreeItem.SetText", SafetyLevel.Dangerous)])
    assert_scan("GHSA-6w4w-5w54-rjvr.pkl", [Global("idlelib.autocomplete", "AutoComplete.get_entity", SafetyLevel.Dangerous)])
    assert_scan("GHSA-7cq8-mj8x-j263.pkl", [Global("idlelib.autocomplete", "AutoComplete.fetch_completions", SafetyLevel.Dangerous)])
    assert_scan("GHSA-cj3c-v495-4xqh.pkl", [Global("code", "InteractiveInterpreter.runcode", SafetyLevel.Dangerous)])
    assert_scan("GHSA-8r4j-24qv-fmq9.pkl", [Global("idlelib.calltip", "Calltip.fetch_tip", SafetyLevel.Dangerous)])
    assert_scan("GHSA-9xph-j2h6-g47v.pkl", [Global("idlelib.calltip", "get_entity", SafetyLevel.Dangerous)])
    assert_scan("GHSA-4whj-rm5r-c2v8.pkl", [Global("torch.utils.bottleneck.__main__", "run_autograd_prof", SafetyLevel.Dangerous)])
    assert_scan("GHSA-xp4f-hrf8-rxw7.pkl", [Global("ensurepip", "_run_pip", SafetyLevel.Dangerous)])
    assert_scan("GHSA-p9w7-82w4-7q8m.pkl", [Global("lib2to3.pgen2.pgen", "ParserGenerator.make_label", SafetyLevel.Dangerous)])
    assert_scan("GHSA-m869-42cg-3xwr.pkl", [Global("idlelib.run", "Executive.runcode", SafetyLevel.Dangerous)])
    assert_scan("GHSA-j343-8v2j-ff7w.pkl", [Global("idlelib.pyshell", "ModifiedInterpreter.runcommand", SafetyLevel.Dangerous)])
    assert_scan("GHSA-3gf5-cxq9-w223.pkl", [Global("idlelib.pyshell", "ModifiedInterpreter.runcode", SafetyLevel.Dangerous)])
    assert_scan("GHSA-fqq6-7vqf-w3fg.pkl", [Global("doctest", "debug_script", SafetyLevel.Dangerous)])
    assert_scan("GHSA-9w88-8rmg-7g2p.pkl", [Global("cProfile", "runctx", SafetyLevel.Dangerous)])
    assert_scan("GHSA-49gj-c84q-6qm9.pkl", [Global("cProfile", "run", SafetyLevel.Dangerous)])
    assert_scan("GHSA-q77w-mwjj-7mqx.pkl", [Global("asyncio.unix_events", "_UnixSubprocessTransport._start", SafetyLevel.Dangerous)])
    assert_scan("GHSA-jgw4-cr84-mqxg.bin", [Global("asyncio.unix_events", "_UnixSubprocessTransport._start", SafetyLevel.Dangerous)])
    assert_scan("GHSA-m273-6v24-x4m4.pkl", [Global("distutils.file_util", "write_file", SafetyLevel.Dangerous)])
    assert_scan("GHSA-4675-36f9-wf6r.pkl", [Global("ctypes", "CDLL", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-84r2-jw7c-4r5q.pkl",
        [
            Global("pydoc", "locate", SafetyLevel.Dangerous),
            Global("operator", "methodcaller", SafetyLevel.Dangerous),
        ],
    )
    assert_scan("GHSA-vqmv-47xg-9wpr.pkl", [Global("pty", "spawn", SafetyLevel.Dangerous)])
    assert_scan("GHSA-r8g5-cgf2-4m4m.pkl", [Global("numpy.f2py.crackfortran", "getlincoef", SafetyLevel.Dangerous)])
    assert_scan("malicious1_crc.zip", [Global("builtins", name="eval", safety=SafetyLevel.Dangerous)])
    assert_scan("keyerror-exploit.pkl", [Global("os", "system", SafetyLevel.Dangerous), Global("unknown", "os", SafetyLevel.Dangerous)])
    assert_scan("type-confusion-exploit.pkl", [Global("42", "os", SafetyLevel.Suspicious), Global("os", "system", SafetyLevel.Dangerous)])
    assert_scan(
        "GHSA-955r-x9j8-7rhh.pkl",
        [Global("_operator", "methodcaller", SafetyLevel.Dangerous), Global("builtins", "__import__", SafetyLevel.Suspicious)],
    )
    assert_scan(
        "GHSA-46h3-79wf-xr6c.pkl",
        [Global("_operator", "attrgetter", SafetyLevel.Dangerous), Global("builtins", "__import__", SafetyLevel.Suspicious)],
    )
    assert_scan("io_FileIO.pkl", [Global("_io", "FileIO", SafetyLevel.Dangerous)])
    assert_scan("urllib_request_urlopen.pkl", [Global("urllib.request", "urlopen", SafetyLevel.Dangerous)])
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
            Global("_rebuild_tensor", "unknown", SafetyLevel.Dangerous),
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
        ],
        scanned_files=44,
        issues_count=43,
        infected_files=37,
        # scan_err=True because some files (broken_model.pkl, malicious-invalid-bytes.pkl) have partial parsing errors
        scan_err=True,
    )
    compare_scan_results(scan_directory_path(f"{_root_path}/data/"), sr)


def test_scan_url():
    safe = ScanResult([], 1, 0, 0)
    compare_scan_results(scan_url("https://localhost/mock/pickle/benign"), safe)
    compare_scan_results(scan_url("https://localhost/mock/zip/benign"), safe)

    malicious = ScanResult([Global(os.name, "system", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_url("https://localhost/mock/pickle/malicious"), malicious)

    malicious_zip = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_url("https://localhost/mock/zip/malicious"), malicious_zip)


def test_scan_huggingface_model():
    eval_sr = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_huggingface_model("ykilcher/totally-harmless-model"), eval_sr)


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
