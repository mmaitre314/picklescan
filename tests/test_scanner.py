import aiohttp
import http.client
import importlib
import io
import os
import pickle
import pytest
import requests
import socket
import subprocess
import sys
from unittest import TestCase
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


class Malicious3:
    def __reduce__(self):
        return http.client.HTTPSConnection, ("github.com",)


malicious3_pickle_bytes = pickle.dumps(
    Malicious3(), protocol=0
)  # Malicious3 needs to be pickled before HTTPSConnection is mocked below


class Malicious4:
    def __reduce__(self):
        return requests.get, ("https://github.com",)


class Malicious5:
    def __reduce__(self):
        return aiohttp.ClientSession, tuple()


class Malicious6:
    def __reduce__(self):
        return socket.create_connection, (("github.com", 80),)


class Malicious7:
    def __reduce__(self):
        return subprocess.run, (["ls", "-l"],)


class Malicious8:
    def __reduce__(self):
        return sys.exit, (0,)


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
        elif (
            target
            == "GET https://huggingface.co/api/models/ykilcher/totally-harmless-model"
        ):
            self.response = HTTPResponse(
                200, b'{"siblings": [{"rfilename": "pytorch_model.bin"}]}'
            )
        elif (
            target
            == "GET https://huggingface.co/ykilcher/totally-harmless-model/resolve/main/pytorch_model.bin"
        ):
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


def initialize_pickle_file(path, obj, version):
    if not os.path.exists(path):
        with open(path, "wb") as file:
            pickle.dump(obj, file, protocol=version)


def initialize_data_file(path, data):
    if not os.path.exists(path):
        with open(path, "wb") as file:
            file.write(data)


def initialize_zip_file(path, file_name, data):
    if not os.path.exists(path):
        with zipfile.ZipFile(path, "w") as zip:
            zip.writestr(file_name, data)


def initialize_numpy_file(path):
    import numpy as np

    # create numpy object array
    with open(path, "wb") as f:
        data = [(1, 2), (3, 4)]
        x = np.empty((2, 2), dtype=object)
        x[:] = data
        np.save(f, x)


def initialize_pickle_files():
    os.makedirs(f"{_root_path}/data", exist_ok=True)

    # Test with Pickle versions 0, 3, and 4:
    # - Pickle versions 0, 1, 2 have built-in functions under '__builtin__' while versions 3 and 4 have them under 'builtins'
    # - Pickle versions 0, 1, 2, 3 use 'GLOBAL' opcode while 4 uses 'STACK_GLOBAL' opcode
    for version in (0, 3, 4):
        initialize_pickle_file(
            f"{_root_path}/data/benign0_v{version}.pkl", ["a", "b", "c"], version
        )
        initialize_pickle_file(
            f"{_root_path}/data/malicious1_v{version}.pkl", Malicious1(), version
        )
        initialize_pickle_file(
            f"{_root_path}/data/malicious2_v{version}.pkl", Malicious2(), version
        )

    # Malicious Pickle from https://sensepost.com/cms/resources/conferences/2011/sour_pickles/BH_US_11_Slaviero_Sour_Pickles.pdf
    initialize_data_file(
        f"{_root_path}/data/malicious0.pkl",
        b'c__builtin__\nglobals\n(tRp100\n0c__builtin__\ncompile\n(S\'fl=open("/etc/passwd");picklesmashed=fl.read();'
        + b"'\nS''\nS'exec'\ntRp101\n0c__builtin__\neval\n(g101\ng100\ntRp102\n0c__builtin__\ngetattr\n(c__builtin__\n"
        + b"dict\nS'get'\ntRp103\n0c__builtin__\napply\n(g103\n(g100\nS'picklesmashed'\nltRp104\n0g104\n.",
    )

    initialize_data_file(f"{_root_path}/data/malicious3.pkl", malicious3_pickle_bytes)
    initialize_pickle_file(f"{_root_path}/data/malicious4.pickle", Malicious4(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious5.pickle", Malicious5(), 4)
    initialize_data_file(
        f"{_root_path}/data/malicious6.pkl",
        pickle.dumps(["a", "b", "c"]) + pickle.dumps(Malicious4()),
    )
    initialize_pickle_file(f"{_root_path}/data/malicious7.pkl", Malicious6(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious8.pkl", Malicious7(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious9.pkl", Malicious8(), 4)

    initialize_zip_file(
        f"{_root_path}/data/malicious1.zip",
        "data.pkl",
        pickle.dumps(Malicious1(), protocol=4),
    )

    initialize_numpy_file(f"{_root_path}/data/object_array.npy")

    # Fake PyTorch file (PNG file format) simulating https://huggingface.co/RectalWorm/loras_new/blob/main/Owl_Mage_no_background.pt
    initialize_data_file(f"{_root_path}/data/bad_pytorch.pt", b"\211PNG\r\n\032\n")


initialize_pickle_files()


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
    assert _list_globals(io.BytesIO(pickle.dumps(Malicious1()))) == {
        ("builtins", "eval")
    }


def test_scan_pickle_bytes():
    assert scan_pickle_bytes(
        io.BytesIO(pickle.dumps(Malicious1())), "file.pkl"
    ) == ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)


def test_scan_zip_bytes():

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zip:
        zip.writestr("data.pkl", pickle.dumps(Malicious1()))

    assert scan_zip_bytes(io.BytesIO(buffer.getbuffer()), "test.zip") == ScanResult(
        [Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )


def test_scan_numpy():
    scan_result = ScanResult(
        [
            Global("numpy.core.multiarray", "_reconstruct", SafetyLevel.Suspicious),
            Global("numpy", "ndarray", SafetyLevel.Suspicious),
            Global("numpy", "dtype", SafetyLevel.Suspicious),
        ],
        1,
        0,
        0,
    )
    with open(f"{_root_path}/data/object_array.npy", "rb") as f:
        compare_scan_results(
            scan_numpy(io.BytesIO(f.read()), "object_array.npy"), scan_result
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
        compare_scan_results(
            scan_pytorch(io.BytesIO(f.read()), "pytorch_model.bin"), scan_result
        )
    with open(f"{_root_path}/data/new_pytorch_model.bin", "rb") as f:
        compare_scan_results(
            scan_pytorch(io.BytesIO(f.read()), "pytorch_model.bin"), scan_result
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
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/pytorch_model.bin"), pytorch
    )

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
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious0.pkl"), malicious0
    )

    malicious1_v0 = ScanResult(
        [Global("__builtin__", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_v0.pkl"), malicious1_v0
    )

    malicious1 = ScanResult(
        [Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_v3.pkl"), malicious1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_v4.pkl"), malicious1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1.zip"), malicious1
    )

    malicious2 = ScanResult([Global("posix", "system", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious2_v0.pkl"), malicious2
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious2_v3.pkl"), malicious2
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious2_v4.pkl"), malicious2
    )

    malicious3 = ScanResult(
        [Global("httplib", "HTTPSConnection", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious3.pkl"), malicious3
    )

    malicious4 = ScanResult(
        [Global("requests.api", "get", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious4.pickle"), malicious4
    )

    malicious5 = ScanResult(
        [Global("aiohttp.client", "ClientSession", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious5.pickle"), malicious5
    )

    malicious6 = ScanResult(
        [Global("requests.api", "get", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious6.pkl"), malicious6
    )

    malicious7 = ScanResult(
        [Global("socket", "create_connection", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious7.pkl"), malicious7
    )

    malicious8 = ScanResult(
        [Global("subprocess", "run", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious8.pkl"), malicious8
    )

    malicious9 = ScanResult([Global("sys", "exit", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious9.pkl"), malicious9
    )

    bad_pytorch = ScanResult([], 0, 0, 0, True)
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/bad_pytorch.pt"), bad_pytorch
    )


def test_scan_directory_path():
    sr = ScanResult(
        [
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
            Global("__builtin__", "globals", SafetyLevel.Suspicious),
            Global("requests.api", "get", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("builtins", "eval", SafetyLevel.Dangerous),
            Global("socket", "create_connection", SafetyLevel.Dangerous),
            Global("collections", "OrderedDict", SafetyLevel.Innocuous),
            Global("torch._utils", "_rebuild_tensor_v2", SafetyLevel.Innocuous),
            Global("torch", "FloatStorage", SafetyLevel.Innocuous),
            Global("_rebuild_tensor", "unknown", SafetyLevel.Dangerous),
            Global("torch._utils", "_rebuild_tensor", SafetyLevel.Suspicious),
            Global("torch", "_utils", SafetyLevel.Suspicious),
        ],
        21,
        19,
        16,
    )
    compare_scan_results(scan_directory_path(f"{_root_path}/data/"), sr)


def test_scan_url():
    safe = ScanResult([], 1, 0, 0)
    compare_scan_results(scan_url("https://localhost/mock/pickle/benign"), safe)
    compare_scan_results(scan_url("https://localhost/mock/zip/benign"), safe)

    malicious = ScanResult([Global(os.name, "system", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(scan_url("https://localhost/mock/pickle/malicious"), malicious)

    malicious_zip = ScanResult(
        [Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_url("https://localhost/mock/zip/malicious"), malicious_zip
    )


def test_scan_huggingface_model():
    eval_sr = ScanResult([Global("builtins", "eval", SafetyLevel.Dangerous)], 1, 1, 1)
    compare_scan_results(
        scan_huggingface_model("ykilcher/totally-harmless-model"), eval_sr
    )


def test_main():
    argv = sys.argv
    try:
        sys.argv = ["picklescan", "-u", "https://localhost/mock/pickle/benign"]
        assert main() == 0
        importlib.import_module("picklescan.__main__")
    finally:
        sys.argv = argv
