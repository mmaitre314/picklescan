import aiohttp
import bdb
import http.client
import importlib
import io
import os
import pathlib
import pickle
import pip
import py7zr
import pydoc
import pytest
import requests
import runpy
import socket
import subprocess
import sys
import venv
import zipfile
from functools import partial
from unittest import TestCase

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

try:
    import torch
    import torch._inductor.codecache as codecache
except ImportError:
    # If PyTorch test files need to be regenerated, run 'pip install torch==2.6.0' first
    torch = None
    codecache = None

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


class Malicious13:
    def __reduce__(self):
        return pickle.loads, (b"I12345\n.",)  # Loads the value 12345


class Malicious14:
    def __reduce__(self):
        return runpy._run_code, ("print('456')",)


class Malicious15:
    def __reduce__(self):
        bd = bdb.Bdb()
        return bdb.Bdb.run, (
            bd,
            'import os\nos.system("whoami")',
        )


class Malicious17:
    def __reduce__(self):
        return codecache.compile_file, ("", "", ["sh", "-c", '$(echo "pwned")'])


class Malicious18:
    def __reduce__(self):
        return pydoc.pipepager, ("", 'echo "pwned"')


class Malicious19:
    def __init__(self, path, **kwargs):
        self.path = path
        self.kwargs = kwargs

    def __reduce__(self):
        return partial(torch.load, self.path, **self.kwargs), ()


class Malicious20:
    def __reduce__(self):
        return venv.create, ("venv", False, False, True, False, "$(echo pwned)")


class Malicious16:
    def __reduce__(self):
        return pip.main, (
            [
                "install",
                "some_malicious_package",
                "--no-input",
                "-q",
                "-q",
                "-q",
                "--exists-action",
                "i",
                "--isolated",
            ],
        )


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


def initialize_7z_file(archive_path, file_name):
    file_path = f"{_root_path}/data/malicious1.pkl"
    with open(file_path, "wb") as f:
        pickle.dump(Malicious1(), f, protocol=4)

    if not os.path.exists(archive_path):
        with py7zr.SevenZipFile(archive_path, "w") as archive:
            archive.write(file_path, file_name)

    pathlib.Path.unlink(pathlib.Path(file_path))


def initialize_zip_file(path, file_name, data):
    if not os.path.exists(path):
        with zipfile.ZipFile(path, "w") as zip:
            zip.writestr(file_name, data)


def initialize_corrupt_zip_file_central_directory(path, file_name, data):
    if not os.path.exists(path):
        with zipfile.ZipFile(path, "w") as zip:
            zip.writestr(file_name, data)

        with open(path, "rb") as f:
            data = f.read()

        # Replace only the first occurrence of "data.pkl" with "datap.kl"
        modified_data = data.replace(b"data.pkl", b"datap.kl", 1)

        # Write back the modified content
        with open(path, "wb") as f:
            f.write(modified_data)


def initialize_numpy_files():
    import numpy as np

    os.makedirs(f"{_root_path}/data2", exist_ok=True)

    path = f"{_root_path}/data2/object_array.npy"
    if not os.path.exists(path):
        x = np.empty((2, 2), dtype=object)
        x[:] = [(1, 2), (3, 4)]
        np.save(path, x)

    path = f"{_root_path}/data2/int_array.npy"
    if not os.path.exists(path):
        x = np.empty((2, 2), dtype=int)
        x[:] = [(1, 2), (3, 4)]
        np.save(path, x)

    path = f"{_root_path}/data2/object_arrays.npz"
    if not os.path.exists(path):
        np.savez(
            path,
            a=np.array([0, 1, 2], dtype=object),
            b=np.array([3, 4, 5], dtype=object),
        )

    path = f"{_root_path}/data2/int_arrays.npz"
    if not os.path.exists(path):
        np.savez(
            path, a=np.array([0, 1, 2], dtype=int), b=np.array([3, 4, 5], dtype=int)
        )

    path = f"{_root_path}/data2/object_arrays_compressed.npz"
    if not os.path.exists(path):
        np.savez_compressed(
            path,
            a=np.array([0, 1, 2], dtype=object),
            b=np.array([3, 4, 5], dtype=object),
        )

    path = f"{_root_path}/data2/int_arrays_compressed.npz"
    if not os.path.exists(path):
        np.savez_compressed(
            path, a=np.array([0, 1, 2], dtype=int), b=np.array([3, 4, 5], dtype=int)
        )


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

    # Malicious Pickle with an INST opcode
    #     0: (    MARK
    #     1: S        STRING     'raise RuntimeError("Injection running")'
    #    44: i        INST       '__builtin__ exec' (MARK at 0)
    #    62: .    STOP
    initialize_data_file(
        f"{_root_path}/data/malicious10.pkl",
        b"(S'raise RuntimeError(\"Injection running\")'\ni__builtin__\nexec\n.",
    )

    # Malicious Pickle from Capture-the-Flag challenge 'Misc/Safe Pickle' at https://imaginaryctf.org/Challenges
    # GitHub Issue: https://github.com/mmaitre314/picklescan/issues/22
    initialize_data_file(
        f"{_root_path}/data/malicious11.pkl",
        b"".join(
            [
                pickle.UNICODE + b"os\n",
                pickle.PUT + b"2\n",
                pickle.POP,
                pickle.UNICODE + b"system\n",
                pickle.PUT + b"3\n",
                pickle.POP,
                pickle.UNICODE + b"torch\n",
                pickle.PUT + b"0\n",
                pickle.POP,
                pickle.UNICODE + b"LongStorage\n",
                pickle.PUT + b"1\n",
                pickle.POP,
                pickle.GET + b"2\n",
                pickle.GET + b"3\n",
                pickle.STACK_GLOBAL,
                pickle.MARK,
                pickle.UNICODE + b"cat flag.txt\n",
                pickle.TUPLE,
                pickle.REDUCE,
                pickle.STOP,
            ]
        ),
    )

    initialize_data_file(
        f"{_root_path}/data/malicious-invalid-bytes.pkl",
        b"".join(
            [
                pickle.UNICODE + b"os\n",
                pickle.PUT + b"2\n",
                pickle.POP,
                pickle.UNICODE + b"system\n",
                pickle.PUT + b"3\n",
                pickle.POP,
                pickle.UNICODE + b"torch\n",
                pickle.PUT + b"0\n",
                pickle.POP,
                pickle.UNICODE + b"LongStorage\n",
                pickle.PUT + b"1\n",
                pickle.POP,
                pickle.GET + b"2\n",
                pickle.GET + b"3\n",
                pickle.STACK_GLOBAL,
                pickle.MARK,
                pickle.UNICODE + b"cat flag.txt\n",
                pickle.TUPLE,
                pickle.REDUCE,
                pickle.STOP,
                b"\n\n\t\t",
            ]
        ),
    )

    # Broken model
    initialize_data_file(
        f"{_root_path}/data/broken_model.pkl",
        b"cbuiltins\nexec\n(X>\nf = open('my_file.txt', 'a'); f.write('Malicious'); f.close()tRX.",
    )

    # Code which created malicious12.pkl using pickleassem (see https://github.com/gousaiyang/pickleassem)
    #
    # p = PickleAssembler(proto=4)
    #
    # # get operator.attrgetter onto stack
    # p.push_short_binunicode("operator")
    # p.memo_memoize()
    # p.push_short_binunicode("attrgetter")
    # p.memo_memoize()
    # p.build_stack_global()
    # p.memo_memoize()
    #
    # # get operator.attrgetter("system") onto stack
    # p.push_short_binunicode("system")
    # p.memo_memoize()
    # p.build_tuple1()
    # p.memo_memoize()
    # p.build_reduce()
    # p.memo_memoize()
    #
    # # get os module onto stack
    # p.push_short_binunicode("builtins")
    # p.memo_memoize()
    # p.push_short_binunicode("__import__")
    # p.memo_memoize()
    # p.build_stack_global()
    # p.memo_memoize()
    # p.push_short_binunicode("os")
    # p.memo_memoize()
    # p.build_tuple1()
    # p.memo_memoize()
    # p.build_reduce()
    # p.memo_memoize()
    #
    # # get os.system onto stack
    # p.build_tuple1()
    # p.memo_memoize()
    # p.build_reduce()
    # p.memo_memoize()
    #
    # # call os.system("echo pwned")
    # p.push_short_binunicode("echo pwned")
    # p.memo_memoize()
    # p.build_tuple1()
    # p.memo_memoize()
    # p.build_reduce()
    # p.memo_memoize()

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
    initialize_pickle_file(
        f"{_root_path}/data/malicious13a.pkl", Malicious13(), 0
    )  # pickle module serialized as cpickle
    initialize_pickle_file(
        f"{_root_path}/data/malicious13b.pkl", Malicious13(), 4
    )  # pickle module serialized as _pickle
    initialize_pickle_file(
        f"{_root_path}/data/malicious14.pkl", Malicious14(), 4
    )  # runpy
    initialize_pickle_file(f"{_root_path}/data/malicious15a.pkl", Malicious15(), 2)
    initialize_pickle_file(f"{_root_path}/data/malicious15b.pkl", Malicious15(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious16.pkl", Malicious16(), 0)

    initialize_pickle_file(f"{_root_path}/data/malicious17.pkl", Malicious17(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious18.pkl", Malicious18(), 4)

    # This exploit serializes kwargs and passes them into a torch.load call
    initialize_pickle_file(
        f"{_root_path}/data/malicious19.pkl",
        Malicious19(
            "some_other_model.bin", pickle_file="config.json", weights_only=False
        ),
        4,
    )

    initialize_pickle_file(f"{_root_path}/data/malicious20.pkl", Malicious20(), 4)
    initialize_7z_file(
        f"{_root_path}/data/malicious1.7z",
        "data.pkl",
    )

    initialize_zip_file(
        f"{_root_path}/data/malicious1.zip",
        "data.pkl",
        pickle.dumps(Malicious1(), protocol=4),
    )

    initialize_corrupt_zip_file_central_directory(
        f"{_root_path}/data/malicious1_central_directory.zip",
        "data.pkl",
        pickle.dumps(Malicious1(), protocol=4),
    )

    initialize_zip_file(
        f"{_root_path}/data/malicious1_wrong_ext.zip",
        "data.txt",  # Pickle file with a non-standard extension
        pickle.dumps(Malicious1(), protocol=4),
    )

    # Fake PyTorch file (PNG file format) simulating https://huggingface.co/RectalWorm/loras_new/blob/main/Owl_Mage_no_background.pt
    initialize_data_file(f"{_root_path}/data/bad_pytorch.pt", b"\211PNG\r\n\032\n")


initialize_pickle_files()
initialize_numpy_files()


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
    with open(f"{_root_path}/data2/object_array.npy", "rb") as f:
        compare_scan_results(
            scan_numpy(io.BytesIO(f.read()), "object_array.npy"),
            ScanResult(
                [
                    Global(
                        "numpy.core.multiarray", "_reconstruct", SafetyLevel.Innocuous
                    ),
                    Global("numpy", "ndarray", SafetyLevel.Innocuous),
                    Global("numpy", "dtype", SafetyLevel.Innocuous),
                ],
                1,
                0,
                0,
            ),
        )

    with open(f"{_root_path}/data2/int_array.npy", "rb") as f:
        compare_scan_results(
            scan_numpy(io.BytesIO(f.read()), "int_array.npy"),
            ScanResult(
                [],
                1,
                0,
                0,
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
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_central_directory.zip"),
        malicious1,
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_0x1.zip"), malicious1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_0x20.zip"), malicious1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_0x40.zip"), malicious1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1.7z"), malicious1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious1_wrong_ext.zip"), malicious1
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

    malicious10 = ScanResult(
        [Global("__builtin__", "exec", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious10.pkl"), malicious10
    )

    bad_pytorch = ScanResult([], 0, 0, 0, True)
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/bad_pytorch.pt"), bad_pytorch
    )

    malicious14 = ScanResult(
        [Global("runpy", "_run_code", SafetyLevel.Dangerous)], 1, 1, 1
    )
    compare_scan_results(
        scan_file_path(f"{_root_path}/data/malicious14.pkl"), malicious14
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
            2,
            0,
            0,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/int_arrays.npz"),
        ScanResult(
            [],
            2,
            0,
            0,
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
            2,
            0,
            0,
        ),
    )

    compare_scan_results(
        scan_file_path(f"{_root_path}/data2/int_arrays_compressed.npz"),
        ScanResult(
            [],
            2,
            0,
            0,
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
        ],
        scanned_files=38,
        issues_count=39,
        infected_files=33,
        scan_err=True,
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


def test_pickle_files():
    with open(f"{_root_path}/data/malicious13a.pkl", "rb") as file:
        assert pickle.load(file) == 12345
    with open(f"{_root_path}/data/malicious13b.pkl", "rb") as file:
        assert pickle.load(file) == 12345


def test_invalid_bytes_err():
    malicious_invalid_bytes = ScanResult(
        [Global("os", "system", SafetyLevel.Dangerous)], 1, 1, 1, True
    )
    with open(f"{_root_path}/data/malicious-invalid-bytes.pkl", "rb") as file:
        compare_scan_results(
            scan_pickle_bytes(file, f"{_root_path}/data/malicious-invalid-bytes.pkl"),
            malicious_invalid_bytes,
        )
