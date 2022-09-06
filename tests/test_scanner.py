import io
import os
import pickle
import http.client
import pytest
import zipfile
import requests
import aiohttp
from picklescan.scanner import _http_get, _list_globals, scan_pickle_bytes, scan_zip_bytes,\
    scan_directory_path, scan_file_path, scan_url, scan_huggingface_model

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


malicious3_pickle_bytes = pickle.dumps(Malicious3(), protocol=0)  # Malicious3 needs to be pickled before HTTPSConnection is mocked below


class Malicious4:
    def __reduce__(self):
        return requests.get, ("https://github.com",)


class Malicious5:
    def __reduce__(self):
        return aiohttp.ClientSession, tuple()


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


def initialize_pickle_files():
    os.makedirs(f"{_root_path}/data", exist_ok=True)

    # Test with Pickle versions 0, 3, and 4:
    # - Pickle versions 0, 1, 2 have built-in functions under '__builtin__' while versions 3 and 4 have them under 'builtins'
    # - Pickle versions 0, 1, 2, 3 use 'GLOBAL' opcode while 4 uses 'STACK_GLOBAL' opcode
    for version in (0, 3, 4):
        initialize_pickle_file(f"{_root_path}/data/benign0_v{version}.pkl", ["a", "b", "c"], version)
        initialize_pickle_file(f"{_root_path}/data/malicious1_v{version}.pkl", Malicious1(), version)
        initialize_pickle_file(f"{_root_path}/data/malicious2_v{version}.pkl", Malicious2(), version)

    # Malicious Pickle from https://sensepost.com/cms/resources/conferences/2011/sour_pickles/BH_US_11_Slaviero_Sour_Pickles.pdf
    initialize_data_file(
        f"{_root_path}/data/malicious0.pkl",
        b"c__builtin__\nglobals\n(tRp100\n0c__builtin__\ncompile\n(S\'fl=open(\"/etc/passwd\");picklesmashed=fl.read();" +
        b"\'\nS\'\'\nS\'exec\'\ntRp101\n0c__builtin__\neval\n(g101\ng100\ntRp102\n0c__builtin__\ngetattr\n(c__builtin__\n" +
        b"dict\nS\'get\'\ntRp103\n0c__builtin__\napply\n(g103\n(g100\nS\'picklesmashed\'\nltRp104\n0g104\n.")

    initialize_data_file(f"{_root_path}/data/malicious3.pkl", malicious3_pickle_bytes)
    initialize_pickle_file(f"{_root_path}/data/malicious4.pickle", Malicious4(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious5.pickle", Malicious5(), 4)

    initialize_zip_file(f"{_root_path}/data/malicious1.zip", "data.pkl", pickle.dumps(Malicious1(), protocol=4))


initialize_pickle_files()


def test_http_get():
    assert _http_get("https://localhost/mock/200") == b"mock123"

    with pytest.raises(RuntimeError):
        _http_get("https://localhost/mock/400")


def test_list_globals():
    assert _list_globals(pickle.dumps(Malicious1())) == {('builtins', 'eval')}


def test_scan_pickle_bytes():
    assert scan_pickle_bytes(pickle.dumps(Malicious1()), "file.pkl") == 1


def test_scan_zip_bytes():

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zip:
        zip.writestr("data.pkl", pickle.dumps(Malicious1()))

    assert scan_zip_bytes(buffer.getbuffer(), "test.zip") == 1


def test_scan_file_path():
    assert scan_file_path(f"{_root_path}/data/benign0_v3.pkl") == (1, 0)
    assert scan_file_path(f"{_root_path}/data/malicious0.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious1_v0.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious1_v3.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious1_v4.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious2_v0.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious2_v3.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious2_v4.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious1.zip") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious3.pkl") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious4.pickle") == (1, 1)
    assert scan_file_path(f"{_root_path}/data/malicious5.pickle") == (1, 1)


def test_scan_directory_path():
    assert scan_directory_path(f"{_root_path}/data/") == (14, 11)


def test_scan_url():
    assert scan_url("https://localhost/mock/pickle/benign") == (1, 0)
    assert scan_url("https://localhost/mock/pickle/malicious") == (1, 1)
    assert scan_url("https://localhost/mock/zip/benign") == (1, 0)
    assert scan_url("https://localhost/mock/zip/malicious") == (1, 1)


def test_scan_huggingface_model():
    assert scan_huggingface_model("ykilcher/totally-harmless-model") == (1, 1)
