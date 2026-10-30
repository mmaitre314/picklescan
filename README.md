<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/mmaitre314/picklescan/raw/main/img/banner_dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/mmaitre314/picklescan/raw/main/img/banner_light.svg">
    <img alt="Python Pickle Malware Scanner" src="https://github.com/mmaitre314/picklescan/raw/main/img/banner_light.svg" width="445" height="105" style="max-width: 100%;">
  </picture>
  <br/>
  <br/>
</p>

<p align="center">
  <a href="https://pypi.org/project/picklescan/"><img alt="PyPI" src="https://badge.fury.io/py/picklescan.svg"></a>
  <a href="https://github.com/mmaitre314/picklescan/actions/workflows/test.yml"><img alt="Test" src="https://github.com/mmaitre314/picklescan/workflows/Test/badge.svg"></a>
</p>

Security scanner detecting Python Pickle files performing suspicious actions.

## Getting started

Scan a malicious model on [Hugging Face](https://huggingface.co/):
```bash
pip install picklescan
picklescan --huggingface ykilcher/totally-harmless-model
```
The scanner reports that the Pickle is calling `eval()` to execute arbitrary code:
```bash
https://huggingface.co/ykilcher/totally-harmless-model/resolve/main/pytorch_model.bin (archive/data.pkl): dangerous import __builtin__.eval FOUND
----------- SCAN SUMMARY -----------
Scanned files: 1
Infected files: 1
Suspicious globals: 0
Dangerous globals: 1
Scan errors: 0
Not scanned: 0
```

The scanner can also load Pickles from local files, directories, URLs, and archives:
```bash
picklescan --path downloads/pytorch_model.bin
picklescan --path downloads
picklescan --url https://huggingface.co/sshleifer/tiny-distilbert-base-cased-distilled-squad/resolve/main/pytorch_model.bin
```

## What gets scanned

Files are recognized by their content, not their extension:
- Pickle files, including protocol 0 and 1 pickles (which have no magic bytes) and files holding several pickles
- PyTorch files: zip files written by `torch.save` (the `data.pkl` pickle) and legacy files (a sequence of pickles)
- NumPy `.npy` and `.npz` files (arrays of Python objects are pickles; NumPy itself is not needed)
- joblib files, including the array data joblib writes between pickle opcodes
- Compressed files: gzip, bz2, xz, lzma and zlib (joblib, `pandas.read_pickle`), plus zstd and lz4 when a decompressor is installed
- Archives: zip, tar (also compressed: `.tar.gz`...) and 7z (`pip install picklescan[7z]`). The members of an archive are scanned like
  files of their own, and archives found among them are reported as not scanned rather than opened (see limits below).

Directories and Hugging Face repositories are scanned file by file, whatever the file names. Remote files are read with HTTP range
requests, so only the parts a scan needs are downloaded: a file that is not a pickle costs a few small requests (its start, and
its end to look for a zip archive), not a download.

Text often parses as a few pickle opcodes before failing (Python source, for instance): for content without pickle magic bytes
that fails to parse, imports whose names Python could not import are not reported.

### What a clean result means

picklescan reads files the way the standard loaders do (`pickle.load` with CPython's unpicklers, `torch.load`, `np.load`,
`joblib.load`, `pandas.read_pickle`), and reports the imports they would make. A clean result means that no dangerous import was
found where those loaders look. Payloads outside of that are checked on a best-effort basis, or not at all: data a standard loader
does not read (after the end of what it reads, in archives nested deeper than the limits...), files read by custom loading code,
or formats other than the ones above. Treat a clean result as a statement about the standard loaders, not about every way a file
could be opened.

## Usage

### Exit codes

The scanner exit status codes are (a-la [ClamAV](https://www.clamav.net/)):
- `0`: scan did not find malware
- `1`: scan found malware
- `2`: scan failed (part of the content could not be scanned), whether or not it found malware

### Scan errors

When part of the content cannot be scanned, the scan goes on with the rest and reports what was not scanned, where, and why:
```
error[parse]: unknown opcode b'\xff' at position 40
 --> model.zip (archive/data.pkl), offset 40
  = note: imports found up to this point are reported; what follows was not scanned

skipped: zip archive nested in another archive: not opened (ScanLimits.max_archive_depth)
 --> model.zip (inner.zip)
```

From Python, `ScanResult.errors` and `ScanResult.skipped` hold the same information (kind, location, offset, message), and each
`Global` found has a `location` too.

### Limits

Scans are bounded so that a small crafted file cannot make them do much more work than its size suggests, or fill memory or
disk (`picklescan.scanner.ScanLimits`): archive nesting depth (1 by default), number of archive members, decompressed size, nested
compression, and NumPy header size. Large pickle arguments (tensor data pickled in-band, for instance) are skipped rather than
loaded into memory.

### Telling file formats apart

`picklescan.scanner.detect_file` and `detect_file_path` tell what a file contains, including the content of archives and compressed
files, without scanning it.

### Colors

On a terminal, the output is colored, unless the `NO_COLOR` environment variable is set. `--color always` or `never` decides
regardless of the terminal, as does `FORCE_COLOR`.

### Filtering files and directories

When scanning directories, files and subdirectories can be filtered using regular expressions (again modeled after ClamAV). Each option can be specified multiple times:

| Option | Description |
|---|---|
| `--exclude=REGEX` | Don't scan files whose path matches the regex |
| `--include=REGEX` | Only scan files whose path matches the regex |
| `--exclude-dir=REGEX` | Don't descend into directories whose path matches the regex |
| `--include-dir=REGEX` | Only descend into directories whose path matches the regex |

Key behaviors:
- **Excludes always win over includes.** A file or directory matching both an exclude and an include pattern is skipped.
- **Multiple patterns OR together.** A file is included if it matches *any* `--include` pattern.
- **No includes = everything eligible.** Include patterns only narrow the scan when specified.
- **`--exclude-dir` prunes traversal.** The directory and all of its contents are skipped entirely.

```bash
# Only scan .pkl files, skip the cache/ subdirectory
picklescan --path models/ --include='\.pkl$' --exclude-dir='cache'
```

## Develop

Create and activate the conda environment ([miniconda](https://docs.conda.io/en/latest/miniconda.html) is sufficient):
```
conda env create -f conda.yaml
conda activate picklescan
```

Install the package in editable mode to develop and test:
```
python3 -m pip install -e .
```

Edit with [VS Code](https://code.visualstudio.com/):
```
code .
```

Run unit tests:
```
pytest tests
```

Run manual tests:
- Local PyTorch (zip) file
```bash
mkdir downloads
wget -O downloads/pytorch_model.bin https://huggingface.co/ykilcher/totally-harmless-model/resolve/main/pytorch_model.bin
picklescan -l DEBUG -p downloads/pytorch_model.bin
```
- Remote PyTorch (zip) URL
```bash
picklescan -l DEBUG -u https://huggingface.co/prajjwal1/bert-tiny/resolve/main/pytorch_model.bin
```

Lint the code:
```
black src tests --line-length 140
flake8 src tests --count --show-source
```

Publish the package to [PyPI](https://pypi.org/project/picklescan/): bump the package version in `setup.cfg` and create a GitHub release. This triggers the `publish` workflow.

Alternative manual steps to publish the package:
```
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade build
python3 -m build
python3 -m twine upload dist/*
```

Test the package: bump the version of `picklescan` in `conda.test.yaml` and run
```
conda env remove -n picklescan-test
conda env create -f conda.test.yaml
conda activate picklescan-test
picklescan --huggingface ykilcher/totally-harmless-model
```

Tested on `Linux 5.10.102.1-microsoft-standard-WSL2 x86_64` (WSL2).

## References

- [pickledoc](https://github.com/Legoclones/pickledoc) -- Non-official but in-depth documentation of the Pickle file format
- [pickledbg](https://github.com/Legoclones/pickledbg) -- Step-by-step Pickle dissassembly debugger
- [pickletools.py](https://github.com/python/cpython/blob/main/Lib/pickletools.py) -- The official "documentation" of the Pickle file format (where documentation == code).
- [Machine Learning Attack Series: Backdooring Pickle Files](https://embracethered.com/blog/posts/2022/machine-learning-attack-series-injecting-code-pickle-files/), Johann Rehberger, 2022
- [Hugging Face Pickle Scanning](https://huggingface.co/docs/hub/security-pickle), Luc Georges, 2022
- [The hidden dangers of loading open-source AI models (ARBITRARY CODE EXPLOIT!](https://www.youtube.com/watch?v=2ethDz9KnLk), Yannic Kilcher, 2022
- [Secure Machine Learning at Scale with MLSecOps](https://github.com/EthicalML/fml-security#2---load-pickle-and-inject-malicious-code), Alejandro Saucedo, 2022
- [Backdooring Pickles: A decade only made things worse](https://coldwaterq.com/presentations/ColdwaterQ%20-%20BACKDOORING%20Pickles%20A%20decade%20only%20made%20things%20worse%20-%20v1.pdf), ColdwaterQ, DEFCON 2022
- [Never a dill moment: Exploiting machine learning pickle files](https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/), Evan Sultanik, 2021 (tool: [Fickling](https://github.com/trailofbits/fickling))
- [Exploiting Python pickles](https://davidhamann.de/2020/04/05/exploiting-python-pickle/), David Hamann, 2020
- [Dangerous Pickles - malicious python serialization](https://intoli.com/blog/dangerous-pickles/), Evan Sangaline, 2017
- [Python Pickle Security Problems and Solutions](https://www.smartfile.com/blog/python-pickle-security-problems-and-solutions/), Travis Cunningham, 2015
- [Arbitrary code execution with Python pickles](https://checkoway.net/musings/pickle/), Stephen Checkoway, 2013
- [Sour Pickles, A serialised exploitation guide in one part](https://www.youtube.com/watch?v=HsZWFMKsM08), Marco Slaviero, BlackHat USA 2011 (see also: [doc](https://sensepost.com/cms/resources/conferences/2011/sour_pickles/BH_US_11_Slaviero_Sour_Pickles.pdf), [slides](https://www.slideshare.net/sensepost/sour-pickles))
