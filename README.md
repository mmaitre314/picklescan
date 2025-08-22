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

> For more generic model scanning, Protect AI's [modelscan](https://github.com/protectai/modelscan) is now available to scan not only Pickle files but
> also PyTorch, TensorFlow, and Keras.

## Getting started

Scan a malicious model on [Hugging Face](https://huggingface.co/):
```bash
pip install picklescan
picklescan --huggingface ykilcher/totally-harmless-model
```
The scanner reports that the Pickle is calling `eval()` to execute arbitrary code:
```bash
https://huggingface.co/ykilcher/totally-harmless-model/resolve/main/pytorch_model.bin:archive/data.pkl: global import '__builtin__ eval' FOUND
----------- SCAN SUMMARY -----------
Scanned files: 1
Infected files: 1
Dangerous globals: 1
```

The scanner can also load Pickles from local files, directories, URLs, and zip archives (a-la [PyTorch](https://pytorch.org/)):
```bash
picklescan --path downloads/pytorch_model.bin
picklescan --path downloads
picklescan --url https://huggingface.co/sshleifer/tiny-distilbert-base-cased-distilled-squad/resolve/main/pytorch_model.bin
```

To scan Numpy's `.npy` files, pip install the `numpy` package first.

The scanner exit status codes are (a-la [ClamAV](https://www.clamav.net/)):
- `0`: scan did not find malware
- `1`: scan found malware
- `2`: scan failed

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
