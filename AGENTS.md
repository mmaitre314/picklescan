This repo contains a security scanner which analyzes Python Pickle files and reports dangerous function calls.

# Code style

After making code changes, lint the code using:
```
black src tests --line-length 140
flake8 src tests --count --show-source
```

# Bug fixes

## Update block-list

The scanner relies on an allow-list called `_safe_globals` and a block-list called `_unsafe_globals` in `src/picklescan/scanner.py`. Those lists need to be updated when bugs or security advisories report detection issues.

To update the block-list, create a sample Pickle file reproing the issue, add a test for it, verify that the test fails, update the block-list, and verify the test passes.

In more details:

Step 1: Update and run `tests/init_data_files.py` to create the sample Pickle file.

First create a `reduce_xxx()` function calling the function to add to the block list. For instance:
```python
def reduce_GHSA_4whj_rm5r_c2v8():
    import torch.utils.bottleneck.__main__ as bottleneck_main

    return bottleneck_main.run_autograd_prof, (_payload, {})
```

The `reduce_xxx()` function must be self-contained: include `import` statements directly in the function and not at the top of the file (i.e. do not follow the typical Python convention). If a package needs to be intalled, run `python3 -m pip install <package>==<version>` to install it in the current virtual environment, and add `<package>==<version>` in `requirements_extras.txt` for future reference.

In `initialize_pickle_files()`, serialize the `reduce_xxx()` function to a file:
```python
initialize_pickle_file_from_reduce("GHSA-4whj-rm5r-c2v8.pkl", reduce_GHSA_4whj_rm5r_c2v8)
```

Finally run `python3 tests/init_data_files.py` to create the sample file.

Step 2: add code validating the output of the scanner for the sample file. In `tests/test_scanner.py`, add an assert in `test_scan_file_path()`. For instance:
```python
assert_scan("GHSA-4whj-rm5r-c2v8.pkl", [Global("torch.utils.bottleneck.__main__", "run_autograd_prof", SafetyLevel.Dangerous)])
```

Run the test and verify it fails:
```bash
pytest tests -k test_scan_file_path -vv
```

Step 3: add a new entry in dictionary `_unsafe_globals` of `src/picklescan/scanner.py` and rerun the test to verify it passes.
