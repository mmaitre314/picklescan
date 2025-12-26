This repo contains a security scanner which analyzes Python Pickle files and reports dangerous function calls. It relies on an allow-list called `_safe_globals` and a block-list called `_unsafe_globals` in `src/picklescan/scanner.py`. Those lists need to be updated when bugs or security advisories report detection issues.

To update the block list, create a sample Pickle file reproing the issue, add a test for it, verify that the test fails, update the block list, and verify the test passes.

In more details, start by updating tests in `tests/test_scanner.py`. First create a `reduce_xxx()` function calling the function to add to the block list. For instance:

```python
def reduce_GHSA_4whj_rm5r_c2v8():
    import torch.utils.bottleneck.__main__ as bottleneck_main

    return bottleneck_main.run_autograd_prof, (_payload, {})
```

The `reduce_xxx()` function must be self-contained: include `import` statements directly in the function and not at the top of the file (i.e. do not follow the typical Python convention). When tests are run as part of GitHub Actions, the package being imported here may not be present and the tests will rely on sample Pickle files instead.

In `initialize_pickle_files()`, serialize the `reduce_xxx()` function to a file:
```python
initialize_pickle_file_from_reduce("GHSA-4whj-rm5r-c2v8.pkl", reduce_GHSA_4whj_rm5r_c2v8)
```

In `test_scan_file_path()`, add validation of the scanner output function list for the new Pickle file:
```python
assert_scan("GHSA-4whj-rm5r-c2v8.pkl", [Global("torch.utils.bottleneck.__main__", "run_autograd_prof", SafetyLevel.Dangerous)])
```

Run the tests and verify they fail:
```bash
pytest tests -k test_scan_file_path -vv
```

Add a new entry in dictionary `_unsafe_globals` of `src/picklescan/scanner.py` and rerun the tests to verify they pass.
