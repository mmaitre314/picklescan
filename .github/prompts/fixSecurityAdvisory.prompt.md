---
description: Fix a picklescan security advisory reported on the GitHub repo.
agent: agent
tools: vscode, execute, read, agent, edit, search, todo, web, gh-security_advisories/list_repository_security_advisories
---

- Use #tool:gh-security_advisories/list_repository_security_advisories to list advisories on GitHub repo `mmaitre314/picklescan`
- Find the one with ID ${input:ghsa_id}
- Read its description
- Make a fix
