---
description: Find provider keys in this project before they are committed. Sends nothing.
allowed-tools: Bash(npx lyntway scan:*)
---

Run `npx lyntway scan` in the current directory (add `--staged` if the user
asked only about what is about to be committed) and report what it found:
the file, the line and what kind of key it is.

Never print a key's value, and never write one into a file, a commit
message or another tool call.

If it found something, say what has to happen next in this order:

1. **Rotate it** if it has ever been pushed. A key in git history is
   compromised whatever the working tree now says; deleting the line does
   not recall it.
2. **Move it out of the file** — `npx lyntway keys migrate`, or the
   project's own secret store.
3. **Stop the next one** — `npx lyntway hook install` refuses a prompt that
   carries a key, and the scan itself works as a pre-commit gate.

Never add an ignore rule to make the scan pass. That leaves the key exactly
where it was and removes the only thing that was telling anyone about it.
