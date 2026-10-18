# Lyntway for Claude Code

Keeps a provider key out of what your agent sends, and signs a receipt of
what passed.

```
/plugin marketplace add lynt-x-global/lyntway-tools
/plugin install lyntway@lyntway
```

The plugin adds a skill the agent reads when a secret is in play, and a
`/lyntway-scan` command. Both drive the `lyntway` CLI, which is installed
on demand by `npx` — nothing here needs an account, and the scan, the hook
and `guard` send nothing anywhere.

See https://lyntway.com/skill.md for the full reference.
