# Agent Operating Guidelines

Please refer to [CLAUDE.md](./CLAUDE.md) for full engineering standards, directory layout, and communication protocol.

Unit tests (`#[cfg(test)]`) isolate default active-home lookups automatically, but before running
any `cargo` command or manual binary/subprocess invocation, still sandbox the credentials as
defense-in-depth so nothing can touch the real ones under `~/.gemini`:

```bash
export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
export GEMINI_HOME=/tmp/sagy-canary
```
