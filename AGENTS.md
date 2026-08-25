# Agent Operating Guidelines

Please refer to [CLAUDE.md](./CLAUDE.md) for full engineering standards, directory layout, and communication protocol.

Before running any `cargo` command, sandbox the credentials so the test suite cannot overwrite the
real ones under `~/.gemini`:

```bash
export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
export GEMINI_HOME=/tmp/sagy-canary
```
