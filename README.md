<p align="center">
  <img src="assets/logo.png" width="200" alt="t3code-lockdown">
</p>

<p align="center">
  <a href="t3code-lockdown"><img src="https://img.shields.io/badge/skill-t3code--lockdown-24292f?style=flat-square&labelColor=555" alt="skill: t3code-lockdown"></a>
  &nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-24292f?style=flat-square&labelColor=555&logo=github&logoColor=white" alt="license: MIT"></a>
</p>

<p align="center">
  <strong>English</strong> | <a href="README.zh-TW.md">繁體中文</a>
</p>

# t3code-lockdown

An Agent Skill that locks T3 Code down so it stops sending usage telemetry, cannot use T3 Connect, and does not auto-update. It works with any agent that supports the standard Agent Skills layout (`SKILL.md` plus optional scripts) and is not tied to a specific product.

After installing it, ask your agent to set up, audit, or roll back T3 Code privacy and telemetry settings on a machine. Full steps, verification, and rollback are in [`t3code-lockdown/SKILL.md`](t3code-lockdown/SKILL.md).

## Install

Copy the `t3code-lockdown` folder into the skills directory your agent reads. Common locations include:

- Generic / multi-agent: `~/.agents/skills/t3code-lockdown`
- Claude Code: `~/.claude/skills/t3code-lockdown`
- Codex: `~/.codex/skills/t3code-lockdown`
- Cursor: the project's or the user's skills folder (the exact path depends on your Cursor version and settings)

Then start a new session, or reload skills in whatever way your agent expects.

```bash
git clone git@github.com:Gratia2533/t3code-lockdown.git
cp -R t3code-lockdown/t3code-lockdown ~/.agents/skills/t3code-lockdown
```

For HTTPS, clone `https://github.com/Gratia2533/t3code-lockdown.git` instead. This is a private repository, so the GitHub account you use needs access.

## Contents

- `t3code-lockdown/SKILL.md` — skill description and steps
- `t3code-lockdown/scripts/lockdown.sh` — Linux / WSL / macOS (`apply` / `verify` / `rollback`)
- `t3code-lockdown/scripts/lockdown.ps1` — Windows

Both scripts are idempotent: running them again only reports `unchanged`, and they back up files before changing them.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Gratia2533.
