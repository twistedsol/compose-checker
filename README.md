# Docker Compose checker

![tests](https://github.com/twistedsol/compose-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads `docker-compose.yml` files and flags risky settings, with line numbers. It only reads the file. It never starts a container or contacts Docker. Standard library only, no installs.

## Run it

```
python compose_checker.py sample_compose/01_risky.yml
python compose_checker.py sample_compose/*.yml
python compose_checker.py sample_compose/01_risky.yml --format json
```

On Windows I use `py -3.13` instead of `python`. You can point it at the compose file in any project.

Three sample files are included. They are made up for practice:

| File | What it is | Findings |
|---|---|---|
| `01_risky.yml` | A badly written compose file | 20 (7 high) |
| `02_okay_with_gaps.yml` | Looks fine but leaves gaps | 3 (0 high) |
| `03_hardened.yml` | A hardened compose file | 0 |

## What it checks

| Rule | Severity | Flags |
|---|---|---|
| privileged | high | `privileged: true` |
| host-network | high | `network_mode: host` |
| host-pid / host-ipc | high | `pid: host` or `ipc: host` |
| dangerous-capability | high | `cap_add` with ALL, SYS_ADMIN, SYS_MODULE, SYS_PTRACE and similar |
| docker-socket | high | Mounting `/var/run/docker.sock` (even read-only) |
| sensitive-host-mount | high | Mounting `/`, `/etc`, `/root`, `/proc`, `/sys`, `/boot` and similar |
| hardcoded-secret | high | A password, token or key with its value written in `environment:` |
| db-port-public | medium | A database port (MySQL, PostgreSQL, Redis, MongoDB and others) published on all interfaces |
| unconfined-security-profile | medium | `seccomp:unconfined` or `apparmor:unconfined` |
| image-latest-tag | medium | An image with no tag or the `latest` tag |
| no-user | low | No `user:` set (the image may set one, so this is only a hint) |
| no-new-privileges | low | `no-new-privileges:true` missing |

Secret values are never printed. Variables such as `${DB_PASSWORD}` and `_FILE` settings are treated as fine.

## Options

- `--format text|json` (default text)
- `--min-severity low|medium|high` hides findings below that level
- `--fail-on low|medium|high` sets which level makes the exit code 1 (default high)

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` bad input (missing file, unreadable file, or not a compose file).

## Test it

```
python -m unittest -v
```

76 tests cover the YAML reader, each rule and its edges, the output formats, bad input, the command line and the sample files. GitHub Actions runs them on Python 3.10 and 3.12.

## How I built it

I used AI to help write the code and tests. The reader is a small one I wrote for this tool, because the standard library has no YAML support and I wanted no installs. I ran everything myself and checked the sample results by hand.

## Limits

- It reads one file. It does not merge `docker-compose.override.yml`, `include:` files or `.env` files.
- It does not support YAML anchors, merge keys (`<<`) or multi-document files. It stops with an error instead of guessing.
- It cannot see what is inside an image, so it cannot tell if an image already runs as a non-root user.
- A variable such as `${IMAGE}` is skipped, because the real value is not in the file.
- It does not check the running containers, only the file.

## Next ideas

- Read the `.env` file and override files too.
- Check `read_only`, `cap_drop` and resource limits.
- A Kubernetes manifest checker with the same pattern.
