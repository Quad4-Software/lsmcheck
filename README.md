# lsmcheck

[![CI](https://github.com/Quad4-Software/lsmcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/lsmcheck/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/lsmcheck/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/lsmcheck/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/lsmcheck/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/lsmcheck)
[![PyPI](https://img.shields.io/pypi/v/lsmcheck.svg)](https://pypi.org/project/lsmcheck/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Linux Security Module introspection from procfs and sysfs only: which
LSMs the kernel runs, the security attributes of a process, and the
state of AppArmor, SELinux, Yama and lockdown. No dependencies, no
shell-outs. Every reader degrades to None when the feature is absent.

Requires Python 3.10+ and Linux.

## Install

    pip install lsmcheck

## Example

    import lsmcheck

    print(lsmcheck.active_lsms())          # [LSM.CAPABILITY, LSM.YAMA, ...]
    ctx = lsmcheck.apparmor.current()
    if ctx and ctx.mode == lsmcheck.apparmor.AppArmorMode.ENFORCE:
        print("confined by", ctx.profile)

## Development

    uv sync --group dev
    make check

License: 0BSD. Quad4 Software, https://quad4.io
