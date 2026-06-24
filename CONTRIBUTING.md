# Contributing to MemNixFS

Thanks for your interest in improving MemNixFS! Bug reports, fixes, and features
are all welcome. This guide keeps contributions smooth for everyone.

## Before you start — please propose first

Some of MemNixFS's development happens in a separate working repository before it
lands here, so a feature or fix you have in mind **may already be in progress**.
To save your effort:

- **Non-trivial work** (a feature, a new file, a behavior change, a refactor):
  **open an issue first** (or comment on an existing one) describing what you
  want to do, and wait for a maintainer to give the go-ahead before writing code.
  We'll quickly tell you if it's already in flight, or point you at the best
  approach.
- **Trivial fixes** (a typo, a one-line bug, a doc nit): just open the PR
  directly — no need to ask first.

This isn't gatekeeping — it's so two people don't unknowingly build the same
thing. We try to label issues we're already working on; if an issue isn't
claimed, it's fair game once we ack it.

## What makes a good PR

- **One concern per PR**, and ideally one concern per commit. If you fixed a bug
  *and* added a feature, split them — it makes review (and reverting, if ever
  needed) far easier.
- **Say what you tested it on.** This is a memory-forensics tool; "it builds"
  isn't enough. Tell us the **dump format and kernel version** you verified
  against — e.g. *"Ubuntu 5.15.0-43 LiME dump: 323 processes, `/proc/1-systemd/maps`
  shows 150 VMAs with correct ranges."* Real evidence from a real dump is the
  single most useful thing you can include.
- **Build and test on both platforms** before submitting (see below).
- **Update the docs** under `docs/` when you change behavior or add a feature.
- **Don't commit large binaries or memory dumps.** Describe how to reproduce, or
  link to the image instead.

## Building and testing

```bash
# Windows (MSVC + vcpkg + WinFsp)
cmake --preset msvc-x64
cmake --build build/msvc-x64 --config Release

# Linux (Ninja + FUSE; needs FUSE3 dev headers and a C++17 toolchain —
# see CMakeLists.txt for the full dependency list)
cmake -S . -B build/linux -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build/linux
```

Then:

```bash
ctest --test-dir build/<dir> -C Release      # unit tests must pass
memnixfs --dump <your-dump> list             # smoke against a real dump
memnixfs --dump <your-dump> -v list          # check -v output for new warnings
```

## Code style

- **Naming:** `snake_case` for functions, `CamelCase` for types/namespaces,
  `kPascalCase` for constants. `#pragma once` in headers.
- **Layout:** 4-space indent, no tabs, ~100-column soft limit. Group includes
  (project / system / stdlib), one per line.
- **Comments explain _why_, not _what_** — the code already says what. When
  behavior depends on a kernel quirk or version, cite the kernel struct/commit
  so the next reader understands.
- **Errors:** throw via `throw_error("…{}…", args)` (from `core/error.h`) for
  hard failures. For soft failures, log and degrade — **never crash on malformed
  dump input** (dumps are attacker-influenced data).
- **Logging:** `log::note` for the handful of clean status lines a normal run
  shows; `log::error` for serious failures. `info` / `warn` / `debug` are hidden
  unless `-v`, `trace` unless `-vv`. Keep a default run quiet.
- **Headers** include only what their declarations need; push implementation
  includes into the `.cpp`.

## Commit messages

```
Short imperative summary (~50 chars)

Why the change is needed and what it does. Wrap the body at ~72 chars.
- Bullet the notable points.

Closes #123
```

Keep one logical change per commit.

## Scope and ethics

MemNixFS is a **defensive / authorized-analysis** tool: it reads Linux memory
images for incident response, forensics, and research. Please keep contributions
within that scope — only analyze images you are authorized to handle, and don't
add features whose primary purpose is evasion or offense.

## Pull-request checklist

The PR template will prompt you, but in short: linked issue · single concern ·
builds on Windows **and** Linux · `ctest` green · tested against a real dump (say
which kernel) · docs updated.

## Questions

Open an issue with the **question** label, or ask in the relevant issue/PR
thread. We're happy to help you land your change.
