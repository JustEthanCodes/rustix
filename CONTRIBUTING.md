# Contributing to Rustix

Thanks for your interest in Rustix. It is an experimental `no_std` Rust kernel for `x86_64-unknown-none`; it is not yet a general-purpose or security-reviewed operating system. Unix-like behavior is a long-term goal, not a claim of POSIX compatibility. Please keep implementation status and limitations explicit.

## Before you start

- Read the [documentation index](docs/index.md) and [roadmap](docs/roadmap/README.md) to understand current scope and validation status.
- For the subsystem you plan to change, read its architecture document and the [security and unsafe-code policy](docs/security.md).
- For bugs and proposals, use the GitHub issue forms where they fit. Feature requests should account for current architecture and roadmap dependencies.

## Development setup

The [build guide](docs/development/building.md) describes prerequisites and available commands. You can use the repository's Dev Container for a ready-to-use environment; otherwise install the Rust toolchain and host tools listed in that guide.

Run commands from the repository root:

```sh
just fmt
just test
just check
just verify
```

`just test` runs host-side tests. `just check` checks the freestanding target. `just verify` also builds the boot image and runs the QEMU prompt smoke test, so it requires the image and emulator tools and may need network access for the first pinned Limine download. See [Testing and verification](docs/development/testing.md) for what these checks do and do not establish.

Run the narrowest relevant checks first, then broaden as appropriate. For boot, memory-management, architecture, or other hardware-sensitive changes, run `just verify` when the environment permits. If a check cannot be run, say so and explain the blocker; do not report unrun checks as passing.

## Making changes

- Prefer small, focused changes that preserve the kernel's `no_std` and freestanding constraints. Avoid adding dependencies without a concrete need.
- Keep unsafe and hardware operations narrow, and document the assumptions that make them valid. Preserve explicit ownership, range validation, and failure behavior at boot and memory boundaries.
- Keep host-testable policy separate from privileged hardware paths where practical. Add tests for success and failure cases, and add QEMU checks when changes affect behavior that host tests cannot exercise.
- Update relevant architecture or development documentation when behavior, assumptions, or validation evidence changes.
- Do not mark roadmap work complete merely because an interface or implementation exists. Record only validation that was actually achieved.

## Pull requests

Use the [pull request template](.github/pull_request_template.md). Describe the motivation and behavior change, list tests and commands with their observed results, and call out limitations or hardware paths that were not exercised. Keep unrelated changes out of the pull request when practical.

Rustix is licensed under [Apache-2.0](LICENSE). Contributions intentionally submitted for inclusion in Rustix are made under that license, unless a separate written agreement says otherwise.
