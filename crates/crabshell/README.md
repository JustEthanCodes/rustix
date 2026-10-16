# Crabshell command parser

`crabshell` is a small `no_std`, allocation-free Rust library containing the command enum and parser used by the Rustix shell. It intentionally knows nothing about serial terminals, kernel privileges, filesystems, or process management.

The initial grammar supports `help`, `clear`, `pwd`, `ls`, `cd`, `mkdir`, `touch`, `write`, `append`, `cp`, `mv`, `cat`, `rm`, and `rmdir`. `write` and `append` borrow the remaining text from the input line and optionally remove matching outer quotes. See [`../../docs/architecture/crabshell.md`](../../docs/architecture/crabshell.md) for command semantics, limits, and current kernel integration.

Run its parser tests from the repository root with `cargo test -p crabshell --lib` or `just test`.
