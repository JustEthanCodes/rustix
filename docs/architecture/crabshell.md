# Crabshell and the early RAM filesystem

Crabshell is Rustix's first command-line interface. The current implementation is a **kernel-mode bootstrap shell** attached to COM1, not a separate user process. Its command parser is isolated in a separate crate so the same grammar can later be reused by a graphical terminal frontend or by a userspace terminal application.

## Crate boundary

- `crates/crabshell` is an allocation-free `no_std` Rust library. It parses a borrowed command line into a `Command` value and performs no I/O, filesystem access, scheduling, or privilege changes.
- `src/shell.rs` adapts the parser to the kernel serial driver, provides a small line editor, implements commands, and owns the current working-directory node.
- `src/vfs.rs` is a fixed-capacity in-memory filesystem used by the early shell. It is not a disk filesystem and is not persistent.

This is a useful separation now: future terminal frontends can reuse parsing without importing kernel hardware or filesystem code. A future user-mode Crabshell should keep its frontend/parser layer but execute operations through a documented syscall/VFS interface; it must not link the kernel's internal filesystem as a privilege shortcut.

## Build and run

```sh
just test
just image
just smoke
just run
```

`just run` starts a headless QEMU machine and connects the guest serial port to the current terminal. Use `Ctrl+C` in the host terminal to stop QEMU. The BIOS/UEFI boot image is `target/rustix.iso`.

The kernel welcomes the user in `/home/rustix`. The initial namespace contains `/bin`, `/dev`, `/etc`, `/home/rustix`, `/tmp`, and `/var`; `/etc/motd` explains that storage is volatile.

## Commands

| Command | Behavior |
|---|---|
| `help` | List available commands and limits. |
| `clear` | Send the ANSI clear-screen/home sequence. |
| `pwd` | Print the absolute working directory. |
| `ls [PATH]` | List a directory; a file path prints that file's name and size. Defaults to the current directory. |
| `cd PATH` | Change to an existing directory. Supports absolute and relative paths, `.`, and `..`. |
| `mkdir PATH` | Create one directory; its parent must already exist. |
| `touch PATH` | Create an empty file, or leave an existing file unchanged. |
| `write PATH TEXT` | Create a file if needed and replace its contents with the remaining line. Matching outer single or double quotes around the text are removed. |
| `append PATH TEXT` | Create a file if needed and append the remaining line. |
| `cp SOURCE DEST` | Copy a file; an existing destination file is replaced. |
| `mv SOURCE DEST` | Move/rename a file; directories and existing destinations are rejected. |
| `cat PATH` | Print a UTF-8 text file. Binary data is not displayed. |
| `rm PATH` | Remove a file. Directories are rejected. |
| `rmdir PATH` | Remove an empty directory other than the current directory. |

Example:

```text
root@rustix:/home/rustix# mkdir notes
root@rustix:/home/rustix# write notes/hello.txt "hello from Rustix"
root@rustix:/home/rustix# cat notes/hello.txt
hello from Rustix
root@rustix:/home/rustix# cd ..
root@rustix:/home# pwd
/home
```

The grammar intentionally does not yet support quoted paths, escaped quotes, variables, pipes, redirection, globbing, command substitution, history, or a process launcher. Input is a single ASCII line (up to 256 bytes) from the serial port.

## RAM filesystem contract

- The root plus at most 31 live entries fit in the fixed 32-node table.
- Path components are limited to 31 UTF-8 bytes; file contents are limited to 1024 bytes each.
- Paths may be absolute or relative and support repeated `/`, `.`, and `..`.
- `write` replaces a file; `append` adds bytes; `touch` never truncates.
- `cp` copies files and replaces an existing destination file. `mv` moves files only and refuses to overwrite an existing destination. `rm` handles files only. `rmdir` refuses non-empty directories and the current directory.
- Filesystem allocation is fixed-capacity; errors are reported rather than allocating a heap.
- Every file and directory disappears when the machine resets. There is no block device, journaling, metadata persistence, permission model, links, or concurrent access yet.

## Tests and limitations

Host-side tests cover path traversal, file create/write/append/copy/move/remove, entry kinds, path rendering, directory emptiness, and the parser's syntax/arity. The automated QEMU smoke test checks that the serial shell reaches its prompt. A separate manual `just run` session exercised `help`, `ls`, `meminfo`, `mkdir`, `cd`, `touch`, `write`, `append`, `cat`, `cp`, `mv`, `rm`, `rmdir`, and `pwd`; `cat` returned the appended text, `cp` replaced an existing destination with source contents, `rmdir` refused a nonempty directory, and `pwd` returned to `/home/rustix` after cleanup. The unsupported `memtest` command produced the expected unknown-command response. These checks do not emulate reboot persistence, exhaustively test shell interactions, or prove isolation. Since the shell runs in ring 0, a parser or filesystem bug can panic the entire kernel. This implementation must not be presented as a secure or POSIX-compliant shell.
