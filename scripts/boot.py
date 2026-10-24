#!/usr/bin/env python3
"""Build a pinned Limine hybrid ISO and smoke-test it in QEMU.

Only Python's standard library is required. The Limine binary archive is kept
under target/ and checked against the SHA-256 published for the pinned release.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import stat
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
TARGET_DIR = ROOT / "target"
LIMINE_VERSION = "12.9.3"
LIMINE_ARCHIVE_NAME = "limine-binary.zip"
LIMINE_ARCHIVE_SHA256 = "1bdbbcda650c5dba9b1eca5833d598137bf11bd6289bc89b6bcc4f8f112fa676"
LIMINE_ARCHIVE_URL = (
    "https://github.com/Limine-Bootloader/Limine/releases/download/"
    f"v{LIMINE_VERSION}/{LIMINE_ARCHIVE_NAME}"
)
KERNEL = TARGET_DIR / "x86_64-unknown-none" / "release" / "rustix"
ISO_ROOT = TARGET_DIR / "rustix-iso-root"
ISO_PATH = TARGET_DIR / "rustix.iso"

REQUIRED_LIMINE_FILES = (
    "limine-bios.sys",
    "limine-bios-cd.bin",
    "limine-uefi-cd.bin",
    "BOOTX64.EFI",
)


class BuildError(RuntimeError):
    """An actionable error while preparing or testing the boot image."""


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise BuildError(f"required tool '{name}' was not found on PATH")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for member in archive.infolist():
        name = PurePosixPath(member.filename)
        mode = member.external_attr >> 16
        if not name.parts or name.is_absolute() or ".." in name.parts or ":" in name.parts[0]:
            raise BuildError(f"unsafe path in Limine archive: {member.filename}")
        if stat.S_ISLNK(mode):
            raise BuildError(f"symlink in Limine archive is not allowed: {member.filename}")
        output = (destination / Path(*name.parts)).resolve()
        if output != root and root not in output.parents:
            raise BuildError(f"archive member escapes extraction directory: {member.filename}")
    archive.extractall(destination)


def ensure_limine() -> tuple[Path, Path]:
    cache = TARGET_DIR / "tools" / f"limine-{LIMINE_VERSION}"
    archive_path = TARGET_DIR / "tools" / LIMINE_ARCHIVE_NAME
    extracted = cache / "archive"
    cache.mkdir(parents=True, exist_ok=True)
    extracted.mkdir(parents=True, exist_ok=True)

    if not archive_path.exists():
        print(f"Downloading Limine {LIMINE_VERSION} binary release...")
        request = urllib.request.Request(
            LIMINE_ARCHIVE_URL,
            headers={"User-Agent": "Rustix-OS-build/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response, archive_path.open(
                "wb"
            ) as output:
                shutil.copyfileobj(response, output)
        except Exception as error:
            archive_path.unlink(missing_ok=True)
            raise BuildError(f"could not download pinned Limine release: {error}") from error

    actual_hash = sha256(archive_path)
    if actual_hash != LIMINE_ARCHIVE_SHA256:
        archive_path.unlink(missing_ok=True)
        raise BuildError(
            "Limine archive SHA-256 mismatch: "
            f"expected {LIMINE_ARCHIVE_SHA256}, got {actual_hash}"
        )

    try:
        with zipfile.ZipFile(archive_path) as archive:
            safe_extract(archive, extracted)
    except (OSError, zipfile.BadZipFile) as error:
        raise BuildError(f"could not extract the pinned Limine archive: {error}") from error

    def find_asset(name: str) -> Path:
        matches = sorted(extracted.rglob(name))
        if not matches:
            raise BuildError(f"Limine {LIMINE_VERSION} archive is missing {name}")
        return matches[0]

    if sys.platform == "win32":
        limine_tool = find_asset("limine.exe")
    else:
        limine_source = find_asset("limine.c")
        limine_tool = limine_source.with_name("limine")
        if not limine_tool.is_file():
            compiler = require_tool("cc")
            print("Building Limine host utility from the pinned source...")
            subprocess.run(
                [
                    compiler,
                    "-g",
                    "-O2",
                    "-pipe",
                    "-std=c99",
                    "-D_FILE_OFFSET_BITS=64",
                    limine_source.name,
                    "-o",
                    str(limine_tool),
                ],
                cwd=limine_source.parent,
                check=True,
            )
        limine_tool.chmod(
            limine_tool.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
    return limine_tool, extracted


def build_image() -> None:
    if not KERNEL.is_file():
        raise BuildError("kernel ELF not found; run 'just build' first")
    xorriso = require_tool("xorriso")
    limine_tool, limine_root = ensure_limine()

    shutil.rmtree(ISO_ROOT, ignore_errors=True)
    boot_dir = ISO_ROOT / "boot" / "limine"
    efi_dir = ISO_ROOT / "EFI" / "BOOT"
    boot_dir.mkdir(parents=True)
    efi_dir.mkdir(parents=True)
    shutil.copy2(KERNEL, ISO_ROOT / "boot" / "rustix")
    shutil.copy2(ROOT / "limine.conf", ISO_ROOT / "limine.conf")

    for name in REQUIRED_LIMINE_FILES:
        source = next(iter(sorted(limine_root.rglob(name))), None)
        if source is None:
            raise BuildError(f"Limine archive is missing required file {name}")
        if name == "BOOTX64.EFI":
            shutil.copy2(source, efi_dir / name)
        else:
            shutil.copy2(source, boot_dir / name)

    ISO_PATH.parent.mkdir(parents=True, exist_ok=True)
    xorriso_command = [
        xorriso,
        "-as",
        "mkisofs",
        "-R",
        "-r",
        "-J",
        "-b",
        "boot/limine/limine-bios-cd.bin",
        "-no-emul-boot",
        "-boot-load-size",
        "4",
        "-boot-info-table",
        "-hfsplus",
        "-apm-block-size",
        "2048",
        "--efi-boot",
        "boot/limine/limine-uefi-cd.bin",
        "-efi-boot-part",
        "--efi-boot-image",
        "--protective-msdos-label",
        str(ISO_ROOT),
        "-o",
        str(ISO_PATH),
    ]
    subprocess.run(xorriso_command, cwd=ROOT, check=True)
    subprocess.run([str(limine_tool), "bios-install", str(ISO_PATH)], cwd=ROOT, check=True)
    print(f"Created hybrid BIOS/UEFI image: {ISO_PATH.relative_to(ROOT)}")


def smoke_test(timeout: int) -> None:
    qemu = require_tool("qemu-system-x86_64")
    if not ISO_PATH.is_file():
        raise BuildError("boot image not found; run 'just image' first")

    serial_log = TARGET_DIR / "rustix-qemu-serial.log"
    serial_log.parent.mkdir(parents=True, exist_ok=True)
    serial_log.unlink(missing_ok=True)
    serial_device = "file:" + serial_log.relative_to(ROOT).as_posix()
    command = [
        qemu,
        "-machine",
        "q35",
        "-m",
        "256M",
        "-cdrom",
        str(ISO_PATH),
        "-boot",
        "d",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        serial_device,
        "-no-reboot",
        "-no-shutdown",
    ]

    timed_out = False
    try:
        result = subprocess.run(command, cwd=ROOT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        timed_out = True
        result = None

    if not timed_out and result is not None and result.returncode != 0:
        details = serial_log.read_text(encoding="latin-1") if serial_log.exists() else ""
        raise BuildError(
            f"QEMU exited with status {result.returncode} before the smoke-test timeout.\n"
            f"Serial output:\n{details}"
        )

    output = serial_log.read_text(encoding="latin-1") if serial_log.exists() else ""
    expected = (
        "Rustix kernel: x86_64 Rust bootstrap",
        "kernel HHDM aliases validated: text/rodata R/NX, data RW/NX, PAT preserved",
        "page-table transition passed:",
        "kernel heap probe passed: alignment, reuse, deterministic exhaustion",
        "crabshell: ready (volatile RAM filesystem)",
        "root@rustix:/home/rustix# ",
    )
    missing = [marker for marker in expected if marker not in output]
    tlb_flush_markers = (
        "page-table transition: global TLB flushed via CR4.PGE toggle",
        "page-table transition: CR4.PGE clear; CR3 reload flushed active translations",
    )
    if not any(marker in output for marker in tlb_flush_markers):
        missing.append("a page-table transition TLB invalidation marker")
    if missing:
        raise BuildError(
            "QEMU did not reach the expected kernel state; missing serial markers: "
            + ", ".join(repr(marker) for marker in missing)
            + f"\nSerial output:\n{output or '<empty>'}"
        )

    print(f"QEMU boot smoke test passed (bounded to {timeout}s).")
    print(f"Captured serial log: {serial_log.relative_to(ROOT)}")


def fault_smoke_test(kind: str, timeout: int) -> None:
    qemu = require_tool("qemu-system-x86_64")
    if not ISO_PATH.is_file():
        raise BuildError("boot image not found; build the fault-injection image first")

    serial_log = TARGET_DIR / f"rustix-qemu-fault-{kind}.log"
    serial_log.parent.mkdir(parents=True, exist_ok=True)
    serial_log.unlink(missing_ok=True)
    serial_device = "file:" + serial_log.relative_to(ROOT).as_posix()
    command = [
        qemu,
        "-machine",
        "q35",
        "-m",
        "256M",
        "-cdrom",
        str(ISO_PATH),
        "-boot",
        "d",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        serial_device,
        "-no-reboot",
        "-no-shutdown",
    ]

    timed_out = False
    try:
        result = subprocess.run(command, cwd=ROOT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        timed_out = True
        result = None

    output = serial_log.read_text(encoding="latin-1") if serial_log.exists() else ""
    if kind == "page-fault":
        expected = (
            "fault injection: triggering page fault at 0x00000000deadbeef",
            "KERNEL EXCEPTION: vector 14 (page fault)",
            "page fault address (CR2): 0x00000000deadbeef",
        )
    elif kind == "invalid-opcode":
        expected = (
            "fault injection: triggering invalid opcode with ud2",
            "KERNEL EXCEPTION: vector 6 (invalid opcode)",
        )
    else:
        raise BuildError(f"unsupported fault-injection test: {kind}")

    missing = [marker for marker in expected if marker not in output]
    if missing:
        raise BuildError(
            f"QEMU did not report the expected {kind} exception; missing serial markers: "
            + ", ".join(repr(marker) for marker in missing)
            + f"\nSerial output:\n{output or '<empty>'}"
        )
    if "root@rustix:/home/rustix# " in output:
        raise BuildError(f"kernel reached the shell after {kind} injection\nSerial output:\n{output}")
    if "fault injection unexpectedly returned" in output:
        raise BuildError(f"{kind} instruction returned instead of faulting\nSerial output:\n{output}")
    if not timed_out:
        status = result.returncode if result is not None else "unknown"
        raise BuildError(
            f"QEMU did not remain halted after {kind} (exit status {status})\n"
            f"Serial output:\n{output}"
        )

    print(f"QEMU {kind} fault-injection test passed (halt observed within {timeout}s).")
    print(f"Captured serial log: {serial_log.relative_to(ROOT)}")


def build_kernel(features: tuple[str, ...] = ()) -> None:
    command = ["cargo", "build", "--release", "--target", "x86_64-unknown-none"]
    if features:
        command.extend(["--features", ",".join(features)])
    subprocess.run(command, cwd=ROOT, check=True)


def frame_smoke_workflow(timeout: int) -> None:
    failure: BaseException | None = None
    try:
        build_kernel(("probe-hhdm-frame",))
        build_image()
        smoke_test(timeout)
        serial_log = TARGET_DIR / "rustix-qemu-serial.log"
        output = serial_log.read_text(encoding="latin-1") if serial_log.exists() else ""
        markers = (
            "HHDM frame probe passed: wrote, read, cleared, and reclaimed one frame",
            "inherited root HHDM probe passed: read 512 entries",
            "candidate inherited-root clone probe passed:",
            "candidate page-table probe passed: mapped, walked, unmapped, and released",
        )
        missing = [marker for marker in markers if marker not in output]
        if missing:
            raise BuildError(
                "QEMU did not report successful HHDM access probes; missing markers: "
                + ", ".join(repr(marker) for marker in missing)
                + f"\nSerial output:\n{output}"
            )
        print("QEMU HHDM, inherited-mapping, cloned-root, and candidate-map probes passed.")
    except BaseException as error:
        failure = error

    try:
        build_kernel()
        build_image()
    except BaseException as restore_error:
        if failure is not None:
            raise BuildError(
                f"HHDM frame workflow failed ({failure}); restoring the default image "
                f"also failed ({restore_error})"
            ) from restore_error
        raise

    if failure is not None:
        raise BuildError(
            f"HHDM frame workflow failed; the default release image was restored: {failure}"
        ) from failure
    print("Restored the default release kernel and ISO after the HHDM frame probe.")


def fault_smoke_workflow(timeout: int) -> None:
    tests = (
        ("page-fault", "inject-page-fault"),
        ("invalid-opcode", "inject-invalid-opcode"),
    )
    failure: BaseException | None = None
    try:
        for kind, feature in tests:
            build_kernel((feature,))
            build_image()
            fault_smoke_test(kind, timeout)
    except BaseException as error:
        failure = error

    try:
        build_kernel()
        build_image()
    except BaseException as restore_error:
        if failure is not None:
            raise BuildError(
                f"fault-injection workflow failed ({failure}); restoring the default image "
                f"also failed ({restore_error})"
            ) from restore_error
        raise

    if failure is not None:
        raise BuildError(
            f"fault-injection workflow failed; the default release image was restored: {failure}"
        ) from failure
    print("Restored the default release kernel and ISO after fault-injection tests.")


def run_interactive() -> None:
    qemu = require_tool("qemu-system-x86_64")
    if not ISO_PATH.is_file():
        raise BuildError("boot image not found; run 'just image' first")
    command = [
        qemu,
        "-machine",
        "q35",
        "-m",
        "256M",
        "-cdrom",
        str(ISO_PATH),
        "-boot",
        "d",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-no-shutdown",
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode != 0:
        raise BuildError(f"QEMU exited with status {result.returncode}")


def run_debug() -> None:
    qemu = require_tool("qemu-system-x86_64")
    if not ISO_PATH.is_file():
        raise BuildError("boot image not found; run 'just debug-image' first")

    command = [
        qemu,
        "-machine",
        "q35",
        "-m",
        "256M",
        "-cdrom",
        str(ISO_PATH),
        "-boot",
        "d",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-gdb",
        "tcp:127.0.0.1:1234",
        "-S",
        "-no-reboot",
        "-no-shutdown",
    ]
    print("QEMU is paused; GDB stub listening on 127.0.0.1:1234.", flush=True)
    print("Attach with the Rustix: QEMU (CodeLLDB) debug configuration.", flush=True)
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode != 0:
        raise BuildError(f"QEMU exited with status {result.returncode}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("image", help="create a pinned Limine BIOS/UEFI hybrid ISO")
    smoke = subparsers.add_parser("smoke", help="boot the ISO and check its serial output")
    smoke.add_argument("--timeout", type=int, default=20, help="QEMU time limit in seconds")
    frame_smoke = subparsers.add_parser(
        "frame-smoke", help="probe HHDM access and an inactive candidate root in QEMU"
    )
    frame_smoke.add_argument("--timeout", type=int, default=20, help="QEMU time limit in seconds")
    fault_smoke = subparsers.add_parser(
        "fault-smoke", help="test fatal exceptions in QEMU, then restore the default image"
    )
    fault_smoke.add_argument("--timeout", type=int, default=10, help="per-test QEMU time limit")
    subparsers.add_parser("run", help="run the ISO with an interactive serial terminal")
    subparsers.add_parser("debug", help="run the ISO paused with a loopback GDB stub")
    args = parser.parse_args()

    try:
        if args.command == "image":
            build_image()
        elif args.command == "run":
            run_interactive()
        elif args.command == "debug":
            run_debug()
        elif args.command == "frame-smoke":
            if args.timeout <= 0:
                raise BuildError("--timeout must be a positive number of seconds")
            frame_smoke_workflow(args.timeout)
        elif args.command == "fault-smoke":
            if args.timeout <= 0:
                raise BuildError("--timeout must be a positive number of seconds")
            fault_smoke_workflow(args.timeout)
        else:
            if args.timeout <= 0:
                raise BuildError("--timeout must be a positive number of seconds")
            smoke_test(args.timeout)
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"Rustix boot workflow failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
