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
        "crabshell: ready (volatile RAM filesystem)",
        "root@rustix:/home/rustix# ",
    )
    missing = [marker for marker in expected if marker not in output]
    if missing:
        raise BuildError(
            "QEMU did not reach the expected kernel state; missing serial markers: "
            + ", ".join(repr(marker) for marker in missing)
            + f"\nSerial output:\n{output or '<empty>'}"
        )

    print(f"QEMU boot smoke test passed (bounded to {timeout}s).")
    print(f"Captured serial log: {serial_log.relative_to(ROOT)}")


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("image", help="create a pinned Limine BIOS/UEFI hybrid ISO")
    smoke = subparsers.add_parser("smoke", help="boot the ISO and check its serial output")
    smoke.add_argument("--timeout", type=int, default=20, help="QEMU time limit in seconds")
    subparsers.add_parser("run", help="run the ISO with an interactive serial terminal")
    args = parser.parse_args()

    try:
        if args.command == "image":
            build_image()
        elif args.command == "run":
            run_interactive()
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
