#![no_std]

//! Small `no_std` wrappers for the stable Rustix syscall ABI v1.
//!
//! The raw syscall entry accepts register-sized values and never dereferences
//! them in Rust; the kernel validates all user pointers before access. Prefer
//! the typed wrappers when they match the operation being performed.

use core::arch::asm;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("rustix-user currently supports x86_64 only");

pub const ABI_VERSION: u64 = 0x0001_0000;
pub const SYS_ABI_VERSION: u64 = 0;
pub const SYS_EXIT: u64 = 1;
pub const SYS_WRITE: u64 = 2;
pub const SYS_WAIT: u64 = 3;

pub const STDOUT: u64 = 1;
pub const STDERR: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallError {
    InvalidArgument,
    BadFileDescriptor,
    Fault,
    OutOfMemory,
    NoChild,
    Interrupted,
    Io,
    NotImplemented,
    ArgumentListTooLong,
    Overflow,
    NotSupported,
    ResultOutOfRange,
    Unknown(i64),
}

/// Invoke one v1 syscall using the documented x86_64 register convention.
///
/// This low-level entry is safe because pointer values are passed opaquely to
/// the kernel, which validates ranges and permissions before dereferencing.
/// Prefer [`write`], [`wait`], and [`exit`] when possible.
#[inline]
pub fn syscall(number: u64, arguments: [u64; 6]) -> i64 {
    let [first, second, third, fourth, fifth, sixth] = arguments;
    let result: u64;
    // SAFETY: The v1 ABI assigns RAX and the six argument registers exactly as
    // declared here. Rustix's DPL-3 gate and entry stub preserve Rust's memory
    // validity invariants by treating user pointers as integers in the kernel.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") first,
            in("rsi") second,
            in("rdx") third,
            in("r10") fourth,
            in("r8") fifth,
            in("r9") sixth,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    result as i64
}

pub fn abi_version() -> Result<u64, SyscallError> {
    decode_result(syscall(SYS_ABI_VERSION, [0; 6]))
}

/// Write one buffer to a v1 file descriptor. A successful short write is valid.
pub fn write(file_descriptor: u64, bytes: &[u8]) -> Result<usize, SyscallError> {
    let result = decode_result(syscall(
        SYS_WRITE,
        [
            file_descriptor,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        ],
    ))?;
    usize::try_from(result).map_err(|_| SyscallError::ResultOutOfRange)
}

/// Write all bytes, retrying successful short writes.
///
/// A zero-length write before the buffer is complete is reported as [`SyscallError::Io`]
/// to avoid an infinite loop.
pub fn write_all(file_descriptor: u64, bytes: &[u8]) -> Result<(), SyscallError> {
    write_all_with(bytes, |remaining| write(file_descriptor, remaining))
}

/// Format directly to a file descriptor without allocating.
///
/// Formatting stops at the first write failure and returns its syscall error.
pub fn write_fmt(
    file_descriptor: u64,
    arguments: core::fmt::Arguments<'_>,
) -> Result<(), SyscallError> {
    write_fmt_with(arguments, |bytes| write(file_descriptor, bytes))
}

/// Best-effort panic reporting to stderr followed by process exit status 127.
pub fn panic_exit(info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = write_fmt(STDERR, format_args!("rustix: panic: {info}\n"));
    exit(127)
}

fn write_all_with<W>(mut remaining: &[u8], mut write: W) -> Result<(), SyscallError>
where
    W: FnMut(&[u8]) -> Result<usize, SyscallError>,
{
    while !remaining.is_empty() {
        let written = write(remaining)?;
        if written == 0 {
            return Err(SyscallError::Io);
        }
        if written > remaining.len() {
            return Err(SyscallError::ResultOutOfRange);
        }
        remaining = &remaining[written..];
    }
    Ok(())
}

fn write_fmt_with<W>(arguments: core::fmt::Arguments<'_>, write: W) -> Result<(), SyscallError>
where
    W: FnMut(&[u8]) -> Result<usize, SyscallError>,
{
    let mut output = SyscallFormatter { write, error: None };
    match core::fmt::write(&mut output, arguments) {
        Ok(()) => Ok(()),
        Err(_) => Err(output.error.unwrap_or(SyscallError::Io)),
    }
}

struct SyscallFormatter<W> {
    write: W,
    error: Option<SyscallError>,
}

impl<W> core::fmt::Write for SyscallFormatter<W>
where
    W: FnMut(&[u8]) -> Result<usize, SyscallError>,
{
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        match write_all_with(text.as_bytes(), |remaining| (self.write)(remaining)) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.error = Some(error);
                Err(core::fmt::Error)
            }
        }
    }
}

/// Wait for a child and optionally copy its signed 32-bit status to `status`.
///
/// The current kernel probe supports already-exited children; a running child
/// returns [`SyscallError::NotSupported`] until blocking process scheduling is
/// integrated.
pub fn wait(child_pid: u64, status: Option<&mut i32>) -> Result<u64, SyscallError> {
    let status_address = status.map_or(0, |status| status as *mut i32 as u64);
    decode_result(syscall(SYS_WAIT, [child_pid, status_address, 0, 0, 0, 0]))
}

/// Exit the current process. The kernel ABI does not return from a successful exit.
pub fn exit(status: i32) -> ! {
    let _ = syscall(SYS_EXIT, [status as u32 as u64, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

fn decode_result(result: i64) -> Result<u64, SyscallError> {
    if result >= 0 {
        return Ok(result as u64);
    }
    match result.checked_neg() {
        Some(1) => Err(SyscallError::InvalidArgument),
        Some(2) => Err(SyscallError::BadFileDescriptor),
        Some(3) => Err(SyscallError::Fault),
        Some(4) => Err(SyscallError::OutOfMemory),
        Some(5) => Err(SyscallError::NoChild),
        Some(6) => Err(SyscallError::Interrupted),
        Some(7) => Err(SyscallError::Io),
        Some(8) => Err(SyscallError::NotImplemented),
        Some(9) => Err(SyscallError::ArgumentListTooLong),
        Some(10) => Err(SyscallError::Overflow),
        Some(11) => Err(SyscallError::NotSupported),
        _ => Err(SyscallError::Unknown(result)),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_result, write_all_with, write_fmt_with, SyscallError, ABI_VERSION};

    #[test]
    fn decodes_nonnegative_results_and_stable_v1_errors() {
        assert_eq!(decode_result(ABI_VERSION as i64), Ok(ABI_VERSION));
        assert_eq!(decode_result(0), Ok(0));
        assert_eq!(decode_result(-3), Err(SyscallError::Fault));
        assert_eq!(decode_result(-5), Err(SyscallError::NoChild));
        assert_eq!(decode_result(-11), Err(SyscallError::NotSupported));
        assert_eq!(decode_result(-12), Err(SyscallError::Unknown(-12)));
        assert_eq!(
            decode_result(i64::MIN),
            Err(SyscallError::Unknown(i64::MIN))
        );
    }

    #[test]
    fn write_all_retries_short_writes_until_complete() {
        let mut output = [0; 5];
        let mut output_length = 0;
        let result = write_all_with(b"hello", |remaining| {
            let count = remaining.len().min(2);
            output[output_length..output_length + count].copy_from_slice(&remaining[..count]);
            output_length += count;
            Ok(count)
        });
        assert_eq!(result, Ok(()));
        assert_eq!(&output[..output_length], b"hello");
    }

    #[test]
    fn write_all_rejects_zero_and_impossible_write_counts() {
        assert_eq!(write_all_with(b"x", |_| Ok(0)), Err(SyscallError::Io));
        assert_eq!(
            write_all_with(b"x", |_| Ok(2)),
            Err(SyscallError::ResultOutOfRange)
        );
        assert_eq!(
            write_all_with(b"x", |_| Err(SyscallError::Fault)),
            Err(SyscallError::Fault)
        );
    }

    #[test]
    fn formatting_is_allocation_free_and_preserves_write_errors() {
        let mut output = [0; 8];
        let mut output_length = 0;
        let result = write_fmt_with(format_args!("value={}", 42), |remaining| {
            let count = remaining.len().min(3);
            output[output_length..output_length + count].copy_from_slice(&remaining[..count]);
            output_length += count;
            Ok(count)
        });
        assert_eq!(result, Ok(()));
        assert_eq!(&output[..output_length], b"value=42");

        assert_eq!(
            write_fmt_with(format_args!("failure"), |_| Err(SyscallError::Fault)),
            Err(SyscallError::Fault)
        );
    }
}
