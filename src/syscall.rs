//! Stable, host-testable decoding for the initial Rustix syscall ABI.
//!
//! This module defines ABI values, validates register-level request shape,
//! sanitizes user return frames, and provides a host-testable bounded write
//! service. It does not install an entry gate or dispatch requests from hardware.

pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 0;
pub const ABI_VERSION: u64 = (ABI_MAJOR as u64) << 16 | ABI_MINOR as u64;
pub const MAX_WRITE_BYTES: u64 = 4096;
pub const USER_SYSCALL_VECTOR: u8 = 0x80;
pub const USER_DATA_SELECTOR: u16 = 0x2b;
pub const USER_CODE_SELECTOR: u16 = 0x33;
pub const SAFE_USER_RFLAGS: u64 = 1 << 1;

const RFLAGS_IOPL: u64 = 3 << 12;
const RFLAGS_NESTED_TASK: u64 = 1 << 14;
const RFLAGS_VIRTUAL_8086: u64 = 1 << 17;

pub mod number {
    pub const ABI_VERSION: u64 = 0;
    pub const EXIT: u64 = 1;
    pub const WRITE: u64 = 2;
    pub const WAIT: u64 = 3;
}

/// Stable v1 error numbers. Syscall returns encode these as negative `i64`s.
#[repr(i64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallError {
    InvalidArgument = 1,
    BadFileDescriptor = 2,
    Fault = 3,
    OutOfMemory = 4,
    NoChild = 5,
    Interrupted = 6,
    Io = 7,
    NoSys = 8,
    TooBig = 9,
    Overflow = 10,
    NotSupported = 11,
}

impl SyscallError {
    pub const fn return_value(self) -> i64 {
        -(self as i64)
    }
}

/// The six argument registers reserved by the x86_64 v1 calling convention.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallArguments {
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

/// Register and privilege frame saved by the dedicated `int 0x80` entry stub.
///
/// The field order matches the assembly push sequence, followed by the five-word
/// hardware frame created by a CPL3-to-CPL0 interrupt transition.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallContext {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub instruction_pointer: u64,
    pub code_selector: u64,
    pub flags: u64,
    pub stack_pointer: u64,
    pub stack_selector: u64,
}

const _: [(); 160] = [(); core::mem::size_of::<SyscallContext>()];
const _: [(); 0] = [(); core::mem::offset_of!(SyscallContext, r15)];
const _: [(); 112] = [(); core::mem::offset_of!(SyscallContext, rax)];
const _: [(); 120] = [(); core::mem::offset_of!(SyscallContext, instruction_pointer)];
const _: [(); 128] = [(); core::mem::offset_of!(SyscallContext, code_selector)];
const _: [(); 136] = [(); core::mem::offset_of!(SyscallContext, flags)];
const _: [(); 144] = [(); core::mem::offset_of!(SyscallContext, stack_pointer)];
const _: [(); 152] = [(); core::mem::offset_of!(SyscallContext, stack_selector)];

/// The five-word privilege-return frame consumed by `IRETQ` in long mode.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserIretFrame {
    pub instruction_pointer: u64,
    pub code_selector: u64,
    pub flags: u64,
    pub stack_pointer: u64,
    pub stack_selector: u64,
}

/// A user return frame with validated selectors/addresses and kernel-chosen flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedUserIretFrame(UserIretFrame);

impl ValidatedUserIretFrame {
    pub const fn into_raw(self) -> UserIretFrame {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserIretFrameError {
    InvalidAddressWidth,
    InvalidSelectors,
    InvalidFlags,
    InvalidInstructionPointer,
    InvalidStackPointer,
}

/// Validate the initial privilege-return frame, including the required 16-byte
/// stack alignment, and replace user flags with a conservative kernel value.
///
/// The safe flags deliberately leave IF clear until a process-aware interrupt
/// scheduler is installed. The caller must separately verify that RIP names an
/// executable process mapping and RSP names a writable stack mapping.
pub fn sanitize_user_iret_frame(
    frame: UserIretFrame,
    virtual_address_bits: u8,
) -> Result<ValidatedUserIretFrame, UserIretFrameError> {
    sanitize_user_frame(frame, virtual_address_bits, true)
}

/// Sanitize a syscall's saved user return frame without imposing a new stack
/// alignment on an in-function RSP. SysV permits transient stack alignment while
/// executing a function; the active process root must still validate its mapping.
pub fn sanitize_user_syscall_return_frame(
    frame: UserIretFrame,
    virtual_address_bits: u8,
) -> Result<ValidatedUserIretFrame, UserIretFrameError> {
    sanitize_user_frame(frame, virtual_address_bits, false)
}

fn sanitize_user_frame(
    frame: UserIretFrame,
    virtual_address_bits: u8,
    require_aligned_stack: bool,
) -> Result<ValidatedUserIretFrame, UserIretFrameError> {
    if !matches!(virtual_address_bits, 48 | 57) {
        return Err(UserIretFrameError::InvalidAddressWidth);
    }
    if frame.code_selector != u64::from(USER_CODE_SELECTOR)
        || frame.stack_selector != u64::from(USER_DATA_SELECTOR)
    {
        return Err(UserIretFrameError::InvalidSelectors);
    }
    if frame.flags & (1 << 1) == 0
        || frame.flags & (RFLAGS_IOPL | RFLAGS_NESTED_TASK | RFLAGS_VIRTUAL_8086) != 0
    {
        return Err(UserIretFrameError::InvalidFlags);
    }

    let lower_half_end = 1u64 << (virtual_address_bits - 1);
    if frame.instruction_pointer >= lower_half_end
        || !crate::memory::is_canonical_virtual_address(
            frame.instruction_pointer,
            virtual_address_bits,
        )
    {
        return Err(UserIretFrameError::InvalidInstructionPointer);
    }
    let stack_last = frame
        .stack_pointer
        .checked_sub(1)
        .filter(|address| *address < lower_half_end)
        .filter(|address| {
            crate::memory::is_canonical_virtual_address(*address, virtual_address_bits)
        });
    if stack_last.is_none() || (require_aligned_stack && frame.stack_pointer & 0xf != 0) {
        return Err(UserIretFrameError::InvalidStackPointer);
    }

    Ok(ValidatedUserIretFrame(UserIretFrame {
        instruction_pointer: frame.instruction_pointer,
        code_selector: u64::from(USER_CODE_SELECTOR),
        flags: SAFE_USER_RFLAGS,
        stack_pointer: frame.stack_pointer,
        stack_selector: u64::from(USER_DATA_SELECTOR),
    }))
}

/// A syscall whose number and register-level arguments have been decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallRequest {
    AbiVersion,
    Exit {
        status: i32,
    },
    Write {
        fd: u64,
        user_buffer: u64,
        length: usize,
    },
    Wait {
        child_pid: u64,
        status_address: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleStream {
    Stdout,
    Stderr,
}

/// The kernel-side sink for the v1 console descriptors.
pub trait ConsoleOutput {
    type Error;

    fn write(&mut self, stream: ConsoleStream, bytes: &[u8]) -> Result<usize, Self::Error>;
}

/// Copy and write one bounded v1 user buffer through a process root.
///
/// The complete user range is preflighted by `copy_from_user` before output.
/// If the frame backend faults after copying a prefix, that prefix is still
/// offered to the console and a positive short write is returned when accepted.
///
/// # Safety
/// The current kernel stack, including this function's fixed scratch buffer,
/// must not be mapped as a user frame in `process`. The boot allocator enforces
/// this by excluding the kernel image and bootstrap-stack spans from usable
/// frame allocation; future kernel stacks must preserve the same invariant.
pub unsafe fn write_user_buffer<M, U, O>(
    roots: &crate::paging::ProcessAddressSpaceRoots<'_, '_, '_, M>,
    process: crate::paging::ProcessAddressSpaceHandle,
    fd: u64,
    user_buffer: u64,
    length: usize,
    user_memory: &mut U,
    output: &mut O,
) -> Result<usize, SyscallError>
where
    M: crate::paging::CandidatePageTableMemory,
    U: crate::paging::UserFrameMemory,
    O: ConsoleOutput,
{
    use crate::paging::{ProcessUserCopyError, MAX_PROCESS_USER_COPY_BYTES};

    let stream = match fd {
        1 => ConsoleStream::Stdout,
        2 => ConsoleStream::Stderr,
        _ => return Err(SyscallError::BadFileDescriptor),
    };
    if length > MAX_WRITE_BYTES as usize {
        return Err(SyscallError::TooBig);
    }
    if length == 0 {
        return Ok(0);
    }

    let mut scratch = [0; MAX_PROCESS_USER_COPY_BYTES];
    let copied = match unsafe {
        roots.copy_from_user(process, user_buffer, &mut scratch[..length], user_memory)
    } {
        Ok(copied) if copied <= length => copied,
        Ok(_) => return Err(SyscallError::Fault),
        Err(failure) if failure.transferred > 0 && failure.transferred <= length => {
            failure.transferred
        }
        Err(failure) => {
            return Err(match failure.cause {
                ProcessUserCopyError::LengthTooLarge => SyscallError::TooBig,
                ProcessUserCopyError::Memory(_) => SyscallError::Io,
                ProcessUserCopyError::InvalidHandle
                | ProcessUserCopyError::Releasing
                | ProcessUserCopyError::InvalidRange
                | ProcessUserCopyError::Unmapped
                | ProcessUserCopyError::PermissionDenied => SyscallError::Fault,
            });
        }
    };
    if copied == 0 {
        return Err(SyscallError::Io);
    }

    let written = output
        .write(stream, &scratch[..copied])
        .map_err(|_| SyscallError::Io)?;
    if written == 0 || written > copied {
        return Err(SyscallError::Io);
    }
    Ok(written)
}

/// Decode a v1 syscall number and its register arguments without touching user memory.
///
/// The exit status uses the low 32 bits of RDI, interpreted as a signed value.
/// A zero-length write preserves the supplied pointer without validating it; the
/// eventual syscall implementation must return zero before inspecting that pointer.
pub const fn decode_syscall(
    syscall_number: u64,
    arguments: SyscallArguments,
) -> Result<SyscallRequest, SyscallError> {
    match syscall_number {
        number::ABI_VERSION => Ok(SyscallRequest::AbiVersion),
        number::EXIT => Ok(SyscallRequest::Exit {
            status: arguments.rdi as u32 as i32,
        }),
        number::WRITE => {
            if arguments.rdx > MAX_WRITE_BYTES {
                return Err(SyscallError::TooBig);
            }
            Ok(SyscallRequest::Write {
                fd: arguments.rdi,
                user_buffer: arguments.rsi,
                length: arguments.rdx as usize,
            })
        }
        number::WAIT => Ok(SyscallRequest::Wait {
            child_pid: arguments.rdi,
            status_address: if arguments.rsi == 0 {
                None
            } else {
                Some(arguments.rsi)
            },
        }),
        _ => Err(SyscallError::NoSys),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_syscall, number, sanitize_user_iret_frame, sanitize_user_syscall_return_frame,
        SyscallArguments, SyscallError, SyscallRequest, UserIretFrame, UserIretFrameError,
        ABI_VERSION, MAX_WRITE_BYTES, SAFE_USER_RFLAGS, USER_CODE_SELECTOR, USER_DATA_SELECTOR,
    };

    const EMPTY_ARGUMENTS: SyscallArguments = SyscallArguments {
        rdi: 0,
        rsi: 0,
        rdx: 0,
        r10: 0,
        r8: 0,
        r9: 0,
    };

    fn valid_iret_frame() -> UserIretFrame {
        UserIretFrame {
            instruction_pointer: 0x4000_0000,
            code_selector: u64::from(USER_CODE_SELECTOR),
            flags: 0x202,
            stack_pointer: 0x7fff_fff0,
            stack_selector: u64::from(USER_DATA_SELECTOR),
        }
    }

    #[test]
    fn abi_version_and_syscall_numbers_are_stable() {
        assert_eq!(ABI_VERSION, 0x0001_0000);
        assert_eq!(number::ABI_VERSION, 0);
        assert_eq!(number::EXIT, 1);
        assert_eq!(number::WRITE, 2);
        assert_eq!(number::WAIT, 3);
        assert_eq!(
            decode_syscall(number::ABI_VERSION, EMPTY_ARGUMENTS),
            Ok(SyscallRequest::AbiVersion)
        );
    }

    #[test]
    fn error_numbers_encode_as_negative_i64_results() {
        assert_eq!(SyscallError::InvalidArgument.return_value(), -1);
        assert_eq!(SyscallError::BadFileDescriptor.return_value(), -2);
        assert_eq!(SyscallError::Fault.return_value(), -3);
        assert_eq!(SyscallError::OutOfMemory.return_value(), -4);
        assert_eq!(SyscallError::NoChild.return_value(), -5);
        assert_eq!(SyscallError::Interrupted.return_value(), -6);
        assert_eq!(SyscallError::Io.return_value(), -7);
        assert_eq!(SyscallError::NoSys.return_value(), -8);
        assert_eq!(SyscallError::TooBig.return_value(), -9);
        assert_eq!(SyscallError::Overflow.return_value(), -10);
        assert_eq!(SyscallError::NotSupported.return_value(), -11);
    }

    #[test]
    fn exit_status_is_the_signed_low_32_bits_of_rdi() {
        let arguments = SyscallArguments {
            rdi: 0xfeed_beef_ffff_fffe,
            ..EMPTY_ARGUMENTS
        };
        assert_eq!(
            decode_syscall(number::EXIT, arguments),
            Ok(SyscallRequest::Exit { status: -2 })
        );
    }

    #[test]
    fn write_decoding_accepts_zero_and_maximum_lengths_without_pointer_access() {
        let zero_length = SyscallArguments {
            rdi: 1,
            rsi: u64::MAX,
            ..EMPTY_ARGUMENTS
        };
        assert_eq!(
            decode_syscall(number::WRITE, zero_length),
            Ok(SyscallRequest::Write {
                fd: 1,
                user_buffer: u64::MAX,
                length: 0,
            })
        );

        let maximum = SyscallArguments {
            rdi: 2,
            rsi: 0x4000,
            rdx: MAX_WRITE_BYTES,
            ..EMPTY_ARGUMENTS
        };
        assert_eq!(
            decode_syscall(number::WRITE, maximum),
            Ok(SyscallRequest::Write {
                fd: 2,
                user_buffer: 0x4000,
                length: MAX_WRITE_BYTES as usize,
            })
        );
    }

    #[test]
    fn write_larger_than_the_v1_limit_is_rejected() {
        let arguments = SyscallArguments {
            rdx: MAX_WRITE_BYTES + 1,
            ..EMPTY_ARGUMENTS
        };
        assert_eq!(
            decode_syscall(number::WRITE, arguments),
            Err(SyscallError::TooBig)
        );
    }

    #[test]
    fn wait_decoding_distinguishes_optional_status_pointer() {
        assert_eq!(
            decode_syscall(number::WAIT, EMPTY_ARGUMENTS),
            Ok(SyscallRequest::Wait {
                child_pid: 0,
                status_address: None,
            })
        );

        let arguments = SyscallArguments {
            rdi: 42,
            rsi: 0x7000,
            ..EMPTY_ARGUMENTS
        };
        assert_eq!(
            decode_syscall(number::WAIT, arguments),
            Ok(SyscallRequest::Wait {
                child_pid: 42,
                status_address: Some(0x7000),
            })
        );
    }

    #[test]
    fn user_iret_frame_checks_selectors_addresses_alignment_and_sanitizes_flags() {
        let mut frame = valid_iret_frame();
        let sanitized = sanitize_user_iret_frame(frame, 48).unwrap().into_raw();
        assert_eq!(sanitized.instruction_pointer, frame.instruction_pointer);
        assert_eq!(sanitized.code_selector, u64::from(USER_CODE_SELECTOR));
        assert_eq!(sanitized.stack_selector, u64::from(USER_DATA_SELECTOR));
        assert_eq!(sanitized.flags, SAFE_USER_RFLAGS);
        assert_eq!(sanitized.stack_pointer, frame.stack_pointer);

        frame.code_selector = 0x08;
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidSelectors)
        );
        frame = valid_iret_frame();
        frame.stack_selector = 0x10;
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidSelectors)
        );
    }

    #[test]
    fn syscall_return_frame_preserves_valid_in_function_stack_alignment() {
        let mut frame = valid_iret_frame();
        frame.stack_pointer = 0x7fff_fff8;
        let sanitized = sanitize_user_syscall_return_frame(frame, 48)
            .unwrap()
            .into_raw();
        assert_eq!(sanitized.stack_pointer, 0x7fff_fff8);
        assert_eq!(sanitized.flags, SAFE_USER_RFLAGS);
    }

    #[test]
    fn user_iret_frame_rejects_bad_flags_and_non_user_addresses() {
        let mut frame = valid_iret_frame();
        frame.flags |= 3 << 12;
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidFlags)
        );
        frame = valid_iret_frame();
        frame.flags &= !(1 << 1);
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidFlags)
        );
        frame = valid_iret_frame();
        frame.instruction_pointer = 1 << 47;
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidInstructionPointer)
        );
        frame = valid_iret_frame();
        frame.stack_pointer = 0x7fff_fff8;
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidStackPointer)
        );
        frame = valid_iret_frame();
        frame.stack_pointer = 0x0000_8000_0000_0000;
        assert!(sanitize_user_iret_frame(frame, 48).is_ok());
        frame.stack_pointer += 16;
        assert_eq!(
            sanitize_user_iret_frame(frame, 48),
            Err(UserIretFrameError::InvalidStackPointer)
        );
        assert_eq!(
            sanitize_user_iret_frame(valid_iret_frame(), 52),
            Err(UserIretFrameError::InvalidAddressWidth)
        );
    }

    #[test]
    fn unassigned_numbers_return_enosys() {
        assert_eq!(decode_syscall(4, EMPTY_ARGUMENTS), Err(SyscallError::NoSys));
        assert_eq!(
            decode_syscall(u64::MAX, EMPTY_ARGUMENTS),
            Err(SyscallError::NoSys)
        );
    }
}
