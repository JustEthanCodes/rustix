//! Kernel-side Crabshell frontend: serial input, prompts, and RAM-filesystem commands.

use crabshell::{parse, Command, ParseError, MAX_LINE_LENGTH};
use rustix_kernel::vfs::{EntryKind, FsError, RamFs, MAX_PATH_CAPACITY};

use crate::arch::x86_64::serial;
use crate::boot::BootInfo;

/// Run Crabshell forever on the bootstrap CPU.
pub fn run(filesystem: &mut RamFs, mut cwd: usize, boot_info: &BootInfo) -> ! {
    crate::kprintln!("crabshell: ready (volatile RAM filesystem)");
    print_motd(filesystem, cwd);

    let mut input = [0u8; MAX_LINE_LENGTH];
    loop {
        print_prompt(filesystem, cwd);
        let length = read_line(&mut input);
        if length == 0 {
            continue;
        }

        let line = match core::str::from_utf8(&input[..length]) {
            Ok(line) => line,
            Err(_) => {
                crate::kprintln!("crabshell: input must be valid UTF-8");
                continue;
            }
        };

        match parse(line) {
            Ok(Some(command)) => execute(command, filesystem, &mut cwd, boot_info),
            Ok(None) => {}
            Err(error) => print_parse_error(error),
        }
    }
}

fn print_prompt(filesystem: &RamFs, cwd: usize) {
    let mut path = [0u8; MAX_PATH_CAPACITY];
    match filesystem.write_path(cwd, &mut path) {
        Ok(length) => match core::str::from_utf8(&path[..length]) {
            Ok(path) => serial::print(format_args!("root@rustix:{}# ", path)),
            Err(_) => serial::print(format_args!("root@rustix:/?# ")),
        },
        Err(_) => serial::print(format_args!("root@rustix:/?# ")),
    }
}

fn read_line(input: &mut [u8; MAX_LINE_LENGTH]) -> usize {
    let mut length = 0;
    loop {
        let Some(byte) = serial::try_read_byte() else {
            core::hint::spin_loop();
            continue;
        };

        match byte {
            b'\r' | b'\n' => {
                crate::kprintln!();
                return length;
            }
            0x03 => {
                crate::kprintln!("^C");
                return 0;
            }
            0x08 | 0x7f if length > 0 => {
                length -= 1;
                serial::print(format_args!("\x08 \x08"));
            }
            0x20..=0x7e if length < input.len() => {
                input[length] = byte;
                length += 1;
                serial::print(format_args!("{}", byte as char));
            }
            0x20..=0x7e => serial::print(format_args!("\x07")),
            _ => {}
        }
    }
}

fn execute(command: Command<'_>, filesystem: &mut RamFs, cwd: &mut usize, boot_info: &BootInfo) {
    match command {
        Command::Help => print_help(),
        Command::Clear => serial::print(format_args!("\x1b[2J\x1b[H")),
        Command::Pwd => {
            let mut path = [0u8; MAX_PATH_CAPACITY];
            match filesystem.write_path(*cwd, &mut path) {
                Ok(length) => match core::str::from_utf8(&path[..length]) {
                    Ok(path) => crate::kprintln!("{}", path),
                    Err(_) => crate::kprintln!("crabshell: could not display current path"),
                },
                Err(error) => report_fs_error(error),
            }
        }
        Command::Meminfo => {
            let managed = boot_info.frame_allocator.managed_frames();
            let free = boot_info.frame_allocator.free_frames();
            crate::kprintln!("usable RAM: {} bytes", boot_info.memory_map.usable_bytes());
            crate::kprintln!(
                "physical frames: {} managed, {} free, {} allocated",
                managed,
                free,
                managed - free
            );
        }
        Command::Ls(path) => {
            let directory = match path {
                Some(path) => match filesystem.resolve(*cwd, path) {
                    Ok(node) => node,
                    Err(error) => {
                        report_fs_error(error);
                        return;
                    }
                },
                None => *cwd,
            };
            list_directory(filesystem, directory);
        }
        Command::Cd(path) => match filesystem.resolve(*cwd, path) {
            Ok(node) => match filesystem.kind(node) {
                Ok(EntryKind::Directory) => *cwd = node,
                Ok(EntryKind::File) => report_fs_error(FsError::NotDirectory),
                Err(error) => report_fs_error(error),
            },
            Err(error) => report_fs_error(error),
        },
        Command::Mkdir(path) => match filesystem.create_dir_path(*cwd, path) {
            Ok(_) => {}
            Err(error) => report_fs_error(error),
        },
        Command::Touch(path) => match filesystem.open_or_create_file(*cwd, path) {
            Ok(_) => {}
            Err(error) => report_fs_error(error),
        },
        Command::Write { path, contents } => {
            if let Err(error) = filesystem.write_file_path(*cwd, path, contents.as_bytes()) {
                report_fs_error(error);
            }
        }
        Command::Append { path, contents } => {
            if let Err(error) = filesystem.append_file_path(*cwd, path, contents.as_bytes()) {
                report_fs_error(error);
            }
        }
        Command::Cp {
            source,
            destination,
        } => match filesystem.copy_file_path(*cwd, source, destination) {
            Ok(()) => {}
            Err(error) => report_fs_error(error),
        },
        Command::Mv {
            source,
            destination,
        } => match filesystem.move_file_path(*cwd, source, destination) {
            Ok(()) => {}
            Err(error) => report_fs_error(error),
        },
        Command::Cat(path) => match filesystem.resolve(*cwd, path) {
            Ok(node) => match filesystem.read_file(node) {
                Ok(bytes) => match core::str::from_utf8(bytes) {
                    Ok(text) => print_file_contents(text),
                    Err(_) => crate::kprintln!("crabshell: binary file display is not supported"),
                },
                Err(error) => report_fs_error(error),
            },
            Err(error) => report_fs_error(error),
        },
        Command::Rm(path) => match filesystem.remove_file_path(*cwd, path) {
            Ok(()) => {}
            Err(error) => report_fs_error(error),
        },
        Command::Rmdir(path) => match filesystem.resolve(*cwd, path) {
            Ok(node) if node == *cwd => {
                crate::kprintln!("crabshell: cannot remove the current directory");
            }
            Ok(node) => match filesystem.remove_dir(node) {
                Ok(()) => {}
                Err(error) => report_fs_error(error),
            },
            Err(error) => report_fs_error(error),
        },
    }
}

fn list_directory(filesystem: &RamFs, directory: usize) {
    match filesystem.kind(directory) {
        Ok(EntryKind::File) => match filesystem.entry(directory) {
            Ok(entry) => crate::kprintln!("{} ({} bytes)", entry.name, entry.size),
            Err(error) => report_fs_error(error),
        },
        Err(error) => report_fs_error(error),
        Ok(EntryKind::Directory) => match filesystem.child_count(directory) {
            Ok(0) => crate::kprintln!("(empty)"),
            Ok(count) => {
                for index in 0..count {
                    let Some(entry) = filesystem.child_at(directory, index) else {
                        crate::kprintln!("crabshell: directory changed while listing");
                        return;
                    };
                    match entry.kind {
                        EntryKind::Directory => crate::kprintln!("{}/", entry.name),
                        EntryKind::File => {
                            crate::kprintln!("{}  {} bytes", entry.name, entry.size)
                        }
                    }
                }
            }
            Err(error) => report_fs_error(error),
        },
    }
}

fn print_file_contents(text: &str) {
    for (index, line) in text.split('\n').enumerate() {
        if index != 0 {
            serial::print(format_args!("\r\n"));
        }
        serial::print(format_args!("{}", line.strip_suffix('\r').unwrap_or(line)));
    }
    if !text.ends_with('\n') {
        crate::kprintln!();
    }
}

fn print_motd(filesystem: &RamFs, cwd: usize) {
    if let Ok(node) = filesystem.resolve(cwd, "/etc/motd") {
        if let Ok(bytes) = filesystem.read_file(node) {
            if let Ok(text) = core::str::from_utf8(bytes) {
                print_file_contents(text);
            }
        }
    }
}

fn print_help() {
    crate::kprintln!("Crabshell commands:");
    crate::kprintln!("  help                 show this help");
    crate::kprintln!("  clear                clear an ANSI-compatible terminal");
    crate::kprintln!("  pwd                  print the current directory");
    crate::kprintln!("  meminfo              show validated memory and frame counts");
    crate::kprintln!("  ls [PATH]            list a directory or file");
    crate::kprintln!("  cd PATH              change the current directory");
    crate::kprintln!("  mkdir PATH            create a directory");
    crate::kprintln!("  touch PATH            create an empty file");
    crate::kprintln!("  write PATH TEXT       replace a file's contents");
    crate::kprintln!("  append PATH TEXT      append text to a file");
    crate::kprintln!("  cp SOURCE DEST        copy a file, replacing DEST if it exists");
    crate::kprintln!("  mv SOURCE DEST        move/rename; refuse existing DEST");
    crate::kprintln!("  cat PATH              print a text file");
    crate::kprintln!("  rm PATH               remove a file");
    crate::kprintln!("  rmdir PATH            remove an empty directory");
    crate::kprintln!("  write/append accept a quoted or unquoted text remainder.");
    crate::kprintln!("  RAM filesystem: 31 entries plus root; files up to 1024 bytes.");
}

fn print_parse_error(error: ParseError) {
    match error {
        ParseError::UnknownCommand => crate::kprintln!("crabshell: unknown command (try 'help')"),
        ParseError::MissingArgument => crate::kprintln!("crabshell: missing path argument"),
        ParseError::MissingText => {
            crate::kprintln!("crabshell: missing text (usage: write PATH TEXT)")
        }
        ParseError::TooManyArguments => crate::kprintln!("crabshell: too many arguments"),
        ParseError::UnterminatedQuote => crate::kprintln!("crabshell: unterminated text quote"),
    }
}

fn report_fs_error(error: FsError) {
    let message = match error {
        FsError::InvalidPath => "invalid path",
        FsError::InvalidName => "invalid file name",
        FsError::NameTooLong => "file name is too long (maximum 31 UTF-8 bytes)",
        FsError::AlreadyExists => "an entry with that name already exists",
        FsError::NotFound => "path not found",
        FsError::NotDirectory => "a path component is not a directory",
        FsError::IsDirectory => "operation requires a file, not a directory",
        FsError::DirectoryNotEmpty => "directory is not empty",
        FsError::NoSpace => "RAM filesystem is full",
        FsError::FileTooLarge => "file exceeds the 1024-byte limit",
        FsError::RootOperation => "operation is not permitted on the root directory",
        FsError::BufferTooSmall => "path exceeds the display buffer",
    };
    crate::kprintln!("crabshell: {}", message);
}
