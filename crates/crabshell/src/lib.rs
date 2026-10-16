#![no_std]

//! Small, allocation-free command parsing for Rustix's Crabshell.
//!
//! This crate deliberately contains no terminal, filesystem, or kernel code.
//! The same command model can later be driven by a graphical terminal frontend
//! or a userspace process without coupling it to the current serial console.

/// The longest command line accepted by the bootstrap shell, excluding its NUL.
pub const MAX_LINE_LENGTH: usize = 256;

/// Parsed shell operations. The command borrows its path and text from the input
/// line, so parsing needs no allocator and the caller controls all I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command<'a> {
    Help,
    Clear,
    Pwd,
    Meminfo,
    Ls(Option<&'a str>),
    Cd(&'a str),
    Mkdir(&'a str),
    Touch(&'a str),
    Write {
        path: &'a str,
        contents: &'a str,
    },
    Append {
        path: &'a str,
        contents: &'a str,
    },
    Cp {
        source: &'a str,
        destination: &'a str,
    },
    Mv {
        source: &'a str,
        destination: &'a str,
    },
    Cat(&'a str),
    Rm(&'a str),
    Rmdir(&'a str),
}

/// Errors in command syntax. Unknown command names are reported separately so
/// the caller can echo the original name in its diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    UnknownCommand,
    MissingArgument,
    MissingText,
    TooManyArguments,
    UnterminatedQuote,
}

/// Parse one command line. An empty or whitespace-only line returns `Ok(None)`.
///
/// `write` and `append` accept the remaining text verbatim; wrapping the whole
/// text in matching single or double quotes removes those outer quotes. Escape
/// sequences and quoted paths are intentionally not part of this first grammar.
pub fn parse(line: &str) -> Result<Option<Command<'_>>, ParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }

    let (name, rest) = take_word(line).ok_or(ParseError::MissingArgument)?;
    let command = match name {
        "help" => {
            no_arguments(rest)?;
            Command::Help
        }
        "clear" => {
            no_arguments(rest)?;
            Command::Clear
        }
        "pwd" => {
            no_arguments(rest)?;
            Command::Pwd
        }
        "meminfo" => {
            no_arguments(rest)?;
            Command::Meminfo
        }
        "ls" => Command::Ls(optional_path(rest)?),
        "cd" => Command::Cd(one_path(rest)?),
        "mkdir" => Command::Mkdir(one_path(rest)?),
        "touch" => Command::Touch(one_path(rest)?),
        "write" => {
            let (path, contents) = path_and_text(rest)?;
            Command::Write { path, contents }
        }
        "append" => {
            let (path, contents) = path_and_text(rest)?;
            Command::Append { path, contents }
        }
        "cp" => {
            let (source, destination) = two_paths(rest)?;
            Command::Cp {
                source,
                destination,
            }
        }
        "mv" => {
            let (source, destination) = two_paths(rest)?;
            Command::Mv {
                source,
                destination,
            }
        }
        "cat" => Command::Cat(one_path(rest)?),
        "rm" => Command::Rm(one_path(rest)?),
        "rmdir" => Command::Rmdir(one_path(rest)?),
        _ => return Err(ParseError::UnknownCommand),
    };

    Ok(Some(command))
}

fn take_word(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    Some((&input[..end], input[end..].trim_start()))
}

fn no_arguments(rest: &str) -> Result<(), ParseError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(ParseError::TooManyArguments)
    }
}

fn optional_path(rest: &str) -> Result<Option<&str>, ParseError> {
    match take_word(rest) {
        None => Ok(None),
        Some((path, rest)) => {
            no_arguments(rest)?;
            Ok(Some(path))
        }
    }
}

fn one_path(rest: &str) -> Result<&str, ParseError> {
    let (path, rest) = take_word(rest).ok_or(ParseError::MissingArgument)?;
    no_arguments(rest)?;
    Ok(path)
}

fn two_paths(rest: &str) -> Result<(&str, &str), ParseError> {
    let (source, rest) = take_word(rest).ok_or(ParseError::MissingArgument)?;
    let (destination, rest) = take_word(rest).ok_or(ParseError::MissingArgument)?;
    no_arguments(rest)?;
    Ok((source, destination))
}

fn path_and_text(rest: &str) -> Result<(&str, &str), ParseError> {
    let (path, text) = take_word(rest).ok_or(ParseError::MissingArgument)?;
    if text.is_empty() {
        return Err(ParseError::MissingText);
    }

    let first = text.as_bytes()[0];
    if first == b'\'' || first == b'"' {
        if text.len() < 2 || text.as_bytes()[text.len() - 1] != first {
            return Err(ParseError::UnterminatedQuote);
        }
        return Ok((path, &text[1..text.len() - 1]));
    }

    Ok((path, text))
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use super::{parse, Command, ParseError};

    #[test]
    fn blank_lines_are_ignored() {
        assert_eq!(parse(" \t "), Ok(None));
    }

    #[test]
    fn parses_basic_navigation_and_file_commands() {
        assert_eq!(parse("pwd"), Ok(Some(Command::Pwd)));
        assert_eq!(parse("meminfo"), Ok(Some(Command::Meminfo)));
        assert_eq!(parse("ls /home"), Ok(Some(Command::Ls(Some("/home")))));
        assert_eq!(parse("cd .."), Ok(Some(Command::Cd(".."))));
        assert_eq!(
            parse("mkdir /tmp/work"),
            Ok(Some(Command::Mkdir("/tmp/work")))
        );
        assert_eq!(
            parse("touch note.txt"),
            Ok(Some(Command::Touch("note.txt")))
        );
        assert_eq!(parse("cat note.txt"), Ok(Some(Command::Cat("note.txt"))));
        assert_eq!(
            parse("cp note.txt copy.txt"),
            Ok(Some(Command::Cp {
                source: "note.txt",
                destination: "copy.txt",
            }))
        );
        assert_eq!(
            parse("mv copy.txt saved.txt"),
            Ok(Some(Command::Mv {
                source: "copy.txt",
                destination: "saved.txt",
            }))
        );
    }

    #[test]
    fn write_preserves_spaces_and_strips_outer_quotes() {
        assert_eq!(
            parse("write greeting.txt hello from crabshell"),
            Ok(Some(Command::Write {
                path: "greeting.txt",
                contents: "hello from crabshell",
            }))
        );
        assert_eq!(
            parse("append greeting.txt \" again\""),
            Ok(Some(Command::Append {
                path: "greeting.txt",
                contents: " again",
            }))
        );
        assert_eq!(
            parse("write empty.txt \"\""),
            Ok(Some(Command::Write {
                path: "empty.txt",
                contents: "",
            }))
        );
    }

    #[test]
    fn validates_command_arity_and_text() {
        assert_eq!(parse("cd"), Err(ParseError::MissingArgument));
        assert_eq!(parse("pwd now"), Err(ParseError::TooManyArguments));
        assert_eq!(parse("cp only-one"), Err(ParseError::MissingArgument));
        assert_eq!(parse("mv a b c"), Err(ParseError::TooManyArguments));
        assert_eq!(parse("write file"), Err(ParseError::MissingText));
        assert_eq!(
            parse("write file \"unfinished"),
            Err(ParseError::UnterminatedQuote)
        );
        assert_eq!(parse("not-a-command"), Err(ParseError::UnknownCommand));
    }
}
