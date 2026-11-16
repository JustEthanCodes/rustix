//! Fixed-capacity volatile filesystem for the early kernel shell.
//!
//! This is an in-memory namespace only: it has no disk driver, persistence,
//! permissions, timestamps, links, or concurrent access support.

#![allow(clippy::large_stack_arrays)]

/// Root directory node identifier.
pub const ROOT_NODE: usize = 0;
/// Maximum number of nodes, including the root directory.
pub const MAX_NODES: usize = 32;
/// Maximum UTF-8 bytes in one path component.
pub const NAME_CAPACITY: usize = 31;
/// Maximum bytes in one file.
pub const FILE_CAPACITY: usize = 1024;
/// Maximum byte length of an absolute path in this filesystem.
pub const MAX_PATH_CAPACITY: usize = MAX_NODES * (NAME_CAPACITY + 1) + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    InvalidPath,
    InvalidName,
    NameTooLong,
    AlreadyExists,
    NotFound,
    NotDirectory,
    IsDirectory,
    DirectoryNotEmpty,
    NoSpace,
    FileTooLarge,
    RootOperation,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a str,
    pub kind: EntryKind,
    pub size: usize,
}

#[derive(Clone, Copy)]
struct Node {
    used: bool,
    kind: EntryKind,
    parent: usize,
    name: [u8; NAME_CAPACITY],
    name_len: u8,
    data: [u8; FILE_CAPACITY],
    data_len: usize,
}

impl Node {
    const EMPTY: Self = Self {
        used: false,
        kind: EntryKind::File,
        parent: ROOT_NODE,
        name: [0; NAME_CAPACITY],
        name_len: 0,
        data: [0; FILE_CAPACITY],
        data_len: 0,
    };

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len)]).unwrap_or("")
    }
}

/// A small fixed-capacity filesystem suitable for the pre-allocator shell.
pub struct RamFs {
    nodes: [Node; MAX_NODES],
}

impl RamFs {
    /// Construct a filesystem containing only its root directory.
    pub const fn new() -> Self {
        let mut nodes = [Node::EMPTY; MAX_NODES];
        nodes[ROOT_NODE] = Node {
            used: true,
            kind: EntryKind::Directory,
            parent: ROOT_NODE,
            name: [0; NAME_CAPACITY],
            name_len: 0,
            data: [0; FILE_CAPACITY],
            data_len: 0,
        };
        Self { nodes }
    }

    /// Create a starter Unix-like directory tree and return `/home/rustix`.
    pub fn seed_defaults(&mut self) -> Result<usize, FsError> {
        self.create_dir(ROOT_NODE, "bin")?;
        self.create_dir(ROOT_NODE, "dev")?;
        self.create_dir(ROOT_NODE, "etc")?;
        let home = self.create_dir(ROOT_NODE, "home")?;
        self.create_dir(ROOT_NODE, "tmp")?;
        self.create_dir(ROOT_NODE, "var")?;
        let user_home = self.create_dir(home, "rustix")?;
        let motd = self.create_file_path(ROOT_NODE, "/etc/motd")?;
        self.write_file(
            motd,
            b"Welcome to Rustix. Files in this early shell are volatile RAM files.\n",
        )?;
        Ok(user_home)
    }

    /// Resolve a path from a working directory. `/`, repeated separators, `.`
    /// and `..` are handled; every intermediate component must be a directory.
    pub fn resolve(&self, cwd: usize, path: &str) -> Result<usize, FsError> {
        if path.is_empty() {
            return Err(FsError::InvalidPath);
        }
        let mut current = if path.starts_with('/') {
            ROOT_NODE
        } else {
            cwd
        };
        let start = self.node(current)?;
        if start.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }
            if self.node(current)?.kind != EntryKind::Directory {
                return Err(FsError::NotDirectory);
            }
            match component {
                "." => {}
                ".." => current = self.node(current)?.parent,
                name => {
                    current = self.find_child(current, name).ok_or(FsError::NotFound)?;
                }
            }
        }
        // A trailing separator demands a directory (POSIX ENOTDIR semantics):
        // silently resolving `file/` to the file would let `rm file/` delete it.
        if path.ends_with('/') && self.node(current)?.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(current)
    }

    pub fn create_dir(&mut self, parent: usize, name: &str) -> Result<usize, FsError> {
        self.create_node(parent, name, EntryKind::Directory)
    }

    pub fn create_file(&mut self, parent: usize, name: &str) -> Result<usize, FsError> {
        self.create_node(parent, name, EntryKind::File)
    }

    pub fn create_dir_path(&mut self, cwd: usize, path: &str) -> Result<usize, FsError> {
        let (parent_path, name) = split_parent(path)?;
        let parent = self.resolve(cwd, parent_path)?;
        self.create_dir(parent, name)
    }

    pub fn create_file_path(&mut self, cwd: usize, path: &str) -> Result<usize, FsError> {
        let (parent_path, name) = split_parent(path)?;
        let parent = self.resolve(cwd, parent_path)?;
        self.create_file(parent, name)
    }

    /// Return an existing file node or create it if its path does not exist.
    pub fn open_or_create_file(&mut self, cwd: usize, path: &str) -> Result<usize, FsError> {
        match self.resolve(cwd, path) {
            Ok(node) => {
                if self.node(node)?.kind == EntryKind::Directory {
                    Err(FsError::IsDirectory)
                } else {
                    Ok(node)
                }
            }
            Err(FsError::NotFound) => self.create_file_path(cwd, path),
            Err(error) => Err(error),
        }
    }

    pub fn kind(&self, node: usize) -> Result<EntryKind, FsError> {
        Ok(self.node(node)?.kind)
    }

    pub fn read_file(&self, node: usize) -> Result<&[u8], FsError> {
        let node = self.node(node)?;
        if node.kind == EntryKind::Directory {
            return Err(FsError::IsDirectory);
        }
        Ok(&node.data[..node.data_len])
    }

    pub fn write_file(&mut self, node: usize, contents: &[u8]) -> Result<(), FsError> {
        if contents.len() > FILE_CAPACITY {
            return Err(FsError::FileTooLarge);
        }
        let node = self.node_mut(node)?;
        if node.kind == EntryKind::Directory {
            return Err(FsError::IsDirectory);
        }
        node.data[..contents.len()].copy_from_slice(contents);
        node.data[contents.len()..].fill(0);
        node.data_len = contents.len();
        Ok(())
    }

    pub fn write_file_path(
        &mut self,
        cwd: usize,
        path: &str,
        contents: &[u8],
    ) -> Result<(), FsError> {
        if contents.len() > FILE_CAPACITY {
            return Err(FsError::FileTooLarge);
        }
        let node = self.open_or_create_file(cwd, path)?;
        self.write_file(node, contents)
    }

    pub fn append_file(&mut self, node: usize, contents: &[u8]) -> Result<(), FsError> {
        let node = self.node_mut(node)?;
        if node.kind == EntryKind::Directory {
            return Err(FsError::IsDirectory);
        }
        let new_len = node
            .data_len
            .checked_add(contents.len())
            .filter(|length| *length <= FILE_CAPACITY)
            .ok_or(FsError::FileTooLarge)?;
        node.data[node.data_len..new_len].copy_from_slice(contents);
        node.data_len = new_len;
        Ok(())
    }

    pub fn append_file_path(
        &mut self,
        cwd: usize,
        path: &str,
        contents: &[u8],
    ) -> Result<(), FsError> {
        if contents.len() > FILE_CAPACITY {
            return Err(FsError::FileTooLarge);
        }
        // Pre-check the cumulative bound so a failing append neither creates a
        // node nor leaves a file in a surprising state.
        if let Ok(node) = self.resolve(cwd, path) {
            if self.node(node)?.kind == EntryKind::Directory {
                return Err(FsError::IsDirectory);
            }
            let data_len = self.node(node)?.data_len;
            data_len
                .checked_add(contents.len())
                .filter(|length| *length <= FILE_CAPACITY)
                .ok_or(FsError::FileTooLarge)?;
        }
        let node = self.open_or_create_file(cwd, path)?;
        self.append_file(node, contents)
    }

    /// Copy a file to a destination path, replacing an existing destination
    /// file. If the destination resolves to an existing directory, the file is
    /// copied into it under the source's base name.
    pub fn copy_file_path(
        &mut self,
        cwd: usize,
        source_path: &str,
        destination_path: &str,
    ) -> Result<(), FsError> {
        let source = self.resolve(cwd, source_path)?;
        let mut contents = [0u8; FILE_CAPACITY];
        let length = {
            let source_contents = self.read_file(source)?;
            contents[..source_contents.len()].copy_from_slice(source_contents);
            source_contents.len()
        };
        let destination = match self.resolve(cwd, destination_path) {
            Ok(node) if self.node(node)?.kind == EntryKind::Directory => {
                let base = split_parent(source_path)?.1;
                self.open_or_create_file(node, base)?
            }
            // A trailing separator on a nonexistent destination is an error
            // (POSIX ENOTDIR), not a create-at-path.
            Err(FsError::NotFound) if destination_path.ends_with('/') => {
                return Err(FsError::NotDirectory)
            }
            Ok(_) | Err(FsError::NotFound) => self.open_or_create_file(cwd, destination_path)?,
            Err(error) => return Err(error),
        };
        self.write_file(destination, &contents[..length])
    }

    /// Move or rename a file. Existing destinations are never overwritten. If
    /// the destination resolves to an existing directory, the file is moved
    /// into it under the source's base name.
    pub fn move_file_path(
        &mut self,
        cwd: usize,
        source_path: &str,
        destination_path: &str,
    ) -> Result<(), FsError> {
        let source = self.resolve(cwd, source_path)?;
        if source == ROOT_NODE {
            return Err(FsError::RootOperation);
        }
        if self.kind(source)? == EntryKind::Directory {
            return Err(FsError::IsDirectory);
        }

        // The destination may name a file path or an existing directory to move
        // into; both reuse the never-overwrite logic below.
        let (parent, name) = match self.resolve(cwd, destination_path) {
            Ok(node) if self.node(node)?.kind == EntryKind::Directory => {
                (node, split_parent(source_path)?.1)
            }
            // A trailing separator on a nonexistent destination is an error
            // (POSIX ENOTDIR), not a move-at-path.
            Err(FsError::NotFound) if destination_path.ends_with('/') => {
                return Err(FsError::NotDirectory)
            }
            Ok(_) | Err(FsError::NotFound) => {
                let (parent_path, name) = split_parent(destination_path)?;
                let parent = self.resolve(cwd, parent_path)?;
                if self.node(parent)?.kind != EntryKind::Directory {
                    return Err(FsError::NotDirectory);
                }
                (parent, name)
            }
            Err(error) => return Err(error),
        };
        validate_name(name)?;
        if let Some(existing) = self.find_child(parent, name) {
            return if existing == source {
                Ok(())
            } else {
                Err(FsError::AlreadyExists)
            };
        }

        let node = self.node_mut(source)?;
        node.parent = parent;
        node.name.fill(0);
        node.name[..name.len()].copy_from_slice(name.as_bytes());
        node.name_len = name.len() as u8;
        Ok(())
    }

    pub fn remove_file(&mut self, node: usize) -> Result<(), FsError> {
        if node == ROOT_NODE {
            return Err(FsError::RootOperation);
        }
        let entry = self.node(node)?;
        if entry.kind == EntryKind::Directory {
            return Err(FsError::IsDirectory);
        }
        self.nodes[node] = Node::EMPTY;
        Ok(())
    }

    pub fn remove_dir(&mut self, node: usize) -> Result<(), FsError> {
        if node == ROOT_NODE {
            return Err(FsError::RootOperation);
        }
        let entry = self.node(node)?;
        if entry.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if self
            .nodes
            .iter()
            .any(|child| child.used && child.parent == node)
        {
            return Err(FsError::DirectoryNotEmpty);
        }
        self.nodes[node] = Node::EMPTY;
        Ok(())
    }

    pub fn remove_file_path(&mut self, cwd: usize, path: &str) -> Result<(), FsError> {
        let node = self.resolve(cwd, path)?;
        self.remove_file(node)
    }

    pub fn remove_dir_path(&mut self, cwd: usize, path: &str) -> Result<(), FsError> {
        let node = self.resolve(cwd, path)?;
        self.remove_dir(node)
    }

    pub fn entry(&self, node: usize) -> Result<Entry<'_>, FsError> {
        let node = self.node(node)?;
        Ok(Entry {
            name: node.name(),
            kind: node.kind,
            size: node.data_len,
        })
    }

    pub fn child_count(&self, directory: usize) -> Result<usize, FsError> {
        if self.node(directory)?.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(self
            .nodes
            .iter()
            .filter(|node| {
                node.used
                    && node.parent == directory
                    && !(directory == ROOT_NODE && node.name_len == 0)
            })
            .count())
    }

    pub fn child_at(&self, directory: usize, ordinal: usize) -> Option<Entry<'_>> {
        if self.node(directory).ok()?.kind != EntryKind::Directory {
            return None;
        }
        self.nodes
            .iter()
            .filter(|node| {
                node.used
                    && node.parent == directory
                    && !(directory == ROOT_NODE && node.name_len == 0)
            })
            .nth(ordinal)
            .map(|node| Entry {
                name: node.name(),
                kind: node.kind,
                size: node.data_len,
            })
    }

    /// Write an absolute path into caller-provided storage and return its length.
    pub fn write_path(&self, node: usize, output: &mut [u8]) -> Result<usize, FsError> {
        self.node(node)?;
        let mut ancestors = [ROOT_NODE; MAX_NODES];
        let mut depth = 0;
        let mut current = node;
        while current != ROOT_NODE {
            if depth == MAX_NODES {
                return Err(FsError::InvalidPath);
            }
            ancestors[depth] = current;
            depth += 1;
            current = self.node(current)?.parent;
        }

        let component_bytes = (0..depth)
            .map(|index| usize::from(self.nodes[ancestors[index]].name_len))
            .sum::<usize>();
        let required = 1 + component_bytes + depth.saturating_sub(1);
        if output.len() < required {
            return Err(FsError::BufferTooSmall);
        }

        output[0] = b'/';
        let mut length = 1;
        for index in (0..depth).rev() {
            if length > 1 {
                output[length] = b'/';
                length += 1;
            }
            let name = self.nodes[ancestors[index]].name();
            output[length..length + name.len()].copy_from_slice(name.as_bytes());
            length += name.len();
        }
        Ok(length)
    }

    fn create_node(
        &mut self,
        parent: usize,
        name: &str,
        kind: EntryKind,
    ) -> Result<usize, FsError> {
        let parent_node = self.node(parent)?;
        if parent_node.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        validate_name(name)?;
        if self.find_child(parent, name).is_some() {
            return Err(FsError::AlreadyExists);
        }
        let index = self
            .nodes
            .iter()
            .position(|node| !node.used)
            .ok_or(FsError::NoSpace)?;
        let mut node = Node::EMPTY;
        node.used = true;
        node.kind = kind;
        node.parent = parent;
        node.name[..name.len()].copy_from_slice(name.as_bytes());
        node.name_len = name.len() as u8;
        self.nodes[index] = node;
        Ok(index)
    }

    fn find_child(&self, parent: usize, name: &str) -> Option<usize> {
        self.nodes.iter().position(|node| {
            node.used && node.parent == parent && node.name_len != 0 && node.name() == name
        })
    }

    fn node(&self, index: usize) -> Result<&Node, FsError> {
        self.nodes
            .get(index)
            .filter(|node| node.used)
            .ok_or(FsError::NotFound)
    }

    fn node_mut(&mut self, index: usize) -> Result<&mut Node, FsError> {
        self.nodes
            .get_mut(index)
            .filter(|node| node.used)
            .ok_or(FsError::NotFound)
    }
}

impl Default for RamFs {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_name(name: &str) -> Result<(), FsError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(FsError::InvalidName);
    }
    if name.len() > NAME_CAPACITY {
        return Err(FsError::NameTooLong);
    }
    Ok(())
}

fn split_parent(path: &str) -> Result<(&str, &str), FsError> {
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(FsError::RootOperation);
    }
    match path.rsplit_once('/') {
        Some(("", name)) => Ok(("/", name)),
        Some((parent, name)) if !name.is_empty() => Ok((parent, name)),
        Some(_) => Err(FsError::InvalidPath),
        None => Ok((".", path)),
    }
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use super::{EntryKind, FsError, RamFs, FILE_CAPACITY, MAX_NODES, ROOT_NODE};

    #[test]
    fn resolves_absolute_relative_and_parent_components() {
        let mut fs = RamFs::new();
        let home = fs.create_dir(ROOT_NODE, "home").unwrap();
        let user = fs.create_dir(home, "rustix").unwrap();
        let notes = fs.create_dir(user, "notes").unwrap();

        assert_eq!(fs.resolve(user, ".").unwrap(), user);
        assert_eq!(fs.resolve(notes, "../..").unwrap(), home);
        assert_eq!(fs.resolve(ROOT_NODE, "/home/rustix/notes/").unwrap(), notes);
    }

    #[test]
    fn creates_reads_appends_and_removes_files() {
        let mut fs = RamFs::new();
        fs.write_file_path(ROOT_NODE, "/note.txt", b"hello")
            .unwrap();
        fs.append_file_path(ROOT_NODE, "/note.txt", b" rustix")
            .unwrap();
        let file = fs.resolve(ROOT_NODE, "/note.txt").unwrap();
        assert_eq!(fs.read_file(file).unwrap(), b"hello rustix");
        fs.remove_file_path(ROOT_NODE, "/note.txt").unwrap();
        assert_eq!(fs.resolve(ROOT_NODE, "/note.txt"), Err(FsError::NotFound));
    }

    #[test]
    fn oversized_path_writes_and_appends_do_not_create_files_or_consume_nodes() {
        let mut fs = RamFs::new();
        let oversized = [0u8; FILE_CAPACITY + 1];

        for _ in 0..3 {
            assert_eq!(
                fs.write_file_path(ROOT_NODE, "/oversized-write", &oversized),
                Err(FsError::FileTooLarge)
            );
            assert_eq!(
                fs.append_file_path(ROOT_NODE, "/oversized-append", &oversized),
                Err(FsError::FileTooLarge)
            );
        }
        assert_eq!(
            fs.resolve(ROOT_NODE, "/oversized-write"),
            Err(FsError::NotFound)
        );
        assert_eq!(
            fs.resolve(ROOT_NODE, "/oversized-append"),
            Err(FsError::NotFound)
        );

        let names = [
            "entry-00", "entry-01", "entry-02", "entry-03", "entry-04", "entry-05", "entry-06",
            "entry-07", "entry-08", "entry-09", "entry-10", "entry-11", "entry-12", "entry-13",
            "entry-14", "entry-15", "entry-16", "entry-17", "entry-18", "entry-19", "entry-20",
            "entry-21", "entry-22", "entry-23", "entry-24", "entry-25", "entry-26", "entry-27",
            "entry-28", "entry-29", "entry-30",
        ];
        assert_eq!(names.len(), MAX_NODES - 1);
        for name in names {
            fs.create_file(ROOT_NODE, name).unwrap();
        }
        assert_eq!(fs.create_file(ROOT_NODE, "full"), Err(FsError::NoSpace));
    }

    #[test]
    fn path_write_and_append_preserve_existing_file_on_capacity_failure() {
        let mut fs = RamFs::new();
        let file = fs.create_file_path(ROOT_NODE, "/saved").unwrap();
        fs.write_file(file, b"kept").unwrap();
        let oversized = [0u8; FILE_CAPACITY + 1];
        assert_eq!(
            fs.write_file_path(ROOT_NODE, "/saved", &oversized),
            Err(FsError::FileTooLarge)
        );
        assert_eq!(
            fs.append_file_path(ROOT_NODE, "/saved", &oversized),
            Err(FsError::FileTooLarge)
        );
        assert_eq!(fs.read_file(file), Ok(&b"kept"[..]));
    }

    #[test]
    fn copy_replaces_destination_while_move_refuses_to_overwrite() {
        let mut fs = RamFs::new();
        let source = fs.create_file_path(ROOT_NODE, "/source.txt").unwrap();
        fs.write_file(source, b"data").unwrap();

        fs.copy_file_path(ROOT_NODE, "/source.txt", "/copy.txt")
            .unwrap();
        assert_eq!(
            fs.read_file(fs.resolve(ROOT_NODE, "/copy.txt").unwrap()),
            Ok(&b"data"[..])
        );

        let existing = fs.create_file_path(ROOT_NODE, "/existing.txt").unwrap();
        fs.write_file(existing, b"old contents").unwrap();
        fs.copy_file_path(ROOT_NODE, "/source.txt", "/existing.txt")
            .unwrap();
        assert_eq!(fs.read_file(existing), Ok(&b"data"[..]));

        fs.move_file_path(ROOT_NODE, "/copy.txt", "/saved.txt")
            .unwrap();
        assert_eq!(fs.resolve(ROOT_NODE, "/copy.txt"), Err(FsError::NotFound));
        assert_eq!(
            fs.read_file(fs.resolve(ROOT_NODE, "/saved.txt").unwrap()),
            Ok(&b"data"[..])
        );
        assert_eq!(
            fs.move_file_path(ROOT_NODE, "/source.txt", "/saved.txt"),
            Err(FsError::AlreadyExists)
        );
    }

    #[test]
    fn refuses_to_remove_nonempty_directories() {
        let mut fs = RamFs::new();
        let directory = fs.create_dir(ROOT_NODE, "work").unwrap();
        fs.create_file(directory, "note").unwrap();
        assert_eq!(fs.remove_dir(directory), Err(FsError::DirectoryNotEmpty));
    }

    #[test]
    fn trailing_separator_requires_a_directory() {
        let mut fs = RamFs::new();
        fs.write_file_path(ROOT_NODE, "/note.txt", b"data").unwrap();

        assert_eq!(
            fs.resolve(ROOT_NODE, "/note.txt/"),
            Err(FsError::NotDirectory)
        );
        assert_eq!(
            fs.remove_file_path(ROOT_NODE, "/note.txt/"),
            Err(FsError::NotDirectory)
        );
        assert_eq!(
            fs.write_file_path(ROOT_NODE, "/note.txt/", b"clobber"),
            Err(FsError::NotDirectory)
        );
        // Existing file contents must be preserved.
        let file = fs.resolve(ROOT_NODE, "/note.txt").unwrap();
        assert_eq!(fs.read_file(file).unwrap(), b"data");

        let directory = fs.create_dir(ROOT_NODE, "work").unwrap();
        assert_eq!(fs.resolve(ROOT_NODE, "/work/").unwrap(), directory);

        // A trailing separator on a nonexistent destination is ENOTDIR, not a
        // create at the trimmed path.
        assert_eq!(
            fs.copy_file_path(ROOT_NODE, "/note.txt", "/missing/"),
            Err(FsError::NotDirectory)
        );
        assert_eq!(
            fs.move_file_path(ROOT_NODE, "/note.txt", "/missing/"),
            Err(FsError::NotDirectory)
        );
    }

    #[test]
    fn copy_and_move_into_an_existing_directory() {
        let mut fs = RamFs::new();
        let source = fs.create_file_path(ROOT_NODE, "/source.txt").unwrap();
        fs.write_file(source, b"data").unwrap();
        let dest_dir = fs.create_dir(ROOT_NODE, "destdir").unwrap();

        fs.copy_file_path(ROOT_NODE, "/source.txt", "/destdir")
            .unwrap();
        let copied = fs.resolve(dest_dir, "source.txt").unwrap();
        assert_eq!(fs.read_file(copied).unwrap(), b"data");
        // copy with a trailing separator also lands inside the directory
        fs.copy_file_path(ROOT_NODE, "/source.txt", "/destdir/")
            .unwrap();
        assert_eq!(fs.read_file(copied).unwrap(), b"data");

        // mv never overwrites an existing target, even inside a directory
        assert_eq!(
            fs.move_file_path(ROOT_NODE, "/source.txt", "/destdir/"),
            Err(FsError::AlreadyExists)
        );

        // mv succeeds into a directory when the target name is free
        let incoming = fs.create_dir(ROOT_NODE, "incoming").unwrap();
        fs.move_file_path(ROOT_NODE, "/source.txt", "/incoming/")
            .unwrap();
        assert_eq!(fs.resolve(ROOT_NODE, "/source.txt"), Err(FsError::NotFound));
        assert_eq!(
            fs.read_file(fs.resolve(incoming, "source.txt").unwrap())
                .unwrap(),
            b"data"
        );

        // mv a file onto itself is a no-op
        let moved = fs.resolve(incoming, "source.txt").unwrap();
        fs.move_file_path(ROOT_NODE, "/incoming/source.txt", "/incoming/source.txt")
            .unwrap();
        assert_eq!(fs.kind(moved), Ok(EntryKind::File));
    }

    #[test]
    fn append_prechecks_cumulative_capacity_before_touching_nodes() {
        let mut fs = RamFs::new();
        let file = fs.create_file_path(ROOT_NODE, "/fill").unwrap();
        fs.write_file(file, &[b'x'; FILE_CAPACITY]).unwrap();
        // Filling the file must not accept a single extra byte.
        assert_eq!(
            fs.append_file_path(ROOT_NODE, "/fill", b"y"),
            Err(FsError::FileTooLarge)
        );
        assert_eq!(fs.read_file(file).unwrap().len(), FILE_CAPACITY);

        // Fill a file to exactly the limit, then overflow it via the path API;
        // the pre-check must reject before the append mutates anything.
        fs.write_file(file, &[b'z'; FILE_CAPACITY - 4]).unwrap();
        assert_eq!(
            fs.append_file_path(ROOT_NODE, "/fill", b"12345"),
            Err(FsError::FileTooLarge)
        );
        assert_eq!(fs.read_file(file).unwrap(), &[b'z'; FILE_CAPACITY - 4][..]);
    }

    #[test]
    fn path_output_and_kinds_are_consistent() {
        let mut fs = RamFs::new();
        let docs = fs.create_dir_path(ROOT_NODE, "/home").unwrap();
        let file = fs.create_file(docs, "readme").unwrap();
        let mut path = [0; 64];
        let length = fs.write_path(file, &mut path).unwrap();
        assert_eq!(&path[..length], b"/home/readme");
        assert_eq!(fs.kind(docs), Ok(EntryKind::Directory));
        assert_eq!(fs.kind(file), Ok(EntryKind::File));
    }
}
