// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local SP1 verification and synthetic V2 settlement coordination.
//!
//! Neither proof validity nor this local journal authenticates native deposits,
//! consensus selection or withdrawal authority.
pub mod settlement;
pub mod verification;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

/// Reject symlinks at the final path component and non-regular files. The
/// nonblocking flag prevents a raced-in FIFO from hanging before metadata checks.
/// Ancestor directories remain an independently trusted local filesystem path.
pub(crate) fn open_regular(path: &std::path::Path, writable: bool) -> Result<std::fs::File> {
    #[cfg(any(target_os = "macos", all(target_os = "linux", target_arch = "x86_64")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_os = "macos")]
        const FLAGS: i32 = 0x100 | 0x4; // Darwin O_NOFOLLOW | O_NONBLOCK.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        const FLAGS: i32 = 0x20000 | 0x800; // Linux x86_64 O_NOFOLLOW | O_NONBLOCK.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(writable)
            .custom_flags(FLAGS)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(invalid("expected a regular file"));
        }
        Ok(file)
    }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_arch = "x86_64"))))]
    {
        let _ = (path, writable);
        Err(invalid(
            "safe local file opening is implemented only for macOS and Linux x86_64",
        ))
    }
}
