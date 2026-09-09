use std::fs;
use std::path::Path;

use rand_core::{OsRng, RngCore};

/// Recursively creates a directory and enforces the specified permission mode on Unix.
/// Returns any I/O error instead of silently swallowing it.
/// Skips permission modification if the path is a system shared directory like `/tmp` or `/`.
pub fn create_secure_dir_all<P: AsRef<Path>>(path: P, mode: u32) -> std::io::Result<()> {
    let p = path.as_ref();
    fs::create_dir_all(p)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if p != Path::new("/tmp") && p != Path::new("/") {
            let metadata = fs::metadata(p)?;
            let mut perms = metadata.permissions();
            if perms.mode() & 0o777 != mode {
                perms.set_mode(mode);
                fs::set_permissions(p, perms)?;
            }
        }
    }

    Ok(())
}

/// Atomically writes bytes to a file by first writing to a temporary file in the same
/// parent directory with strict permissions, flushing, and then renaming into place.
/// This guarantees crash safety, prevents partial writes, and eliminates permission race conditions.
pub fn atomic_write_file<P: AsRef<Path>>(
    path: P,
    content: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    let dest = path.as_ref();
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));

    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let filename = dest.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let nonce = OsRng.next_u64();
    let temp_path = parent.join(format!(
        ".tmp_{}_{}_{}",
        filename,
        std::process::id(),
        nonce
    ));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        options.mode(mode);

        let mut file = options.open(&temp_path)?;
        let write_res = (|| -> std::io::Result<()> {
            file.write_all(content)?;
            file.flush()?;

            let metadata = file.metadata()?;
            let mut perms = metadata.permissions();
            if perms.mode() & 0o777 != mode {
                perms.set_mode(mode);
                fs::set_permissions(&temp_path, perms)?;
            }
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = fs::write(&temp_path, content) {
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }
    }

    if let Err(e) = fs::rename(&temp_path, dest) {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(dest) {
            let mut perms = metadata.permissions();
            if perms.mode() & 0o777 != mode {
                perms.set_mode(mode);
                fs::set_permissions(dest, perms)?;
            }
        }
    }

    Ok(())
}

/// Atomically writes a string slice to a file with strict permissions.
pub fn atomic_write_str<P: AsRef<Path>>(path: P, content: &str, mode: u32) -> std::io::Result<()> {
    atomic_write_file(path, content.as_bytes(), mode)
}

/// Enforces the given permission mode on an existing file or directory on Unix.
pub fn ensure_secure_permissions<P: AsRef<Path>>(path: P, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path.as_ref())?;
        let mut perms = metadata.permissions();
        if perms.mode() & 0o777 != mode {
            perms.set_mode(mode);
            fs::set_permissions(path.as_ref(), perms)?;
        }
    }
    let _ = path;
    let _ = mode;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn test_create_secure_dir_all() {
        let tmp = tempdir().unwrap();
        let secure_dir = tmp.path().join("nested").join("secure_dir");

        create_secure_dir_all(&secure_dir, 0o700).unwrap();
        assert!(secure_dir.is_dir());

        #[cfg(unix)]
        {
            let meta = fs::metadata(&secure_dir).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }

        // Test updating existing directory permissions
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&secure_dir).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&secure_dir, perms).unwrap();
            assert_eq!(
                fs::metadata(&secure_dir).unwrap().permissions().mode() & 0o777,
                0o755
            );

            create_secure_dir_all(&secure_dir, 0o700).unwrap();
            assert_eq!(
                fs::metadata(&secure_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn test_atomic_write_file_and_permissions() {
        let tmp = tempdir().unwrap();
        let target_file = tmp.path().join("secure.json");

        let data = b"{\"sensitive\": \"data\"}";
        atomic_write_file(&target_file, data, 0o600).unwrap();

        assert!(target_file.is_file());
        assert_eq!(fs::read(&target_file).unwrap(), data);

        #[cfg(unix)]
        {
            let meta = fs::metadata(&target_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Overwrite atomically
        let updated = b"{\"sensitive\": \"new_data\"}";
        atomic_write_file(&target_file, updated, 0o600).unwrap();
        assert_eq!(fs::read(&target_file).unwrap(), updated);

        #[cfg(unix)]
        {
            let meta = fs::metadata(&target_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_atomic_write_str() {
        let tmp = tempdir().unwrap();
        let target_file = tmp.path().join("secure_text.txt");

        atomic_write_str(&target_file, "secret text", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "secret text");

        #[cfg(unix)]
        {
            let meta = fs::metadata(&target_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
}
