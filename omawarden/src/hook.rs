use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn resolve_helper_executable(hint_path: Option<&str>) -> String {
    if let Some(h) = hint_path {
        return h.to_string();
    }

    let xdg_config = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });

    let standard_omawarden = xdg_config
        .join("omarchy")
        .join("plugins")
        .join("icyleaf.bitwarden")
        .join("bin")
        .join("omawarden");
    if standard_omawarden.exists() {
        return standard_omawarden.to_string_lossy().to_string();
    }

    let standard_helper = xdg_config
        .join("omarchy")
        .join("plugins")
        .join("icyleaf.bitwarden")
        .join("bin")
        .join("bitwarden-helper");
    if standard_helper.exists() {
        return standard_helper.to_string_lossy().to_string();
    }

    if let Ok(current_exe) = env::current_exe() {
        if current_exe.is_file() {
            return current_exe.to_string_lossy().to_string();
        }
    }

    if let Ok(found) = which::which("omawarden") {
        return found.to_string_lossy().to_string();
    }

    if let Ok(found) = which::which("bitwarden-helper") {
        return found.to_string_lossy().to_string();
    }

    "omawarden".to_string()
}

pub fn get_lock_hook_script(helper_path: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# Auto-lock Bitwarden vault on system lock
{} auth lock >/dev/null 2>&1 || true
"#,
        helper_path
    )
}

pub fn install_lock_hook(
    helper_path: Option<&str>,
    hooks_base_dir: Option<&Path>,
) -> std::io::Result<PathBuf> {
    let resolved_helper = resolve_helper_executable(helper_path);

    let base_dir = match hooks_base_dir {
        Some(p) => p.to_path_buf(),
        None => {
            let xdg_config = env::var("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    PathBuf::from(home).join(".config")
                });
            xdg_config.join("omarchy").join("hooks")
        }
    };

    let hook_dest_dir = base_dir.join("system-lock.d");
    fs::create_dir_all(&hook_dest_dir)?;

    let hook_file = hook_dest_dir.join("99-bitwarden-lock.sh");
    let content = get_lock_hook_script(&resolved_helper);

    fs::write(&hook_file, content)?;
    let mut perms = fs::metadata(&hook_file)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_file, perms)?;

    Ok(hook_file)
}
