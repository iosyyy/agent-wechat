//! Detect visible open profile files before official-profile takeover.
use anyhow::{bail, Context, Result};
use std::{collections::BTreeSet, io::ErrorKind, os::unix::fs::MetadataExt, path::Path};

use super::GLOBAL;

const UNVERIFIABLE: &str = "official_profile_exclusivity_unverifiable";

fn inventory(
    path: &Path,
    depth: usize,
    visited: &mut usize,
    ids: &mut BTreeSet<(u64, u64)>,
    owners: &mut BTreeSet<u32>,
) -> Result<()> {
    if depth > 6 || *visited >= 16384 {
        bail!("official_profile_inventory_limit");
    }
    *visited += 1;
    let meta = std::fs::symlink_metadata(path)?;
    if wechat_platform::is_link(&meta) {
        bail!("invalid official profile path");
    }
    owners.insert(meta.uid());
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            inventory(&entry?.path(), depth + 1, visited, ids, owners)?;
        }
    } else if meta.is_file() {
        if ids.len() >= 8192 {
            bail!("official_profile_inventory_limit");
        }
        ids.insert((meta.dev(), meta.ino()));
    }
    Ok(())
}

fn process_uses_profile_uid(process: &Path, owners: &BTreeSet<u32>) -> Result<bool> {
    use std::io::Read;
    let file = std::fs::File::open(process.join("status")).context(UNVERIFIABLE)?;
    let mut status = String::new();
    file.take(64 * 1024 + 1)
        .read_to_string(&mut status)
        .context(UNVERIFIABLE)?;
    if status.len() > 64 * 1024 {
        bail!(UNVERIFIABLE);
    }
    let uids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .context(UNVERIFIABLE)?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context(UNVERIFIABLE)?;
    if uids.len() != 4 {
        bail!(UNVERIFIABLE);
    }
    Ok(uids.iter().any(|uid| owners.contains(uid)))
}

fn allow_uninspectable_process(
    process: &Path,
    error: &std::io::Error,
    owners: &BTreeSet<u32>,
) -> Result<()> {
    if error.kind() == ErrorKind::NotFound && !process.try_exists().context(UNVERIFIABLE)? {
        return Ok(());
    }
    // Other users' root/system processes are normally hidden from an unprivileged
    // daemon. Host lifecycle controls must exclude those users and PID namespaces.
    if error.kind() == ErrorKind::PermissionDenied && !process_uses_profile_uid(process, owners)? {
        return Ok(());
    }
    bail!(UNVERIFIABLE)
}

fn reject_open_profile_at(home: &Path, proc_root: &Path, self_pid: u32) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut owners = BTreeSet::from([unsafe { libc::geteuid() }]);
    let mut visited = 0;
    for path in [home.join(GLOBAL), home.join(format!("{GLOBAL}.crc"))] {
        inventory(&path, 0, &mut visited, &mut ids, &mut owners)?;
    }
    for (index, item) in std::fs::read_dir(home.join("xwechat_files"))?.enumerate() {
        if index >= 4096 {
            bail!("official_profile_inventory_limit");
        }
        let account = item?.path();
        for name in ["db_storage", "config"] {
            let path = account.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => inventory(&path, 0, &mut visited, &mut ids, &mut owners)?,
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    let login = home.join(".xwechat/login");
    if login.try_exists()? {
        inventory(&login, 0, &mut visited, &mut ids, &mut owners)?;
    }
    // Matching inodes also catches a container bind mount with another path spelling.
    for process in std::fs::read_dir(proc_root).context(UNVERIFIABLE)? {
        let process = process.context(UNVERIFIABLE)?;
        let name = process.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let process = process.path();
        let fds = match std::fs::read_dir(process.join("fd")) {
            Ok(fds) => fds,
            Err(error) => {
                allow_uninspectable_process(&process, &error, &owners)?;
                continue;
            }
        };
        for fd in fds {
            let fd = fd.context(UNVERIFIABLE)?;
            match fd.path().metadata() {
                Ok(meta) if ids.contains(&(meta.dev(), meta.ino())) => {
                    bail!("official_profile_in_use");
                }
                Ok(_) => {}
                // A descriptor can close between read_dir and metadata.
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => allow_uninspectable_process(&process, &error, &owners)?,
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn reject_open_profile(home: &Path) -> Result<()> {
    reject_open_profile_at(home, Path::new("/proc"), std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let global = home.join(GLOBAL);
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(&global, b"synthetic identity").unwrap();
        std::fs::write(global.with_extension("crc"), b"synthetic metadata").unwrap();
        std::fs::create_dir_all(home.join("xwechat_files/synthetic/db_storage")).unwrap();
        let proc_root = temp.path().join("proc");
        std::fs::create_dir(&proc_root).unwrap();
        (temp, home, proc_root)
    }

    #[test]
    fn official_profile_guard_rejects_uninspectable_descriptor() {
        use std::os::unix::fs::symlink;
        let (_temp, home, proc_root) = fixture();
        let process = proc_root.join("123");
        let fds = process.join("fd");
        std::fs::create_dir_all(&fds).unwrap();
        symlink("7", fds.join("7")).unwrap();
        assert_eq!(
            reject_open_profile_at(&home, &proc_root, 456)
                .unwrap_err()
                .to_string(),
            "official_profile_exclusivity_unverifiable"
        );
    }

    #[test]
    fn official_profile_guard_matches_inodes_and_ignores_closed_or_own_descriptors() {
        use std::os::unix::fs::symlink;
        let (temp, home, proc_root) = fixture();
        let fds = proc_root.join("123/fd");
        std::fs::create_dir_all(&fds).unwrap();
        let alias = temp.path().join("other-mount-spelling");
        std::fs::hard_link(home.join(GLOBAL), &alias).unwrap();
        symlink(&alias, fds.join("7")).unwrap();
        assert_eq!(
            reject_open_profile_at(&home, &proc_root, 456)
                .unwrap_err()
                .to_string(),
            "official_profile_in_use"
        );
        reject_open_profile_at(&home, &proc_root, 123).unwrap();
        std::fs::remove_file(alias).unwrap();
        reject_open_profile_at(&home, &proc_root, 456).unwrap();
    }

    #[test]
    fn official_profile_guard_requires_same_uid_visibility_but_allows_unrelated_root() {
        let (_temp, _home, proc_root) = fixture();
        let process = proc_root.join("123");
        std::fs::create_dir(&process).unwrap();
        let owners = BTreeSet::from([10001]);
        let denied = std::io::Error::from(ErrorKind::PermissionDenied);
        std::fs::write(process.join("status"), "Name:\tsynthetic\nUid:\t0 0 0 0\n").unwrap();
        allow_uninspectable_process(&process, &denied, &owners).unwrap();
        for uids in ["10001 0 0 0", "0 10001 0 0", "0 0 10001 0", "0 0 0 10001"] {
            std::fs::write(process.join("status"), format!("Uid:\t{uids}\n")).unwrap();
            assert_eq!(
                allow_uninspectable_process(&process, &denied, &owners)
                    .unwrap_err()
                    .to_string(),
                UNVERIFIABLE
            );
        }
        for status in ["", "Uid:\t0 0 0", "Uid:\t0 0 0 0 0", "Uid:\t0 0 0 invalid"] {
            std::fs::write(process.join("status"), status).unwrap();
            assert!(allow_uninspectable_process(&process, &denied, &owners).is_err());
        }
        std::fs::remove_file(process.join("status")).unwrap();
        assert!(allow_uninspectable_process(&process, &denied, &owners).is_err());
        std::fs::remove_dir(&process).unwrap();
        allow_uninspectable_process(
            &process,
            &std::io::Error::from(ErrorKind::NotFound),
            &owners,
        )
        .unwrap();
    }

    #[test]
    fn official_profile_guard_includes_saved_login_files_and_rejects_links() {
        use std::os::unix::fs::symlink;
        let (temp, home, proc_root) = fixture();
        let login = home.join(".xwechat/login/synthetic");
        std::fs::create_dir_all(&login).unwrap();
        let saved = login.join("key_info.dat");
        std::fs::write(&saved, b"synthetic saved credentials").unwrap();
        let fds = proc_root.join("123/fd");
        std::fs::create_dir_all(&fds).unwrap();
        symlink(&saved, fds.join("7")).unwrap();
        assert_eq!(
            reject_open_profile_at(&home, &proc_root, 456)
                .unwrap_err()
                .to_string(),
            "official_profile_in_use"
        );
        std::fs::remove_file(fds.join("7")).unwrap();
        std::fs::remove_file(&saved).unwrap();
        symlink(temp.path().join("external"), &saved).unwrap();
        assert_eq!(
            reject_open_profile_at(&home, &proc_root, 456)
                .unwrap_err()
                .to_string(),
            "invalid official profile path"
        );
    }

    #[test]
    fn official_profile_guard_rejects_config_only_writer() {
        use std::os::unix::fs::symlink;
        let (_temp, home, proc_root) = fixture();
        let config = home.join("xwechat_files/synthetic/config");
        std::fs::create_dir(&config).unwrap();
        let fds = proc_root.join("123/fd");
        std::fs::create_dir_all(&fds).unwrap();
        for name in [
            "login_configv2",
            "login_configv2.crc",
            "rs_config",
            "rs_config.crc",
        ] {
            let path = config.join(name);
            std::fs::write(&path, b"synthetic account configuration").unwrap();
            symlink(&path, fds.join("7")).unwrap();
            assert_eq!(
                reject_open_profile_at(&home, &proc_root, 456)
                    .unwrap_err()
                    .to_string(),
                "official_profile_in_use"
            );
            std::fs::remove_file(fds.join("7")).unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn official_profile_guard_rejects_account_config_symlinks() {
        use std::os::unix::fs::symlink;
        let (temp, home, proc_root) = fixture();
        let config = home.join("xwechat_files/synthetic/config");
        let external = temp.path().join("external");
        std::fs::create_dir(&external).unwrap();
        symlink(&external, &config).unwrap();
        for target_exists in [true, false] {
            if !target_exists {
                std::fs::remove_dir(&external).unwrap();
            }
            assert_eq!(
                reject_open_profile_at(&home, &proc_root, 456)
                    .unwrap_err()
                    .to_string(),
                "invalid official profile path"
            );
        }
    }

    #[test]
    fn official_profile_guard_rejects_uninspectable_same_owner_process() {
        use std::os::unix::fs::MetadataExt;
        let (_temp, home, proc_root) = fixture();
        let process = proc_root.join("123");
        std::fs::create_dir(&process).unwrap();
        let uid = home.metadata().unwrap().uid();
        std::fs::write(
            process.join("status"),
            format!("Name:\tsynthetic\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )
        .unwrap();
        assert_eq!(
            reject_open_profile_at(&home, &proc_root, 456)
                .unwrap_err()
                .to_string(),
            "official_profile_exclusivity_unverifiable"
        );
    }
}
