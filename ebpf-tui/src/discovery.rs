use anyhow::Context;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Program {
    pub name: String,
    pub dir: PathBuf,
}

pub fn discover_programs(repo_root: &Path) -> anyhow::Result<Vec<Program>> {
    let mut programs = Vec::new();
    let mut child_dirs: Vec<PathBuf> = Vec::new();

    for entry in std::fs::read_dir(repo_root).context("read repo root")? {
        let entry = entry.context("read dir entry")?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        child_dirs.push(path.clone());

        let folder_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };

        if !looks_like_module_dir(folder_name) {
            continue;
        }

        programs.push(Program {
            name: folder_name.to_string(),
            dir: path.clone(),
        });
    }

    // Fallback: examples can be located under a first-level subdirectory
    // (for example: <repo_root>/eBPF_end_documentation/01_BPF_PROG_TYPE_*).
    if programs.is_empty() {
        for base in child_dirs {
            for entry in std::fs::read_dir(&base)
                .with_context(|| format!("read {}", base.display()))?
            {
                let entry = entry.context("read nested dir entry")?;
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                let folder_name = match path.file_name().and_then(|s| s.to_str()) {
                    Some(s) => s,
                    None => continue,
                };

                if !looks_like_module_dir(folder_name) {
                    continue;
                }

                let rel = path
                    .strip_prefix(repo_root)
                    .ok()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| folder_name.to_string());

                programs.push(Program {
                    name: rel,
                    dir: path,
                });
            }
        }
    }

    programs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(programs)
}

fn looks_like_module_dir(name: &str) -> bool {
    if name.starts_with("CGROUP_") || name.starts_with("BPF_PROG_TYPE_") {
        return true;
    }

    let Some(prefix) = name.get(0..2) else {
        return false;
    };
    let Ok(n) = prefix.parse::<u8>() else {
        return false;
    };

    (1..=25).contains(&n) && name.contains("BPF_PROG_TYPE")
}
