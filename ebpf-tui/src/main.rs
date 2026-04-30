mod discovery;
mod runner;
mod ui;

use anyhow::Context;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    path::PathBuf,
    sync::{mpsc, Arc, atomic::AtomicBool},
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Repo root with eBPF examples (defaults to current directory)
    #[arg(long)]
    repo_root: Option<PathBuf>,

    /// Command used to stream kernel trace (captured during test)
    #[arg(long, default_value = "sudo -n cat /sys/kernel/tracing/trace_pipe")]
    trace_cmd: String,

    /// Where to store artifacts/logs
    #[arg(long, default_value = "artifacts")]
    artifacts_dir: PathBuf,

    /// Optional YAML config file (overrides defaults)
    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let repo_root = resolve_repo_root(args.repo_root)
        .context("resolve repo root")?;

    let config = ui::load_config(args.config.as_deref(), &repo_root)?;
    let trace_cmd = config.trace_cmd.unwrap_or(args.trace_cmd);
    let artifacts_dir = repo_root.join(config.artifacts_dir.unwrap_or(args.artifacts_dir));

    let programs = discovery::discover_programs(&repo_root)?;
    if programs.is_empty() {
        anyhow::bail!(
            "No programs discovered under {} (expected folders like 01_BPF_PROG_TYPE_*).\n\nHint: if you run from ebpf-tui/, use: cargo run --release -- --repo-root ..",
            repo_root.display()
        );
    }

    let (tx, rx) = mpsc::channel();

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alt screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let trace_stop_flag = Arc::new(AtomicBool::new(false));
    runner::spawn_global_trace(
        tx.clone(),
        trace_stop_flag.clone(),
        trace_cmd.clone(),
        artifacts_dir.clone(),
    );

    let mut app = ui::App::new(
        repo_root,
        programs,
        trace_cmd,
        artifacts_dir,
        tx,
        trace_stop_flag,
    );

    let res = run_app(&mut terminal, &mut app, rx);

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    res
}

fn resolve_repo_root(cli_value: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(v) = cli_value {
        return Ok(v);
    }

    let cwd = std::env::current_dir().context("get current dir")?;

    // Common case: launched directly from ebpf-tui/, examples are one level above.
    if cwd
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s == "ebpf-tui")
        .unwrap_or(false)
    {
        if let Some(parent) = cwd.parent() {
            return Ok(parent.to_path_buf());
        }
    }

    if looks_like_repo_root(&cwd) {
        return Ok(cwd.clone());
    }

    // If user runs from ebpf-tui/ (or any subfolder), try to locate a parent directory
    // that contains CGROUP_* / BPF_PROG_TYPE_* examples.
    for candidate in cwd.ancestors() {
        if looks_like_repo_root(candidate) {
            return Ok(candidate.to_path_buf());
        }
    }

    // Also try path relative to the source tree where this binary was built.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(parent) = manifest_dir.parent() {
        if looks_like_repo_root(parent) {
            return Ok(parent.to_path_buf());
        }
    }

    Ok(cwd)
}

fn looks_like_repo_root(dir: &std::path::Path) -> bool {
    let Ok(iter) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in iter.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let numbered = name
            .get(0..2)
            .and_then(|p| p.parse::<u8>().ok())
            .map(|n| (1..=25).contains(&n) && name.contains("BPF_PROG_TYPE"))
            .unwrap_or(false);

        if name.starts_with("CGROUP_") || name.starts_with("BPF_PROG_TYPE_") || numbered {
            return true;
        }
    }
    false
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut ui::App,
    rx: mpsc::Receiver<runner::RunnerEvent>,
) -> anyhow::Result<()> {
    loop {
        while let Ok(ev) = rx.try_recv() {
            app.apply_runner_event(ev);
        }

        terminal.draw(|frame| ui::render(frame, app))?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') => {
                        app.request_stop();
                        return Ok(());
                    }
                    KeyCode::Up => app.select_prev(),
                    KeyCode::Down => app.select_next(),
                    KeyCode::Char('r') => app.run_selected(),
                    KeyCode::Char('b') => app.build_selected(),
                    KeyCode::Char('l') => app.load_selected(),
                    KeyCode::Char('t') => app.test_selected(),
                    KeyCode::Char('u') => app.unload_selected(),
                    KeyCode::Char('a') => app.run_all(),
                    KeyCode::Char('s') => app.stop_runs(),
                    _ => {}
                },
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}
