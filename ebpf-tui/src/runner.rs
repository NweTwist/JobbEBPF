use crate::discovery::Program;
use anyhow::{anyhow, Context};
use chrono::Local;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
        Arc, Mutex,
    },
    thread,
};

#[derive(Clone, Debug)]
pub enum ProgramStatus {
    Idle,
    Running(&'static str),
    Success,
    Stopped,
    Failed(String),
    MissingScripts,
}

#[derive(Clone, Debug)]
pub enum RunnerEvent {
    Status { index: usize, status: ProgramStatus },
    Message { text: String },
    LogLine { index: usize, line: String },
    TraceLine { line: String },
    ModuleState { index: usize, attached: Option<bool> },
}

#[derive(Clone, Debug)]
pub struct RunConfig {
    pub trace_cmd: String,
    pub artifacts_dir: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub enum RunAction {
    Auto,
    Build,
    Load,
    Test,
    Unload,
}

impl RunAction {
    fn label(self) -> &'static str {
        match self {
            RunAction::Auto => "auto",
            RunAction::Build => "build",
            RunAction::Load => "load",
            RunAction::Test => "test",
            RunAction::Unload => "unload",
        }
    }
}

pub fn spawn_run_action_selected(
    tx: mpsc::Sender<RunnerEvent>,
    stop_flag: Arc<AtomicBool>,
    index: usize,
    program: Program,
    config: RunConfig,
    action: RunAction,
) {
    thread::spawn(move || {
        if stop_flag.load(Ordering::Relaxed) {
            return;
        }

        let res = match action {
            RunAction::Auto => run_pipeline(&tx, &stop_flag, index, &program, &config),
            _ => run_manual_action(&tx, &stop_flag, index, &program, action),
        };

        handle_run_result(&tx, index, &program, action, res);
    });
}

pub fn spawn_run_all(
    tx: mpsc::Sender<RunnerEvent>,
    stop_flag: Arc<AtomicBool>,
    programs: Vec<Program>,
    config: RunConfig,
) {
    thread::spawn(move || {
        for (index, program) in programs.into_iter().enumerate() {
            if stop_flag.load(Ordering::Relaxed) {
                return;
            }

            let res = run_pipeline(&tx, &stop_flag, index, &program, &config);
            if let Err(err) = res {
                if is_stop_error(&err) {
                    let _ = tx.send(RunnerEvent::Status {
                        index,
                        status: ProgramStatus::Stopped,
                    });
                    let _ = tx.send(RunnerEvent::Message {
                        text: format!("{}: STOPPED", program.name),
                    });
                    return;
                }
                let _ = tx.send(RunnerEvent::Status {
                    index,
                    status: ProgramStatus::Failed(extract_failed_step(&err.to_string())),
                });
                let _ = tx.send(RunnerEvent::Message {
                    text: format!("{}: FAILED: {:#}", program.name, err),
                });
                // continue with next program
            }
        }
    });
}

fn handle_run_result(
    tx: &mpsc::Sender<RunnerEvent>,
    index: usize,
    program: &Program,
    action: RunAction,
    res: anyhow::Result<()>,
) {
    if let Err(err) = res {
        if is_stop_error(&err) {
            let _ = tx.send(RunnerEvent::Status {
                index,
                status: ProgramStatus::Stopped,
            });
            let _ = tx.send(RunnerEvent::Message {
                text: format!("{}: STOPPED", program.name),
            });
            return;
        }
        let failed = match action {
            RunAction::Auto => extract_failed_step(&err.to_string()),
            _ => action.label().to_string(),
        };
        let _ = tx.send(RunnerEvent::Status {
            index,
            status: ProgramStatus::Failed(failed),
        });
        let _ = tx.send(RunnerEvent::Message {
            text: format!("{}: FAILED: {:#}", program.name, err),
        });
    }
}

fn extract_failed_step(err: &str) -> String {
    for step in ["build", "load", "test", "unload"] {
        if err.contains(&format!("{} failed", step)) {
            return step.to_string();
        }
    }

    "pipeline".to_string()
}

fn is_stop_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("Stop requested") || msg.contains("interrupted by stop request")
}

fn run_pipeline(
    tx: &mpsc::Sender<RunnerEvent>,
    stop_flag: &AtomicBool,
    index: usize,
    program: &Program,
    config: &RunConfig,
) -> anyhow::Result<()> {
    let scripts = Scripts::detect(&program.dir);
    let pmi_commands = discover_pmi_commands(&program.dir)?;
    let use_pmi = !scripts.is_complete() && !pmi_commands.is_empty();

    if stop_flag.load(Ordering::Relaxed) {
        return Err(anyhow!("Stop requested"));
    }

    if !scripts.is_complete() && !use_pmi {
        tx.send(RunnerEvent::Status {
            index,
            status: ProgramStatus::MissingScripts,
        })
        .ok();
        return Err(anyhow!(
            "Missing scripts in {} and no PMI markdown commands found",
            program.dir.display()
        ));
    }

    let out_dir = config
        .artifacts_dir
        .join(program.name.replace('/', "__"));
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    tx.send(RunnerEvent::Message {
        text: format!("{}: artifacts -> {}", program.name, out_dir.display()),
    })
    .ok();

    let run_res = if use_pmi {
        tx.send(RunnerEvent::Status {
            index,
            status: ProgramStatus::Running("pmi"),
        })
        .ok();

        match run_pmi_pipeline(tx, stop_flag, index, program, &pmi_commands, &out_dir) {
            Ok(()) => {
                tx.send(RunnerEvent::Status {
                    index,
                    status: ProgramStatus::Success,
                })
                .ok();
                tx.send(RunnerEvent::Message {
                    text: format!("{}: OK (PMI)", program.name),
                })
                .ok();
                Ok(())
            }
            Err(err) => Err(err),
        }
    } else {
        if let Err(err) = run_step(tx, stop_flag, index, program, "build", &scripts.build, &out_dir) {
            Err(err)
        } else if let Err(err) = run_step(tx, stop_flag, index, program, "load", &scripts.load, &out_dir) {
            Err(err)
        } else {
            let test_res = run_step(tx, stop_flag, index, program, "test", &scripts.test, &out_dir);
            // try unload even if test failed
            let unload_res = run_step(tx, stop_flag, index, program, "unload", &scripts.unload, &out_dir);

            match (test_res, unload_res) {
                (Ok(()), Ok(())) => {
                    tx.send(RunnerEvent::Status {
                        index,
                        status: ProgramStatus::Success,
                    })
                    .ok();
                    tx.send(RunnerEvent::Message {
                        text: format!("{}: OK", program.name),
                    })
                    .ok();
                    Ok(())
                }
                (Err(err), _) => Err(err),
                (_, Err(err)) => Err(err),
            }
        }
    };

    let summary = write_status_summary(program, &out_dir, use_pmi, run_res.as_ref().err());
    if let Err(err) = summary {
        tx.send(RunnerEvent::Message {
            text: format!("{}: warn: summary log write failed: {:#}", program.name, err),
        })
        .ok();
    }

    run_res
}

fn run_manual_action(
    tx: &mpsc::Sender<RunnerEvent>,
    stop_flag: &AtomicBool,
    index: usize,
    program: &Program,
    action: RunAction,
) -> anyhow::Result<()> {
    let scripts = Scripts::detect(&program.dir);
    let out_dir = config.artifacts_dir.join(program.name.replace('/', "__"));
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    tx.send(RunnerEvent::Message {
        text: format!("{}: manual action {}", program.name, action.label()),
    })
    .ok();

    let state = ModuleStateFiles::new(&out_dir);

    match action {
        RunAction::Build => {
            run_step_to_log(
                tx,
                stop_flag,
                index,
                program,
                "build",
                &scripts.build,
                &out_dir.join("manual_build.log"),
            )?;
            tx.send(RunnerEvent::Status {
                index,
                status: ProgramStatus::Success,
            })
            .ok();
        }
        RunAction::Load => {
            run_step_to_log(
                tx,
                stop_flag,
                index,
                program,
                "load",
                &scripts.load,
                &out_dir.join("manual_load.log"),
            )?;
            state.set_attached(true)?;
            tx.send(RunnerEvent::ModuleState {
                index,
                attached: Some(true),
            })
            .ok();
            tx.send(RunnerEvent::Status {
                index,
                status: ProgramStatus::Success,
            })
            .ok();
        }
        RunAction::Test => {
            run_step_to_log(
                tx,
                stop_flag,
                index,
                program,
                "test",
                &scripts.test,
                &out_dir.join("manual_test.log"),
            )?;
            tx.send(RunnerEvent::Status {
                index,
                status: ProgramStatus::Success,
            })
            .ok();
        }
        RunAction::Unload => {
            run_step_to_log(
                tx,
                stop_flag,
                index,
                program,
                "unload",
                &scripts.unload,
                &out_dir.join("manual_unload.log"),
            )?;
            state.set_attached(false)?;
            tx.send(RunnerEvent::ModuleState {
                index,
                attached: Some(false),
            })
            .ok();
            tx.send(RunnerEvent::Status {
                index,
                status: ProgramStatus::Success,
            })
            .ok();
        }
        RunAction::Auto => {
            return run_pipeline(tx, stop_flag, index, program, config);
        }
    }

    Ok(())
}

fn kill_process_group(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGTERM);
    }
}


fn send_log_line(tx: &mpsc::Sender<RunnerEvent>, index: usize, line: String) {
    let _ = tx.send(RunnerEvent::LogLine { index, line });
}

fn send_trace_line(tx: &mpsc::Sender<RunnerEvent>, line: String) {
    let _ = tx.send(RunnerEvent::TraceLine { line });
}

fn write_status_summary(
    program: &Program,
    out_dir: &Path,
    use_pmi: bool,
    run_err: Option<&anyhow::Error>,
) -> anyhow::Result<()> {
    let title = if use_pmi {
        "PMI pipeline"
    } else {
        "Script pipeline"
    };
    let result = if run_err.is_some() { "FAIL" } else { "PASS" };
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut status_log = String::new();
    status_log.push_str("====================================\n");
    status_log.push_str(" eBPF TUI STATUS SUMMARY\n");
    status_log.push_str("====================================\n");
    status_log.push_str(&format!("Program : {}\n", program.name));
    status_log.push_str(&format!("Mode    : {}\n", title));
    status_log.push_str(&format!("Result  : {}\n", result));
    status_log.push_str(&format!("Time    : {}\n", now));
    if let Some(err) = run_err {
        status_log.push_str("Error   : ");
        status_log.push_str(&format!("{}\n", err));
    }

    status_log.push_str("\nLogs:\n");
    for name in ["build.log", "load.log", "test.log", "unload.log", "trace.log", "pmi.txt"] {
        let path = out_dir.join(name);
        let mark = if path.exists() { "[x]" } else { "[ ]" };
        status_log.push_str(&format!("{} {}\n", mark, name));
    }

    let status_path = out_dir.join("status.log");
    fs::write(&status_path, status_log.as_bytes())
        .with_context(|| format!("write {}", status_path.display()))?;

    let mut md = String::new();
    md.push_str("# eBPF TUI Run Report\n\n");
    md.push_str(&format!("- Program: `{}`\n", program.name));
    md.push_str(&format!("- Mode: `{}`\n", title));
    md.push_str(&format!("- Result: `{}`\n", result));
    md.push_str(&format!("- Generated: `{}`\n", now));
    if let Some(err) = run_err {
        md.push_str(&format!("- Error: `{}`\n", err));
    }

    md.push_str("\n## Logs\n\n");
    for name in ["build.log", "load.log", "test.log", "unload.log", "trace.log", "pmi.txt", "status.log"] {
        let path = out_dir.join(name);
        if path.exists() {
            md.push_str(&format!("- {}\n", name));
        }
    }

    let report_path = out_dir.join("run_report.md");
    fs::write(&report_path, md.as_bytes())
        .with_context(|| format!("write {}", report_path.display()))?;

    Ok(())
}

fn run_pmi_pipeline(
    tx: &mpsc::Sender<RunnerEvent>,
    stop_flag: &AtomicBool,
    index: usize,
    program: &Program,
    commands: &[String],
    out_dir: &Path,
) -> anyhow::Result<()> {
    let mut merged = String::new();

    for (i, cmd) in commands.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) {
            return Err(anyhow!("Stop requested"));
        }

        let step_name = if i + 1 == commands.len() {
            "run"
        } else {
            "build"
        };
        tx.send(RunnerEvent::Status {
            index,
            status: ProgramStatus::Running(step_name),
        })
        .ok();

        merged.push_str(&format!("$ {}\n", cmd));
        send_log_line(
            tx,
            index,
            format!("$ {}", cmd),
        );

        let result = run_shell_and_stream(
            tx,
            stop_flag,
            index,
            &program.dir,
            cmd,
            None,
        )
        .with_context(|| format!("run pmi command for {}: {}", program.name, cmd))?;

        merged.push_str(&result.output);

        if stop_flag.load(Ordering::Relaxed) {
            let log_path = out_dir.join("pmi.txt");
            fs::write(&log_path, merged.as_bytes())
                .with_context(|| format!("write {}", log_path.display()))?;
            return Err(anyhow!("pmi interrupted by stop request (see {})", log_path.display()));
        }

        if !result.success {
            let log_path = out_dir.join("pmi.txt");
            fs::write(&log_path, merged.as_bytes())
                .with_context(|| format!("write {}", log_path.display()))?;
            return Err(anyhow!("pmi command failed: {} (see {})", cmd, log_path.display()));
        }
    }

    let log_path = out_dir.join("pmi.txt");
    fs::write(&log_path, merged.as_bytes())
        .with_context(|| format!("write {}", log_path.display()))?;

    if !merged.contains("[VERIFY] PASS") {
        return Err(anyhow!(
            "pmi verification failed: missing [VERIFY] PASS (see {})",
            log_path.display()
        ));
    }

    Ok(())
}

fn discover_pmi_commands(dir: &Path) -> anyhow::Result<Vec<String>> {
    let md_path = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with("_Программа_и_методика_испытаний.md"))
                .unwrap_or(false)
        });

    let Some(md_path) = md_path else {
        return Ok(Vec::new());
    };

    let raw = fs::read_to_string(&md_path)
        .with_context(|| format!("read {}", md_path.display()))?;

    let commands = raw
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("bpftool ")
                || line.starts_with("clang ")
                || line.starts_with("gcc ")
                || line.starts_with("./")
                || line.starts_with("\\./")
        })
        .map(|line| line.replace('\\', ""))
        .collect::<Vec<_>>();

    Ok(commands)
}

fn run_step(
    tx: &mpsc::Sender<RunnerEvent>,
    stop_flag: &AtomicBool,
    index: usize,
    program: &Program,
    step: &'static str,
    script: &Path,
    out_dir: &Path,
) -> anyhow::Result<()> {
    let log_path = out_dir.join(format!("{}.log", step));
    run_step_to_log(tx, stop_flag, index, program, step, script, &log_path)
}

fn run_step_to_log(
    tx: &mpsc::Sender<RunnerEvent>,
    stop_flag: &AtomicBool,
    index: usize,
    program: &Program,
    step: &'static str,
    script: &Path,
    log_path: &Path,
) -> anyhow::Result<()> {
    if !script.exists() {
        return Err(anyhow!(
            "missing {} script in {}",
            step,
            program.dir.display()
        ));
    }

    if stop_flag.load(Ordering::Relaxed) {
        return Err(anyhow!("Stop requested"));
    }

    tx.send(RunnerEvent::Status {
        index,
        status: ProgramStatus::Running(step),
    })
    .ok();

    let script_name = script
        .file_name()
        .ok_or_else(|| anyhow!("invalid script path: {}", script.display()))?
        .to_string_lossy();
    let command = format!("chmod +x '{}' && './{}'", script.display(), script_name);

    let result = run_shell_and_stream(
        tx,
        stop_flag,
        index,
        &program.dir,
        &command,
        Some(step),
    )
    .with_context(|| format!("run {} for {}", step, program.name))?;

    let mut file = fs::File::create(log_path)
        .with_context(|| format!("create log {}", log_path.display()))?;
    file.write_all(result.output.as_bytes()).ok();

    if stop_flag.load(Ordering::Relaxed) {
        return Err(anyhow!("{} interrupted by stop request (see {})", step, log_path.display()));
    }

    if !result.success {
        return Err(anyhow!("{} failed (see {})", step, log_path.display()));
    }

    Ok(())
}

struct ModuleStateFiles {
    attached_flag: PathBuf,
}

impl ModuleStateFiles {
    fn new(out_dir: &Path) -> Self {
        Self {
            attached_flag: out_dir.join(".attached"),
        }
    }

    fn set_attached(&self, attached: bool) -> anyhow::Result<()> {
        if attached {
            fs::write(&self.attached_flag, b"attached\n")
                .with_context(|| format!("write {}", self.attached_flag.display()))?;
        } else if self.attached_flag.exists() {
            fs::remove_file(&self.attached_flag)
                .with_context(|| format!("remove {}", self.attached_flag.display()))?;
        }
        Ok(())
    }
}

fn run_shell_and_stream(
    tx: &mpsc::Sender<RunnerEvent>,
    stop_flag: &AtomicBool,
    index: usize,
    current_dir: &Path,
    command: &str,
    step: Option<&'static str>,
) -> anyhow::Result<CommandResult> {
    let mut cmd = Command::new("bash");
    cmd.arg("-lc")
        .arg(command)
        .current_dir(current_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            unsafe {
                libc::setpgid(0, 0);
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn command: {}", command))?;

    let stdout = child.stdout.take().context("capture stdout")?;
    let stderr = child.stderr.take().context("capture stderr")?;

    let (line_tx, line_rx) = mpsc::channel::<(bool, String)>();

    {
        let line_tx = line_tx.clone();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        let _ = line_tx.send((false, trimmed.to_string()));
                    }
                    Err(_) => break,
                }
            }
        });
    }

    thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    let _ = line_tx.send((true, trimmed.to_string()));
                }
                Err(_) => break,
            }
        }
    });

    let mut collected = String::new();
    let mut killed_by_stop = false;
    let child_pid = child.id();
    let success;

    loop {
        while let Ok((is_stderr, line)) = line_rx.try_recv() {
            if is_stderr {
                let rendered = format!("[stderr] {}", line);
                send_log_line(tx, index, format_line_for_status(step, &rendered));
                collected.push_str(&rendered);
                collected.push('\n');
            } else {
                send_log_line(tx, index, format_line_for_status(step, &line));
                collected.push_str(&line);
                collected.push('\n');
            }
        }

        if stop_flag.load(Ordering::Relaxed) {
            killed_by_stop = true;
            kill_process_group(child_pid);
        }

        if let Some(status) = child.try_wait().context("wait command status")? {
            success = status.success() && !killed_by_stop;
            while let Ok((is_stderr, line)) = line_rx.try_recv() {
                if is_stderr {
                    let rendered = format!("[stderr] {}", line);
                    send_log_line(tx, index, format_line_for_status(step, &rendered));
                    collected.push_str(&rendered);
                } else {
                    send_log_line(tx, index, format_line_for_status(step, &line));
                    collected.push_str(&line);
                }
                collected.push('\n');
            }

            collected.push_str("--- EXIT CODE: ");
            collected.push_str(&status.code().unwrap_or(-1).to_string());
            collected.push_str(" ---\n");
            break;
        }

        thread::sleep(std::time::Duration::from_millis(100));
    }

    if killed_by_stop {
        send_log_line(tx, index, format_line_for_status(step, "stopped by user"));
    }

    Ok(CommandResult {
        output: collected,
        success,
    })
}

pub fn spawn_global_trace(
    tx: mpsc::Sender<RunnerEvent>,
    stop_flag: Arc<AtomicBool>,
    trace_cmd: String,
    artifacts_dir: PathBuf,
) {
    thread::spawn(move || {
        if let Err(err) = fs::create_dir_all(&artifacts_dir) {
            let _ = tx.send(RunnerEvent::Message {
                text: format!("trace: failed to create artifacts dir: {}", err),
            });
            return;
        }

        let log_path = artifacts_dir.join("trace_global.log");
        let log_file = match fs::File::create(&log_path) {
            Ok(f) => f,
            Err(err) => {
                let _ = tx.send(RunnerEvent::Message {
                    text: format!("trace: failed to create log: {}", err),
                });
                return;
            }
        };

        let log_writer = Arc::new(Mutex::new(std::io::BufWriter::new(log_file)));

        let mut cmd = Command::new("bash");
        cmd.arg("-lc")
            .arg(&trace_cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(|| {
                unsafe {
                    libc::setpgid(0, 0);
                }
                Ok(())
            });
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                let _ = tx.send(RunnerEvent::Message {
                    text: format!("trace: failed to start: {}", err),
                });
                return;
            }
        };

        let _ = tx.send(RunnerEvent::Message {
            text: format!("trace started -> {}", log_path.display()),
        });

        let pid = child.id();
        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => return,
        };
        let stderr = match child.stderr.take() {
            Some(s) => s,
            None => return,
        };

        let tx_out = tx.clone();
        let log_out = log_writer.clone();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        send_trace_line(&tx_out, trimmed.to_string());
                        if let Ok(mut w) = log_out.lock() {
                            let _ = writeln!(w, "{}", trimmed);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let tx_err = tx.clone();
        let log_err = log_writer.clone();
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        let rendered = format!("[stderr] {}", trimmed);
                        send_trace_line(&tx_err, rendered.clone());
                        if let Ok(mut w) = log_err.lock() {
                            let _ = writeln!(w, "{}", rendered);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        loop {
            if stop_flag.load(Ordering::Relaxed) {
                kill_process_group(pid);
                break;
            }

            if let Ok(Some(_)) = child.try_wait() {
                break;
            }

            thread::sleep(std::time::Duration::from_millis(100));
        }

        let _ = tx.send(RunnerEvent::Message {
            text: "trace stopped".to_string(),
        });
    });
}

fn format_line_for_status(step: Option<&'static str>, line: &str) -> String {
    match step {
        Some(s) => format!("[{}] {}", s, line),
        None => line.to_string(),
    }
}

struct CommandResult {
    output: String,
    success: bool,
}


#[derive(Clone, Debug)]
struct Scripts {
    build: PathBuf,
    load: PathBuf,
    test: PathBuf,
    unload: PathBuf,
}

impl Scripts {
    fn detect(dir: &Path) -> Self {
        Self {
            build: dir.join("build.sh"),
            load: dir.join("load.sh"),
            test: dir.join("test.sh"),
            unload: dir.join("unload.sh"),
        }
    }

    fn is_complete(&self) -> bool {
        self.build.exists() && self.load.exists() && self.test.exists() && self.unload.exists()
    }
}
