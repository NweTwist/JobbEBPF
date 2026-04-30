use crate::{discovery::Program, runner};
use anyhow::Context;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
        Arc,
    },
};

#[derive(Debug, Deserialize, Default)]
pub struct ConfigFile {
    pub trace_cmd: Option<String>,
    pub artifacts_dir: Option<PathBuf>,
}

pub fn load_config(config_path: Option<&Path>, repo_root: &Path) -> anyhow::Result<ConfigFile> {
    let path = config_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| repo_root.join("ebpf-tui.yaml"));

    if !path.exists() {
        return Ok(ConfigFile::default());
    }

    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read config {}", path.display()))?;
    let cfg: ConfigFile = serde_yaml::from_str(&content)
        .with_context(|| format!("parse yaml {}", path.display()))?;
    Ok(cfg)
}

#[derive(Clone, Debug)]
pub struct ProgramEntry {
    pub program: Program,
    pub status: runner::ProgramStatus,
    pub attached: bool,
}

pub struct App {
    pub entries: Vec<ProgramEntry>,
    pub selected: usize,
    pub last_message: String,
    pub status_lines: VecDeque<String>,
    pub trace_cmd: String,
    pub artifacts_dir: PathBuf,
    pub tx: mpsc::Sender<runner::RunnerEvent>,
    pub stop_flag: Arc<AtomicBool>,
    pub trace_stop_flag: Arc<AtomicBool>,
    pub trace_running: bool,
}

impl App {
    pub fn new(
        _repo_root: PathBuf,
        programs: Vec<Program>,
        trace_cmd: String,
        artifacts_dir: PathBuf,
        tx: mpsc::Sender<runner::RunnerEvent>,
        trace_stop_flag: Arc<AtomicBool>,
    ) -> Self {
        let entries = programs
            .into_iter()
            .map(|p| ProgramEntry {
                program: p,
                status: runner::ProgramStatus::Idle,
                attached: false,
            })
            .collect();

        Self {
            entries,
            selected: 0,
            last_message: "Ready. Keys: r auto, b build, l load, t test, u unload, s stop".to_string(),
            status_lines: VecDeque::new(),
            trace_cmd,
            artifacts_dir,
            tx,
            stop_flag: Arc::new(AtomicBool::new(false)),
            trace_stop_flag,
            trace_running: true,
        }
    }

    pub fn select_prev(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        if self.selected == 0 {
            self.selected = self.entries.len() - 1;
        } else {
            self.selected -= 1;
        }
    }

    pub fn select_next(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.entries.len();
    }

    pub fn apply_runner_event(&mut self, ev: runner::RunnerEvent) {
        match ev {
            runner::RunnerEvent::Status { index, status } => {
                if let Some(entry) = self.entries.get_mut(index) {
                    entry.status = status;
                }
            }
            runner::RunnerEvent::Message { text } => {
                self.last_message = text;
                self.push_status_line(self.last_message.clone());
            }
            runner::RunnerEvent::LogLine { index, line } => {
                let prefix = self
                    .entries
                    .get(index)
                    .map(|e| e.program.name.clone())
                    .unwrap_or_else(|| "module".to_string());
                self.push_status_line(format!("{} | {}", prefix, line));
            }
            runner::RunnerEvent::TraceLine { line } => {
                self.push_status_line(format!("trace | {}", line));
            }
            runner::RunnerEvent::ModuleState { index, attached } => {
                if let Some(entry) = self.entries.get_mut(index) {
                    if let Some(v) = attached {
                        entry.attached = v;
                    }
                }
            }
        }
    }

    pub fn request_stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.trace_stop_flag.store(true, Ordering::Relaxed);
    }

    pub fn stop_runs(&mut self) {
        self.request_stop();
        self.last_message = "Stop requested: waiting for running step to terminate...".to_string();
        self.push_status_line(self.last_message.clone());
    }

    pub fn run_selected(&mut self) {
        self.run_action(runner::RunAction::Auto);
    }

    pub fn build_selected(&mut self) {
        self.run_action(runner::RunAction::Build);
    }

    pub fn load_selected(&mut self) {
        self.run_action(runner::RunAction::Load);
    }

    pub fn test_selected(&mut self) {
        self.run_action(runner::RunAction::Test);
    }

    pub fn unload_selected(&mut self) {
        self.run_action(runner::RunAction::Unload);
    }

    pub fn run_all(&mut self) {
        self.stop_flag.store(false, Ordering::Relaxed);
        let programs: Vec<Program> = self.entries.iter().map(|e| e.program.clone()).collect();
        let config = runner::RunConfig {
            trace_cmd: self.trace_cmd.clone(),
            artifacts_dir: self.artifacts_dir.clone(),
        };
        runner::spawn_run_all(self.tx.clone(), self.stop_flag.clone(), programs, config);
    }

    fn run_action(&mut self, action: runner::RunAction) {
        if self.entries.is_empty() {
            return;
        }
        self.stop_flag.store(false, Ordering::Relaxed);
        let index = self.selected;
        let program = self.entries[index].program.clone();
        let config = runner::RunConfig {
            trace_cmd: self.trace_cmd.clone(),
            artifacts_dir: self.artifacts_dir.clone(),
        };
        runner::spawn_run_action_selected(
            self.tx.clone(),
            self.stop_flag.clone(),
            index,
            program,
            config,
            action,
        );
    }

    fn push_status_line(&mut self, line: String) {
        const MAX_STATUS_LINES: usize = 200;
        self.status_lines.push_back(line);
        while self.status_lines.len() > MAX_STATUS_LINES {
            self.status_lines.pop_front();
        }
    }

    fn status_text(&self) -> String {
        if self.status_lines.is_empty() {
            return self.last_message.clone();
        }

        let mut out = String::new();
        for line in self.status_lines.iter().rev().take(24).rev() {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(5)])
        .split(frame.size());

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    let items: Vec<ListItem> = app
        .entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let status = status_text(&entry.status);
            let is_selected = idx == app.selected;
            let style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default()
            };

            let line = Line::from(vec![
                Span::styled(entry.program.name.clone(), style.add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(status, style),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Programs"));
    frame.render_widget(list, main[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(main[1]);

    let info = Paragraph::new(app.status_text())
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(info, right[0]);

    let details = selected_program_details(app);
    let details_widget = Paragraph::new(details)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Module card"));
    frame.render_widget(details_widget, right[1]);

    let help = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            "↑/↓",
            Style::default().add_modifier(Modifier::BOLD),
        ), Span::raw(" select  ")]),
        Line::from(vec![
            Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" auto  "),
            Span::styled("b", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" build  "),
            Span::styled("l", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" load  "),
            Span::styled("t", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" test"),
        ]),
        Line::from(vec![
            Span::styled("u", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" unload  "),
            Span::styled("a", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" run all auto  "),
            Span::styled("s", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" stop run  "),
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" quit"),
        ]),
        Line::from(vec![Span::raw("Trace: always on (trace_global.log)")]),
        Line::from(vec![Span::raw(
            "Logs are stored in artifacts/<program>/ (PMI: pmi.txt, plus status.log/run_report.md).",
        )]),
    ])
    .block(Block::default().borders(Borders::ALL).title("Help"));
    frame.render_widget(help, chunks[1]);
}

fn selected_program_details(app: &App) -> Vec<Line<'static>> {
    let Some(entry) = app.entries.get(app.selected) else {
        return vec![Line::from("No program selected")];
    };

    let (progress, tone) = status_progress(&entry.status);
    let micro = module_microcopy(&entry.program.name);
    let bar = progress_bar(progress, 18);
    let status = status_text(&entry.status);

    vec![
        Line::from(vec![
            Span::styled("Module: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(entry.program.name.clone()),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(status, Style::default().fg(tone)),
        ]),
        Line::from(vec![
            Span::styled("Progress: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(bar, Style::default().fg(tone)),
            Span::raw(format!(" {}%", progress)),
        ]),
        Line::from(vec![
            Span::styled("Attached: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(if entry.attached { "yes" } else { "no" }),
            Span::raw("    "),
            Span::styled("Trace: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(if app.trace_running { "on" } else { "off" }),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Micro: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(micro.to_string()),
        ]),
    ]
}

fn status_progress(status: &runner::ProgramStatus) -> (u8, Color) {
    match status {
        runner::ProgramStatus::Idle => (0, Color::Gray),
        runner::ProgramStatus::Running("build") => (25, Color::Yellow),
        runner::ProgramStatus::Running("load") => (45, Color::Yellow),
        runner::ProgramStatus::Running("test") => (75, Color::Yellow),
        runner::ProgramStatus::Running("unload") => (90, Color::Yellow),
        runner::ProgramStatus::Running("trace") => (60, Color::Yellow),
        runner::ProgramStatus::Running("trace-stop") => (95, Color::Yellow),
        runner::ProgramStatus::Running("pmi") => (40, Color::Yellow),
        runner::ProgramStatus::Running("run") => (80, Color::Yellow),
        runner::ProgramStatus::Running(_) => (55, Color::Yellow),
        runner::ProgramStatus::Success => (100, Color::Green),
        runner::ProgramStatus::Stopped => (100, Color::LightYellow),
        runner::ProgramStatus::Failed(_) => (100, Color::Red),
        runner::ProgramStatus::MissingScripts => (100, Color::LightRed),
    }
}

fn progress_bar(progress: u8, width: usize) -> String {
    let filled = (usize::from(progress) * width) / 100;
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "#".repeat(filled), "-".repeat(empty))
}

fn module_microcopy(name: &str) -> &'static str {
    if name.contains("XDP") {
        "Fast path packet gate. Hooks early in RX path."
    } else if name.contains("TRACEPOINT") || name.contains("KPROBE") {
        "Kernel observability probe. Captures execution-level events."
    } else if name.contains("CGROUP") {
        "Policy lens for cgroup-bound resource and network controls."
    } else if name.contains("SOCKET") || name.contains("SOCK") {
        "Socket pipeline control. Shapes behavior at transport boundaries."
    } else if name.contains("SCHED") {
        "Scheduler datapath module. Classify and steer queued traffic."
    } else if name.contains("NETFILTER") {
        "Netfilter hook module. Makes decisions on packet traversal."
    } else {
        "eBPF module under validation. Build, attach, trigger, verify."
    }
}

fn status_text(status: &runner::ProgramStatus) -> String {
    match status {
        runner::ProgramStatus::Idle => "idle".to_string(),
        runner::ProgramStatus::Running(step) => format!("running: {}", step),
        runner::ProgramStatus::Success => "ok".to_string(),
        runner::ProgramStatus::Stopped => "stopped".to_string(),
        runner::ProgramStatus::Failed(step) => format!("failed: {}", step),
        runner::ProgramStatus::MissingScripts => "missing scripts".to_string(),
    }
}
