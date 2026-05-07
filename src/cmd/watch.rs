#[cfg(feature = "tui")]
pub mod tui {
    use anyhow::Result;
    use clap::{ArgMatches, Command};
    use crate::CmdExit;

    pub fn command() -> Command {
        Command::new("watch")
            .about("Live TUI dashboard — tails the audit log (requires --features tui)")
    }

    pub fn run(_matches: &ArgMatches, _sub: &ArgMatches) -> Result<CmdExit> {
        run_tui_dashboard()?;
        Ok(CmdExit { code: exitcode::OK, message: None })
    }

    // ── Shared app state ──────────────────────────────────────────────────────

    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use crate::engine::event::ThreatEvent;

    struct AppState {
        events:        VecDeque<ThreatEvent>,
        monitor_stats: HashMap<String, (u64, String)>,  // monitor → (count, last_time)
        source:        String,
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    fn run_tui_dashboard() -> Result<()> {
        use std::io::stdout;
        use ratatui::crossterm::terminal::{
            disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
        };
        use ratatui::crossterm::ExecutableCommand;
        use ratatui::{backend::CrosstermBackend, Terminal};

        let log_path = crate::config::Config::expand_path("~/.tav/audit.jsonl");
        let source   = log_path.display().to_string();

        let state = Arc::new(Mutex::new(AppState {
            events:        VecDeque::new(),
            monitor_stats: HashMap::new(),
            source,
        }));

        // Load existing events (last 50, newest first)
        if log_path.exists() {
            let content = std::fs::read_to_string(&log_path).unwrap_or_default();
            let mut locked = state.lock().unwrap();
            // Collect the newest 50 lines, then process oldest-first so push_front
            // leaves the newest at the head of the deque.
            let lines: Vec<&str> = content.lines().rev().take(50).collect();
            for line in lines.into_iter().rev() {
                if let Ok(event) = serde_json::from_str::<ThreatEvent>(line) {
                    push_event(&mut locked, event);
                }
            }
        }

        // Background tailer thread
        let tailer_state = state.clone();
        let tailer_path  = log_path.clone();
        std::thread::spawn(move || {
            tail_file(&tailer_path, tailer_state);
        });

        // Set up terminal
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let backend  = CrosstermBackend::new(stdout());
        let mut terminal = Terminal::new(backend)?;

        let result = event_loop(&mut terminal, &state);

        // Restore terminal regardless of result
        disable_raw_mode()?;
        terminal.backend_mut().execute(LeaveAlternateScreen)?;

        result
    }

    fn push_event(state: &mut AppState, event: ThreatEvent) {
        let ts = event.timestamp.format("%H:%M:%S").to_string();
        let entry = state.monitor_stats.entry(event.monitor.clone()).or_insert((0, ts.clone()));
        entry.0 += 1;
        entry.1 = ts;
        state.events.push_front(event);
        if state.events.len() > 50 {
            state.events.pop_back();
        }
    }

    // ── File tailer ───────────────────────────────────────────────────────────

    fn tail_file(path: &std::path::Path, state: Arc<Mutex<AppState>>) {
        use std::io::{BufRead, BufReader, Seek, SeekFrom};
        use std::time::Duration;

        let Ok(file) = std::fs::File::open(path) else { return };
        let mut file = file;
        let _ = file.seek(SeekFrom::End(0));
        let mut reader = BufReader::new(file);
        let mut line   = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => std::thread::sleep(Duration::from_millis(200)),
                Ok(_) => {
                    if let Ok(event) = serde_json::from_str::<ThreatEvent>(line.trim()) {
                        push_event(&mut state.lock().unwrap(), event);
                    }
                }
                Err(_) => break,
            }
        }
    }

    // ── Main event loop ───────────────────────────────────────────────────────

    fn event_loop<B: ratatui::backend::Backend>(
        terminal: &mut ratatui::Terminal<B>,
        state:    &Arc<Mutex<AppState>>,
    ) -> Result<()> {
        use std::time::Duration;
        use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

        loop {
            terminal.draw(|frame| draw(frame, &state.lock().unwrap()))?;

            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => break,
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    fn draw(frame: &mut ratatui::Frame, state: &AppState) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

        let area = frame.area();
        let stats_height = (state.monitor_stats.len().max(1) as u16) + 2;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(stats_height),
            ])
            .split(area);

        // Header
        let header_text = format!(
            "  Source: {}   [q] quit",
            state.source
        );
        let header = Paragraph::new(header_text)
            .block(Block::default().title(" TAV ").borders(Borders::ALL))
            .style(Style::default().fg(Color::Cyan));
        frame.render_widget(header, chunks[0]);

        // Events list
        let items: Vec<ListItem> = state.events.iter().map(|e| {
            let (sev_str, sev_color) = match e.severity {
                crate::config::Severity::Critical => ("[CRIT]", Color::Red),
                crate::config::Severity::High     => ("[HIGH]", Color::LightRed),
                crate::config::Severity::Medium   => ("[MED] ", Color::Yellow),
                crate::config::Severity::Low      => ("[LOW] ", Color::Blue),
                crate::config::Severity::Info     => ("[INFO]", Color::White),
            };
            let ts = e.timestamp.format("%H:%M:%S").to_string();
            let line = Line::from(vec![
                Span::styled(format!("{} ", ts), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{} ", sev_str), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{:<22}", e.monitor), Style::default().fg(Color::Cyan)),
                Span::raw(e.matched_rule.clone()),
            ]);
            ListItem::new(line)
        }).collect();

        let events_block = Block::default()
            .title(" Recent Events (newest first — [q] quit) ")
            .borders(Borders::ALL);
        let events_list = List::new(items).block(events_block);
        frame.render_widget(events_list, chunks[1]);

        // Monitor stats
        let stat_items: Vec<ListItem> = {
            let mut entries: Vec<_> = state.monitor_stats.iter().collect();
            entries.sort_by_key(|(k, _)| k.as_str());
            entries.iter().map(|(name, (count, last))| {
                let text = format!("  {:<30}  events: {:<6}  last: {}", name, count, last);
                ListItem::new(text)
            }).collect()
        };
        let stats_block = Block::default().title(" Monitor Stats ").borders(Borders::ALL);
        let stats_list  = List::new(stat_items).block(stats_block);
        frame.render_widget(stats_list, chunks[2]);
    }
}
