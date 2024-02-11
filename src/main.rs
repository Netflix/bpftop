/**
 *
 *  Copyright 2024 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{println, thread, vec};

use anyhow::Result;
use crossterm::event::{self, poll, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use libbpf_rs::query::ProgInfoIter;
use libbpf_sys::bpf_enable_stats;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::{Frame, Terminal};

struct BpfProgram {
    id: String,
    bpf_type: String,
    name: String,
    run_time_ns: u64,
    run_cnt: u64,
}

impl BpfProgram {
    pub fn average_runtime(&self) -> u64 {
        if self.run_cnt == 0 {
            return 0;
        }
        self.run_time_ns / self.run_cnt
    }
}

impl From<&BpfProgram> for Row<'_> {
    fn from(bpf_program: &BpfProgram) -> Self {
        let height = 1;
        let cells = vec![
            Cell::from(bpf_program.id.to_string()),
            Cell::from(bpf_program.bpf_type.to_string()),
            Cell::from(bpf_program.name.to_string()),
            Cell::from(bpf_program.average_runtime().to_string()),
            Cell::from(bpf_program.run_time_ns.to_string()),
            Cell::from(bpf_program.run_cnt.to_string()),
        ];

        Row::new(cells).height(height as u16).bottom_margin(1)
    }
}

struct App {
    state: TableState,
    items: Arc<Mutex<Vec<BpfProgram>>>,
}

impl App {
    fn new() -> App {
        App {
            state: TableState::default(),
            items: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn start_background_thread(&self) {
        let items_clone = Arc::clone(&self.items);

        thread::spawn(move || loop {
            // Lock items for this thread's exclusive use.
            let mut items = items_clone.lock().unwrap();
            items.clear();

            let iter = ProgInfoIter::default();
            for prog in iter {
                let prog_name = prog.name.to_str().unwrap().to_string();

                if prog_name.is_empty() {
                    continue;
                }

                let bpf_program = BpfProgram {
                    id: prog.id.to_string(),
                    bpf_type: prog.ty.to_string(),
                    name: prog_name,
                    run_time_ns: prog.run_time_ns,
                    run_cnt: prog.run_cnt,
                };
                items.push(bpf_program);
            }

            // Explicitly drop the MutexGuard returned by lock() to unlock before sleeping.
            drop(items);

            thread::sleep(Duration::from_secs(1));
        });
    }
}

fn main() -> Result<()> {
    if !running_as_root() {
        println!("You must run bpftop as root");
        std::process::exit(1);
    }

    // enable BPF stats while the program is running
    let fd = unsafe { bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
    if fd < 0 {
        println!("Failed to enable BPF_STATS_RUN_TIME");
        std::process::exit(1);
    }
    // The fd will be closed when _file goes out of scope at the end of main.
    let _file = unsafe { File::from_raw_fd(fd) };

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // create app and run it
    let app = App::new();
    app.start_background_thread();
    let res = run_app(&mut terminal, app);

    // // restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen,)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }
    terminal.clear()?;

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        // wait up to 100ms for a keyboard event
        if poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc => return Ok(()),
                    _ => {}
                }
                match (key.modifiers, key.code) {
                    (KeyModifiers::CONTROL, KeyCode::Char('c')) => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let rects = Layout::default()
        .constraints([Constraint::Percentage(100)].as_ref())
        .margin(3)
        .split(f.size());

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let normal_style = Style::default().bg(Color::Blue);
    let header_cells = [
        "ID",
        "Type",
        "Name",
        "Avg Runtime (ns)",
        "Total Runtime (ns)",
        "Run Count",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(Style::default()));
    let header = Row::new(header_cells)
        .style(normal_style)
        .height(1)
        .bottom_margin(1);

    let items = app.items.lock().unwrap();

    let rows: Vec<Row> = items.iter().map(|item| item.into()).collect();

    let widths = [
        Constraint::Percentage(15),
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
    ];

    let t = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" eBPF programs "),
        )
        .highlight_style(selected_style)
        .highlight_symbol(">> ");
    f.render_stateful_widget(t, rects[0], &mut app.state);
}

fn running_as_root() -> bool {
    match nix::unistd::getuid().as_raw() {
        0 => true,
        _ => false,
    }
}
