/**
 *
 *  Copyright 2024 Netflix, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::{println, thread, vec};
use std::collections::HashMap;

use anyhow::Result;
use bpf_program::BpfProgram;
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

mod bpf_program;

impl From<&BpfProgram> for Row<'_> {
    fn from(bpf_program: &BpfProgram) -> Self {
        let height = 1;
        let cells = vec![
            Cell::from(bpf_program.id.to_string()),
            Cell::from(bpf_program.bpf_type.to_string()),
            Cell::from(bpf_program.name.to_string()),
            Cell::from(bpf_program.period_average_runtime_ns().to_string()),
            Cell::from(bpf_program.total_average_runtime_ns().to_string()),
            Cell::from(bpf_program.events_per_second().to_string()),
            Cell::from(round_to_first_non_zero(bpf_program.cpu_time_percent()).to_string()),
        ];

        Row::new(cells).height(height as u16).bottom_margin(1)
    }
}

struct App {
    state: TableState,
    items: Arc<Mutex<Vec<BpfProgram>>>
}

impl App {
    fn new() -> App {
        App {
            state: TableState::default(),
            items: Arc::new(Mutex::new(vec![]))
        }
    }

    pub fn start_background_thread(&self, num_cpus: usize) {
        let items_clone = Arc::clone(&self.items);

        thread::spawn(move || loop {
            // Lock items for this thread's exclusive use.
            let mut items = items_clone.lock().unwrap();

            let items_copy = items.clone();
            let map: HashMap<String, &BpfProgram> = items_copy.iter().map(|prog| (prog.id.clone(), prog)).collect();
            items.clear();

            let iter = ProgInfoIter::default();
            for prog in iter {
                let prog_name = prog.name.to_str().unwrap().to_string();

                if prog_name.is_empty() {
                    continue;
                }

                let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                let timestamp_nanos = duration_since_epoch.as_nanos();

                let mut bpf_program = BpfProgram {
                    id: prog.id.to_string(),
                    bpf_type: prog.ty.to_string(),
                    name: prog_name,
                    prev_runtime_ns: 0,
                    run_time_ns: prog.run_time_ns,
                    prev_run_cnt: 0,
                    run_cnt: prog.run_cnt,
                    prev_timestamp_ns: 0,
                    timestamp_ns: timestamp_nanos,
                    num_cpus: num_cpus
                };

                if let Some(prev_bpf_program) = map.get(&bpf_program.id) {
                    bpf_program.prev_runtime_ns = prev_bpf_program.run_time_ns;
                    bpf_program.prev_run_cnt = prev_bpf_program.run_cnt;
                    bpf_program.prev_timestamp_ns = prev_bpf_program.timestamp_ns;
                }

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

    let num_cpus = num_cpus::get();

    // create app and run it
    let app = App::new();
    app.start_background_thread(num_cpus);
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
        "Period Avg Runtime (ns)",
        "Total Avg Runtime (ns)",
        "Events per second",
        "CPU %",
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
        Constraint::Percentage(5),
        Constraint::Percentage(17),
        Constraint::Percentage(17),
        Constraint::Percentage(17),
        Constraint::Percentage(17),
        Constraint::Percentage(17),
        Constraint::Percentage(10),
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

fn round_to_first_non_zero(num: f64) -> f64 {
    if num == 0.0 {
        return 0.0;
    }

    let mut multiplier = 1.0;
    while num * multiplier < 1.0 {
        multiplier *= 10.0;
    }
    (num * multiplier).round() / multiplier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_to_first_non_zero() {
        assert_eq!(round_to_first_non_zero(0.002323), 0.002);
        assert_eq!(round_to_first_non_zero(0.0000012), 0.000001);
        assert_eq!(round_to_first_non_zero(0.00321), 0.003);
    }
}