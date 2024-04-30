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
use anyhow::{anyhow, Context, Result};
use app::SortColumn;
use app::{App, Mode};
use bpf_program::BpfProgram;
use crossterm::event::{self, poll, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use libbpf_sys::bpf_enable_stats;
use procfs::KernelVersion;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{
    Axis, Block, BorderType, Borders, Cell, Chart, Dataset, GraphType, Padding, Paragraph, Row,
    Table,
};
use ratatui::{symbols, Frame, Terminal};
use std::fs;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tui_input::backend::crossterm::EventHandler;

mod app;
mod bpf_program;

const TABLE_FOOTER: &str =
    "(q) quit | (↑,k) move up | (↓,j) move down | (↵) show graphs | (f) filter | (s) sort";
const GRAPHS_FOOTER: &str = "(q) quit | (↵) show program list";
const FILTER_FOOTER: &str = "(↵,Esc) back";
const SORT_CONTROLS_FOOTER: &str =
    "(↑) asc | (↓) desc | (Backspace) clear | (←) move left | (→) move right";
const SORT_INFO_FOOTER: &str = "(Esc) back";

const PROCFS_BPF_STATS_ENABLED: &str = "/proc/sys/kernel/bpf_stats_enabled";

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
            Cell::from(format_percent(bpf_program.cpu_time_percent())),
        ];

        Row::new(cells).height(height as u16).bottom_margin(1)
    }
}

fn main() -> Result<()> {
    if !running_as_root() {
        return Err(anyhow!("This program must be run as root"));
    }

    // Initialize the tracing subscriber with the journald layer
    let registry = tracing_subscriber::registry()
        .with(tracing_journald::layer()?)
        .with(tracing_subscriber::filter::LevelFilter::INFO);
    // Try to set this subscriber as the global default
    registry.try_init()?;

    let kernel_version = KernelVersion::current()?;
    let _owned_fd: OwnedFd;
    let mut stats_enabled_via_procfs = false;

    info!("Starting bpftop...");
    info!("Kernel: {:?}", kernel_version);

    // enable BPF stats via syscall if kernel version >= 5.8
    if kernel_version >= KernelVersion::new(5, 8, 0) {
        let fd = unsafe { bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
        if fd < 0 {
            return Err(anyhow!("Failed to enable BPF stats via syscall"));
        }
        _owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        info!("Enabled BPF stats via syscall")
    } else {
        // otherwise, enable via procfs
        // but first check if procfs bpf stats were already enabled
        if procfs_bpf_stats_is_enabled()? {
            info!("BPF stats already enabled via procfs");
        } else {
            fs::write(PROCFS_BPF_STATS_ENABLED, b"1").context(format!(
                "Failed to enable BPF stats via {}",
                PROCFS_BPF_STATS_ENABLED
            ))?;
            stats_enabled_via_procfs = true;
            info!("Enabled BPF stats via procfs");
        }
    }

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // capture panic to disable BPF stats via procfs and restore terminal
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        if stats_enabled_via_procfs {
            if let Err(err) = procs_bfs_stats_disable() {
                eprintln!("Failed to disable BPF stats via procfs: {:?}", err);
            }
        }

        if let Err(err) = disable_raw_mode() {
            eprintln!("Failed to disable raw mode: {:?}", err);
        }

        previous_hook(panic_info);
    }));

    // create app and run the draw loop
    let app = App::new();
    app.start_background_thread();
    let res = run_draw_loop(&mut terminal, app);

    // restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen,)?;
    terminal.show_cursor()?;
    terminal.clear()?;

    // disable BPF stats via procfs if needed
    if stats_enabled_via_procfs {
        procs_bfs_stats_disable()?;
    }

    #[allow(clippy::question_mark)]
    if res.is_err() {
        return res;
    }

    Ok(())
}

fn procs_bfs_stats_disable() -> Result<()> {
    fs::write(PROCFS_BPF_STATS_ENABLED, b"0").context(format!(
        "Failed to disable BPF stats via {}",
        PROCFS_BPF_STATS_ENABLED
    ))?;
    Ok(())
}

fn procfs_bpf_stats_is_enabled() -> Result<bool> {
    fs::read_to_string(PROCFS_BPF_STATS_ENABLED)
        .context(format!("Failed to read from {}", PROCFS_BPF_STATS_ENABLED))
        .map(|value| value.trim() == "1")
}

fn run_draw_loop<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        // wait up to 100ms for a keyboard event
        if poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match app.mode {
                    Mode::Table => match key.code {
                        KeyCode::Down | KeyCode::Char('j') => app.next_program(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous_program(),
                        KeyCode::Enter => app.show_graphs(),
                        KeyCode::Char('f') => app.toggle_filter(),
                        KeyCode::Char('s') => app.toggle_sort(),
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        _ => {}
                    },
                    Mode::Graph => match key.code {
                        KeyCode::Enter | KeyCode::Esc => app.show_table(),
                        KeyCode::Char('q') => return Ok(()),
                        _ => {}
                    },
                    Mode::Filter => match key.code {
                        KeyCode::Enter | KeyCode::Esc => app.toggle_filter(),
                        _ => {
                            app.filter_input
                                .lock()
                                .unwrap()
                                .handle_event(&Event::Key(key));
                        }
                    },
                    Mode::Sort => match key.code {
                        KeyCode::Esc => app.toggle_sort(),
                        KeyCode::Up => app.sort_column(SortColumn::Ascending(
                            app.selected_column.unwrap_or_default(),
                        )),
                        KeyCode::Down => app.sort_column(SortColumn::Descending(
                            app.selected_column.unwrap_or_default(),
                        )),
                        KeyCode::Backspace => app.sort_column(SortColumn::NoOrder),
                        KeyCode::Left => app.previous_column(),
                        KeyCode::Right => app.next_column(),
                        KeyCode::Enter => app.cycle_sort_exit(),
                        _ => {}
                    },
                }
                if let (KeyModifiers::CONTROL, KeyCode::Char('c')) = (key.modifiers, key.code) {
                    return Ok(());
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let rects = Layout::vertical([Constraint::Min(5), Constraint::Length(3)]).split(f.size());

    match app.mode {
        Mode::Table | Mode::Filter | Mode::Sort => render_table(f, app, rects[0]),
        Mode::Graph => render_graphs(f, app, rects[0]),
    }
    render_footer(f, app, rects[1]);
}

fn render_graphs(f: &mut Frame, app: &mut App, area: Rect) {
    let data_buf = app.data_buf.lock().unwrap();
    let mut cpu_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_buf.len()];
    let mut eps_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_buf.len()];
    let mut runtime_data: Vec<(f64, f64)> = vec![(0.0, 0.0); data_buf.len()];

    let mut total_cpu = 0.0;
    let mut total_eps = 0;
    let mut total_runtime = 0;

    let mut moving_max_cpu = 0.0;
    let mut moving_max_eps = 0;
    let mut moving_max_runtime = 0;

    for (i, val) in data_buf.iter().enumerate() {
        cpu_data[i] = (i as f64, val.cpu_time_percent);
        eps_data[i] = (i as f64, val.events_per_sec as f64);
        runtime_data[i] = (i as f64, val.average_runtime_ns as f64);

        if val.cpu_time_percent > app.max_cpu {
            app.max_cpu = val.cpu_time_percent;
        }
        if val.cpu_time_percent > moving_max_cpu {
            moving_max_cpu = val.cpu_time_percent;
        }

        if val.events_per_sec > app.max_eps {
            app.max_eps = val.events_per_sec;
        }
        if val.events_per_sec > moving_max_eps {
            moving_max_eps = val.events_per_sec;
        }

        if val.average_runtime_ns > app.max_runtime {
            app.max_runtime = val.average_runtime_ns;
        }
        if val.average_runtime_ns > moving_max_runtime {
            moving_max_runtime = val.average_runtime_ns;
        }

        total_cpu += val.cpu_time_percent;
        total_eps += val.events_per_sec;
        total_runtime += val.average_runtime_ns;
    }

    let max_cpu = moving_max_cpu;
    let max_eps = moving_max_eps as f64;
    let max_runtime = moving_max_runtime as f64;

    let mut avg_cpu = 0.0;
    let mut avg_eps = 0.0;
    let mut avg_runtime = 0.0;
    if data_buf.len() > 0 {
        avg_cpu = total_cpu / data_buf.len() as f64;
        avg_eps = total_eps as f64 / data_buf.len() as f64;
        avg_runtime = total_runtime as f64 / data_buf.len() as f64;
    }

    let cpu_y_max = app.max_cpu.ceil();
    let eps_y_max = (app.max_eps as f64 * 2.0).ceil();
    let runtime_y_max = (app.max_runtime as f64 * 2.0).ceil();

    // CPU
    let cpu_dataset = Dataset::default()
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().green())
        .data(&cpu_data);
    let cpu_datasets = vec![cpu_dataset];
    let x_axis = Axis::default()
        .style(Style::default())
        .bounds([0.0, cpu_data.len() as f64]);
    let y_axis = Axis::default()
        .style(Style::default())
        .bounds([0.0, cpu_y_max])
        .labels(vec![
            "0%".into(),
            ((cpu_y_max / 2.0).to_string() + "%").into(),
            (cpu_y_max.to_string() + "%").into(),
        ]);
    let cpu_chart = Chart::new(cpu_datasets)
        .block(
            Block::default()
                .title(format!(
                    " Total CPU % | Moving Avg: {} | Max: {} ",
                    format_percent(avg_cpu),
                    format_percent(max_cpu)
                ))
                .borders(Borders::ALL),
        )
        .x_axis(x_axis)
        .y_axis(y_axis);

    // Events per second
    let eps_dataset = Dataset::default()
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().cyan())
        .data(&eps_data);
    let eps_datasets = vec![eps_dataset];
    let x_axis = Axis::default()
        .style(Style::default())
        .bounds([0.0, eps_data.len() as f64]);
    let y_axis = Axis::default()
        .style(Style::default())
        .bounds([0.0, eps_y_max])
        .labels(vec![
            "0".into(),
            ((eps_y_max / 2.0).to_string()).into(),
            (eps_y_max.to_string()).into(),
        ]);
    let eps_chart = Chart::new(eps_datasets)
        .block(
            Block::default()
                .title(format!(
                    " Events per second | Moving Avg: {} | Max: {} ",
                    avg_eps.ceil(),
                    max_eps.ceil()
                ))
                .borders(Borders::ALL),
        )
        .x_axis(x_axis)
        .y_axis(y_axis);

    // Runtime
    let runtime_dataset = Dataset::default()
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().magenta())
        .data(&runtime_data);
    let runtime_datasets = vec![runtime_dataset];
    let x_axis = Axis::default()
        .style(Style::default())
        .bounds([0.0, runtime_data.len() as f64]);
    let y_axis = Axis::default()
        .style(Style::default())
        .bounds([0.0, runtime_y_max])
        .labels(vec![
            "0".into(),
            ((runtime_y_max / 2.0).to_string()).into(),
            (runtime_y_max.to_string()).into(),
        ]);
    let runtime_chart = Chart::new(runtime_datasets)
        .block(
            Block::default()
                .title(format!(
                    " Avg Runtime (ns) | Moving Avg: {} | Max: {} ",
                    avg_runtime.ceil(),
                    max_runtime.ceil()
                ))
                .borders(Borders::ALL),
        )
        .x_axis(x_axis)
        .y_axis(y_axis);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    let sub_chunks = chunks
        .iter()
        .map(|chunk| {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(*chunk)
        })
        .collect::<Vec<_>>();

    let mut items = vec![
        Row::new(vec![Cell::from("Program ID"), Cell::from("Unknown")]),
        Row::new(vec![Cell::from("Program Type"), Cell::from("Unknown")]),
        Row::new(vec![Cell::from("Program Name"), Cell::from("Unknown")]),
    ];
    let widths = [Constraint::Length(15), Constraint::Min(0)];

    if let Some(bpf_program) = app.graphs_bpf_program.lock().unwrap().clone() {
        items = vec![
            Row::new(vec![
                Cell::from("Program ID".bold()),
                Cell::from(bpf_program.id.to_string()),
            ])
            .height(2),
            Row::new(vec![
                Cell::from("Program Type".bold()),
                Cell::from(bpf_program.bpf_type),
            ])
            .height(2),
            Row::new(vec![
                Cell::from("Program Name".bold()),
                Cell::from(bpf_program.name),
            ])
            .height(2),
        ];
    }

    let table = Table::new(items, widths)
        .block(
            Block::default()
                .title(" Program Information ")
                .padding(Padding::new(3, 0, 1, 0))
                .borders(Borders::ALL),
        )
        .style(Style::default());

    f.render_widget(table, sub_chunks[0][0]); // Top left
    f.render_widget(cpu_chart.clone(), sub_chunks[0][1]); // Top right
    f.render_widget(eps_chart, sub_chunks[1][0]); // Bottom left
    f.render_widget(runtime_chart, sub_chunks[1][1]); // Bottom right
}

fn render_table(f: &mut Frame, app: &mut App, area: Rect) {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let normal_style = Style::default().bg(Color::Blue);

    let columns: Vec<Cell<'_>> = app
        .header_columns
        .iter()
        .enumerate()
        .map(|(i, col)| {
            Cell::new(&**col).style(
                if app.selected_column.is_some_and(|selected| selected == i) {
                    selected_style
                } else {
                    normal_style
                },
            )
        })
        .collect();
    let header = Row::new(columns)
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
    f.render_stateful_widget(t, area, &mut app.table_state);
}

fn render_footer(f: &mut Frame, app: &mut App, area: Rect) {
    let info_text = match app.mode {
        Mode::Table => TABLE_FOOTER,
        Mode::Graph => GRAPHS_FOOTER,
        Mode::Filter => FILTER_FOOTER,
        Mode::Sort => SORT_INFO_FOOTER,
    };
    let info_footer = Paragraph::new(Line::from(info_text)).centered().block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double),
    );

    // Only single footer in table and graph mode
    if let Mode::Table | Mode::Graph = app.mode {
        f.render_widget(info_footer, area);
        return;
    }

    // Two footers in filter and sort mode
    let split_area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
        .split(area);

    // Right footer
    f.render_widget(info_footer, split_area[1]);

    // Left footer
    match app.mode {
        Mode::Filter => {
            let filter_input = app.filter_input.lock().unwrap();
            let filter_footer = Paragraph::new(filter_input.value()).block(
                Block::default()
                    .padding(Padding::horizontal(1))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .title(" Filter Name/Type "),
            );

            f.render_widget(filter_footer, split_area[0]);

            // Displays cursor when inputting
            f.set_cursor(
                split_area[0].x + filter_input.visual_cursor() as u16 + 2,
                split_area[0].y + 1,
            );
            drop(filter_input);
        }
        Mode::Sort => {
            let sort_footer = Paragraph::new(Line::from(SORT_CONTROLS_FOOTER))
                .centered()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Double)
                        .title(" Sort Column "),
                );

            f.render_widget(sort_footer, split_area[0]);
        }
        _ => {}
    }
}

fn running_as_root() -> bool {
    matches!(nix::unistd::getuid().as_raw(), 0)
}

fn format_percent(num: f64) -> String {
    if num < 1.0 {
        round_to_first_non_zero(num).to_string() + "%"
    } else {
        format!("{:.2}%", num)
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
