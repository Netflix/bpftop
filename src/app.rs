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
use crate::{bpf_program::{BpfProgram, Process}, helpers::program_type_to_string};
use circular_buffer::CircularBuffer;
use libbpf_rs::{query::ProgInfoIter, Iter, Link};
use ratatui::widgets::ScrollbarState;
use ratatui::widgets::TableState;
use std::{
    collections::HashMap,
    io::Read,
    ptr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tracing::error;
use tui_input::Input;

pub struct App {
    pub mode: Mode,
    pub table_state: TableState,
    pub vertical_scroll: usize,
    pub vertical_scroll_state: ScrollbarState,
    pub header_columns: [String; 7],
    pub items: Arc<Mutex<Vec<BpfProgram>>>,
    pub data_buf: Arc<Mutex<CircularBuffer<20, PeriodMeasure>>>,
    pub max_cpu: f64,
    pub max_eps: i64,
    pub max_runtime: u64,
    pub filter_input: Arc<Mutex<Input>>,
    pub selected_column: Option<usize>,
    pub graphs_bpf_program: Arc<Mutex<Option<BpfProgram>>>,
    sorted_column: Arc<Mutex<SortColumn>>,
}

pub struct PeriodMeasure {
    pub cpu_time_percent: f64,
    pub events_per_sec: i64,
    pub average_runtime_ns: u64,
}

#[derive(Debug, PartialEq)]
pub enum Mode {
    Table,
    Graph,
    Filter,
    Sort,
}

#[derive(Clone, Copy)]
pub enum SortColumn {
    NoOrder,
    Ascending(usize),
    Descending(usize),
}

#[repr(C)]
pub struct PidIterEntry {
    id: u32,
    pid: i32,
    comm: [u8; 16],
}

fn get_pid_map(link: &Option<Link>) -> HashMap<u32, Vec<Process>> {
    let mut pid_map: HashMap<u32, Vec<Process>> = HashMap::new();

    // Check if there is a link
    if let Some(actual_link) = link {
        let mut iter = match Iter::new(actual_link) {
            Ok(iter) => iter,
            Err(e) => {
                error!("Failed to create iterator: {}", e);
                return pid_map;
            }
        };
        let struct_size = std::mem::size_of::<PidIterEntry>();

        loop {
            let mut buffer = vec![0u8; struct_size];
            match iter.read(&mut buffer) {
                Ok(0) => break, // No more data to read
                Ok(n) => {
                    if n != struct_size {
                        error!("Expected {} bytes, read {} bytes", buffer.len(), n);
                        break;
                    }
                    let pid_entry: PidIterEntry = unsafe { ptr::read(buffer.as_ptr() as *const _) };
                    let process = Process {
                        pid: pid_entry.pid,
                        comm: String::from_utf8_lossy(&pid_entry.comm).to_string(),
                    };

                    pid_map.entry(pid_entry.id).or_default().push(process);
                }
                Err(e) => {
                    error!("Failed to read from iterator: {}", e);
                    break;
                }
            }
        }
    }

    pid_map
}

impl App {
    pub fn new() -> App {
        let mut app = App {
            mode: Mode::Table,
            vertical_scroll: 0,
            vertical_scroll_state: ScrollbarState::new(0),
            table_state: TableState::default(),
            header_columns: [
                String::from("ID"),
                String::from("Type"),
                String::from("Name"),
                String::from("Period Avg Runtime (ns)"),
                String::from("Total Avg Runtime (ns)"),
                String::from("Events/sec"),
                String::from("Total CPU %"),
            ],
            items: Arc::new(Mutex::new(vec![])),
            data_buf: Arc::new(Mutex::new(CircularBuffer::<20, PeriodMeasure>::new())),
            max_cpu: 0.0,
            max_eps: 0,
            max_runtime: 0,
            filter_input: Arc::new(Mutex::new(Input::default())),
            selected_column: None,
            graphs_bpf_program: Arc::new(Mutex::new(None)),
            sorted_column: Arc::new(Mutex::new(SortColumn::NoOrder)),
        };
        // Default sort column is Total CPU % in descending order
        app.sort_column(SortColumn::Descending(6));
        app
    }

    pub fn start_background_thread(&self, iter_link: Option<Link>) {
        let items = Arc::clone(&self.items);
        let data_buf = Arc::clone(&self.data_buf);
        let filter = Arc::clone(&self.filter_input);
        let sort_col = Arc::clone(&self.sorted_column);
        let graphs_bpf_program = Arc::clone(&self.graphs_bpf_program);

        thread::spawn(move || loop {
            let loop_start = Instant::now();

            let mut items = items.lock().unwrap();
            let map: HashMap<u32, BpfProgram> =
                items.drain(..).map(|prog| (prog.id, prog)).collect();

            let filter = filter.lock().unwrap();
            let filter_str = filter.value().to_lowercase();
            drop(filter);

            let pid_map = get_pid_map(&iter_link);
            let iter = ProgInfoIter::default();
            for prog in iter {
                let instant = Instant::now();

                let prog_name = match prog.name.to_str() {
                    Ok(name) => name.to_string(),
                    Err(_) => continue,
                };

                if prog_name.is_empty() {
                    continue;
                }

                // Skip bpf program if it does not match filter
                let bpf_type = program_type_to_string(prog.ty);
                if !filter_str.is_empty()
                    && !bpf_type.to_lowercase().contains(&filter_str)
                    && !prog_name.to_lowercase().contains(&filter_str)
                {
                    continue;
                }

                let processes = pid_map.get(&prog.id).cloned().unwrap_or_default();

                let mut bpf_program = BpfProgram {
                    id: prog.id,
                    bpf_type,
                    name: prog_name,
                    prev_runtime_ns: 0,
                    run_time_ns: prog.run_time_ns,
                    prev_run_cnt: 0,
                    run_cnt: prog.run_cnt,
                    instant,
                    period_ns: 0,
                    processes,
                };

                if let Some(prev_bpf_program) = map.get(&bpf_program.id) {
                    bpf_program.prev_runtime_ns = prev_bpf_program.run_time_ns;
                    bpf_program.prev_run_cnt = prev_bpf_program.run_cnt;
                    bpf_program.period_ns = prev_bpf_program.instant.elapsed().as_nanos();
                }

                if let Some(graphs_bpf_program) = graphs_bpf_program.lock().unwrap().as_ref() {
                    if bpf_program.id == graphs_bpf_program.id {
                        let mut data_buf = data_buf.lock().unwrap();
                        data_buf.push_back(PeriodMeasure {
                            cpu_time_percent: bpf_program.cpu_time_percent(),
                            events_per_sec: bpf_program.events_per_second(),
                            average_runtime_ns: bpf_program.period_average_runtime_ns(),
                        });
                    }
                }

                items.push(bpf_program);
            }

            // Sort items based on index of the column
            let sort_col = sort_col.lock().unwrap();
            match *sort_col {
                SortColumn::Ascending(col_idx) | SortColumn::Descending(col_idx) => {
                    match col_idx {
                        1 => items.sort_unstable_by(|a, b| a.bpf_type.cmp(&b.bpf_type)),
                        2 => items.sort_unstable_by(|a, b| a.name.cmp(&b.name)),
                        3 => items.sort_unstable_by(|a, b| {
                            a.period_average_runtime_ns()
                                .cmp(&b.period_average_runtime_ns())
                        }),
                        4 => items.sort_unstable_by(|a, b| {
                            a.total_average_runtime_ns()
                                .cmp(&b.total_average_runtime_ns())
                        }),
                        5 => items.sort_unstable_by(|a, b| {
                            a.events_per_second().cmp(&b.events_per_second())
                        }),
                        6 => items.sort_unstable_by(|a, b| {
                            a.cpu_time_percent()
                                .partial_cmp(&b.cpu_time_percent())
                                .unwrap()
                        }),
                        _ => items.sort_unstable_by_key(|item| item.id),
                    }
                    if let SortColumn::Descending(_) = *sort_col {
                        items.reverse();
                    }
                }
                SortColumn::NoOrder => {}
            }

            // Explicitly drop the remaining MutexGuards
            drop(items);
            drop(sort_col);

            // Adjust sleep duration to maintain a 1-second sample period, accounting for loop processing time.
            let elapsed = loop_start.elapsed();
            let sleep = if elapsed > Duration::from_secs(1) {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(1) - elapsed
            };
            thread::sleep(sleep);
        });
    }

    pub fn show_graphs(&mut self) {
        self.data_buf.lock().unwrap().clear();
        self.max_cpu = 0.0;
        self.max_eps = 0;
        self.max_runtime = 0;
        self.mode = Mode::Graph;
        self.graphs_bpf_program
            .lock()
            .unwrap()
            .clone_from(&self.selected_program());
    }

    pub fn show_table(&mut self) {
        self.mode = Mode::Table;
        self.data_buf.lock().unwrap().clear();
        self.max_cpu = 0.0;
        self.max_eps = 0;
        self.max_runtime = 0;
        *self.graphs_bpf_program.lock().unwrap() = None;
    }

    pub fn selected_program(&self) -> Option<BpfProgram> {
        let items = self.items.lock().unwrap();

        self.table_state
            .selected()
            .and_then(|i| items.get(i).cloned())
    }

    pub fn next_program(&mut self) {
        let items = self.items.lock().unwrap();
        if items.len() > 0 {
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i >= items.len() - 1 {
                        items.len() - 1
                    } else {
                        self.vertical_scroll = self.vertical_scroll.saturating_add(1);
                        i + 1
                    }
                }
                None => 0,
            };
            self.table_state.select(Some(i));
            self.vertical_scroll_state = self.vertical_scroll_state.position(self.vertical_scroll);
        }
    }

    pub fn previous_program(&mut self) {
        let items = self.items.lock().unwrap();
        if items.len() > 0 {
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i == 0 {
                        0
                    } else {
                        self.vertical_scroll = self.vertical_scroll.saturating_sub(1);
                        i - 1
                    }
                }
                None => return,  // do nothing if table_state == None && previous_program() called
            };
            self.table_state.select(Some(i));
            self.vertical_scroll_state = self.vertical_scroll_state.position(self.vertical_scroll);
        }
    }

    pub fn toggle_filter(&mut self) {
        self.mode = match &self.mode {
            Mode::Table => Mode::Filter,
            _ => Mode::Table,
        }
    }

    pub fn toggle_sort(&mut self) {
        match &self.mode {
            Mode::Table => {
                self.mode = Mode::Sort;

                // Pickup where last selected column left off from
                let sorted_column = self.sorted_column.lock().unwrap();
                self.selected_column = match *sorted_column {
                    SortColumn::Descending(col_idx) | SortColumn::Ascending(col_idx) => {
                        Some(col_idx)
                    }
                    SortColumn::NoOrder => Some(0),
                };
                drop(sorted_column);
            }
            _ => {
                self.mode = Mode::Table;
                self.selected_column = None;
            }
        }
    }

    pub fn next_column(&mut self) {
        if let Some(selected) = self.selected_column.as_mut() {
            let num_cols = self.header_columns.len();
            *selected = (*selected + 1) % num_cols;
        } else {
            self.selected_column = Some(0);
        }
    }

    pub fn previous_column(&mut self) {
        if let Some(selected) = self.selected_column.as_mut() {
            let num_cols = self.header_columns.len();
            *selected = (*selected + num_cols - 1) % num_cols;
        } else {
            self.selected_column = Some(0);
        }
    }

    pub fn sort_column(&mut self, sort_input: SortColumn) {
        let mut sorted_column = self.sorted_column.lock().unwrap();

        // Clear sort symbol of the currently sorted column
        match *sorted_column {
            SortColumn::Ascending(col_idx) | SortColumn::Descending(col_idx) => {
                self.header_columns[col_idx].pop();
            }
            SortColumn::NoOrder => {}
        };

        // Update selected column with new sort
        match sort_input {
            SortColumn::Ascending(col_idx) => {
                self.header_columns[col_idx].push('↑');
            }
            SortColumn::Descending(col_idx) => {
                self.header_columns[col_idx].push('↓');
            }
            SortColumn::NoOrder => {}
        }
        *sorted_column = sort_input;
        drop(sorted_column);
    }

    pub fn cycle_sort_exit(&mut self) {
        let sorted_column = self.sorted_column.lock().unwrap();
        let sorted_col = *sorted_column;
        drop(sorted_column);

        // Toggle sort type
        let selected_idx = self.selected_column.unwrap_or_default();
        match sorted_col {
            SortColumn::Descending(col_idx) if col_idx == selected_idx => {
                self.sort_column(SortColumn::Ascending(selected_idx));
            }
            _ => {
                self.sort_column(SortColumn::Descending(selected_idx));
            }
        }

        // Exit sort mode
        self.toggle_sort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_program_with_empty() {
        let mut app = App::new();

        // Initially no item is selected
        assert_eq!(app.selected_program(), None);

        // After calling next, no item should be selected
        app.next_program();
        assert_eq!(app.selected_program(), None);
    }

    #[test]
    fn test_next_program() {
        let mut app = App::new();
        let prog_1 = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 0,
            processes: vec![],
        };

        let prog_2 = BpfProgram {
            id: 2,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 0,
            processes: vec![],
        };

        // Add some dummy BpfPrograms to the items vector
        app.items.lock().unwrap().push(prog_1.clone());
        app.items.lock().unwrap().push(prog_2.clone());

        // Initially no item is selected
        assert_eq!(app.selected_program(), None, "expected no program");
        assert_eq!(app.vertical_scroll, 0, "expected init with 0, got: {}", app.vertical_scroll);

        // After calling next, the first item should be selected
        app.next_program();
        assert_eq!(app.selected_program(), Some(prog_1.clone()), "expected prog_1");
        assert_eq!(app.vertical_scroll, 0, "expected scroll 0, got: {}", app.vertical_scroll);

        // After calling next again, the second item should be selected
        app.next_program();
        assert_eq!(app.selected_program(), Some(prog_2.clone()), "expected prog_2");
        assert_eq!(app.vertical_scroll, 1, "expected scroll 1, got: {}", app.vertical_scroll);

        // After calling next again, the second item should still be selected without wrapping
        app.next_program();
        assert_eq!(app.selected_program(), Some(prog_2.clone()), "expected prog_2; no wrap around");
        assert_eq!(app.vertical_scroll, 1, "expected scroll 1, got: {}", app.vertical_scroll);

    }

    #[test]
    fn test_previous_program_with_empty() {
        let mut app = App::new();

        // Initially no item is selected
        assert_eq!(app.selected_program(), None);
        
        // Initially ScrollbarState is 0
        assert_eq!(app.vertical_scroll_state, ScrollbarState::new(0), "unexpected ScrollbarState");
        assert_eq!(app.vertical_scroll, 0, "expected 0 vertical_scroll, got: {}", app.vertical_scroll);

        // After calling previous, no item should be selected
        app.previous_program();
        assert_eq!(app.selected_program(), None);

        assert_eq!(app.vertical_scroll_state, ScrollbarState::new(0), "unexpected ScrollbarState");
        assert_eq!(app.vertical_scroll, 0, "expected 0 vertical_scroll, got: {}", app.vertical_scroll);
    }

    #[test]
    fn test_previous_program() {
        let mut app = App::new();
        let prog_1 = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 0,
            processes: vec![],
        };

        let prog_2 = BpfProgram {
            id: 2,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 0,
            processes: vec![],
        };

        // Add some dummy BpfPrograms to the items vector
        app.items.lock().unwrap().push(prog_1.clone());
        app.items.lock().unwrap().push(prog_2.clone());

        // Initially no item is selected
        assert_eq!(app.selected_program(), None, "expected no program");
        assert_eq!(app.vertical_scroll, 0, "expected init with 0");

        // After calling previous with no table state, nothing should be selected
        app.previous_program();
        assert_eq!(app.selected_program(), None, "expected None");
        assert_eq!(app.vertical_scroll, 0, "still 0, no wrapping");

        // After calling previous again, still nothing should be selected
        app.previous_program();
        assert_eq!(app.selected_program(), None, "still None");
        assert_eq!(app.vertical_scroll, 0, "still 0, no wrapping");

        app.next_program();  // populate table state and expect prog_1 selected
        assert_eq!(app.selected_program(), Some(prog_1.clone()), "expected prog_1");
        assert_eq!(app.vertical_scroll, 0, "expected scroll 0");

        // After calling previous again, prog_1 should still be selected (0th index)
        app.previous_program();
        assert_eq!(app.selected_program(), Some(prog_1.clone()), "still expecting prog_1");
        assert_eq!(app.vertical_scroll, 0, "still 0, no wrapping");
    }

    #[test]
    fn test_toggle_graphs() {
        let mut app = App::new();

        // Initially, UI should be in table mode
        assert_eq!(app.mode, Mode::Table);

        // After calling show_graphs, UI should be in graph mode
        app.show_graphs();
        assert_eq!(app.mode, Mode::Graph);

        // Set max_cpu, max_eps, and max_runtime to non-zero values
        app.max_cpu = 10.0;
        app.max_eps = 5;
        app.max_runtime = 100;
        app.data_buf.lock().unwrap().push_back(PeriodMeasure {
            cpu_time_percent: 10.0,
            events_per_sec: 5,
            average_runtime_ns: 100,
        });

        // After calling show_table, UI should be in table mode again
        app.show_table();
        assert_eq!(app.mode, Mode::Table);

        // max_cpu, max_eps, and max_runtime should be reset to 0
        assert_eq!(app.max_cpu, 0.0);
        assert_eq!(app.max_eps, 0);
        assert_eq!(app.max_runtime, 0);

        // and data_buf should be empty again
        assert!(app.data_buf.lock().unwrap().is_empty());
    }
}
