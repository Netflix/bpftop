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
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use circular_buffer::CircularBuffer;
use libbpf_rs::query::ProgInfoIter;
use ratatui::widgets::TableState;

use crate::bpf_program::BpfProgram;

pub struct App {
    pub state: Arc<Mutex<TableState>>,
    pub items: Arc<Mutex<Vec<BpfProgram>>>,
    pub data_buf: Arc<Mutex<CircularBuffer<20, PeriodMeasure>>>,
    pub show_graphs: bool,
    pub max_cpu: f64,
    pub max_eps: i64,
    pub max_runtime: u64,
}

pub struct PeriodMeasure {
    pub cpu_time_percent: f64,
    pub events_per_sec: i64,
    pub average_runtime_ns: u64,
}

impl App {
    pub fn new() -> App {
        App {
            state: Arc::new(Mutex::new(TableState::default())),
            items: Arc::new(Mutex::new(vec![])),
            data_buf: Arc::new(Mutex::new(CircularBuffer::<20, PeriodMeasure>::new())),
            show_graphs: false,
            max_cpu: 0.0,
            max_eps: 0,
            max_runtime: 0,
        }
    }

    pub fn start_background_thread(&self) {
        let items = Arc::clone(&self.items);
        let data_buf = Arc::clone(&self.data_buf);
        let state = Arc::clone(&self.state);

        thread::spawn(move || loop {
            // Lock items for this thread's exclusive use.
            let mut items = items.lock().unwrap();
            let mut data_buf = data_buf.lock().unwrap();
            let state = state.lock().unwrap();

            let items_copy = items.clone();
            let map: HashMap<String, &BpfProgram> = items_copy
                .iter()
                .map(|prog| (prog.id.clone(), prog))
                .collect();
            items.clear();

            let iter = ProgInfoIter::default();
            for prog in iter {
                let instant = Instant::now();

                let prog_name = prog.name.to_str().unwrap().to_string();

                if prog_name.is_empty() {
                    continue;
                }

                let mut bpf_program = BpfProgram {
                    id: prog.id.to_string(),
                    bpf_type: prog.ty.to_string(),
                    name: prog_name,
                    prev_runtime_ns: 0,
                    run_time_ns: prog.run_time_ns,
                    prev_run_cnt: 0,
                    run_cnt: prog.run_cnt,
                    instant,
                    period_ns: 0,
                };

                if let Some(prev_bpf_program) = map.get(&bpf_program.id) {
                    bpf_program.prev_runtime_ns = prev_bpf_program.run_time_ns;
                    bpf_program.prev_run_cnt = prev_bpf_program.run_cnt;
                    bpf_program.period_ns = prev_bpf_program.instant.elapsed().as_nanos();
                }

                items.push(bpf_program);
            }

            if let Some(index) = state.selected() {
                let bpf_program = &items[index];
                data_buf.push_back(PeriodMeasure {
                    cpu_time_percent: bpf_program.cpu_time_percent(),
                    events_per_sec: bpf_program.events_per_second(),
                    average_runtime_ns: bpf_program.period_average_runtime_ns(),
                });
            }

            // Explicitly drop the MutexGuard returned by lock() to unlock before sleeping.
            drop(items);
            drop(data_buf);
            drop(state);

            thread::sleep(Duration::from_secs(1));
        });
    }

    pub fn toggle_graphs(&mut self) {
        self.data_buf.lock().unwrap().clear();
        self.max_cpu = 0.0;
        self.max_eps = 0;
        self.max_runtime = 0;
        self.show_graphs = !self.show_graphs;
    }

    pub fn selected_program(&self) -> Option<BpfProgram> {
        let items = self.items.lock().unwrap().clone();
        let state = self.state.lock().unwrap();

        match state.selected() {
            Some(i) => Some(items[i].clone()),
            None => None,
        }
    }

    pub fn next(&mut self) {
        let items = self.items.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();

        let i = match state.selected() {
            Some(i) => {
                if i >= items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let items = self.items.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();

        let i = match state.selected() {
            Some(i) => {
                if i == 0 {
                    items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        state.select(Some(i));
    }
}
