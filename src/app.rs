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

use libbpf_rs::query::ProgInfoIter;
use ratatui::widgets::TableState;

use crate::bpf_program::BpfProgram;

pub struct App {
    pub state: TableState,
    pub items: Arc<Mutex<Vec<BpfProgram>>>,
}

impl App {
    pub fn new() -> App {
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

            // Explicitly drop the MutexGuard returned by lock() to unlock before sleeping.
            drop(items);

            thread::sleep(Duration::from_secs(1));
        });
    }
}
