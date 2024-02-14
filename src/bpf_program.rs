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

#[derive(Clone)]
pub struct BpfProgram {
    pub id: String,
    pub bpf_type: String,
    pub name: String,
    pub prev_runtime_ns: u64,
    pub run_time_ns: u64,
    pub prev_run_cnt: u64,
    pub run_cnt: u64,
    pub prev_timestamp_ns: u128,
    pub timestamp_ns: u128,
    pub num_cpus: usize,
}

impl BpfProgram {

    pub fn period_average_runtime_ns(&self) -> u64 {
        if self.run_cnt_delta() == 0 {
            return 0;
        }

        self.runtime_delta() / self.run_cnt_delta()
    }
    
    pub fn total_average_runtime_ns(&self) -> u64 {
        if self.run_cnt == 0 {
            return 0;
        }

        self.run_time_ns / self.run_cnt
    }

    pub fn runtime_delta(&self) -> u64 {
        self.run_time_ns - self.prev_runtime_ns
    }

    pub fn run_cnt_delta(&self) -> u64 {
        self.run_cnt - self.prev_run_cnt
    }

    pub fn timestamp_delta(&self) -> u128 {
        self.timestamp_ns - self.prev_timestamp_ns
    }

    pub fn events_per_second(&self) -> i64 {
        if self.timestamp_delta() == 0 {
            return 0;
        }
        let events_per_second =
            self.run_cnt_delta() as f64 / self.timestamp_delta() as f64 * 1_000_000_000.0;
        events_per_second.round() as i64
    }

    pub fn cpu_time_percent(&self) -> f64 {
        if self.run_time_ns == 0 {
            return 0.0;
        }
        (self.runtime_delta() as f64 / self.num_cpus as f64) / self.timestamp_delta() as f64 * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_period_average_runtime_ns() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            prev_timestamp_ns: 1000,
            timestamp_ns: 2000,
            num_cpus: 4,
        };
        assert_eq!(prog.period_average_runtime_ns(), 100);
    }

    #[test]
    fn test_total_average_runtime_ns() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 1000,
            prev_run_cnt: 1,
            run_cnt: 5,
            prev_timestamp_ns: 1000,
            timestamp_ns: 2000,
            num_cpus: 4,
        };
        assert_eq!(prog.total_average_runtime_ns(), 200);
    }

    #[test]
    fn test_runtime_delta() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            prev_timestamp_ns: 1000,
            timestamp_ns: 2000,
            num_cpus: 4,
        };
        assert_eq!(prog.runtime_delta(), 100);
    }

    #[test]
    fn test_run_cnt_delta() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 5,
            run_cnt: 8,
            prev_timestamp_ns: 1000,
            timestamp_ns: 2000,
            num_cpus: 4,
        };
        assert_eq!(prog.run_cnt_delta(), 3);
    }

    #[test]
    fn test_timestamp_delta() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            prev_timestamp_ns: 1000,
            timestamp_ns: 3000,
            num_cpus: 4,
        };
        assert_eq!(prog.timestamp_delta(), 2000);
    }

    #[test]
    fn test_events_per_second() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 10,
            run_cnt: 50,
            prev_timestamp_ns: 1_000_000_000,
            timestamp_ns: 2_000_000_000,
            num_cpus: 4,
        };
        assert_eq!(prog.events_per_second(), 40);
    }

    #[test]
    fn test_cpu_time_percent() {
        let prog = BpfProgram {
            id: "test".to_string(),
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            prev_timestamp_ns: 1000,
            timestamp_ns: 2000,
            num_cpus: 4,
        };
        // Calculate expected value: ((200 - 100) / 4) / (2000 - 1000) * 100 = 2.5
        let expected = 2.5;
        assert_eq!(prog.cpu_time_percent(), expected);
    }
}
