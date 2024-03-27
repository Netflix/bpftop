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
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct BpfProgram {
    pub id: u32,
    pub bpf_type: String,
    pub name: String,
    pub prev_runtime_ns: u64,
    pub run_time_ns: u64,
    pub prev_run_cnt: u64,
    pub run_cnt: u64,
    pub instant: Instant,
    pub period_ns: u128,
}

impl PartialEq for BpfProgram {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
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

    pub fn events_per_second(&self) -> i64 {
        if self.period_ns == 0 {
            return 0;
        }
        let events_per_second =
            self.run_cnt_delta() as f64 / self.period_ns as f64 * 1_000_000_000.0;
        events_per_second.round() as i64
    }

    pub fn cpu_time_percent(&self) -> f64 {
        if self.period_ns == 0 {
            return 0.0;
        }
        self.runtime_delta() as f64 / self.period_ns as f64 * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_eq() {
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
        };

        assert_eq!(prog_1, prog_1);
        assert_ne!(prog_1, prog_2);
    }

    #[test]
    fn test_period_average_runtime_ns() {
        let prog = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 0,
        };
        assert_eq!(prog.period_average_runtime_ns(), 100);
    }

    #[test]
    fn test_total_average_runtime_ns() {
        let prog = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 1000,
            prev_run_cnt: 1,
            run_cnt: 5,
            instant: Instant::now(),
            period_ns: 1000,
        };
        assert_eq!(prog.total_average_runtime_ns(), 200);
    }

    #[test]
    fn test_runtime_delta() {
        let prog = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 1,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 0,
        };
        assert_eq!(prog.runtime_delta(), 100);
    }

    #[test]
    fn test_run_cnt_delta() {
        let prog = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 5,
            run_cnt: 8,
            instant: Instant::now(),
            period_ns: 0,
        };
        assert_eq!(prog.run_cnt_delta(), 3);
    }

    #[test]
    fn test_events_per_second() {
        let prog = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100,
            run_time_ns: 200,
            prev_run_cnt: 10,
            run_cnt: 50,
            instant: Instant::now(),
            period_ns: 1_000_000_000,
        };
        assert_eq!(prog.events_per_second(), 40);
    }

    #[test]
    fn test_cpu_time_percent() {
        let prog = BpfProgram {
            id: 1,
            bpf_type: "test".to_string(),
            name: "test".to_string(),
            prev_runtime_ns: 100_000_000,
            run_time_ns: 200_000_000,
            prev_run_cnt: 0,
            run_cnt: 2,
            instant: Instant::now(),
            period_ns: 1_000_000_000,
        };
        // Calculate expected value: (200_000_000 - 100_000_000) / 1_000_000_000 * 100 = 10.0
        let expected = 10.0;
        assert_eq!(prog.cpu_time_percent(), expected);
    }
}
