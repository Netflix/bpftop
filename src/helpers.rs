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
use libbpf_rs::ProgramType;

pub fn format_percent(num: f64) -> String {
    if num < 1.0 {
        round_to_first_non_zero(num).to_string() + "%"
    } else {
        format!("{num:.2}%")
    }
}

pub fn round_to_first_non_zero(num: f64) -> f64 {
    if num == 0.0 {
        return 0.0;
    }

    let mut multiplier = 1.0;
    while num * multiplier < 1.0 {
        multiplier *= 10.0;
    }
    (num * multiplier).round() / multiplier
}

pub fn program_type_to_string(program_type: ProgramType) -> String {
    match program_type {
        ProgramType::Unspec => "Unspec",
        ProgramType::SocketFilter => "SocketFilter",
        ProgramType::Kprobe => "Kprobe",
        ProgramType::SchedCls => "SchedCls",
        ProgramType::SchedAct => "SchedAct",
        ProgramType::Tracepoint => "Tracepoint",
        ProgramType::Xdp => "Xdp",
        ProgramType::PerfEvent => "PerfEvent",
        ProgramType::CgroupSkb => "CgroupSkb",
        ProgramType::CgroupSock => "CgroupSock",
        ProgramType::LwtIn => "LwtIn",
        ProgramType::LwtOut => "LwtOut",
        ProgramType::LwtXmit => "LwtXmit",
        ProgramType::SockOps => "SockOps",
        ProgramType::SkSkb => "SkSkb",
        ProgramType::CgroupDevice => "CgroupDevice",
        ProgramType::SkMsg => "SkMsg",
        ProgramType::RawTracepoint => "RawTracepoint",
        ProgramType::CgroupSockAddr => "CgroupSockAddr",
        ProgramType::LwtSeg6local => "LwtSeg6local",
        ProgramType::LircMode2 => "LircMode2",
        ProgramType::SkReuseport => "SkReuseport",
        ProgramType::FlowDissector => "FlowDissector",
        ProgramType::CgroupSysctl => "CgroupSysctl",
        ProgramType::RawTracepointWritable => "RawTracepointWritable",
        ProgramType::CgroupSockopt => "CgroupSockopt",
        ProgramType::Tracing => "Tracing",
        ProgramType::StructOps => "StructOps",
        ProgramType::Ext => "Ext",
        ProgramType::Lsm => "Lsm",
        ProgramType::SkLookup => "SkLookup",
        ProgramType::Syscall => "Syscall",
        _ => "Unknown",
    }
    .to_string()
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

    #[test]
    fn test_program_type_to_string() {
        let str = program_type_to_string(ProgramType::CgroupSkb);
        assert_eq!(str, "CgroupSkb");
    }
}
