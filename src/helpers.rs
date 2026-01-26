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
use libbpf_rs::{ProgramAttachType::{self, *}, ProgramType, query::LinkTypeInfo};

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

pub const fn program_type_as_str(program_type: &ProgramType) -> &'static str {
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
}

pub(crate) fn link_type_as_str(link_type: &LinkTypeInfo) -> &'static str {
    match link_type {
        LinkTypeInfo::RawTracepoint(_) => "RawTracepoint",
        LinkTypeInfo::Tracing(_) => "Tracing",
        LinkTypeInfo::Cgroup(_) => "Cgroup",
        LinkTypeInfo::Iter => "Iter",
        LinkTypeInfo::NetNs(_) => "NetNs",
        LinkTypeInfo::Unknown => "Unknown",
    }
}

pub(crate) fn attach_type_as_str(attach_type: ProgramAttachType) -> &'static str {
    match attach_type {
        CgroupInetIngress => "CgroupInetIngress",
        CgroupInetEgress => "CgroupInetEgress",
        CgroupInetSockCreate => "CgroupInetSockCreate",
        CgroupSockOps => "CgroupSockOps",
        SkSkbStreamParser => "SkSkbStreamParser",
        SkSkbStreamVerdict => "SkSkbStreamVerdict",
        CgroupDevice => "CgroupDevice",
        SkMsgVerdict => "SkMsgVerdict",
        CgroupInet4Bind => "CgroupInet4Bind",
        CgroupInet6Bind => "CgroupInet6Bind",
        CgroupInet4Connect => "CgroupInet4Connect",
        CgroupInet6Connect => "CgroupInet6Connect",
        CgroupInet4PostBind => "CgroupInet4PostBind",
        CgroupInet6PostBind => "CgroupInet6PostBind",
        CgroupUdp4Sendmsg => "CgroupUdp4Sendmsg",
        CgroupUdp6Sendmsg => "CgroupUdp6Sendmsg",
        LircMode2 => "LircMode2",
        FlowDissector => "FlowDissector",
        CgroupSysctl => "CgroupSysctl",
        CgroupUdp4Recvmsg => "CgroupUdp4Recvmsg",
        CgroupUdp6Recvmsg => "CgroupUdp6Recvmsg",
        CgroupGetsockopt => "CgroupGetsockopt",
        CgroupSetsockopt => "CgroupSetsockopt",
        TraceRawTp => "TraceRawTp",
        TraceFentry => "TraceFentry",
        TraceFexit => "TraceFexit",
        ModifyReturn => "ModifyReturn",
        LsmMac => "LsmMac",
        TraceIter => "TraceIter",
        CgroupInet4Getpeername => "CgroupInet4Getpeername",
        CgroupInet6Getpeername => "CgroupInet6Getpeername",
        CgroupInet4Getsockname => "CgroupInet4Getsockname",
        CgroupInet6Getsockname => "CgroupInet6Getsockname",
        XdpDevmap => "XdpDevmap",
        CgroupInetSockRelease => "CgroupInetSockRelease",
        XdpCpumap => "XdpCpumap",
        SkLookup => "SkLookup",
        Xdp => "Xdp",
        SkSkbVerdict => "SkSkbVerdict",
        SkReuseportSelect => "SkReuseportSelect",
        SkReuseportSelectOrMigrate => "SkReuseportSelectOrMigrate",
        PerfEvent => "PerfEvent",
        _ => "Unknown",
    }
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
        let str = program_type_as_str(&ProgramType::CgroupSkb);
        assert_eq!(str, "CgroupSkb");
    }

    #[test]
    fn test_link_type_to_string() {
        let str = link_type_as_str(&LinkTypeInfo::Iter);
        assert_eq!(str, "Iter");
    }

    #[test]
    fn test_attach_type_to_string() {
        let str = attach_type_as_str(ProgramAttachType::Xdp);
        assert_eq!(str, "Xdp");
    }
}
