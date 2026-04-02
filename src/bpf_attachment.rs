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

use anyhow::Result;
use libbpf_rs::{
    query::{
        CgroupLinkInfo, KprobeMultiLinkInfo, LinkInfo, LinkInfoIter, LinkTypeInfo::*,
        NetNsLinkInfo, NetfilterLinkInfo, NetkitLinkInfo, RawTracepointLinkInfo, SockMapLinkInfo,
        StructOpsLinkInfo, TcxLinkInfo, TracingLinkInfo, UprobeMultiLinkInfo, XdpLinkInfo,
    },
    ProgramType,
};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_DUMP,
    NLM_F_MULTIPART, NLM_F_REQUEST,
};
use netlink_packet_route::{
    link::{LinkAttribute, LinkMessage},
    tc::{TcAttribute, TcBpfFlags, TcFilterBpfOption, TcHandle, TcMessage, TcOption},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use nix::net::if_::if_indextoname;
use ratatui::{style::Stylize as _, text::Line, widgets::ListItem};

use crate::helpers::{attach_type_as_str, link_type_as_str, program_type_as_str};

/// Collect and render all attachments used by the BPF program as a list of [`ListItem`]:
///
/// ```text
/// BPF Links (<number-of-links-used>)
///   ID <link-id>: <link-type>  <link-specific-metadata>
///   ...
/// TC Filters (<number-of-tc-filters-used>)
///   <iface>(<ifindex>)  <direction>  [direct-action]
///   ...
/// ```
pub(crate) fn render_prog_attachments<'a>(prog_id: u32, prog_type: &str, sock: &mut Option<Socket>) -> Vec<ListItem<'a>> {
    // Collect BPF links
    let links = LinkInfoIter::default()
        .filter_map(move |link| (link.prog_id == prog_id).then_some(link))
        .collect::<Vec<_>>();

    // Collect TC filters only if relevant
    const SCHED_CLS: &str = program_type_as_str(&ProgramType::SchedCls);
    const SCHED_ACT: &str = program_type_as_str(&ProgramType::SchedAct);
    let tc_filters = match prog_type {
        SCHED_CLS | SCHED_ACT => {
            if sock.is_none() {
                *sock = open_route_sock().ok();
            }
            match sock {
                Some(route_sock) => prog_tc_filters(route_sock, prog_id).unwrap_or_default(),
                None => vec![],
            }
        },
        _ => vec![],
    };

    let mut attachments = Vec::with_capacity(2 + links.len() + tc_filters.len());
    if !links.is_empty() {
        attachments.push(
            ListItem::new(Line::from_iter([
                "BPF Links".bold(),
                format!(" ({})", links.len()).into()
            ]))
        );

        for link in links {
            attachments.push(ListItem::new(render_bpf_link(link)));
        }
    }
    if !tc_filters.is_empty() {
        attachments.push(
            ListItem::new(Line::from_iter([
                "TC Filters".bold(),
                format!(" ({})", tc_filters.len()).into()
            ]))
        );

        for filter in tc_filters {
            attachments.push(ListItem::new(render_tc_filter(filter)));
        }
    }

    attachments
}

/// Render the BPF link info as a [`Line`]: `  ID <link-id>: <link-type> <link-specific-metadata>`
fn render_bpf_link<'a>(link: LinkInfo) -> Line<'a> {
    let link_type = link_type_as_str(&link.info);
    let metadata = match link.info {
        RawTracepoint(info) => {
            let RawTracepointLinkInfo { name } = info;
            format!(" {}", name)
        }
        Tracing(info) => {
            let TracingLinkInfo { attach_type } = info;
            let attach = attach_type_as_str(attach_type);

            format!(" {}", attach)
        }
        Cgroup(info) => {
            let CgroupLinkInfo { cgroup_id, attach_type } = info;
            let attach = attach_type_as_str(attach_type);

            format!( " {} CgroupId({})", attach, cgroup_id)
        }
        Iter => "".into(),
        NetNs(info) => {
            let NetNsLinkInfo { ino, attach_type } = info;
            let attach = attach_type_as_str(attach_type);

            format!(" {} Inode({})", attach, ino)
        }
        Xdp(info) => {
            let XdpLinkInfo { ifindex } = info;
            let ifname_cstr = if_indextoname(ifindex).unwrap_or_default();

            format!(" {}({})", ifname_cstr.to_string_lossy(), ifindex)
        }
        StructOps(info) => {
            let StructOpsLinkInfo { map_id } = info;
            format!(" MapId({})", map_id)
        }
        Netfilter(info) => {
            let NetfilterLinkInfo { protocol_family, hooknum, priority, flags } = info;
            let nf_proto = match protocol_family as i32 {
                libbpf_rs::NFPROTO_IPV4 => "IPv4",
                libbpf_rs::NFPROTO_IPV6 => "IPv6",
                _ => "",
            };
            let inet_hook = match hooknum as i32 {
                libbpf_rs::NF_INET_PRE_ROUTING => "PreRouting",
                libbpf_rs::NF_INET_LOCAL_IN => "LocalIn",
                libbpf_rs::NF_INET_FORWARD => "Forward",
                libbpf_rs::NF_INET_LOCAL_OUT => "LocalOut",
                libbpf_rs::NF_INET_POST_ROUTING => "PostRouting",
                _ => "",
            };
            let ip_defrag = if flags & libbpf_sys::BPF_F_NETFILTER_IP_DEFRAG != 0 { "IpDefrag" } else { "" };

            format!(" {} {} Priority({}) {}", nf_proto, inet_hook, priority, ip_defrag)
        }
        KprobeMulti(info) => {
            let KprobeMultiLinkInfo { count, flags, missed } = info;
            let ret_probe = if flags & libbpf_sys::BPF_F_KPROBE_MULTI_RETURN != 0 { "Return" } else { "" };

            format!(" Count({}) Missed({}) {}", count, missed, ret_probe)
        }
        UprobeMulti(info) => {
            let UprobeMultiLinkInfo { count, flags, pid, .. } = info;
            let ret_probe = if flags & libbpf_sys::BPF_F_UPROBE_MULTI_RETURN != 0 { "Return" } else { "" };

            format!(" TargetPid({}) Count({}) {}", pid, count, ret_probe)
        }
        Tcx(info) => {
            let TcxLinkInfo { ifindex, attach_type } = info;
            let ifname_cstr = if_indextoname(ifindex).unwrap_or_default();
            let attach = attach_type_as_str(attach_type);

            format!(" {}({}) {}", ifname_cstr.to_string_lossy(), ifindex, attach)
        }
        Netkit(info) => {
            let NetkitLinkInfo { ifindex, attach_type } = info;
            let ifname_cstr = if_indextoname(ifindex).unwrap_or_default();
            let attach = attach_type_as_str(attach_type);

            format!(" {}({}) {}", ifname_cstr.to_string_lossy(), ifindex, attach)
        }
        SockMap(info) => {
            let SockMapLinkInfo { map_id, attach_type } = info;
            let attach = attach_type_as_str(attach_type);

            format!(" MapId({}) {}", map_id, attach)
        }
        PerfEvent => "".into(),
        Unknown => "".into(),
    };

    Line::from_iter([
        format!("  ID {}: {}", link.id, link_type).bold(),
        metadata.into(),
    ])
}

/// Render the TC filter info as a [`Line`]: `  <iface>(<ifindex>) <direction> [is-direct-action]`
fn render_tc_filter<'a>(filter: TcFilter) -> Line<'a> {
    let TcFilter { ifindex, ifname, direction, direct_action } = filter;

    let direction_str = match direction {
        Direction::Ingress => "Ingress",
        Direction::Egress => "Egress",
    };
    let direct_act = if direct_action { "DirectAction" } else { "" };

    Line::from_iter([
        format!("  {}({})", ifname, ifindex).bold(),
        format!(" {} {}", direction_str, direct_act).into(),
    ])
}

/// TC BPF programs attached as TC filter on a clsact qdisc.
struct TcFilter {
    ifindex: i32,
    ifname: String,
    direction: Direction,
    direct_action: bool,
}

/// TC filter traffic direction.
#[derive(Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}

fn open_route_sock() -> Result<Socket> {
    let mut sock = Socket::new(NETLINK_ROUTE)?;
    sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0))?;
    Ok(sock)
}

// Collect TC filters used by prog.
fn prog_tc_filters(sock: &Socket, prog_id: u32) -> Result<Vec<TcFilter>> {
    let ifaces = get_ifaces(&sock)?;

    const HANDLES: [(TcHandle, Direction); 2] = [
        (TcHandle { major: u16::MAX, minor: TcHandle::MIN_INGRESS }, Direction::Ingress),
        (TcHandle { major: u16::MAX, minor: TcHandle::MIN_EGRESS }, Direction::Egress),
    ];

    let mut tc_filters = vec![];

    for (ifindex, ifname) in ifaces {
        for (handle, direction) in HANDLES {
            let mut tcmsg = TcMessage::default();
            tcmsg.header.family = AddressFamily::Unspec;
            tcmsg.header.index = ifindex;
            tcmsg.header.parent = handle;

            let mut pkt = NetlinkMessage::new(
                NetlinkHeader::default(),
                NetlinkPayload::from(RouteNetlinkMessage::GetTrafficFilter(tcmsg)),
            );
            pkt.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
            pkt.header.sequence_number = 1;
            pkt.finalize();

            let rx_tc_filters = send_and_recv(&sock, pkt)?.into_iter().filter_map(|rtm| {
                let RouteNetlinkMessage::NewTrafficFilter(rx_tcmsg) = rtm else {
                    return None;
                };
                if !rx_tcmsg.attributes.iter().any(|attr| matches!(attr, TcAttribute::Kind(k) if k == "bpf")) {
                    return None;
                }

                // Only collect filters used by prog
                let Some(tc_opts) = rx_tcmsg.attributes.into_iter().find_map(|attr| match attr {
                    TcAttribute::Options(tc_opts)
                        if tc_opts.iter().any(|opt| matches!(
                            opt,
                            TcOption::Bpf(TcFilterBpfOption::ProgId(id)) if &prog_id == id
                        )) =>
                    {
                        Some(tc_opts)
                    },
                    _ => None,
                }) else {
                    return None;
                };

                let direct_action = tc_opts.iter().any(|opt| matches!(
                    opt,
                    TcOption::Bpf(TcFilterBpfOption::Flags(f)) if f.contains(TcBpfFlags::DirectAction)
                ));

                Some(TcFilter { ifindex, ifname: ifname.clone(), direction, direct_action })
            });

            tc_filters.extend(rx_tc_filters);
        }
    }

    Ok(tc_filters)
}

// Collect network interfaces as: (ifindex, ifname)
fn get_ifaces(sock: &Socket) -> Result<impl Iterator<Item = (i32, String)>> {
    let mut pkt = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(LinkMessage::default())),
    );
    pkt.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    pkt.header.sequence_number = 1;
    pkt.finalize();

    let ifaces = send_and_recv(&sock, pkt)?.into_iter()
        .filter_map(|rtm_msg| match rtm_msg {
            RouteNetlinkMessage::NewLink(link_msg) => {
                let ifindex = link_msg.header.index as i32;
                let ifname = link_msg.attributes.into_iter().find_map(|attr| {
                    match attr {
                        LinkAttribute::IfName(name) => Some(name),
                        _ => None,
                    }
                }).unwrap_or_default();
                Some((ifindex, ifname))
            },
            _ => None,
        });
    Ok(ifaces)
}

// Send and receive netlink packet.
fn send_and_recv<I>(sock: &Socket, pkt: NetlinkMessage<I>) -> Result<Vec<RouteNetlinkMessage>>
where
    I: NetlinkSerializable,
{
    let mut send_buf = vec![0; pkt.header.length as usize];
    pkt.serialize(&mut send_buf[..]);
    sock.send(&send_buf[..], 0)?;

    let mut rx_buf = vec![0; 4096];
    let mut rx_dump = vec![];

    // NLM_F_DUMP flag expect a multipart rx_pkt in response.
    let mut dump_done = false;
    let mut multipart = true;
    while !dump_done && multipart {
        multipart = false;
        let size = sock.recv(&mut &mut rx_buf[..], 0)?;

        let mut offset = 0;
        while offset < size {
            let rx_pkt: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(&rx_buf[offset..])?;
            multipart = rx_pkt.header.flags & NLM_F_MULTIPART != 0;
            if rx_pkt.header.length == 0 {
                break;
            }

            match rx_pkt.payload {
                NetlinkPayload::Done(_) => {
                    dump_done = true;
                    break;
                }
                NetlinkPayload::InnerMessage(msg) => {
                    rx_dump.push(msg);
                }
                _ => {}
            }

            offset += rx_pkt.header.length as usize;
        }
    }

    Ok(rx_dump)
}
