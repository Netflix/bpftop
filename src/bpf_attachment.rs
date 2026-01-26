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
use libbpf_rs::{ProgramType, query::{LinkInfo, LinkInfoIter, LinkTypeInfo::*}};
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_MULTIPART, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_route::{
    AddressFamily,
    RouteNetlinkMessage,
    link::{LinkAttribute, LinkMessage}, tc::{TcAttribute, TcBpfFlags, TcFilterBpfOption, TcHandle, TcMessage, TcOption},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use ratatui::{style::Stylize as _, widgets::{Cell, Row}};

use crate::helpers::{attach_type_as_str, link_type_as_str, program_type_as_str};

/// Info on the BPF program attachment.
///
/// Attachment info depends on how the program was attached and it's type.
/// Some attachments do not use BPF links, e.g. TC filter via netlink.
pub(crate) enum BpfAttachment {
    /// BPF programs attached via BPF link.
    BpfLink(LinkInfo),
    /// TC BPF programs attached as TC filter on a clsact qdisc.
    TcFilter {
        ifindex: i32,
        ifname: String,
        direction: &'static str,
        direct_action: bool,
    },
}

impl From<LinkInfo> for BpfAttachment {
    fn from(link_info: LinkInfo) -> Self {
        Self::BpfLink(link_info)
    }
}

impl BpfAttachment {
    /// Render the BPF attachment info into a vstack [`Row`]s component.
    pub(crate) fn render<'a>(self) -> Vec<Row<'a>> {
        let mut vstack = vec![];
        match self {
            Self::BpfLink(link_info) => {
                vstack.push(Row::new([
                    Cell::from("Link ID".bold()),
                    Cell::from(format!("{}: {}", link_info.id.to_string(), link_type_as_str(&link_info.info))),
                ]));

                match link_info.info {
                    RawTracepoint(info) => {
                        vstack.push(Row::new([
                            Cell::from("  Hook".bold()),
                            Cell::from(info.name),
                        ]));
                    }
                    Tracing(info) => {
                        vstack.push(Row::new([
                            Cell::from("  Attach Type".bold()),
                            Cell::from(attach_type_as_str(info.attach_type)),
                        ]));
                    }
                    Cgroup(info) => {
                        vstack.push(Row::new([
                            Cell::from("  Attach Type".bold()),
                            Cell::from(attach_type_as_str(info.attach_type)),
                        ]));
                        vstack.push(Row::new([
                            Cell::from("  Cgroup ID".bold()),
                            Cell::from(info.cgroup_id.to_string()),
                        ]));
                    }
                    Iter => {}
                    NetNs(info) => {
                        vstack.push(Row::new([
                            Cell::from("  Attach Type".bold()),
                            Cell::from(attach_type_as_str(info.attach_type)),
                        ]));
                        vstack.push(Row::new([
                            Cell::from("  Inode".bold()),
                            Cell::from(info.ino.to_string()),
                        ]));
                    }
                    _ => {}
                }
            }
            Self::TcFilter { ifindex, ifname, direction, direct_action } => {
                vstack.push(Row::new([Cell::from("TC Filter".bold())]));

                vstack.push(Row::new([
                    Cell::from("  Interface".bold()),
                    Cell::from(format!("{} ({})", ifname, ifindex)),
                ]));
                vstack.push(Row::new([
                    Cell::from("  Direction".bold()),
                    Cell::from(direction),
                ]));
                vstack.push(Row::new([
                    Cell::from("  Direct Action".bold()),
                    Cell::from(direct_action.to_string()),
                ]));
            }
        }

        vstack
    }
}

/// Collect all attachments used by the BPF program.
pub(crate) fn get_prog_attachments(prog_id: u32, prog_type: &str) -> Result<Vec<BpfAttachment>> {
    // Collect BPF links
    let mut attachments: Vec<BpfAttachment> = LinkInfoIter::default()
        .filter_map(move |link| (link.prog_id == prog_id).then_some(BpfAttachment::from(link)))
        .collect();

    // Collect TC filters
    const SCHED_CLS: &str = program_type_as_str(&ProgramType::SchedCls);
    const SCHED_ACT: &str = program_type_as_str(&ProgramType::SchedAct);
    if matches!(prog_type, SCHED_CLS | SCHED_ACT) {
        attachments.extend(prog_tc_filters(prog_id)?);
    }

    Ok(attachments)
}

// Collect TC filters used by prog.
fn prog_tc_filters(prog_id: u32) -> Result<Vec<BpfAttachment>> {
    let mut sock = Socket::new(NETLINK_ROUTE)?;
    sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0))?;

    let ifaces = get_ifaces(&sock)?;

    const HANDLES: [(TcHandle, &str); 2] = [
        (TcHandle { major: u16::MAX, minor: TcHandle::MIN_INGRESS }, "Ingress"),
        (TcHandle { major: u16::MAX, minor: TcHandle::MIN_EGRESS }, "Egress"),
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

                Some(BpfAttachment::TcFilter { ifindex, ifname: ifname.clone(), direction, direct_action })
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
    // Check that send buffer in is big enough for the packet, other `serialize()` panics.
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
